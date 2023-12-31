/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.memory;

/++
 + Memory for sensitive data - hardened using OS memory protection mechanisms, as well
 + as providing constant-time operations to help mitigate timing attacks.
 +
 + Performance:
 +  Please note that this struct has to make a _lot_ of syscalls, and is therefore
 +  pretty slow compared to general-purpose memory, especially due to mmap and munmap.
 +
 +  You should only use this for secret data, and potentially setup something like an object pool to
 +  reuse the memory if you need to do a lot of operations on it, as even deallocation
 +  is slow.
 +
 +  Kind reminder to never let performance get in the way of security - benchmark results
 +  matter a lot less than security results.
 +
 + Technical:
 +  This struct directly uses mmap and munmap for memory allocation and deallocation.
 +
 +  The user memory range is locked in RAM using mlock, so that it probably won't be swapped;
 +  it is also marked as MADV_DONTDUMP, so that it probably won't be dumped to disk e.g. by a core dump.
 +
 +  More minorly, the memory is also marked as MADV_WIPEONFORK, so that it is wiped on fork,
 +  in case you use fork() + Juptune for some reason (which isn't supported anyway, btw)
 +
 +  Given a desired length of 1024 bytes; a page size of 4096 bytes; and a padding of 32 bytes:
 +    - Two guard pages are allocated, one before the user memory, and one after the user/padding memory.
 +    - A page for the user memory is allocated. (1024 < 4096)
 +    - A page for the padding is allocated. (32 < 4096)
 +
 +  The memory layout is as follows:
 +  
 +  ========================================
 +  = Guard Page (1 page)                  =
 +  ========================================
 +  = User Memory (enough pages as needed) =
 +  ========================================
 +  = Padding (enough pages as needed)     =
 +  ========================================
 +  = Guard Page (1 page)                  =
 +  ========================================
 +
 +  The guard pages are guard pages - they will crash on access.
 +
 +  The user memory is a set of (by default) read/write pages. The slice returned to the user
 +  ends at the very last page, so that any overflow will be caught by the guard page.
 +
 +  The start of the user memory therefore is unused by the user. This is filled with a canary
 +  value of 0xCC, which is checked on deallocation to ensure that no data has underflowed out
 +  of the user memory.
 +
 +  The padding, if any, is a set of read-only pages. The first byte is set to 0x80, which is
 +  the ISO/IEC 7816-4 value for padding. The padding is in its own page so that it can be set
 +  to read-only independently of the user memory, as, outside of encryption, this memory should
 +  never be mutated by the user directly.
 +
 +  The guard page at the end is... also a guard page - it will crash on access.
 + ++/
struct SecureMemory
{
    import juptune.core.util : Result, resultAssert;

    private
    {
        enum CANARY_VALUE = 0xCC;

        void[] _userMemory;
        void[] _userAndPaddingMemory;
        void[] _entireMemory;
        void*  _preGuardPage;
        void*  _postGuardPage;

        int    _currentProtection;
        size_t _userMemoryRequestedSize;

        invariant(_entireMemory !is null, "SecureMemory is not initialised");
        invariant(_userMemory !is null, "SecureMemory is not initialised");
        invariant(_userMemoryRequestedSize <= _userMemory.length, "bug: user memory requested size is larger than user memory length"); // @suppress(dscanner.style.long_line)
    }

    @disable this(this){}

    /++
     + Provides a safe(ish) way to access the underlying user memory.
     +
     + Notes:
     +  This wrapper function is used to help enforce the `scope` attribute.
     +
     +  You'll probably have to mark your delegate `@trusted`, just be wary this prevents
     +  `scope` from being checked by the compiler.
     +
     +  D's compiler is god awful when it comes to error messages, so you may want to store
     +  `func` inside a variable first to see what's going wrong with it.
     +
     + Params:
     +  func - The delegate to call. It will be passed two slices, the first being the user memory,
     +         and the second being the user memory including the padding (if any).
     + ++/
    void access(scope void delegate(scope void[], scope const void[] withPadding) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    {
        func(this._userAndPaddingMemory[0..this._userMemoryRequestedSize], this._userAndPaddingMemory);
    }

    /// ditto
    void access(scope void delegate(scope void[], scope const void[] withPadding) @safe nothrow func) @safe nothrow
    {
        func(this._userAndPaddingMemory[0..this._userMemoryRequestedSize], this._userAndPaddingMemory);
    }

    @nogc nothrow:

    ~this() @trusted
    {
        if(this._entireMemory is null)
        {
            assert(this._userMemory is null, "bug: user memory is not null");
            assert(this._userAndPaddingMemory is null, "bug: padding is not null");
            assert(this._preGuardPage is null, "bug: pre guard page is not null");
            assert(this._postGuardPage is null, "bug: post guard page is not null");
            return;
        }

        // Check that the canary value is intact.
        import std.algorithm : all;
        assert(
            (cast(ubyte[])this._userMemory[0..$-this._userMemoryRequestedSize]).all!(b => b == CANARY_VALUE), 
            "bug: canary value is not correct - something underflowed out of the user memory"
        );

        // Unmap the memory.
        version(linux)
        {
            import core.sys.linux.errno        : errno;
            import core.sys.linux.sys.mman     : munmap, munlock, mprotect, PROT_WRITE;
            import juptune.core.internal.linux : linuxErrorAsResult;

            auto result = munlock(this._userMemory.ptr, this._userMemory.length);
            if(result != 0)
                linuxErrorAsResult("bug: munlock failed", errno()).resultAssert;

            if((this._currentProtection & PROT_WRITE) == 0)
            {
                result = mprotect(this._userMemory.ptr, this._userMemory.length, PROT_WRITE);
                if(result != 0)
                    linuxErrorAsResult("bug: mprotect failed", errno()).resultAssert;
            }

            (cast(ubyte[])this._userMemory)[] = 0;

            result = munmap(this._entireMemory.ptr, this._entireMemory.length);
            if(result != 0)
                linuxErrorAsResult("bug: munmap failed", errno()).resultAssert;
        }

        // Since we don't have any other types with dtors, we can make a simple memory clear.
        (cast(ubyte*)&this)[0..SecureMemory.sizeof] = 0;
    }

    /++
     + Allocates a new SecureMemory struct, with the given length, with some additional padding
     + if desired.
     +
     + Notes:
     +  Please see the struct documentation for more information on the memory layout.
     +
     +  If the length is already a multiple of the pad boundary, padding will still be added as
     +  a state of "no padding" is not supported outside of setting the pad boundary to 0.
     +
     +  A length of 0 is valid, though not really recommended.
     +
     + Params:
     +  memory      = The SecureMemory struct to allocate.
     +  length      = The length of the user memory to allocate.
     +  padBoundary = The boundary to align the padding to. If 0, no padding will be added.
     +
     + Throws:
     +  If any of the syscalls fail, a Result will be thrown with the OS error code + message.
     +
     + Returns:
     +  Result.noError on success, or an error otherwise.
     + ++/
    version(linux) static Result allocate(
        scope out SecureMemory memory, 
        size_t length,
        size_t padBoundary = 0,
    ) @trusted
    {
        import core.sys.linux.errno         : errno;
        import core.sys.linux.sys.mman      : mmap, munmap, mlock, mprotect, madvise, PROT_READ, PROT_WRITE, 
                                              PROT_NONE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_NORESERVE,
                                              MAP_FAILED, MADV_DONTDUMP;
        import core.sys.posix.unistd        : sysconf, _SC_PAGESIZE;
        import juptune.core.internal.linux  : linuxErrorAsResult;

        const minPadding = 
            (padBoundary == 0) ? 0 
                : (length % padBoundary == 0)
                    ? padBoundary
                    : padBoundary - (length % padBoundary);

        const pageSize          = sysconf(_SC_PAGESIZE);
        const paddingSize       = (minPadding + (pageSize * (minPadding % pageSize > 0))) & ~(pageSize-1); // Round up to a valid page size if not already aligned.
        const userMemorySize    = (length + (pageSize * (length % pageSize > 0))) & ~(pageSize-1); // Round up to a valid page size if not already aligned.
        const totalSize         = userMemorySize + (pageSize * 2) + paddingSize;
        assert(userMemorySize % pageSize == 0, "bug: user memory size is not page aligned");
        assert(totalSize % pageSize == 0, "bug: total size is not page aligned");

        auto entirePtr = mmap(
            null,
            totalSize,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0
        );
        if(entirePtr is MAP_FAILED)
            return linuxErrorAsResult("Failed to map memory", errno());

        auto entireMemory   = entirePtr[0..totalSize];
        auto preGuardPtr    = entirePtr;
        auto postGuardPtr   = (entirePtr + totalSize) - pageSize;
        auto userMemory     = (entirePtr + pageSize)[0..userMemorySize];
        auto paddingMemory  = (entirePtr + pageSize + userMemorySize)[0..paddingSize];
        assert(userMemory.ptr == (entirePtr + pageSize), "bug: user memory does not start at the right address");
        assert(userMemory.ptr + userMemory.length == paddingMemory.ptr, "bug: user memory does not end at the right address"); // @suppress(dscanner.style.long_line)
        assert(paddingMemory.ptr + paddingMemory.length == postGuardPtr, "bug: padding memory does not end at the right address"); // @suppress(dscanner.style.long_line)
        assert(postGuardPtr + pageSize == entireMemory.ptr + entireMemory.length, "bug: post guard page does not end at the right address"); // @suppress(dscanner.style.long_line)

        bool unmapOnExit = true;
        scope(exit) if(unmapOnExit) // So we don't accidentally leak memory on failure.
            munmap(entirePtr, totalSize);

        auto result = mprotect(preGuardPtr, pageSize, PROT_NONE);
        if(result != 0)
            return linuxErrorAsResult("Failed to protect pre guard page", errno());

        result = mprotect(postGuardPtr, pageSize, PROT_NONE);
        if(result != 0)
            return linuxErrorAsResult("Failed to protect post guard page", errno());

        result = madvise(entirePtr, totalSize, MADV_DONTDUMP);
        if(result != 0)
            return linuxErrorAsResult("Failed to set MADV_DONTDUMP", errno());

        enum MADV_WIPEONFORK = 18; // D's bindings being incomplete as usual.
        result = madvise(entirePtr, totalSize, MADV_WIPEONFORK);
        if(result != 0)
            return linuxErrorAsResult("Failed to set MADV_WIPEONFORK", errno());

        result = mlock(userMemory.ptr, userMemory.length);
        if(result != 0)
            return linuxErrorAsResult("Failed to lock memory", errno());

        if(paddingMemory.length > 0)
        {
            (cast(ubyte[])paddingMemory)[0] = 0x80; // ISO/IEC 7816-4
            result = mprotect(paddingMemory.ptr, paddingMemory.length, PROT_READ);
            if(result != 0)
                return linuxErrorAsResult("Failed to protect padding memory", errno());
        }

        // Set unused memory to 0xCC, and used memory to 0x00.
        (cast(ubyte[])userMemory[0..$-length])[] = CANARY_VALUE;
        (cast(ubyte[])userMemory[$-length..$])[] = 0x00;

        memory._entireMemory            = entireMemory;
        memory._userMemory              = userMemory;
        memory._preGuardPage            = preGuardPtr;
        memory._postGuardPage           = postGuardPtr;
        memory._userMemoryRequestedSize = length;
        memory._currentProtection       = PROT_READ | PROT_WRITE;
        memory._userAndPaddingMemory    = userMemory.ptr[
            (userMemory.length - length)
            ..
            userMemory.length + minPadding
        ];

        unmapOnExit = false;
        return Result.noError;
    }

    import core.sys.linux.sys.mman : PROT_NONE, PROT_READ, PROT_WRITE;
    alias makeReadWrite = setProtection!(PROT_READ | PROT_WRITE); /// Sets the memory to read/write.
    alias makeWriteOnly = setProtection!(PROT_WRITE); /// Sets the memory to write-only.
    alias makeReadOnly  = setProtection!(PROT_READ); /// Sets the memory to read-only.
    alias makeNoAccess  = setProtection!(PROT_NONE); /// Sets the memory to no access.
    private version(linux) Result setProtection(int Flags)() @trusted
    {
        import core.sys.linux.errno        : errno;
        import core.sys.linux.sys.mman     : mprotect;
        import juptune.core.internal.linux : linuxErrorAsResult;

        if(this._currentProtection == Flags)
            return Result.noError;

        auto result = mprotect(this._userMemory.ptr, this._userMemory.length, Flags);
        if(result != 0)
            return linuxErrorAsResult("Failed to change memory protection", errno());

        this._currentProtection = Flags;
        return Result.noError;
    }

    /++
     + Compares this memory to another memory in constant time for the given length of this
     + memory.
     +
     + Assertions:
     +  `other` must have the same length as this memory, not including any padding from this memory.
     +  There is no valid usecase for comparing secure memory of different lengths.
     +
     + Notes:
     +  You should always use this function if `other` contains sensitive data. Failure
     +  to do so opens you up to timing attacks.
     +
     + Params:
     +  other = The memory to compare to.
     +
     + Returns:
     +  true if the memory is equal, false otherwise.
     + ++/ 
    bool constantTimeCompare(const scope void[] other) const @trusted
    in(other.length == this._userMemoryRequestedSize, "bug: this function should never be called for data with different lengths") // @suppress(dscanner.style.long_line)
    {
        // While the code body for a constant-time compare is simple, I completely lack the knowledge
        // required to safely navigate compiler and linker optimisations, both of which could easily
        // break the constant-time property of this function.
        //
        // So until/if I ever bother to look into this properly, I'm just going to use libsodium's
        // implementation - unideal because I want as much of the code to be in D as possible, but
        // this is something I don't want to get wrong.

        version(Juptune_LibSodium)
        {
            import juptune.crypto.libsodium : sodium_memcmp;
            return sodium_memcmp(this._userAndPaddingMemory.ptr, other.ptr, other.length) == 0;
        }
        else assert(false, "Not implemented - no crypto implementation was chosen at build time");
    }

    /// ditto.
    bool constantTimeCompare(const scope ref SecureMemory other) const @trusted
    {
        return this.constantTimeCompare(other.unsafeSlice);
    }

    /// Unless you realllllly need this, just use `access` or `constantTimeCompare` instead.
    inout(void)[] unsafeSlice() inout
    {
        return this._userMemory[$-this._userMemoryRequestedSize..$];
    }
}

/++++ Tests ++++/

version(unittest) import juptune.core.util : resultAssert;

@("SecureMemory - allocate + dtor")
unittest
{
    // Testing that: allocate doesn't crash; we can access the entire requested range; dtor doesn't crash.
    SecureMemory mem;
    SecureMemory.allocate(mem, ubyte.max).resultAssert;
    mem.access((scope voidMem, scope withPadding) @trusted @nogc nothrow
    {
        auto memory = cast(ubyte[])voidMem;
        foreach(i, ref b; memory)
            b = cast(ubyte)i;
        assert(memory.length == ubyte.max, "bug: memory length is not correct");
        assert(withPadding.length == voidMem.length, "bug: there shouldn't be any padding");
    });

    auto array = new ubyte[ubyte.max];
    foreach(i; 0..array.length)
        array[i] = cast(ubyte)i;

    assert(mem.constantTimeCompare(array), "bug: memory content is not correct");
    assert(mem.unsafeSlice.length == ubyte.max, "bug: memory length is not correct");
}

@("SecureMemory - alloc 0")
unittest
{
    SecureMemory mem;
    SecureMemory.allocate(mem, 0).resultAssert;
    assert(mem._userMemory.length == 0, "bug: user memory length is not correct");
    assert(mem._userAndPaddingMemory.length == 0, "bug: there shouldn't be any padding");
}

@("SecureMemory - alloc page size")
version(linux) unittest
{
    import core.sys.posix.unistd : sysconf, _SC_PAGESIZE;

    const pageSize = sysconf(_SC_PAGESIZE);

    SecureMemory mem;
    SecureMemory.allocate(mem, pageSize).resultAssert;
    mem.access((scope voidMem, scope withPadding) @trusted @nogc nothrow
    {
        auto memory = cast(ubyte[])voidMem;
        memory[] = 0xFF;
        assert(memory.length == pageSize, "bug: memory length is not correct");
        assert(withPadding.length == voidMem.length, "bug: there shouldn't be any padding");
    });

    foreach(i, b; cast(ubyte[])mem.unsafeSlice)
        assert(b == 0xFF, "bug: memory content is not correct");
    assert(mem.unsafeSlice.length == pageSize, "bug: memory length is not correct");
}

@("SecureMemory - padding, when length is already aligned")
unittest
{
    SecureMemory mem;
    SecureMemory.allocate(mem, 32, 32).resultAssert;
    mem.access((scope voidMem, scope withPadding) @trusted @nogc nothrow
    {
        assert(voidMem.ptr is withPadding.ptr, "bug: memory does not start at the right address");
        assert(voidMem.length == 32, "bug: memory length is not correct");
        assert(withPadding.length == 64, "bug: padding length is not correct");
    });
}

@("SecureMemory - padding, when length is not aligned")
unittest
{
    SecureMemory mem;
    SecureMemory.allocate(mem, 16, 32).resultAssert;
    mem.access((scope voidMem, scope withPadding) @trusted @nogc nothrow
    {
        assert(voidMem.ptr is withPadding.ptr, "bug: memory does not start at the right address");
        assert(voidMem.length == 16, "bug: memory length is not correct");
        assert(withPadding.length == 32, "bug: padding length is not correct");
    });
}

@("SecureMemory - padding, when length is 0")
unittest
{
    SecureMemory mem;
    SecureMemory.allocate(mem, 0, 32).resultAssert;
    mem.access((scope voidMem, scope withPadding) @trusted @nogc nothrow
    {
        assert(voidMem.ptr is withPadding.ptr, "bug: memory does not start at the right address");
        assert(voidMem.length == 0, "bug: memory length is not correct");
        assert(withPadding.length == 32, "bug: padding length is not correct");
    });
}