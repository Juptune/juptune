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
 +  Given a desired length of 1024 bytes, and a page size of 4096 bytes:
 +    - Two guard pages are allocated, one before the user memory, and one after the user memory.
 +    - A page for the user memory is allocated. (1024 < 4096)
 +
 +  The memory layout is as follows:
 +  
 +  ========================================
 +  = Guard Page (1 page)                  =
 +  ========================================
 +  = User Memory (enough pages as needed) =
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
 +  The guard page at the end is... also a guard page - it will crash on access.
 + ++/
struct SecureMemory
{
    import juptune.core.util : Result, resultAssert;

    /++
     + A loose wrapper around a `T[]` that originates from a `SecureMemory` struct.
     +
     + Use this type when you want random length slices, but only from hardened memory.
     +
     + Notes:
     +  A rarity for Juptune - this struct is copyable as there just isn't really a clean way
     +  to enforce that it's not copied outside of the `SecureMemory` struct's lifetime without
     +  it getting in the way.
     +
     +  In case it's not clear. $(B This slice must not outlive the `SecureMemory` struct it came from).
     +
     + Safeguards:
     +  The slice can never be accessed when its unerlying slice is null.
     +
     +  If you're slicing up a bunch of memory, please use `mustNotOverlap` and `mustBeContiguous`
     +  to help ensure you've sliced things correctly.
     + ++/
    static struct Slice(T)
    {
        private
        {
            T[] _memory;

            invariant(_memory !is null, "SecureMemory.Slice is not initialised");
        }

        @nogc nothrow:

        private this(T[] memory) @trusted
        in(memory.length % T.sizeof == 0, "bug: memory length is not a multiple of T.sizeof")
        {
            this._memory = cast(T[])memory;
        }

        inout(T[]) memory() @safe inout
        {
            return this._memory;
        }

        Slice!T opSlice(size_t _)(size_t start, size_t end) return
            => Slice!T(this._memory[start..end]);

        static if(is(T == void))
        {
            Slice!NewT reinterpret(NewT)() @trusted
            {
                return Slice!NewT(cast(NewT[])this._memory);
            }

            const(Slice!NewT) reinterpret(NewT)() @trusted const
            {
                return Slice!NewT(cast(NewT[])this._memory);
            }
        }

        bool mustNotOverlap(scope const Slice!T other) const @trusted
        {
            assert(
                (this._memory.ptr + this._memory.length <= other._memory.ptr) ||
                (other._memory.ptr + other._memory.length <= this._memory.ptr),
                "bug: memory slices overlap"
            );
            return true;
        }

        bool mustBeContiguous(scope const Slice!T other) const @trusted
        {
            assert(
                (this._memory.ptr + this._memory.length == other._memory.ptr) ||
                (other._memory.ptr + other._memory.length == this._memory.ptr),
                "bug: memory slices are not contiguous"
            );
            return true;
        }
    }

    private
    {
        enum CANARY_VALUE = 0xCC;

        void[] _userMemory;
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
     +  func = The delegate to call.
     + ++/
    void access(scope void delegate(scope void[]) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    {
        func(this._userMemory[$-this._userMemoryRequestedSize..$]);
    }

    /// ditto
    void access(scope void delegate(scope void[]) @safe nothrow func) @safe nothrow
    {
        func(this._userMemory[$-this._userMemoryRequestedSize..$]);
    }

    @nogc nothrow:

    ~this() @trusted
    {
        if(this._entireMemory is null)
        {
            assert(this._userMemory is null, "bug: user memory is not null");
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

            if((this._currentProtection & PROT_WRITE) == 0)
            {
                auto result = mprotect(this._userMemory.ptr, this._userMemory.length, PROT_WRITE);
                if(result != 0)
                    linuxErrorAsResult("bug: mprotect failed", errno()).resultAssert;
            }

            (cast(ubyte[])this._userMemory)[] = 0;

            auto result = munlock(this._userMemory.ptr, this._userMemory.length);
            if(result != 0)
                linuxErrorAsResult("bug: munlock failed", errno()).resultAssert;

            result = munmap(this._entireMemory.ptr, this._entireMemory.length);
            if(result != 0)
                linuxErrorAsResult("bug: munmap failed", errno()).resultAssert;
        }

        // Since we don't have any other types with dtors, we can make a simple memory clear.
        (cast(ubyte*)&this)[0..SecureMemory.sizeof] = 0;
    }

    /++
     + Allocates a new SecureMemory struct, with the given length.
     +
     + Notes:
     +  Please see the struct documentation for more information on the memory layout.
     +
     +  A length of 0 is valid, though not really recommended.
     +
     + Params:
     +  memory  = The SecureMemory struct to allocate.
     +  length  = The length of the user memory to allocate.
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
    ) @trusted
    {
        import core.sys.linux.errno         : errno;
        import core.sys.linux.sys.mman      : mmap, munmap, mlock, mprotect, madvise, PROT_READ, PROT_WRITE, 
                                              PROT_NONE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_NORESERVE,
                                              MAP_FAILED, MADV_DONTDUMP;
        import core.sys.posix.unistd        : sysconf, _SC_PAGESIZE;
        import juptune.core.internal.linux  : linuxErrorAsResult;

        const pageSize          = sysconf(_SC_PAGESIZE);
        const userMemorySize    = (length + (pageSize * (length % pageSize > 0))) & ~(pageSize-1); // Round up to a valid page size if not already aligned.
        const totalSize         = userMemorySize + (pageSize * 2);
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
        assert(userMemory.ptr == (entirePtr + pageSize), "bug: user memory does not start at the right address");
        assert(userMemory.ptr + userMemory.length == postGuardPtr, "bug: user memory does not end at the right address"); // @suppress(dscanner.style.long_line)
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

        // Set unused memory to 0xCC, and used memory to 0x00.
        (cast(ubyte[])userMemory[0..$-length])[] = CANARY_VALUE;
        (cast(ubyte[])userMemory[$-length..$])[] = 0x00;

        memory._entireMemory            = entireMemory;
        memory._userMemory              = userMemory;
        memory._preGuardPage            = preGuardPtr;
        memory._postGuardPage           = postGuardPtr;
        memory._userMemoryRequestedSize = length;
        memory._currentProtection       = PROT_READ | PROT_WRITE;

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
     +  `other` must have the same length as this memory.
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
            return sodium_memcmp(this.unsafeSlice.ptr, other.ptr, other.length) == 0;
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

    /++
     + Creates a `SecureMemory.Slice` from the specified memory range.
     +
     + Generally you should use `access` when possible to help prevent use-after-free bugs, but
     + there are normal cases where code needs to access only parts of the secure memory without
     + caring about the struct in its entirety.
     +
     + So to allow code to statically specify that they want a slice of `SecureMemory`, this overload
     + is provided.
     +
     + This is not marked @safe or @trusted since there is no way to prevent the returned slice
     + from outliving the `SecureMemory` struct, so the user code itself can only be @trusted at best.
     + ++/
    Slice!void opSlice(size_t _ = 0)(size_t start, size_t end) return
        => Slice!void(this.unsafeSlice[start..end]);

    /++
     + Slices the memory into the specified slices, ensuring that the slices do not overlap.
     +
     + Assertions:
     +  `lengths` and `slices` must be the same length.
     +
     +  The lengths must all be an exact multiple of `T.sizeof`.
     +
     +  The slices must all be non-null.
     +
     +  The total length of the slices cannot exceed the length of the memory.
     +
     +  Additionally there is an internal numeric overflow check.
     +
     + Notes:
     +  `lengths[0]` matches with `slices[0]`, `lengths[1]` with `slices[1]`, etc...
     +
     + Params:
     +  lengths = The lengths of the slices to create.
     +  slices  = The individual slices to fill out.
     + ++/
    void contigiousSlice(T)(scope const size_t[] lengths, scope Slice!T*[] slices) const @trusted
    in(lengths.length == slices.length, "bug: lengths and slices are not the same length")
    {
        import juptune.core.util : checkedAdd, resultAssert;

        size_t offset = 0;
        foreach(i, length; lengths)
        {
            assert(length % T.sizeof == 0, "bug: length is not a multiple of T.sizeof");
            assert(slices[i] !is null, "bug: slice is null");
            *slices[i] = Slice!void(cast(void[])this.unsafeSlice[offset..offset+length]).reinterpret!T;
            checkedAdd(offset, length, offset).resultAssert;
        }
    }

    alias opDollar = length;

    size_t length() const
    {
        return this._userMemoryRequestedSize;
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
    mem.access((scope voidMem) @trusted @nogc nothrow
    {
        auto memory = cast(ubyte[])voidMem;
        foreach(i, ref b; memory)
            b = cast(ubyte)i;
        assert(memory.length == ubyte.max, "bug: memory length is not correct");
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
}

@("SecureMemory - alloc page size")
version(linux) unittest
{
    import core.sys.posix.unistd : sysconf, _SC_PAGESIZE;

    const pageSize = sysconf(_SC_PAGESIZE);

    SecureMemory mem;
    SecureMemory.allocate(mem, pageSize).resultAssert;
    mem.access((scope voidMem) @trusted @nogc nothrow
    {
        auto memory = cast(ubyte[])voidMem;
        memory[] = 0xFF;
        assert(memory.length == pageSize, "bug: memory length is not correct");
    });

    foreach(i, b; cast(ubyte[])mem.unsafeSlice)
        assert(b == 0xFF, "bug: memory content is not correct");
    assert(mem.unsafeSlice.length == pageSize, "bug: memory length is not correct");
}