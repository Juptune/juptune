/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.ds.string;

import core.stdc.stdlib;

// version = DontUseSSO;
version(X86_64)
{
    version(DontUseSSO)
        private enum UseSSO = false;
    else
        private enum UseSSO = true;
}
else
    private enum UseSSO = false;

struct String
{
    /++
        So, this abuses a few things:
            * Pointers only actually use 48-bits, with the upper 16-bits being sign extended.
            * The 47th bit is pretty much always 0 in user mode, so the upper 16-bits are also 0.
            * Little endian is an important metric for why the pointer is put last, and x86_64 is a little endian architecture.
        For 'small' strings:
            * Bytes 0-22 contain the small string.
            * Byte 23 contains the null terminator (since I want libd's strings to always provide one without reallocation needed - cheaper integration with C libs).
            * Byte 24 contains the 'small' length, which will always be non-0 for small strings.
        For 'big' strings:
            * Bytes 0-8 contain the length.
            * Bytes 8-16 contain the capacity.
            * Bytes 16-24 contain the allocated pointer.
                * Because of little endian, and the fact the upper 16-bits of a pointer will be 0, this sets the 'small' length to 0
                  which we can use as a flag to determine between small and big strings.
        Special case 'empty':
            If the string is completely empty, then Bits 16-24 will be all 0, indicating both that there's no 'small' length, and also a null 'big' pointer.
     + ++/
    private union Store
    {
        struct // smol
        {
            // D chars init to 0xFF (invalid utf-8 character), which we don't want here.
            // Although, because it's in a union, I don't actually know how D inits this memory by default. Better safe than sorry.
            char[22] smallString   = '\0';
            char     smallNullTerm = '\0';
            ubyte    smallLength;
        }

        struct // big
        {
            size_t bigLength;
            size_t bigCapacity;
            char*  bigPtr;
        }
    }
    private Store _store;
    static assert(typeof(this).sizeof == 24, "String isn't 24 bytes anymore :(");

    @nogc nothrow:

    @trusted
    this(scope string str)
    {
        this = str;
    }

    @trusted // Bounds checking + always confirming pointer validity *should* make this safe.
    this(scope const(char)[] str)
    {
        this = str;
    }

    this(scope const char* ptr)
    {
        import core.stdc.string : strlen;
        if(!ptr)
            return;
        const length = strlen(ptr);
        this.put(ptr[0..length]);
    }

    this(scope ref return String src) @trusted
    {
        this._store = src._store;
        if(!this.isCompletelyEmpty && !this.isSmall)
        {
            auto slice = (cast(char*)malloc(this._store.bigLength+1))[0..this._store.bigLength+1]; // We'll just allocate the length and not use Growth or capacity.
            if(slice is null)
                assert(slice.ptr);
            slice[0..$-1] = this._store.bigPtr[0..this._store.bigLength];
            slice[$-1]    = '\0';
            this._store.bigPtr      = slice.ptr;
            this._store.bigLength   = slice.length-1; // Otherwise we include the null term in this value, which we don't do. // @suppress(dscanner.suspicious.length_subtraction)
            this._store.bigCapacity = slice.length-1; // ^^^ // @suppress(dscanner.suspicious.length_subtraction)
        }
    }

    @trusted
    ~this()
    {
        this.disposeBigStringIfExists();
        this._store = Store.init;
    }

    @trusted
    uint toHash()
    {
        import std.digest.murmurhash;

        uint hash;
        MurmurHash3!32 hasher;
        hasher.start();
        hasher.put(cast(const ubyte[])this.range());
        const bytes = hasher.finish();
        hash = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
        return hash;
    }

    @trusted
    void putMany(Params...)(scope Params params)
    {
        foreach(param; params)
            this.put(param);
    }
    
    @trusted // This is technically safe by itself due to all the checks, but `chars` might point to bad memory. Can't express that in D though.
    void put(scope const(char)[] chars)
    {
        auto newLength = chars.length;
        if(this.isSmall)
            newLength += this._store.smallLength;
        else
            newLength += this._store.bigLength;

        if(this.isSmall || this.isCompletelyEmpty)
        {
            if(newLength <= this._store.smallString.length && UseSSO)
            {
                const start = this._store.smallLength;
                this._store.smallString[start..start + chars.length] = chars[0..$];
                this._store.smallLength += chars.length;
                return;
            }

            this.moveToBigString();
        }

        this.growBigStringIfNeeded(newLength+1); // +1 for null term.
        const start = this._store.bigLength;
        this._store.bigPtr[start..start+chars.length] = chars[0..$];
        this._store.bigLength += chars.length;
        this._store.bigPtr[this._store.bigLength] = '\0';
    }

    @trusted
    void put()(scope const auto ref String str)
    {
        this.put(str.slice);
    }

    @trusted
    void put(char ch)
    {
        char[] fakeArray = (&ch)[0..1];
        this.put(fakeArray);
    }

    void put(Range)(Range r)
    if(!is(Range : const(char)[]))
    {
        foreach(value; r)
            this.put(value);
    }

    @trusted
    bool opEquals(scope const(char)[] other) const
    {
        return __equals(this.slice, other);
    }

    @trusted
    bool opEquals()(scope auto ref const String other) const
    {
        return this.slice == other.slice;
    }

    @safe
    bool opEquals(typeof(null) _) const
    {
        return this.isCompletelyEmpty;
    }

    @trusted
    void opAssign(scope const(char)[] str)
    {   
        if(str is null)
            this = null;
        else if(str.length <= this._store.smallString.length && UseSSO)
            this.setSmallString(str);
        else
            this.setBigString(str);
    }

    @trusted
    void opAssign(typeof(null) _)
    {
        this.__xdtor();
    }

    @safe
    size_t opDollar() const
    {
        return this.length;
    }

    @trusted
    const(char)[] opIndex() const
    {
        return this.slice;
    }

    @trusted
    char opIndex(size_t index) const
    {
        assert(index < this.length, "Index is out of bounds.");
        return this.slice[index];
    }

    @trusted // Function is @safe, further usage by user is not.
    const(char)[] opSlice(size_t start, size_t end) const
    {
        assert(end <= this.length, "End index is out of bounds.");
        assert(start <= end, "Start index is greater than End index.");
        return this.slice[start..end];
    }

    @trusted // HEAVILY assumes that the allocated memory is still valid. Since at the moment we always use malloc, this should be guarenteed outside of bugs in this struct.
    void opIndexAssign(char v, size_t index)
    {
        assert(index < this.length, "Index is out of bounds.");
        cast()this.slice[index] = v; // cast away const is fine for internal functions like this.
    }

    @trusted
    void opSliceAssign(char v, size_t start, size_t end)
    {
        auto slice = cast(char[])this[start..end];
        slice[] = v;
    }

    @trusted
    void opSliceAssign(const(char)[] str, size_t start, size_t end)
    {
        auto slice = cast(char[])this[start..end];
        assert(end - start == str.length, "Mismatch between str.length, and (end - start).");
        slice[0..$] = str[0..$];
    }

    @trusted
    String opBinary(string op)(const scope auto ref String rhs) const
    if(op == "~")
    {
        String ret = cast()this; // NRVO better come into play here.
        ret.put(rhs);
        return ret;
    }

    @trusted
    String opBinary(string op)(scope const(char)[] rhs) const
    if(op == "~")
    {
        String ret = cast()this; // NRVO better come into play here.
        ret.put(rhs);
        return ret;
    }

    @trusted
    void opOpAssign(string op)(const scope auto ref String rhs)
    if(op == "~")
    {
        this.put(rhs);
    }

    @trusted
    void opOpAssign(string op)(scope const(char)[] rhs)
    if(op == "~")
    {
        this.put(rhs);
    }

    @property
    const(char)[] range() const
    {
        return this.slice;
    }

    @property @safe
    size_t length() const
    {
        return (this.isSmall) ? this._store.smallLength : this._store.bigLength; 
    }

    @property
    void length(size_t newLen)
    {
        if(this.isCompletelyEmpty && newLen == 0)
            return; // edge case.

        if(this.isSmall && !this.isCompletelyEmpty)
        {
            if(newLen > this._store.smallString.length)
            {
                this.moveToBigString();
                assert(!this.isSmall);
                this.length = newLen; // So we don't have to duplicate logic.
            }
            else
                this._store.smallLength = cast(ubyte)newLen;
            return;
        }

        // Lazy choice: Once we're a big string, we're always a big string.
        //              Will eventually *not* do this, but >x3
        if(newLen > this._store.bigLength)
        {
            const start = this._store.bigLength;
            this.growBigStringIfNeeded(newLen);
            this._store.bigPtr[start..newLen] = char.init;
        }

        this._store.bigLength = newLen;
        this._store.bigPtr[newLen] = '\0';
    }

    @property
    const(char)* ptr() const return
    {
        return (this.isSmall) ? &this._store.smallString[0] : this._store.bigPtr;
    }

    @property
    const(char)[] slice() const return
    {
        return (this.isSmall) 
        ? this._store.smallString[0..this._store.smallLength] 
        : this._store.bigPtr[0..this._store.bigLength];
    }

    @trusted
    private void setSmallString(scope const(char)[] chars)
    {
        version(DontUseSSO)
            assert(false, "This shouldn't have been called, SSO is disabled");
        else
        {
            assert(chars.length <= this._store.smallString.length);
            this.disposeBigStringIfExists(); // Resets us to a "completely empty" state.
            this._store.smallString[0..chars.length] = chars[0..$];
            this._store.smallLength = cast(ubyte)chars.length;
        }
    }

    @trusted
    private void setBigString(scope const(char)[] chars)
    {
        this.growBigStringIfNeeded(chars.length+1); // +1 for null term.
        assert(this._store.smallLength == 0, "Nani?");
        this._store.bigLength               = chars.length;
        this._store.bigPtr[0..chars.length] = chars[0..$];
        this._store.bigPtr[chars.length]    = '\0';
        assert(!this.isSmall, "Eh?");
    }

    @trusted
    private void moveToBigString()
    {
        if(this.isCompletelyEmpty || !this.isSmall)
            return;

        // Have to copy into a buffer first, otherwise setBigString will overwrite the string data before it ends up copying it.
        char[22] buffer;
        buffer[0..$]      = this._store.smallString[0..$];
        const smallLength = this._store.smallLength;
        this.setBigString(buffer[0..smallLength]);
    }

    @trusted
    private void growBigStringIfNeeded(size_t newSize)
    {
        if(this.isCompletelyEmpty || this.isSmall)
        {
            this._store.bigCapacity = newSize * 2;
            this._store.bigPtr      = cast(char*)malloc(this._store.bigCapacity);
            if(this._store.bigPtr is null)
                assert(null);
            return;
        }

        if(newSize > this._store.bigCapacity)
        {
            this._store.bigCapacity = newSize * 2;
            this._store.bigPtr      = cast(char*)realloc(this._store.bigPtr, this._store.bigCapacity);
            if(this._store.bigPtr is null)
                assert(null);
        }
    }

    @trusted
    private void disposeBigStringIfExists()
    {
        if(!this.isCompletelyEmpty && !this.isSmall)
        {
            free(this._store.bigPtr);
            this._store.smallString[] = '\0';
            assert(this.isCompletelyEmpty, "?");
        }
    }

    @trusted
    private bool isCompletelyEmpty() const
    {
        return this._store.bigPtr is null;
    }

    @safe
    private bool isSmall() const
    {
        return this._store.smallLength > 0 && UseSSO;
    }
}
///
@("String")
@nogc nothrow
unittest
{
    auto s = String("Hello");
    assert(s.isSmall || !UseSSO); // .isSmall is a private function
    assert(!s.isCompletelyEmpty); // ^^^
    assert(s.length == 5);
    assert(s == "Hello");
    assert(s.ptr[5] == '\0');

    auto s2 = s;
    assert((s2.isSmall || !UseSSO) && !s2.isCompletelyEmpty);
    assert(s2.length == 5);
    assert(s2 == "Hello");
    s2.put(", world!");
    assert(s2.length == 13);
    assert(s.length == 5);
    assert(s2 == "Hello, world!");
    assert(s2.ptr[13] == '\0');

    s = String("This is a big string that is bigger than 22 characters long!");
    assert(!s.isSmall);
    assert(s.length == 60);
    assert(s == "This is a big string that is bigger than 22 characters long!");
    assert(s.ptr[60] == '\0');

    s2 = s;
    assert(!s2.isSmall);
    assert(s2.length == 60);
    assert(s2._store.bigPtr !is s._store.bigPtr);
    s.__xdtor();
    s2.put("This shouldn't crash because we copied things.");
    assert(s2 == "This is a big string that is bigger than 22 characters long!This shouldn't crash because we copied things."); // @suppress(dscanner.style.long_line)
    assert(s2.ptr[s2.length] == '\0');

    s2.length = 60;
    assert(s2.length == 60);
    assert(s2 == "This is a big string that is bigger than 22 characters long!");
    assert(s2.ptr[60] == '\0');

    s2.length = 61;
    assert(s2 == "This is a big string that is bigger than 22 characters long!"~char.init);
    assert(s2.ptr[61] == '\0');

    // Making sure we don't crash when using any of these things from a .init state.
    s2.__xdtor();
    assert(!s2.isSmall && s2.isCompletelyEmpty);
    assert(s2.ptr is null);
    assert(s2.slice is null);
    assert(s2.length == 0);
    s2.put("abc");
    assert(s2.isSmall || !UseSSO);

    assert(s2 == "abc");
    assert(s2 == String("abc"));
    assert(s2 != null);
    s2 = null;
    assert(s2 == null);

    s2 = "abc";
    assert(s2.isSmall || !UseSSO);
    assert(s2 == "abc");
    assert(s2[1] == 'b');
    assert(s2[0..2] == "ab");
    assert(s2[3..3].length == 0);
    assert(s2[] == "abc");

    s2[1] = 'd';
    assert(s2 == "adc");
    s2[0..2] = 'b';
    assert(s2 == "bbc");
    s2[0..3] = "put";
    assert(s2 == "put");

    assert(s2 ~ "in" == "putin");
    assert(s2 ~ String("ty") == "putty");
    s2 ~= " it ";
    assert(s2 == "put it ");
    s2 ~= String("in mah belleh");
    assert(s2 == "put it in mah belleh");
}

@("String - length = 0 edge case")
unittest
{
    String s;
    s.length = 0; // Shouldn't crash.
}