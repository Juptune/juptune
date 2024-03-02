module juptune.core.ds.string2;

struct String2
{
    import std.range : isInputRange, ElementEncodingType;
    import std.traits : isInstanceOf, Unqual;
    import juptune.core.ds : ArrayBase;

    private static struct OpSlice { size_t start; size_t end; }

    private static struct Payload
    {
        uint refCount;
        size_t length;
        // Rest of the memory is the string data

        static Payload* create(size_t length) @trusted @nogc nothrow
        {
            import core.stdc.stdlib : malloc;
            import core.stdc.string : memset;
            import juptune.core.util : checkedAdd, resultAssert;

            size_t allocSize = length;
            checkedAdd(allocSize, Payload.sizeof + 1, allocSize).resultAssert; // + 1 for null terminator

            Payload* payload = cast(Payload*)malloc(allocSize);
            assert(payload !is null, "Memory allocation failed");
            payload.refCount = 1;
            payload.length = length;

            scope slice = payload.slice;
            memset(slice.ptr, char.init, slice.length);
            *(slice.ptr + slice.length + 1) = 0; // Null terminator
            return payload;
        }

        Payload* clone(size_t newLen) @trusted @nogc nothrow const
        in(newLen >= this.length, "New length is smaller than the old length")
        {
            Payload* payload = Payload.create(newLen);
            payload.slice[0..this.length] = this.sliceConst[0..this.length];
            return payload;
        }

        void destroy() @trusted @nogc nothrow
        {
            import core.stdc.stdlib : free;
            free(&this);
        }

        void acquire() @safe @nogc nothrow
        in(refCount < uint.max, "Reference count overflow")
        {
            refCount++;
        }

        void release() @safe @nogc nothrow
        in(refCount > 0, "Reference count underflow")
        {
            if(--refCount == 0)
                this.destroy();
        }

        char[] slice() @trusted @nogc nothrow
        in(this.refCount > 0, "String2 is not initialized")
        out(slice; slice.ptr !is null && slice.length == this.length)
        {
            return ((cast(char*)&this) + Payload.sizeof)[0..this.length];
        }

        const(char)[] sliceConst() @trusted @nogc nothrow const
        in(this.refCount > 0, "String2 is not initialized")
        out(slice; slice.ptr !is null && slice.length == this.length)
        {
            return ((cast(char*)&this) + Payload.sizeof)[0..this.length];
        }
    }

    private
    {
        enum SSO_OVERHEAD_BYTES = 1;
        union
        {
            // Big string
            struct 
            {
                Payload* _payload;
                size_t   _length;
                ubyte[size_t.sizeof - SSO_OVERHEAD_BYTES] _unused; 
            }

            // Small string
            struct
            {
                char[(size_t.sizeof*3) - SSO_OVERHEAD_BYTES] _ssoData;
            }
        }
        ubyte _ssoLength; // NOTE: >= 0 means small string. > than _ssodata.length means big string.
    }

    auto access(RetT)(scope RetT delegate(scope const(char)[]) @safe accessor) @trusted
    {
        static if(is(RetT == void))
            accessor(this.slice);
        else
            return accessor(this.slice);
    }

    auto access(RetT)(scope RetT delegate(scope const(char)[]) @safe @nogc nothrow accessor) @trusted @nogc nothrow
    {
        static if(is(RetT == void))
            accessor(this.slice);
        else
            return accessor(this.slice);
    }

    @nogc nothrow:

    // Immutable is incompatible with ref counting.
    // Immutable strings may exist in read-only memory, and thus cannot be circumvented like const strings.
    @disable this(scope ref return immutable String2 other);

    this(scope ref return const String2 other) @trusted
    {
        if(this._payload !is null)
            this.__xdtor();

        if(other.isBig)
        {
            // While we _are_ casting away the payload's const, due to our usage of
            // the underlying memory, `other` is technically left unmodified.
            this.markBig();
            this._payload = cast(Payload*)other._payload;
            this._length = other._length;

            if(this._payload !is null)
                this._payload.acquire();
        }
        else
        {
            this._ssoLength = other._ssoLength;
            this._ssoData = other._ssoData;
        }
    }

    ~this() @trusted
    {
        if(this.isBig && this._payload !is null)
            this._payload.release();

        (cast(ubyte*)(&this))[0..String2.sizeof] = 0;
    }

    this(scope const(char)[] str) @safe
    {
        if(str.length <= this._ssoData.length)
            this.setupSmallString(str);
        else
            this.setupBigString(str);
    }

    this(RangeT)(scope RangeT range)
    if(isInputRange!RangeT && is(ElementEncodingType!RangeT == char))
    {
        import std.range : walkLength;

        const len = range.walkLength;
        char[] str;
        if(len <= this._ssoData.length)
        {
            this._ssoLength = cast(ubyte)len;
            str = this._ssoData[0..len];
        }
        else
        {
            this.markBig();
            this._payload = Payload.create(len);
            this._length = len;
            str = this._payload.slice;
        }

        foreach(ref c; str)
            c = range.front;
    }

    static String2 fromDestroyingArray(ArrayT)(scope ref ArrayT arr)
    if(isInstanceOf!(ArrayBase, ArrayT) && is(ArrayT.ValueT == char))
    {
        auto ret = String2(arr[]);
        arr.__xdtor();
        return ret;
    }

    const(OpSlice) opSlice(size_t start, size_t end) @safe const
    in(start <= end, "Start index is greater than end index")
    in(end <= this.length, "End index is greater than the string length")
    {
        return OpSlice(start, end);
    }

    String2 opIndex(const OpSlice slice) @trusted const
    {
        if(slice.start > 0)
            return String2(this.sliceMaybeFromStack()[slice.start..slice.end]);

        if(slice.end == 0)
            return String2.init;

        String2 ret = this;
        ret._length = slice.end;
        return ret;
    }

    char opIndex(const size_t index) @trusted const
    in(index < this.length, "Index is out of bounds")
    {
        return this.sliceMaybeFromStack()[index];
    }

    template opBinary(string op)
    if(op == "~")
    {
        String2 opBinary(scope const(char)[] rhs) @trusted const
        {
            String2 ret;
            const newLen = this.length + rhs.length;
            
            if(!this.isBig && newLen <= this._ssoData.length)
            {
                ret._ssoLength = cast(ubyte)newLen;
                ret._ssoData[0..this._ssoLength] = this.sliceMaybeFromStack[0..$];
                ret._ssoData[this._ssoLength..newLen] = rhs;
                return ret;
            }

            ret.markBig();
            ret._payload = Payload.create(newLen);
            ret._payload.slice[0..this._length] = this.sliceMaybeFromStack[0..$];
            ret._payload.slice[this._length..newLen] = rhs[0..$];
            ret._length = newLen;

            return ret;
        }

        String2 opBinary(scope const String2 rhs) @trusted const 
            => this ~ rhs.sliceMaybeFromStack();

        String2 opBinary(scope const ref String2 rhs) @trusted const 
            => this ~ rhs.sliceMaybeFromStack();
    }
    private alias _opCat = opBinary!"~";

    template opOpAssign(string op)
    if(op == "~")
    {
        void opOpAssign(scope const(char)[] rhs) @trusted
        {
            const newLen = rhs.length;

            if(!this.isBig && newLen <= this._ssoData.length)
            {
                this._ssoData[this._ssoLength..newLen] = rhs;
                this._ssoLength = cast(ubyte)newLen;
                return;
            }

            this.moveToBigString();
            this._payload.slice[this._length..newLen] = rhs[0..$];
            this._length = newLen;
        }

        void opOpAssign(scope const String2 rhs) @trusted
        {
            this = this ~ rhs.sliceMaybeFromStack();
        }

        void opOpAssign(scope const ref String2 rhs) @trusted
        {
            this = this ~ rhs.sliceMaybeFromStack();
        }
    }
    private alias _opCatAssign = opOpAssign!"~";

    bool opEquals(scope const(char)[] rhs) @trusted const
    {
        if(this.length != rhs.length)
            return false;

        return this.sliceMaybeFromStack() == rhs;
    }

    bool opEquals(scope const String2 rhs) @trusted const
        => this.sliceMaybeFromStack() == rhs.sliceMaybeFromStack();

    bool opEquals(scope const ref String2 rhs) @trusted const
        => this.sliceMaybeFromStack() == rhs.sliceMaybeFromStack();

    void opAssign(CtorParam)(scope CtorParam param) @trusted
    if(!is(Unqual!CtorParam == String2))
    {
        this = String2(param);
    }

    uint toHash() @trusted const
    {
        import std.digest.murmurhash;
        MurmurHash3!32 hasher;
        hasher.start();
        hasher.put(cast(ubyte[])this.sliceMaybeFromStack());

        const bytes = hasher.finish();
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
    }

    const(char)[] sliceMaybeFromStack() const
    {
        return this.isBig ? this._payload.sliceConst : this._ssoData[0..this._ssoLength];
    }

    const(char)[] slice()
    {
        // Force us to be a big string so we're not providing a slice onto the stack.
        if(!this.isBig && this._ssoLength == 0)
            return null;

        this.moveToBigString();
        return this._payload.slice;
    }

    size_t length() @safe const
    {
        return this.isBig ? this._length : this._ssoLength;
    }
    alias opDollar = length;

    private bool isBig() @safe const
    {
        return this._ssoLength > this._ssoData.length;
    }

    private void markBig() @safe
    {
        this._ssoLength = ubyte.max;
    }

    private void moveToBigString() @trusted
    {
        if(!this.isBig)
        {
            auto copy = this._ssoData;
            this._payload = Payload.create(this._ssoLength);
            this._length = this._ssoLength;
            this._payload.slice[0..this._ssoLength] = copy[0..this._ssoLength];
            this.markBig();
        }
    }

    private void setupSmallString(scope const(char)[] str) @trusted
    in(str.length <= this._ssoData.length, "String2 is not large enough to hold the string")
    {
        this._ssoLength = cast(ubyte)str.length;
        this._ssoData[0..str.length] = str;
    }

    private void setupBigString(scope const(char)[] str) @trusted
    {
        this.markBig();
        this._payload = Payload.create(str.length);
        this._length = str.length;
        this._payload.slice[0..str.length] = str;
    }
}
static assert(String2.sizeof == size_t.sizeof * 3, "String2 is not the expected size");

/++++ Unittests ++++/

@("String2 - .init behaviour")
unittest
{
    String2 str;
    str.__xdtor(); // Make sure dtor doesn't crash
    assert(str.length == 0);
    assert(str.slice is null);
    assert(str.sliceMaybeFromStack.length == 0);
    assert(str == str);
}

@("String2 - ctor")
unittest
{
    import std.algorithm : equal;
    import std.array     : array;
    import std.range     : repeat;

    // Test for small string
    foreach(i; 0..(String2.sizeof - String2.SSO_OVERHEAD_BYTES) + 1)
    {
        auto str = String2(repeat('a', i));
        assert(!str.isBig);
        assert(str.length == i);
        assert(str.sliceMaybeFromStack.equal(repeat('a', i)));
    }

    // Test for big string (use char[] overloads for testing as well)
    const input = 'a'.repeat(String2.sizeof).array;
    auto str = String2(input);
    assert(str.isBig);
    assert(str.length == String2.sizeof);
    assert(str == input);

    // Make sure dtor cleans up
    str.__xdtor();
    assert(str == String2.init);

    // Test fromDestroyingArray
    import juptune.core.ds : Array;
    Array!char arr;
    arr.put("abc123");
    str = String2.fromDestroyingArray(arr);
    assert(arr.length == 0);
    assert(str == "abc123");
}