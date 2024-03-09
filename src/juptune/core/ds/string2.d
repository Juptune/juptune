module juptune.core.ds.string2;

/++ 
 + An immutable string implemenetation with small string optimization, focused on making
 + it safe and efficient to pass around a string by value by trading off the ability to
 + mutate the string.
 +
 + This struct is **not** thread safe.
 +
 + Design:
 +  This struct will apply small string optimization (SSO) to store small strings in the
 +  struct itself, and will allocate memory for larger strings (or under specific conditions).
 +
 +  The SSO length will be ((void*).sizeof * 3) - 1, which is 23 bytes on x86_64 for example.
 +
 +  This struct contains a ref counted payload, which is shared amongst copies of this struct.
 +  This is to make it very easy to pass the struct around without worrying about allocations.
 +
 +  This struct will never expose a mutable slice to the underlying memory, as it is assumed
 +  thet the string has already been fully constructed.
 +
 +  While this struct does provide a concat operation, it will always create a copy of the
 +  string, and thus is very inefficient for large strings. This is by design, use `Array!char` instead.
 +
 +  To help avoid the need to provide direct access to the underlying slice (and risking escape),
 +  this struct attempts to provide enough operator overloads to make it easy to work with, for things
 +  like "String2 == char[]" operations.
 +
 +  Additionally there are 3 different ways to access the underlying slice, depending on use case and
 +  safety concerns: (`String2.slice`, `String2.sliceMaybeFromStack`, `String2.access`), as well as
 +  a safer but more limited way via the `String2.range` function.
 +
 +  In the rare instances you need to pass the slice to a native C function, please note that
 +  the underlying memory is null terminated (but not subslices of the payload).
 +
 + Performance:
 +  Not yet measured to any reasonable degree, however logically it should be much more efficient than
 +  the previous implementation which would do a full copy on every struct copy, and had gaping memory
 +  safety holes.
 +
 + Safety:
 +  The assumption is that any operation self contained within the struct's code is @safe,
 +  and any operation that requires the underlying slice to be exposed is to be explicitly marked
 +  as @trusted by the caller.
 +
 +  This struct is only safe to move as long as there's no living slices to the string's SSO buffer.
 + ++/
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
            *(slice.ptr + slice.length) = 0; // Null terminator
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

    /++
     + A safer-ish way to access the underlying slice, by forcing it to go through a scoped delegate.
     +
     + This should be preferred over `String2.slice` when the underlying slice needs to be accessed,
     + as it helps to ensure that the slice is not leaked.
     +
     + Notes:
     +  Under the hood this function calls `slice`, which will force the string to become allocated
     +  on the heap if small string optimization is in use. This is extra security to help prevent
     +  stack corruption.
     +
     + Params:
     +  RetT     = The return type of the accessor delegate, can be `void`.
     +  accessor = The delegate to access the underlying slice.
     +
     + Returns:
     +  Anything returned by the accessor delegate if `RetT` is not `void`.
     + ++/
    auto access(RetT)(scope RetT delegate(scope const(char)[]) @safe accessor) @trusted
    {
        static if(is(RetT == void))
            accessor(this.slice);
        else
            return accessor(this.slice);
    }

    /// ditto.
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

    /// Copy ctor - either increases the payload's ref count, or copies the small string into the stack buffer.
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

    /++
     + Basic ctor that will copy the given string.
     +
     + Notes:
     +  If possible, the string will be copied into the stack buffer (small string optimisation),
     +  otherwise it will be allocated on the heap.
     +
     + Params:
     +  str = The string to copy.
     + ++/
    this(scope const(char)[] str) @safe
    {
        if(str.length <= this._ssoData.length)
            this.setupSmallString(str);
        else
            this.setupBigString(str);
    }

    /++
     + Basic ctor that will copy the given char-based InputRange into the string.
     +
     + Notes:
     +  The range will be walked twice in total, once to get the length, and once to copy the data.
     +  If your range can only be walked once, use `Array!char.put` instead, and then convert it into a string
     +  using `String2.fromDestroyingArray`.
     +
     +  If possible, the string will be copied into the stack buffer (small string optimisation),
     +
     + Params:
     +  RangeT = The type of the range to copy.
     + ++/
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

    /++
     + A named constructor for `String2` that will convert the given char-based `Array` into a string,
     + and then destroy the array, effectively "moving" the array into a string.
     +
     + Notes:
     +  At some point in the future I will implement an optimisation to make sure the array's memory
     +  doesn't need to be copied, but for now it's just a simple alloc + copy, and is no different
     +  than just passing the char slice to the `String2` ctor.
     +
     +  If possible, the string will be copied into the stack buffer (small string optimisation).
     +
     +  If it wasn't clear, `arr` will have its dtor called, as the planned optimisation will require
     +  transfer of owernship of the array's underlying memory.
     +
     + Params:
     +  arr = The array to convert into a string.
     +
     + Returns:
     +  The string that was created from the array.
     + ++/
    static String2 fromDestroyingArray(ArrayT)(scope ref ArrayT arr)
    if(isInstanceOf!(ArrayBase, ArrayT) && is(ArrayT.ValueT == char))
    {
        auto ret = String2(arr[]);
        arr.__xdtor();
        return ret;
    }

    // TODO: Document this once I figure out why the compiler isn't doing what the spec says it should.
    const(OpSlice) opSlice(size_t start, size_t end) @safe const
    in(start <= end, "Start index is greater than end index")
    in(end <= this.length, "End index is greater than the string length")
    {
        return OpSlice(start, end);
    }

    // TODO: Document this once I figure out why the compiler isn't doing what the spec says it should.
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

    /// Simple [] operator to access the character at the given index.
    char opIndex(const size_t index) @trusted const
    in(index < this.length, "Index is out of bounds")
    {
        return this.sliceMaybeFromStack()[index];
    }

    /++
     + Concatenation operator.
     +
     + Notes:
     +  This will always create a new string, and will never mutate the existing string.
     +
     +  If the string is small enough, it will be concatenated into the stack buffer, otherwise
     +  it will be allocated on the heap.
     + ++/
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
            else if(this.isBig && this._payload !is null)
                ret._payload.release();

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

    /++
     + Concatenation assignment operator.
     +
     + Notes:
     +  This will always create a new string, and will never mutate the existing string.
     +
     +  If the string is small enough, it will be concatenated into the stack buffer, otherwise
     +  it will be allocated on the heap.
     + ++/
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

    /++
     + Basic equality operator for common string types, including `char[]`, and `String2`.
     + ++/
    bool opEquals(scope const(char)[] rhs) @trusted const
    {
        if(this.length != rhs.length)
            return false;

        return this.sliceMaybeFromStack() == rhs;
    }

    /// ditto.
    bool opEquals(scope const String2 rhs) @trusted const
        => this.sliceMaybeFromStack() == rhs.sliceMaybeFromStack();

    /// ditto.
    bool opEquals(scope const ref String2 rhs) @trusted const
        => this.sliceMaybeFromStack() == rhs.sliceMaybeFromStack();

    /// Simple assignment operator that forwards to the appropriate ctor.
    void opAssign(CtorParam)(scope CtorParam param) @trusted
    if(!is(Unqual!CtorParam == String2))
    {
        this = String2(param);
    }

    /// Hashes the contents of the string using MurmurHash3.
    uint toHash() @trusted const
    {
        import std.digest.murmurhash;
        MurmurHash3!32 hasher;
        hasher.start();
        hasher.put(cast(ubyte[])this.sliceMaybeFromStack());

        const bytes = hasher.finish();
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
    }

    /++
     + Provides access to the raw slice of the string, which may be on the stack or heap,
     + depending on if Small String Optimisation is in use.
     +
     + Notes:
     +  This function will never return a `null` slice, you should check if the slice's length is 0 instead.
     +
     +  This function is best used when you're *certain* that the returned slice will not escape and is
     +  short lived, as the underlying payload may be released once the parent `String2` goes out of scope.
     +
     +  Please never pass the slice to a native C function, as the risk of stack corruption is too high.
     +
     + Returns:
     +  A slice to the string's memory.
     +
     + See_Also:
     +  `String2.slice`, `String2.access`
     + ++/
    const(char)[] sliceMaybeFromStack() const scope return
    {
        return this.isBig ? this._payload.sliceConst : this._ssoData[0..this._ssoLength];
    }

    /++
     + Provides access to the raw slice of the string, which will always be on the heap.
     +
     + Notes:
     +  This function may return a `null` slice if the string is empty.
     +
     +  This function will promote the string to become a "Big" string if it wasn't already.
     +  This means that it may allocate memory on the heap.
     +
     +  This function is best used when you're *certain* that the returned slice will not escape and is
     +  short lived, as the underlying payload may be released once the parent `String2` goes out of scope.
     +
     +  This function is safer than `sliceMaybeFromStack` as it will always return a slice to the heap.
     +
     + Returns:
     +  A slice to the string's memory.
     +
     + See_Also:
     +  `String2.sliceMaybeFromStack`, `String2.access`.
     + ++/
    const(char)[] slice() scope return
    {
        // Force us to be a big string so we're not providing a slice onto the stack.
        if(this.length == 0)
            return null;

        this.moveToBigString();
        return this._payload.slice;
    }

    /// The length of the string.
    size_t length() @safe const
    {
        return this.isBig ? this._length : this._ssoLength;
    }
    alias opDollar = length;

    /++
     + Provides an input range over the string's characters.
     +
     + Notes:
     +  This is a lot safer to use than `.slice` when using range algorithms,
     +  as this range will keep the payload alive until the range is destroyed.
     +
     +  This function will promote the string to become a "Big" string if it wasn't already.
     +
     + Returns:
     +  An input range over the string's characters.
     + ++/
    auto range() @trusted
    {
        static struct R
        {
            @safe @nogc nothrow:

            Payload* payload;
            const(char)[] slice;
            bool empty;
            size_t index;
            char front;

            this(Payload* payload) @trusted
            {
                this.payload = payload;
                this.payload.acquire();
                this.slice = payload.sliceConst; // To avoid contract asserts each time we call popFront.
                this.popFront();
            }

            this(scope ref return R other) @trusted
            {
                this.payload = other.payload;
                this.payload.acquire();
                this.slice = other.slice;
                this.empty = other.empty;
                this.index = other.index;
                this.front = other.front;
            }

            ~this() @trusted
            {
                if(payload !is null)
                    payload.release();
                (cast(ubyte*)(&this))[0..R.sizeof] = 0;
            }

            void popFront()
            {
                if(index == slice.length)
                {
                    empty = true;
                    return;
                }

                front = slice[index++];
            }
        }

        import std.range : isInputRange;
        static assert(isInputRange!R);

        this.moveToBigString();
        return R(this._payload);
    }

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

@("String2 - copy ctor")
unittest
{
    auto str = String2("smol");
    auto str2 = str;
    assert(str == str2);

    str = "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig";
    str2 = str;
    assert(str == str2);

    str = String2.init;
    str2 = str;
    assert(str == str2);
}

@("String2 - edge case - init == init")
unittest
{
    assert(String2.init == String2.init);
}

@("String2 - edge case - rvalue == rvalue")
unittest
{
    assert(String2("abc") == String2("abc"));

    assert((){
        import juptune.core.ds : Array;
        Array!char arr;
        arr.put("abc");
        return String2.fromDestroyingArray(arr);
    }() == String2("abc"));
}

@("String2 - ref counting")
unittest
{
    auto s1 = String2("abc");
    s1.moveToBigString();
    auto s2 = s1;

    assert(s1._payload is s2._payload);
    assert(s1._payload.refCount == 2);
    s1.__xdtor();
    assert(s2._payload.refCount == 1);
}

@("String2 - range")
unittest
{
    auto s = String2("abc");
    auto r = s.range;

    assert(s._payload !is null);
    assert(s._payload is r.payload);
    assert(s._payload.refCount == 2);

    auto r2 = r;
    assert(r2.payload.refCount == 3);
    r2.__xdtor();
    assert(r.payload.refCount == 2);
    s.__xdtor();
    assert(r.payload.refCount == 1);

    import std.algorithm : equal;
    assert(r.equal("abc"));
}