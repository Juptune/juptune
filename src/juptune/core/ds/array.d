/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.ds.array;

import core.exception : onOutOfMemoryErrorNoGC;
import std.algorithm : max, move, moveEmplace;
import std.traits : hasElaborateDestructor, hasElaborateCopyConstructor, hasElaborateMove, isArray;
import std.range : isInputRange;
import juptune.core.ds.alloc;

struct ArrayBase(
    alias Alloc,
    size_t DefaultInitSize,
    alias GetGrowSize,
    alias ShouldShrink,
    alias GetShrinkSize,
    alias ValueT_
)
{
    mixin Alloc.InjectState;

    alias ValueT = ValueT_;

    private static struct Slice
    {
        size_t start;
        size_t end;
    }

    private
    {
        ValueT[] _values;
        size_t   _length;
    }

    @trusted @nogc nothrow: // @suppress(dscanner.trust_too_much)

    static if(Alloc.CtorParams.length)
    this(Alloc.CtorParams params)
    {
        this.allocCtor(params);
    }

    static if(!Alloc.IsCopyable)
        @disable this(this){}
    else static if(hasElaborateMove!ValueT)
    {
        @disable this(this){}
        void opPostMove(ref scope typeof(this) src)
        {
        }
    }
    else
        this(ref return scope typeof(this) src)
        {
            this.length = src.length;
            this._length = 0;
            this.put(src.slice);
        }

    ~this()
    {
        this.dtorValues(0, this.length);
        if(this._values.ptr)
        {
            this.free(&this._values[0]);
            this._values = null;
            this._length = 0;
        }
        this.allocDtor();
    }

    void put(T : ValueT)(auto ref T value)
    {
        this.length = this.length + 1;

        static if(!hasElaborateMove!ValueT)
            this._values[this.length-1] = value; // @suppress(dscanner.suspicious.length_subtraction)
        else
            moveEmplace(value, this._values[this.length-1]); // @suppress(dscanner.suspicious.length_subtraction)
    }

    void put(T : ValueT)(T[] values)
    {
        const oldLength = this.length;
        this.length = this.length + values.length;

        static if(hasElaborateMove!ValueT)
            foreach(i, ref value; this._values[oldLength..this.length])
            {
                moveEmplace(values[i], value);
            }
        else static if(hasElaborateCopyConstructor!ValueT)
            foreach(i, ref value; this._values[oldLength..this.length])
                value = values[i];
        else
            this._values[oldLength..this.length] = values[];
    }

    void put(scope ref typeof(this) array)
    {
        this.put(array.slice);
    }

    void put(R)(R range)
    if(!isArray!R && isInputRange!R)
    {
        foreach(ref value; range)
            this.put(value);
    }

    void put(Values...)(auto ref Values values)
    if(Values.length > 1)
    {
        foreach(ref value; values)
            this.put(value);
    }

    ValueT remove(size_t index)
    {
        assert(index < this._length, "Index out of bounds.");
        ValueT value;

        static if(hasElaborateMove!ValueT)
            moveEmplace(this._values[index], value);
        else
            value = this._values[index];

        index++;
        while(index < this._length)
        {
            static if(hasElaborateMove!ValueT)
                moveEmplace(this._values[index], this._values[index-1]);
            else
                this._values[index-1] = this._values[index];
            index++;
        }
        this.length = this.length - 1; // @suppress(dscanner.suspicious.length_subtraction)

        return value;
    }

    void reserve(size_t amount)
    {
        const oldLength = this._length;
        this.length = this.length + amount; // Increases capacity if needed.
        this._length = oldLength;
    }

    inout(ValueT)[] opIndex() inout
    {
        return this.slice;
    }

    ref inout(ValueT) opIndex(size_t index) inout
    {
        assert(index < this._length, "Index out of bounds");
        return this._values[index];
    }

    inout(ValueT)[] opIndex(Slice slice) inout
    {
        return this._values[slice.start..slice.end];
    }

    void opIndexAssign(T : ValueT)(auto ref T value)
    {
        this.opIndexAssign(value, Slice(0, this.length));
    }

    void opIndexAssign(T : ValueT)(auto ref T value, size_t index)
    {
        assert(index < this._length, "Index out of bounds");
        static if(hasElaborateMove!T)
            .move(value, this._values[index]);
        else
            this._values[index] = value;
    }

    void opIndexAssign(T : ValueT)(auto ref T value, Slice slice)
    {
        static assert(!hasElaborateMove!T, "array[0..n] = x; cannot support move-only values.");
        foreach(i, ref v; this._values[slice.start..slice.end])
            v = value;
    }

    void opIndexAssign(T : ValueT)(T[] values, Slice slice)
    {
        assert(values.length == slice.end - slice.start, "Slice length mismatch.");
        foreach(i, ref v; this._values[slice.start..slice.end])
        {
            static if(hasElaborateMove!T)
                .move(values[i], v);
            else
                v = values[i];
        }
    }

    void opIndexOpAssign(string op, T)(T value, size_t index)
    {
        assert(index < this._length, "Index out of bounds");
        mixin("this._values[index]"~op~"value;");
    }

    void opIndexOpAssign(string op, T)(T value, Slice slice)
    {
        foreach(ref v; this._values[slice.start..slice.end])
            mixin("v"~op~"value;");
    }

    ValueT opIndexUnary(string op)(size_t index)
    {
        assert(index < this._length, "Index out of bounds");
        return mixin(op~"this._values[index]");
    }
    
    void opIndexUnary(string op)(Slice slice)
    {
        foreach(ref value; this._values[slice.start..slice.end])
            mixin(op~"value;");
    }

    void opOpAssign(string op, T)(auto ref T value)
    if(op == "~")
    {
        this.put(value);
    }

    Slice opSlice(size_t _)(size_t start, size_t end) const
    {
        assert(start <= end, "Start cannot be greater than end");
        assert(start <= this._length, "Start is greater than the array length");
        assert(end <= this._length, "End is greater than the array length");
        return Slice(start, end);
    }

    bool opEquals()(ref const typeof(this) other) const
    {
        return this.opEquals(other.slice);
    }

    bool opEquals(T : ValueT)(const T[] other) const
    {
        if(other.length != this.length)
            return false;
        foreach(i, ref value; this.slice)
        {
            if(value != other[i])
                return false;
        }
        return true;
    }

    uint toHash() const
    {
        import std.digest.murmurhash;
        MurmurHash3!32 hasher;
        hasher.start();

        static if(__traits(hasMember, ValueT, "toHash") && __traits(compiles, this[0].toHash()))
        {
            foreach(i; 0..this.length)
            {
                const hash = this[i].toHash();
                hasher.put(cast(ubyte[])(&hash)[0..typeof(hash).sizeof]);
            }
        }
        else
            hasher.put(cast(ubyte[])this._values[0..this.length]);

        const bytes = hasher.finish();
        return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
    }

    @property
    inout(ValueT)[] slice() inout
    {
        return this._values[0..this.length];
    }
    alias range = slice;

    @property
    inout(ValueT)* ptr() inout
    {
        return this._values.ptr;
    }

    @property @safe
    size_t capacity() const
    {
        return this._values.length;
    }

    @property @safe
    size_t length() const
    {
        return this._length;
    }
    alias opDollar = length;

    @property
    void length(size_t l)
    {
        if(l == this._length)
            return;

        const oldLength = this._length;
        this._length = l;

        if(!this._values)
        {
            l = max(l, DefaultInitSize);
            this._values = (cast(ValueT*)this.calloc(ValueT.sizeof * l))[0..l];
            if(!this._values.ptr)
                onOutOfMemoryErrorNoGC();
            return;
        }

        if(l > this._values.length)
        {
            const newCapacity = GetGrowSize(l, this._values.length);
            auto slice = (cast(ValueT*)this.calloc(ValueT.sizeof * newCapacity))[0..newCapacity];
            if(!slice.ptr)
                onOutOfMemoryErrorNoGC();
            foreach(i, ref value; this._values[0..oldLength])
            {
                static if(hasElaborateMove!ValueT)
                    moveEmplace(value, slice[i]);
                else
                    slice[i] = value;
            }

            ValueT init;
            static if(!__traits(isZeroInit, ValueT))
            foreach(ref value; slice[oldLength..$])
            {
                static if(hasElaborateMove!ValueT)
                    moveEmplace(init, value);
                else
                    value = init;
            }
            
            this.dtorValues(0, oldLength);
            this.free(this._values.ptr);
            this._values = slice;
        }

        if(l < oldLength)
        {
            this.dtorValues(l, oldLength);
            if(ShouldShrink(l, this._values.length))
            {
                const newCapacity = GetShrinkSize(l, this._values.length);

                static if(!hasElaborateCopyConstructor!ValueT && !hasElaborateMove!ValueT)
                {
                    auto slice = (cast(ValueT*)this.realloc(this._values.ptr, ValueT.sizeof * newCapacity))[0..newCapacity]; // @suppress(dscanner.style.long_line)
                    if(!slice)
                        onOutOfMemoryErrorNoGC();
                    this._values = slice;
                }
                else
                {
                    auto slice = (cast(ValueT*)this.calloc(ValueT.sizeof * newCapacity))[0..newCapacity];
                    if(!slice.ptr)
                        onOutOfMemoryErrorNoGC();
                    foreach(i, ref value; this._values[0..oldLength])
                    {
                        static if(hasElaborateMove!ValueT)
                            moveEmplace(value, slice[i]);
                        else
                            slice[i] = value;
                    }
                    this.dtorValues(0, oldLength);
                    this.free(this._values.ptr);
                    this._values = slice;
                }
            }
        }
    }

    private void dtorValues(size_t start, size_t end)
    {
        static if(hasElaborateDestructor!ValueT)
        if(this._length)
        {
            foreach(ref value; this._values[start..end])
                value.__xdtor;
        }
    }
}

alias ArrayBaseDefault(alias Alloc, alias T) = ArrayBase!(
    Alloc,
    8,
    (length, capacity) => max(capacity, length) * 2,
    (length, capacity) => length < capacity / 2,
    (length, capacity) => capacity / 2,
    T
);
alias Array(alias T) = ArrayBaseDefault!(Malloc, T);

alias ArrayBaseNonShrinkDefault(alias Alloc, alias T) = ArrayBase!(
    Alloc,
    8,
    (length, capacity) => max(capacity, length) * 2,
    (length, capacity) => false,
    (length, capacity) => 0,
    T
);
alias ArrayNonShrink(alias T) = ArrayBaseNonShrinkDefault!(Malloc, T);

@("put - basic type")
@nogc nothrow
unittest
{
    import std.range : iota;

    Array!int arr;

    arr.put(20);
    assert(arr.length == 1);
    assert(arr[0] == 20);

    arr.put(30, 40);
    assert(arr.length == 3);
    assert(arr[1..3] == [30, 40]);

    Array!int arr2;
    arr2.put(arr);
    assert(arr[] == [20, 30, 40]);

    arr2.put(iota(0, 997));
    assert(arr2.length == 1000);
    arr2.length = 1;
    arr2.put(10);
    assert(arr2[] == [20, 10]);
    assert(arr2.length == 2);

    arr2 = arr;
    assert(arr2[] == [20, 30, 40]);
}

@("put - copy ctor type")
@nogc nothrow
unittest
{
    static struct S
    {
        @nogc
        this(ref return scope S s)
        {}

        int value;
    }

    Array!S arr;

    arr.put(S(20));
    assert(arr.length == 1);
    assert(arr[0] == S(20));

    arr.put(S(30), S(40));
    assert(arr.length == 3);
    assert(arr[1..3] == [S(30), S(40)]);

    Array!S arr2;
    arr2.put(arr);
    assert(arr2[] == [S(20), S(30), S(40)]);
    arr2.length = 1;
    arr2.put(S(10));
    assert(arr2[] == [S(20), S(10)]);

    foreach(i; 0..998)
        arr2.put(S(30));

    arr2 = arr;
    assert(arr2[] == [S(20), S(30), S(40)]);
}

@("put - move type")
@nogc nothrow
unittest
{
    static struct S
    {
        @nogc nothrow:

        @disable this(this) {}
        ~this(){}
        void opPostMove(scope ref S s) pure {}

        int value;
    }

    Array!S arr;

    arr.put(S(20));
    assert(arr.length == 1);
    assert(arr[0] == S(20));

    arr.put(S(30), S(40));
    assert(arr.length == 3);
    assert(arr[1..3] == [S(30), S(40)]);

    Array!S arr2;
    arr2.put(arr);
    assert(arr2[] == [S(20), S(30), S(40)]);
    arr2.length = 1;
    arr2.put(S(10));
    assert(arr2[] == [S(20), S(10)]);

    foreach(i; 0..998)
        arr2.put(S(30));

    arr[0] = S(20);
    arr[1] = S(30);
    arr[2] = S(40);
    move(arr, arr2);
    assert(arr2[] == [S(20), S(30), S(40)]);
}

@("remove - basic type")
@nogc nothrow
unittest
{
    Array!int arr;

    arr.put(1, 2, 3);
    assert(arr.remove(1) == 2);
    assert(arr.length == 2);
    assert(arr[] == [1, 3]);
    assert(arr.remove(0) == 1);
    assert(arr.length == 1);
    assert(arr[] == [3]);
    assert(arr.remove(0) == 3);
}

@("remove - copy ctor type")
@nogc nothrow
unittest
{
    static struct S
    {
        @nogc
        this(ref return scope S s)
        {}

        int value;
    }

    Array!S arr;

    arr.put(S(1), S(2), S(3));
    assert(arr.remove(1) == S(2));
    assert(arr.length == 2);
    assert(arr[] == [S(1), S(3)]);
    assert(arr.remove(0) == S(1));
    assert(arr.length == 1);
    assert(arr[] == [S(3)]);
    assert(arr.remove(0) == S(3));
}

@("remove - move type")
@nogc nothrow
unittest
{
    static struct S
    {
        @nogc nothrow:

        @disable this(this) {}
        ~this(){}
        void opPostMove(scope ref S s) pure {}

        int value;
    }

    Array!S arr;

    arr.put(S(1), S(2), S(3));
    assert(arr.remove(1) == S(2));
    assert(arr.length == 2);
    assert(arr[] == [S(1), S(3)]);
    assert(arr.remove(0) == S(1));
    assert(arr.length == 1);
    assert(arr[] == [S(3)]);
    assert(arr.remove(0) == S(3));
}

@("fill - basic type")
@nogc nothrow
unittest
{
    Array!int arr;
    arr.length = 3;
    arr[] = 1;
    assert(arr[] == [1, 1, 1]);
}

@("fill - copy ctor type")
@nogc nothrow
unittest
{
    static struct S
    {
        @nogc
        this(ref return scope S s)
        {}

        int value;
    }

    Array!S arr;
    arr.length = 3;
    arr[] = S(1);
    assert(arr[] == [S(1), S(1), S(1)]);
}

// @("sort")
// unittest
// {
//     import std.algorithm : sort; // sort works in betterC
//     Array!int i;
//     i.put(3, 1, 2);
//     i.slice.sort;
//     assert(i[] == [1, 2, 3]);
// }

@("lifetime")
@nogc nothrow
unittest
{
    int i;
    static struct S
    {
        int* i;
        
        @nogc nothrow:
        this(int* i)
        {
            this.i = i;
            (*this.i)++;
        }

        this(ref return scope S s)
        {
            this.i = s.i;
            (*this.i)++;
        }

        ~this()
        {
            if(this.i)
                (*this.i)--;
        }
    }

    Array!S s;
    s.put(
        S(&i),S(&i),S(&i)
    );
    assert(i == 3);
    
    s.remove(1);
    assert(i == 2);

    s.length = 1;
    assert(i == 1);

    s.__xdtor();
    assert(i == 0);
}