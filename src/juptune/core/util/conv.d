/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.util.conv;


import std.math : abs;
import std.traits : Unqual, isArray, EnumMembers;
import std.range : isOutputRange;
import juptune.core.ds.string, juptune.core.util.result;


private enum MAX_SIZE_T_STRING_LEN = "18446744073709551615".length;
private enum MAX_SIZE_T_HEX_STRING_LEN = "-0xFFFFFFFFFFFFFFFF".length;
alias IntToCharBuffer = char[MAX_SIZE_T_STRING_LEN];
alias IntToHexCharBuffer = char[MAX_SIZE_T_HEX_STRING_LEN];

private immutable BASE10_CHARS = "0123456789";
private immutable BASE16_CHARS = "0123456789ABCDEF";

private immutable BASE16_MAP = (){
    byte[ubyte.max] map;
    map[] = -1;

    foreach(i; 0..10)
        map['0' + i] = cast(byte)i;
    foreach(i; 10..16)
    {
        map['A' + (i - 10)] = cast(byte)i;
        map['a' + (i - 10)] = cast(byte)i;
    }

    return map;
}();

@nogc nothrow:

enum ConvError
{
    none,
    generic
}

void toStringSink(OutputRangeT, ValueT)(auto ref ValueT value, auto ref OutputRangeT range, const size_t base = 10)
{
    static if(is(ValueT == enum))
        range.put(enumToString(value));
    else static if(is(ValueT == bool))
        value ? range.put("true") : range.put("false");
    else static if(is(ValueT == char))
        range.put((&value)[0..1]);
    else static if(__traits(compiles, toBase10(value)))
        range.put(base == 10 ? value.toBase10.slice : value.toBase16.slice);
    else static if(is(ValueT == String))
        range.put(value.slice);
    else static if(is(ValueT == struct))
        structToString(value, range);
    else static if(is(ValueT : const(char)[]))
        range.put(value);
    else static if(is(ValueT : T[], T))
        arrayToString(value, range);
    else static if(is(ValueT : T*, T))
        pointerToString(value, range);
    else static if(is(ValueT == union))
        range.put("<union>");
    else static assert(false, "Don't know how to convert '"~ValueT.stringof~"' into a String.");
}

String to(StringT : String, ValueT)(auto ref ValueT value)
{
    String s;
    toStringSink(value, s);
    return s;
}
///
@("to!String")
unittest
{
    static struct S
    {
        int a;
        string b;
        bool c;
    }

    static struct SS
    {
        string name;
        S s;
    }

    static struct SSS
    {
        void toString(OutputT)(ref OutputT output) const
        {
            output.put("SSS");
        }
    }

    enum E
    {
        a
    }

    assert(127.to!String == "127");
    assert(S(29, "yolo", true).to!String == `S(29, "yolo", true)`);
    assert(SS("ribena cow", S(69, "swag", false)).to!String == `SS("ribena cow", S(69, "swag", false))`);
    assert(SSS().to!String == "SSS");
    assert(E.a.to!String == "a");
}

@Result(ConvError.generic)
bool to(BoolT : bool, ValueT)(scope auto ref ValueT value, scope ref Result result)
{
    result = Result.noError;
    static if(is(ValueT : const String))
        const slice = value.slice;
    else
        const slice = value;

    if(slice == "true")
        return true;
    else if(slice == "false")
        return false;
    else
    {
        result = Result.make(ConvError.generic, "Expected `true` or `false`, but got neither.");
        return false;
    }
}

@Result(ConvError.generic)
NumT to(NumT, ValueT)(scope auto ref ValueT value, ref Result result, const size_t base = 10)
if(__traits(isIntegral, NumT) && !is(NumT == bool))
{
    NumT output;
    string error;

    static if(is(ValueT : const(char)[]))
        output = (base == 10) ? fromBase10!NumT(value, error) : fromBase16!NumT(value, error);
    else static if(is(ValueT == String))
        output = (base == 10) ? fromBase10!NumT(value.range, error) : fromBase16!NumT(value.range, error);
    else static assert(false, "Don't know how to convert `"~ValueT.stringof~"` into a `"~NumT.stringof~"`");

    result = error.length 
        ? Result.make(ConvError.generic, error, value.to!String)
        : Result.noError; 
    
    return output;
}
///
@("to!NumT")
unittest
{
    Result err = Result.noError;
    assert("69".to!int(err) == 69);
    assert(String("-120").to!byte(err) == -120);
}

@Result(ConvError.generic)
Result to(NumT, ValueT)(ValueT value, out NumT output, const size_t base = 10)
if(__traits(isIntegral, NumT))
{
    Result error = Result.noError;

    static if(is(ValueT : const(char)[]))
        output = to!NumT(value, error, base);
    else static if(is(ValueT == String))
        output = to!NumT(value.range, error, base);
    else static assert(false, "Don't know how to convert `"~ValueT.stringof~"` into a `"~NumT.stringof~"`");

    return error;
}

private void arrayToString(ArrayT, OutputT)(ArrayT array, ref OutputT output)
if(isArray!ArrayT && isOutputRange!(OutputT, const(char)[]))
{
    output.put("[");
    foreach(i, ref v; array)
    {
        output.put(v.to!String.slice);
        if(i != array.length-1) // @suppress(dscanner.suspicious.length_subtraction)
            output.put(", ");
    }
    output.put("]");
}
@("array to!String")
unittest
{
    int[3] array = [1, 2, 3];
    auto str = array[].to!String();
    assert(str == "[1, 2, 3]");
}

private void structToString(StructT, OutputT)(auto ref StructT value, ref OutputT output)
if(is(StructT == struct) && isOutputRange!(OutputT, const(char)[]))
{
    static if(__traits(hasMember, StructT, "toString"))
    {
        value.toString(output);
    }
    else
    {
        output.put(__traits(identifier, StructT));
        output.put("(");
        foreach(i, ref v; value.tupleof)
        {{
            static if(is(typeof(v) : const(char)[]) || is(typeof(v) == String))
            {
                output.put("\"");
                output.put(v);
                output.put("\"");
            }
            else
            {
                String s = to!String(v);
                output.put(s.range);
            }

            static if(i < StructT.tupleof.length-1) // @suppress(dscanner.suspicious.length_subtraction)
                output.put(", ");
        }}
        output.put(")");
    }
}

private string enumToString(EnumT)(EnumT value)
{
    final switch(value)
    {
        static foreach(i, member; EnumMembers!EnumT)
            case member:
                return __traits(allMembers, EnumT)[i];
    }
}
@("enumToString")
unittest
{
    enum E
    {
        a, b, c
    }

    assert(E.b.enumToString == "b");
}

private String toBase10(NumT)(NumT num)
{
    // Fun fact, because of SSO, this will always be small enough to go onto the stack.
    // MAX_SIZE_T_STRING_LEN is 20, small strings are up to 22 chars.
    IntToCharBuffer buffer;
    return String(toBase10(num, buffer));
}
///
@("toBase10 - String return")
unittest
{
    assert((cast(byte)127).toBase10!byte == "127");
    assert((cast(byte)-128).toBase10!byte == "-128");
}

private String toBase16(NumT)(NumT num)
{
    IntToHexCharBuffer buffer;
    return String(toBase16(num, buffer));
}
///
@("toBase16 - String return")
unittest
{
    assert((cast(byte)127).toBase16!byte == "0x7F");
    assert((cast(byte)-128).toBase16!byte == "-0x80");
}

private char[] toBase10(NumT)(NumT num_, scope ref return IntToCharBuffer buffer)
{
    Unqual!NumT num = num_;
    size_t cursor = buffer.length-1; // @suppress(dscanner.suspicious.length_subtraction)
    if(num == 0)
    {
        buffer[cursor] = '0';
        return buffer[cursor..$];
    }

    static if(__traits(isScalar, NumT))
    {
        static if(!__traits(isUnsigned, NumT))
        {
            const isNegative = num < 0;
            auto numAbs = isNegative ? num * -1UL : num;
        }
        else
            auto numAbs = num;

        while(numAbs != 0)
        {
            assert(numAbs >= 0);
            buffer[cursor--] = BASE10_CHARS[numAbs % 10];
            numAbs /= 10;
        }

        static if(!__traits(isUnsigned, NumT))
        if(isNegative)
            buffer[cursor--] = '-';
    }
    else static assert(false, "Don't know how to convert '"~NumT.stringof~"' into base-10");

    return buffer[cursor+1..$];    
}
///
@("toBase10")
unittest
{
    IntToCharBuffer buffer;
    assert(toBase10!byte(byte.max, buffer) == "127");
    assert(toBase10!byte(byte.min, buffer) == "-128");
    assert(toBase10!ubyte(ubyte.max, buffer) == "255");
    assert(toBase10!ubyte(ubyte.min, buffer) == "0");

    assert(toBase10!short(short.max, buffer) == "32767");
    assert(toBase10!short(short.min, buffer) == "-32768");
    assert(toBase10!ushort(ushort.max, buffer) == "65535");
    assert(toBase10!ushort(ushort.min, buffer) == "0");

    assert(toBase10!int(int.max, buffer) == "2147483647");
    assert(toBase10!int(int.min, buffer) == "-2147483648");
    assert(toBase10!uint(uint.max, buffer) == "4294967295");
    assert(toBase10!uint(uint.min, buffer) == "0");

    assert(toBase10!long(long.max, buffer) == "9223372036854775807");
    assert(toBase10!long(long.min, buffer) == "-9223372036854775808");
    assert(toBase10!ulong(ulong.max, buffer) == "18446744073709551615");
    assert(toBase10!ulong(ulong.min, buffer) == "0");
}

private char[] toBase16(NumT)(NumT num_, scope ref return IntToHexCharBuffer buffer)
{
    Unqual!NumT num = num_;
    size_t cursor = buffer.length-1; // @suppress(dscanner.suspicious.length_subtraction)
    if(num == 0)
    {
        buffer[cursor-3..cursor] = "0x0";
        return buffer[cursor-3..cursor];
    }

    const isNegative = num < 0;

    static if(__traits(isScalar, NumT))
    {
        static foreach(byteI; 0..NumT.sizeof)
        {
            buffer[cursor--] = BASE16_CHARS[num & 0xF];
            num >>= 4;
            buffer[cursor--] = BASE16_CHARS[num & 0xF];
            num >>= 4;
        }
    }
    else static assert(false, "Don't know how to convert '"~NumT.stringof~"' into base-16");

    buffer[cursor--] = 'x';
    buffer[cursor--] = '0';
    if(isNegative)
        buffer[cursor--] = '-';
    return buffer[cursor+1..$];    
}
///
@("toBase10")
unittest
{
    IntToHexCharBuffer buffer;
    assert(toBase16!byte(byte.max, buffer) == "0x7F");
    assert(toBase16!byte(byte.min, buffer) == "-0x80");
    assert(toBase16!ubyte(ubyte.max, buffer) == "0xFF");
    assert(toBase16!ubyte(ubyte.min, buffer) == "0x0");

    assert(toBase16!short(short.max, buffer) == "0x7FFF");
    assert(toBase16!short(short.min, buffer) == "-0x8000");
    assert(toBase16!ushort(ushort.max, buffer) == "0xFFFF");
    assert(toBase16!ushort(ushort.min, buffer) == "0x0");

    assert(toBase16!int(int.max, buffer) == "0x7FFFFFFF");
    assert(toBase16!int(int.min, buffer) == "-0x80000000");
    assert(toBase16!uint(uint.max, buffer) == "0xFFFFFFFF");
    assert(toBase16!uint(uint.min, buffer) == "0x0");

    assert(toBase16!long(long.max, buffer) == "0x7FFFFFFFFFFFFFFF");
    assert(toBase16!long(long.min, buffer) == "-0x8000000000000000");
    assert(toBase16!ulong(ulong.max, buffer) == "0xFFFFFFFFFFFFFFFF");
    assert(toBase16!ulong(ulong.min, buffer) == "0x0");
}

private NumT fromBase10(NumT)(const(char)[] str, out string error)
{
    if(str.length == 0)
    {
        error = "String is null.";
        return 0;
    }

    ptrdiff_t cursor = cast(ptrdiff_t)str.length-1;
    
    const firstDigit = str[cursor--] - '0';
    if(firstDigit >= 10 || firstDigit < 0)
    {
        error = "String contains non-base10 characters.";
        return 0;
    }

    NumT result = cast(NumT)firstDigit;
    uint exponent = 10;
    while(cursor >= 0)
    {
        if(cursor == 0 && str[cursor] == '-')
        {
            static if(__traits(isUnsigned, NumT))
            {
                error = "Cannot convert a negative number into an unsigned type.";
                return 0;
            }
            else
            {
                result *= -1;
                break;
            }
        }

        const digit = str[cursor--] - '0';
        if(digit >= 10 || digit < 0)
        {
            error = "String contains non-base10 characters.";
            return 0;
        }

        const oldResult = result;
        result += digit * exponent;
        if(result < oldResult)
        {
            error = "Overflow. String contains a number greater than can fit into specified numeric type.";
            return 0;
        }

        exponent *= 10;
    }

    return result;
}
///
@("fromBase10")
unittest
{
    string err;
    assert(!fromBase10!int(null, err) && err);
    assert(fromBase10!int("0", err) == 0 && !err);
    assert(fromBase10!int("1", err) == 1 && !err);
    assert(fromBase10!int("21", err) == 21 && !err);
    assert(fromBase10!int("321", err) == 321 && !err);
    assert(!fromBase10!ubyte("256", err) && err);
    assert(fromBase10!ubyte("255", err) == 255 && !err);
    assert(!fromBase10!int("yolo", err) && err);
    assert(!fromBase10!uint("-20", err) && err);
    assert(fromBase10!int("-231", err) == -231 && !err);
}

private NumT fromBase16(NumT)(const(char)[] str, out string error)
{
    import std.traits : isUnsigned;

    if(str.length == 0)
    {
        error = "String is null.";
        return 0;
    }

    const isNegative = str[0] == '-';
    if(isNegative && isUnsigned!NumT)
    {
        error = "Cannot convert a negative number into an unsigned type.";
        return 0;
    }
    if(isNegative)
        str = str[1..$];
    if(str.length >= 2 && str[0] == '0' && str[1] == 'x')
        str = str[2..$];

    if(str.length > NumT.sizeof * 2)
    {
        error = "String is too long.";
        return 0;
    }

    ptrdiff_t cursor = cast(ptrdiff_t)str.length-1;
    NumT result;
    size_t shift = 0;
    while(cursor >= 0)
    {
        const number = BASE16_MAP[str[cursor--]];
        if(number == -1)
        {
            error = "String contains non-base16 characters.";
            return 0;
        }
        result |= (number << shift);
        shift += 4;
    }

    if(isNegative)
        result *= -1;
    return result;
}
///
@("fromBase10")
unittest
{
    string err;
    assert(!fromBase16!int(null, err) && err);
    assert(fromBase16!int("0", err) == 0 && !err);
    assert(fromBase16!int("1", err) == 1 && !err);
    assert(fromBase16!int("21", err) == 0x21 && !err);
    assert(fromBase16!int("0x321", err) == 0x321 && !err);
    assert(!fromBase16!ubyte("256", err) && err);
    assert(!fromBase16!int("yolo", err) && err);
    assert(!fromBase16!uint("-20", err) && err);
    assert(fromBase16!uint("abCD", err) == 0xABCD && !err);
}

private void pointerToString(T, OutputT)(T* pointer, ref OutputT output)
{
    output.put(toBase10(cast(size_t)pointer));
}