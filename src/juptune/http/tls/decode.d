/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.decode;

import std.traits : isIntegral;

import juptune.core.util : Result;
import juptune.data.buffer : MemoryReader;
import juptune.http.tls.common : bytesRequiredForLength, TlsError;

package:

bool decodeVectorLength(size_t MaxValue)(scope ref MemoryReader reader, scope out uint length)
{
    enum lengthByteCount = bytesRequiredForLength(MaxValue);
    static if(lengthByteCount == 1)
    {
        ubyte rawValue;
        auto success = reader.readU8(rawValue);
    }
    else static if(lengthByteCount == 2)
    {
        ushort rawValue;
        auto success = reader.readU16BE(rawValue);
    }
    else static if(lengthByteCount == 3)
    {
        uint rawValue;
        auto success = reader.readU24BE(rawValue);
    }
    else static if(lengthByteCount == 4)
    {
        uint rawValue;
        auto success = reader.readU32BE(rawValue);
    }
    else static assert(false, "Invalid value for lengthByteCount");

    length = rawValue;
    return success;
}

Result autoDecode(string DebugName, T, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(is(T == struct))
{
    import std.traits : getUDAs;
    import juptune.http.tls.models : RawTlsStruct, Exempt;

    static assert(getUDAs!(T, RawTlsStruct).length != 0, "struct of type "~T.stringof~" cannot be autodecoded as it is missing @RawTlsStruct"); // @suppress(dscanner.style.long_line)

    static foreach(i, field; T.tupleof)
    {{
        enum IsExempt = getUDAs!(field, Exempt).length > 0;
        static if(!IsExempt)
        {
            auto result = autoDecode!(
                DebugName~"."~__traits(identifier, field),
                typeof(field),
                __traits(getAttributes, field)
            )(
                reader, 
                mixin("value.", __traits(identifier, field))
            );
            if(result.isError)
                return result.wrapError("when autodecoding "~DebugName~"."~__traits(identifier, field)~":");
        }
    }}

    return Result.noError;
}

Result autoDecode(string DebugName, T, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out const(ubyte)[] value,
)
if(is(T == const(ubyte)[]))
{
    import juptune.core.ds : String;
    import juptune.http.tls.models : ExactLength, LengthRange;

    // I may add extra UDAs in the future that aren't the "main UDA" but modify decoding logic in some way.
    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactLength))
        {
            alias MainUda = Uda;
        }
        else static if(is(typeof(Uda) == LengthRange!_, _))
        {
            alias MainUda = Uda;
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    static if(is(typeof(MainUda) == ExactLength))
    {
        auto success = reader.readBytes(MainUda.length, value);
        if(!success)
        {
            return Result.make(
                TlsError.eof,
                "[ExactLength] ran out of bytes while reading value of "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String("expected length of ", MainUda.length, " but got length of ", reader.bytesLeft)
            );
        }
    }
    else static if(is(typeof(MainUda) == LengthRange!ElementT, ElementT))
    {
        uint length;
        auto success = decodeVectorLength!(MainUda.upper)(reader, length);

        if(!success)
            return Result.make(TlsError.eof, "ran out of bytes while reading length for field "~DebugName~" when autodecoding"); // @suppress(dscanner.style.long_line)

        if(length < MainUda.lower)
        {
            return Result.make(
                TlsError.lengthRangeConstraintFailed,
                "expected at least a certain amount of bytes for field "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String("expected minimum length of ", MainUda.lower, " but got length of ", length)
            );
        }
        if(length > MainUda.upper)
        {
            return Result.make(
                TlsError.lengthRangeConstraintFailed,
                "expected at most a certain amount of bytes for field "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String("expected maximum length of ", MainUda.lower, " but got length of ", length)
            );
        }

        static if(!is(ElementT == struct) && ElementT.sizeof > 1)
        {
            if(length % ElementT.sizeof != 0)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a size that's a multiple of "~ElementT.stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                    String("expected length that is a multiple of ", ElementT.sizeof, " but got length of ", length) // @suppress(dscanner.style.long_line)
                );
            }
        }

        success = reader.readBytes(length, value);
        if(!success)
        {
            return Result.make(
                TlsError.exactLengthConstraintFailed,
                "[LengthRange] ran out of bytes while reading value of "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String("expected length of ", length, " but got length of ", reader.bytesLeft)
            );
        }
    }
    else
    {
        pragma(msg, "UNHANDLED: ", MainUda);
        static assert(false, "bug: Unhandled main constraint UDA");
    }

    return Result.noError;
}

Result autoDecode(string DebugName, T, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(isIntegral!T && !is(T == enum))
{
    import std.bitmanip : Endian;
    import juptune.core.ds : String;
    import juptune.http.tls.models : ExactValue;

    auto success = reader.tryIntegral!(T, Endian.bigEndian, true)(value);
    if(!success)
        return Result.make(TlsError.eof, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactValue!ValueT, ValueT))
        {
            static assert(is(ValueT == T));
            if(value != Uda.value)
            {
                return Result.make(
                    TlsError.exactValueConstraintFailed,
                    "expected field "~DebugName~" of type "~T.stringof~" to be a specific value when autodecoding",
                    String("expected value of ", Uda.value, " but got value of ", value)
                );
            }
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    return Result.noError;
}

Result autoDecode(string DebugName, T, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(isIntegral!T && is(T == enum))
{
    import std.traits : EnumMembers;

    uint rawValue;
    const success = decodeVectorLength!(T.MAX)(reader, rawValue);
    if(!success)
        return Result.make(TlsError.eof, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    Switch: switch(rawValue)
    {
        static foreach(Member; EnumMembers!T)
        static if(!is(Member == T.FAILSAFE) && !is(Member == T.MAX))
        {
            case Member: value = Member; break Switch;
        }

        default:
            return Result.make(
                TlsError.alertIllegalParameter, 
                "unknown/invalid value when reading enum field "~DebugName~" of type "~T.stringof~" when autodecoding"
            );
    }

    return Result.noError;
}

Result autoDecode(string DebugName, T, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(__traits(isStaticArray, T) && is(typeof(T.init[0]) == ubyte))
{
    import std.traits : EnumMembers;
    import juptune.core.ds : String;

    const(ubyte)[] bytes;
    auto success = reader.readBytes(value.length, bytes);
    if(!success)
        return Result.make(TlsError.eof, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    static foreach(Uda; FieldUdas)
    {
        pragma(msg, "UNHANDLED: ", Uda);
        static assert(false, "bug: Unhandled constraint UDA");
    }

    static if(is(T == enum))
    {
        value = T.unknown;

        static foreach(Member; EnumMembers!T)
        static if(!is(Member == T.FAILSAFE))
        {{
            static immutable StaticInstanceOfMember = Member;
            if(bytes == StaticInstanceOfMember)
                value = StaticInstanceOfMember;
        }}
    }
    else
        value = bytes;
    return Result.noError;
}