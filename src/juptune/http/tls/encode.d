/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.encode;

import std.traits : isIntegral;

import juptune.core.util : Result;
import juptune.data.buffer : MemoryWriter;
import juptune.http.tls.common : TlsError;

package:

struct CanaryLength(alias LengthSymbol)
{
    import juptune.http.tls.models : LengthRange, ExactLength;

    static foreach(Uda; __traits(getAttributes, LengthSymbol))
    {
        static if(is(typeof(Uda) == ExactLength))
            enum Max = Uda.length;
        else static if(is(typeof(Uda) == LengthRange!_, _))
            enum Max = Uda.upper;
    }

    // HACK: This relies on the fact that the compiler will evalulate this _after_ the above code is mixed in properly.
    static assert(__traits(compiles, { size_t x = Max; }), "Could not determine max length");

    private
    {
        size_t _cursorForFirstByte;
        bool _setCanary;
        bool _setActual;

        invariant
        {
            if(!this._setCanary)
                assert(!this._setActual);
            if(this._setActual)
                assert(this._setCanary);
        }
    }

    Result putTemporaryLength(scope ref MemoryWriter writer)
    in(!this._setCanary, "bug: this CanaryLength has already been set, please reset it to .init first")
    {
        this._setCanary = true;
        this._cursorForFirstByte = writer.cursor;

        import juptune.http.tls.common : bytesRequiredForLength;
        enum BytesForLength = bytesRequiredForLength(Max);

        static if(BytesForLength == 1)
            enum Canary = 0xAA;
        else static if(BytesForLength == 2)
            enum Canary = 0xBBBB;
        else static if(BytesForLength == 3)
            enum Canary = 0xCCCCCC;
        else static if(BytesForLength == 4)
            enum Canary = 0xDDDDDDDD;

        const success = encodeVectorLength!Max(writer, Canary);
        if(!success)
        {
            enum DebugName = __traits(identifier, __traits(parent, LengthSymbol))~"."~__traits(identifier, LengthSymbol); // @suppress(dscanner.style.long_line)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing canary of "~DebugName);
        }
        
        return Result.noError;
    }

    void putActualLength(scope ref MemoryWriter writer)
    in(this._setCanary, "bug: this CanaryLength's canary value hasn't been set yet, please call putTemporaryLength")
    in(!this._setActual, "bug: this CanaryLength's actual value has already been set, please reset it to .init first")
    in(this._cursorForFirstByte <= writer.cursor, "bug: writer's cursor is pointing to a byte that's before where the length is supposed to go") // @suppress(dscanner.style.long_line)
    {
        this._setActual = true;

        import juptune.http.tls.common : bytesRequiredForLength;
        enum BytesForLength = bytesRequiredForLength(Max);
        auto subwriter = MemoryWriter(writer.usedBuffer[
            this._cursorForFirstByte
            ..
            this._cursorForFirstByte + BytesForLength
        ]);

        const length = writer.cursor - (this._cursorForFirstByte + BytesForLength);
        assert((this._cursorForFirstByte + BytesForLength) <= writer.cursor, "bug: cursor isn't far enough ahead?");
        assert(length <= uint.max);
        
        const success = encodeVectorLength!Max(subwriter, cast(uint)length);
        assert(success, "bug: it shouldn't be possible for success to fail here?");
    }
}

bool encodeVectorLength(size_t MaxValue)(scope ref MemoryWriter writer, uint length)
{
    if(length > MaxValue)
        return false;

    import juptune.http.tls.common : bytesRequiredForLength;
    enum BytesForLength = bytesRequiredForLength(MaxValue);
    static if(BytesForLength == 1)
        auto success = writer.putU8(cast(ubyte)length);
    else static if(BytesForLength == 2)
        auto success = writer.putU16BE(cast(ushort)length);
    else static if(BytesForLength == 3)
        auto success = writer.putU24BE(length);
    else static if(BytesForLength == 4)
        auto success = writer.putU32BE(length);
    else static assert(false);

    return success;
}

Result autoEncode(string DebugName, T, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const ref T value,
)
if(is(T == struct))
{
    import std.traits : getUDAs;
    import juptune.http.tls.models : RawTlsStruct, Exempt;
    static assert(getUDAs!(T, RawTlsStruct).length != 0, "struct of type "~T.stringof~" cannot be autoencoded as it is missing @RawTlsStruct"); // @suppress(dscanner.style.long_line)

    static foreach(i, field; T.tupleof)
    {{
        enum IsExempt = getUDAs!(field, Exempt).length > 0;
        static if(!IsExempt)
        {
            auto result = autoEncode!(
                DebugName~"."~__traits(identifier, field),
                typeof(field),
                __traits(getAttributes, field)
            )(
                writer, 
                mixin("value.", __traits(identifier, field))
            );
            if(result.isError)
                return result;
        }
    }}

    return Result.noError;
}

Result autoEncode(string DebugName, T, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const ubyte[] value,
)
if(is(T == const(ubyte)[]))
{
    import juptune.core.ds : String2;
    import juptune.http.tls.models : ExactLength, LengthRange;

    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactLength))
        {
            if(value.length != Uda.length)
            {
                return Result.make(
                    TlsError.exactLengthConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a specific length",
                    String2("expected length of ", Uda.length, " but got length of ", value.length)
                );
            }
        }
        else static if(is(typeof(Uda) == LengthRange!ElementT, ElementT))
        {{
            if(value.length < Uda.lower)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be at least a certain size",
                    String2("expected minimum length of ", Uda.lower, " but got length of ", value.length)
                );
            }
            if(value.length > Uda.upper)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be at most a certain size",
                    String2("expected maximum length of ", Uda.lower, " but got length of ", value.length)
                );
            }

            static if(!is(ElementT == struct) && ElementT.sizeof > 1)
            {
                if(value.length % ElementT.sizeof != 0)
                {
                    return Result.make(
                        TlsError.lengthRangeConstraintFailed,
                        "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a size that's a multiple of "~ElementT.stringof, // @suppress(dscanner.style.long_line)
                        String2("expected length that is a multiple of ", ElementT.sizeof, " but got length of ", value.length) // @suppress(dscanner.style.long_line)
                    );
                }
            }

            const success = encodeVectorLength!(Uda.upper)(writer, cast(uint)value.length);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing "~DebugName~" length"); // @suppress(dscanner.style.long_line)
        }}
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    if(value.length > 0)
    {
        auto success = writer.tryBytes(value);
        if(!success)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing "~DebugName~" content"); // @suppress(dscanner.style.long_line)
    }

    return Result.noError;
}

Result autoEncode(string DebugName, T, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const T value,
)
if(isIntegral!T)
{
    import juptune.core.ds          : String2;
    import juptune.data.buffer      : Endian;
    import juptune.http.tls.models  : ExactValue;

    static foreach(Uda; FieldUdas)
    {{
        static if(is(typeof(Uda) == ExactValue!_, _))
        {
            if(value != Uda.value)
            {
                return Result.make(
                    TlsError.exactValueConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a specific value",
                    String2("expected value of ", Uda.value, " but got value of ", value)
                );
            }
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }}

    const success = writer.tryIntegral!(T, Endian.bigEndian)(value);
    if(!success)
        return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing "~DebugName); // @suppress(dscanner.style.long_line)

    return Result.noError;
}