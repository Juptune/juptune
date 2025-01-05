/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.decode.bcd.encoding;

import juptune.core.util : Result;
import juptune.data.buffer : MemoryReader;
import std.sumtype : SumType; // Temporary until D finally gets a built-in sum type, hence making one ourselves is a waste of time

struct Asn1Identifier
{
    enum Class : ubyte // Note: NOT a flag enum - each value is distinct
    {
        universal       = 0b00,
        application     = 0b01,
        contextSpecific = 0b10,
        private_        = 0b11
    }

    enum Encoding : ubyte
    {
        primitive   = 0b0,
        constructed = 0b1
    }

    alias Tag = ulong;

    private
    {
        Class    _class;
        Encoding _encoding;
        Tag      _tag;
    }

    @safe @nogc nothrow pure const:

    this(Class _class, Encoding encoding, Tag tag)
    {
        this._class     = _class;
        this._encoding  = encoding;
        this._tag       = tag;
    }

    Class class_() => _class;
    Encoding encoding() => _encoding;
    Tag tag() =>_tag;
}

struct Asn1LongLength
{
    import std.traits : isUnsigned;

    enum MIN_BYTES = 1;
    enum MAX_BYTES = 127;

    private
    {
        const(ubyte)[] _lengthBytes;
    }

    @safe nothrow pure:

    // version(unittest) since I don't know how I want to handle constructing things manually yet, but I need this for testing at the very least.
    version(unittest) static Asn1LongLength fromNumberGC(T)(T number)
    if(isUnsigned!T)
    {
        import std.bitmanip : nativeToBigEndian;
        auto bytes = nativeToBigEndian(number).dup;
        while(bytes.length > 0 && bytes[0] == 0) // Encode in least amount of bytes
            bytes = bytes[1..$];

        return Asn1LongLength.fromUnownedBytes(bytes);
    }

    static Asn1LongLength fromUnownedBytes(const ubyte[] lengthBytes) @nogc
    in(lengthBytes.length >= MIN_BYTES && lengthBytes.length <= MAX_BYTES, "The amount of bytes must be between 1 and 127") // @suppress(dscanner.style.long_line)
    {
        return Asn1LongLength(lengthBytes);
    }

    const(ubyte)[] lengthBytes() const @nogc => _lengthBytes; // TODO: Note that this is always in big endian.
    
    bool isAtMost64Bits() const @nogc
    {
        return this._lengthBytes.length <= 8;
    }

    ulong length() const @nogc
    in(this.isAtMost64Bits(), "The amount of bytes is too large to represent as a ulong - please check with isAtMost64Bits or amountOfBytes") // @suppress(dscanner.style.long_line)
    {
        ulong result = 0;
        foreach (ubyte b; _lengthBytes)
            result = (result << 8) | b;

        return result;
    }
}

alias Asn1ShortLength = ubyte;
alias Asn1Length = SumType!(Asn1ShortLength, Asn1LongLength);

struct Asn1Bool
{
    private
    {
        ubyte _value;
    }

    @safe @nogc nothrow:

    this(ubyte value) pure const
    {
        this._value = value;
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Bool result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.booleanIsConstructed, "Booleans cannot be constructed - ISO/IEC 8825-1:2021 8.2.1"); // @suppress(dscanner.style.long_line)
        if(mem.bytesLeft != 1)
            return Result.make(Asn1DecodeError.booleanInvalidEncoding, "Boolean value must be exactly one byte long under BER ruleset - ISO/IEC 8825-1:2021 8.2.1"); // @suppress(dscanner.style.long_line)

        ubyte value;
        if(!mem.readU8(value))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading boolean value");

        static if(ruleset == Asn1Ruleset.der)
        {
            if(value != 0 && value != 0xFF)
                return Result.make(Asn1DecodeError.booleanInvalidDerEncoding, "Boolean value must be 0 or 0xFF under CER and DER rulesets - ISO/IEC 8825-1:2021 11.1"); // @suppress(dscanner.style.long_line)
        }

        result = Asn1Bool(value);
        return Result.noError;
    }

    bool asBool() pure const => _value != 0;
    ubyte value() pure const => _value;
}

struct Asn1Integer
{
    import std.traits : isIntegral;

    private
    {
        const(ubyte)[] _value;
    }

    @trusted nothrow: // TODO: Look into why array's dtor is unsafe/untrusted // @suppress(dscanner.trust_too_much)

    // version(unittest) since I don't know how I want to handle constructing things manually yet, but I need this for testing at the very least.
    version(unittest) static Asn1Integer fromNumberGC(T)(T number)
    if(isIntegral!T)
    {
        import std.bitmanip : nativeToBigEndian;
        auto bytes = nativeToBigEndian(number).dup;
        while(bytes.length > 0 && bytes[0] == 0) // Encode in least amount of bytes
            bytes = bytes[1..$];

        return Asn1Integer.fromUnownedBytes(bytes);
    }

    static Asn1Integer fromUnownedBytes(const(ubyte)[] bytes) @nogc @trusted nothrow
    {
        return Asn1Integer(bytes);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Integer result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.integerIsConstructed, "Integers cannot be constructed - ISO/IEC 8825-1:2021 8.3.1"); // @suppress(dscanner.style.long_line)
        if(mem.bytesLeft == 0)
            return Result.make(Asn1DecodeError.integerInvalidEncoding, "Integers require at least one byte under BER ruleset - ISO/IEC 8825-1:2021 8.3.1"); // @suppress(dscanner.style.long_line)

        const(ubyte)[] bytes;
        if(!mem.readBytes(mem.bytesLeft, bytes))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading integer value");

        if(bytes.length > 1)
        {
            const allZero = (bytes[0] == 0) && ((bytes[1] >> 7) == 0); 
            const allOne  = (bytes[0] == 0xFF) && ((bytes[1] >> 7) == 1); 
            if(allZero || allOne)
                return Result.make(Asn1DecodeError.integerInvalidEncoding, "Integers must be encoded using the least amount of bytes - ISO/IEC 8825-1:2021 8.3.2"); // @suppress(dscanner.style.long_line)
        }

        result = Asn1Integer.fromUnownedBytes(bytes);
        return Result.noError;
    }

    Result asInt(IntT)(scope out IntT result) @nogc
    if(isIntegral!IntT)
    {
        if((this._value.length * 7) > (IntT.sizeof * 8))
        {
            enum Error = "Integer value is too large to fit into a native "~IntT.stringof;
            return Result.make(Asn1DecodeError.integerOverBits, Error); // @suppress(dscanner.style.long_line)
        }

        foreach(b; this._value)
            result = (result << 8) | b;

        return Result.noError;
    }
}

// TODO: It'd be nice to have a generic BitString type. The one in Phobos uses the GC of course...
struct Asn1BitString
{
    private
    {
        const(ubyte)[]  _value;
        size_t          _bitCount;
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    static Asn1BitString fromUnownedBytes(const(ubyte)[] bytes, size_t bitCount) @nogc
    in(bytes.length * 8 >= bitCount, "The bit count must be less than or equal to the amount of bits in the byte array") // @suppress(dscanner.style.long_line)
    {
        return Asn1BitString(bytes, bitCount);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1BitString result,
        const Asn1Identifier ident
    )
    {
        static if(ruleset == Asn1Ruleset.der)
        {
            if(ident.encoding() == Asn1Identifier.Encoding.constructed)
                return Result.make(Asn1DecodeError.bitstringIsConstructedUnderDer, "Bit strings cannot be constructed under DER ruleset - ISO/IEC 8825-1:2021 10.2"); // @suppress(dscanner.style.long_line)
        }
        else
        {
            if(ident.encoding() == Asn1Identifier.Encoding.constructed)
                assert(false, "Constructed bit strings are not implemented yet");
        }

        if(mem.bytesLeft == 0)
            return Result.make(Asn1DecodeError.bitstringInvalidEncoding, "Bit strings require at least one byte under BER ruleset - ISO/IEC 8825-1:2021 8.6.2"); // @suppress(dscanner.style.long_line)

        const(ubyte)[] bytes;
        if(!mem.readBytes(mem.bytesLeft, bytes))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading bit string value");

        const unusedBits = bytes[0];
        if(unusedBits > 7)
            return Result.make(Asn1DecodeError.bitstringInvalidEncoding, "The number of unused bits in a bit string must be between 0 and 7 - ISO/IEC 8825-1:2021 8.6.2.2"); // @suppress(dscanner.style.long_line)
        if(bytes.length == 1 && unusedBits != 0)
            return Result.make(Asn1DecodeError.bitstringInvalidEncoding, "The number of unused bits in a bit string must be 0 if the bit string is empty - ISO/IEC 8825-1:2021 8.6.2.3"); // @suppress(dscanner.style.long_line)
    
        static if(ruleset == Asn1Ruleset.der)
        {
            if(bytes.length > 1 && (bytes[$-1] & (0xFF >> (8 - unusedBits))) != 0)
                return Result.make(Asn1DecodeError.bitstringInvalidEncoding, "The unused bits in a bit string must be zero - ISO/IEC 8825-1:2021 11.2.1"); // @suppress(dscanner.style.long_line)
            if(bytes.length > 1 && bytes[$-1] == 0)
                return Result.make(Asn1DecodeError.bitstringInvalidEncoding, "The last byte of a non-empty bit string must not be zero - ISO/IEC 8825-1:2021 11.2.2"); // @suppress(dscanner.style.long_line)
        }

        const bitCount = ((bytes.length - 1) * 8) - unusedBits; // @suppress(dscanner.suspicious.length_subtraction)
        result = Asn1BitString.fromUnownedBytes(bytes[1..$], bitCount);
        return Result.noError;
    }

    size_t bitCount() const => _bitCount;
}

struct Asn1Real
{
    enum Base : ubyte
    {
        base2      = 0b00,
        base8      = 0b01,
        base16     = 0b10,
        _reserved_ = 0b11,

        // Not encoded under the binary encoding of: ISO/IEC 8825-1:2021 8.5.7, but still needs to be represented.
        base10 = ubyte.max,
    }

    enum Special : ushort
    {
        // Other internal flags not part of the encoding
        notSpecial = 0,
        plusZeroNoContentBytes = 0xFFFF,

        // Part of the encoding
        plusInfinity = 0b01000000,
        minusInfinity = 0b01000001,
        notANumber = 0b01000010,
        minusZero = 0b01000011,
    }

    private
    {
        Base _base; // B'
        bool _isNegative; // S
        ubyte _scalingFactor; // F
        const(ubyte)[] _exponent; // 
        const(ubyte)[] _abstractMantissa; // N
        Special _special;
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    private static Asn1Real fromSpecial(Special special) @nogc
    {
        Asn1Real fp;
        fp._special = special;
        return fp;
    }

    static Asn1Real plusZero() @nogc => fromSpecial(Special.plusZeroNoContentBytes);
    static Asn1Real plusInfinity() @nogc => fromSpecial(Special.plusInfinity);
    static Asn1Real minusInfinity() @nogc => fromSpecial(Special.minusInfinity);
    static Asn1Real notANumber() @nogc => fromSpecial(Special.notANumber);
    static Asn1Real minusZero() @nogc => fromSpecial(Special.minusZero);

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Real result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.realInvalidEncoding, "Real numbers cannot be constructed under BER ruleset - ISO/IEC 8825-1:2021 8.5.1"); // @suppress(dscanner.style.long_line)

        if(mem.bytesLeft == 0)
        {
            result = Asn1Real.plusZero();
            return Result.noError;
        }
        
        ubyte headerByte;
        if(!mem.readU8(headerByte))
            assert(false, "How did we run out of bytes when we just checked for that?");

        if((headerByte & 0b1000_0000) != 0) // Binary encoding
            return fromDecodingBinary!ruleset(mem, result, headerByte);
        else if((headerByte >> 6) == 0b00) // Decimal encoding
            return fromDecodingDecimal!ruleset(mem, result, headerByte);
        else if((headerByte >> 6) == 0b01) // Special encoding
            return fromSpecialEncoding!ruleset(mem, result, headerByte);

        return Result.make(Asn1DecodeError.realInvalidEncoding, "Could not detect (supported) real number encoding.");
    }

    Result asDouble(scope out double number) @nogc
    {
        import std.math : pow;
        import juptune.core.util.maths : checkedAdd, checkedMul;

        final switch(this._special) with(Special)
        {
            case notSpecial: break;
            case plusInfinity:
                number = double.infinity;
                return Result.noError;
            case minusInfinity:
                number = -double.infinity;
                return Result.noError;
            case notANumber:
                number = double.nan;
                return Result.noError;
            case minusZero:
                number = -0;
                return Result.noError;
            case plusZeroNoContentBytes:
                number = +0;
                return Result.noError;
        }

        ulong base;
        final switch(this._base) with(Base)
        {
            case base2: base = 2; break;
            case base8: base = 8; break;
            case base16: base = 16; break;
            case base10: assert(false, "base10 floating point not implemented yet");
            case _reserved_: assert(false);
        }

        long exponent;
        auto exponentResult = Asn1Integer.fromUnownedBytes(this._exponent).asInt!long(exponent);
        if(exponentResult.isError)
            return exponentResult;
        exponent = pow(base, exponent);

        ulong abstractMantissa;
        auto mantissaResult = Asn1Integer.fromUnownedBytes(this._abstractMantissa).asInt!ulong(abstractMantissa);
        if(mantissaResult.isError)
            return mantissaResult;

        const sign = this._isNegative ? -1 : 1;
        const factor = pow(2, this._scalingFactor);
        
        ulong mantissa = 0;
        auto mulResult = checkedMul(abstractMantissa, cast(ulong)factor, mantissa);
        if(mulResult.isError)
            return mulResult;
        
        number = cast(double)mantissa * cast(double)exponent * cast(double)sign;
        return Result.noError;
    }

    private static Result fromDecodingBinary(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope ref Asn1Real result,
        const ubyte header,
    )
    {
        result._isNegative = (header & 0b0100_0000) != 0;
        result._base = cast(Base)((header & 0b0011_0000) >> 4);
        result._scalingFactor = (header & 0b0000_1100) >> 2;
        if(result._base == Base._reserved_)
            return Result.make(Asn1DecodeError.realInvalidEncoding, "Reserved base encoding in real number - ISO/IEC 8825-1:2021 8.5.7.2"); // @suppress(dscanner.style.long_line)
    
        uint exponentLength;
        final switch(header & 0b0000_0011)
        {
            case 0b00:
                exponentLength = 1;
                break;
            case 0b01:
                exponentLength = 2;
                break;
            case 0b10:
                exponentLength = 3;
                break;
            case 0b11:
                ubyte length;
                if(!mem.readU8(length))
                    return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading real number exponent length"); // @suppress(dscanner.style.long_line)
                exponentLength = length;
                break;
        }

        if(!mem.readBytes(exponentLength, result._exponent))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading real number exponent of dynamic length"); // @suppress(dscanner.style.long_line)
        if(!mem.readBytes(mem.bytesLeft, result._abstractMantissa))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading real number abstract mantissa");

        if((header & 0b0000_0011) == 0b11) // If we have a dynamic exponent
        {
            switch(exponentLength)
            {
                case 0:
                    return Result.make(Asn1DecodeError.realInvalidEncoding, "Real number exponent length must be at least 1 byte - ISO/IEC 8825-1:2021 8.7.5.4.d"); // @suppress(dscanner.style.long_line)
                case 1:
                    if(result._exponent[0] == 0 || result._exponent[0] == 0xFF)
                        return Result.make(Asn1DecodeError.realInvalidEncoding, "First 9 bits of real number exponent must not be 0 or 1 - ISO/IEC 8825-1:2021 8.7.5.4.d"); // @suppress(dscanner.style.long_line)
                    break;
                default:
                    if(
                        (result._exponent[0] == 0 && (result._exponent[1] & 0b1000_0000) == 0)
                        || (result._exponent[0] == 0xFF && (result._exponent[1] & 0b1000_0000) == 1)
                    )
                        return Result.make(Asn1DecodeError.realInvalidEncoding, "First 9 bits of real number exponent must not be 0 or 1 - ISO/IEC 8825-1:2021 8.7.5.4.d"); // @suppress(dscanner.style.long_line)
                    break;
            }
        }

        static if(ruleset == Asn1Ruleset.der)
        {
            if(result._base == Base.base2)
            {
                if(result._scalingFactor != 0)
                    return Result.make(Asn1DecodeError.realInvalidDerEncoding, "Under DER, the scaling factor must be 0 for base 2 binary encoding - ISO/IEC 8825-1:2021 11.3.1"); // @suppress(dscanner.style.long_line)
                
                const hasAbstractMantissa 
                    = result._abstractMantissa.length > 0; // Not sure how this is actually encoded.
                const abstractMantissaIsZero 
                    = result._abstractMantissa.length == 1 
                    && result._abstractMantissa[0] == 0;
                const abstractMantissaIsEven 
                    = result._abstractMantissa.length > 0 
                    && (result._abstractMantissa[$-1] & 0b0000_0001) == 0;
                
                const notZero = !hasAbstractMantissa || !abstractMantissaIsZero;
                if(notZero && abstractMantissaIsEven)
                    return Result.make(Asn1DecodeError.realInvalidDerEncoding, "Under DER, the abstract mantissa either be 0 or odd when using base 2 binary encoding - ISO/IEC 8825-1:2021 11.3.1"); // @suppress(dscanner.style.long_line)
            }
        }

        return Result.noError;
    }

    private static Result fromDecodingDecimal(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope ref Asn1Real result,
        const ubyte header,
    )
    {
        result._base = Base.base10;
        const nrForm = header & 0b0011_1111;

        if(nrForm != 3)
            return Result.make(Asn1DecodeError.realUnsupportedDecimalEncoding, "Unsupported NR form in real number - ISO/IEC 8825-1:2021 8.5.8"); // @suppress(dscanner.style.long_line)

        return Result.make(Asn1DecodeError.notImplemented, "Not implemented yet");
    }

    private static Result fromSpecialEncoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope ref Asn1Real result,
        const ubyte header,
    )
    {
        ubyte content;
        if(!mem.readU8(content))
            return Result.make(Asn1DecodeError.realInvalidEncoding, "Expected content byte for SpecialRealValue encoding - ISO/IEC 8825-1:2021 8.5.9"); // @suppress(dscanner.style.long_line)

        switch(content) with(Special)
        {
            case plusInfinity:
                result._special = plusInfinity;
                return Result.noError;

            case minusInfinity:
                result._special = minusInfinity;
                return Result.noError;

            case notANumber:
                result._special = notANumber;
                return Result.noError;

            case minusZero:
                result._special = minusZero;
                return Result.noError;

            default:
                return Result.make(Asn1DecodeError.realUnsupportedSpecialEncoding, "Unknown SpecialRealValue - ISO/IEC 8825-1:2021 8.5.9"); // @suppress(dscanner.style.long_line)
        }
    }
}

struct Asn1OctetString
{
    private
    {
        const(ubyte)[] _data;
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    static Asn1OctetString fromUnownedBytes(const(ubyte)[] data) @nogc
    {
        return Asn1OctetString(data);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1OctetString result,
        const Asn1Identifier ident
    )
    {
        static if(ruleset == Asn1Ruleset.der)
        {
            if(ident.encoding() == Asn1Identifier.Encoding.constructed)
                return Result.make(Asn1DecodeError.octetstringIsConstructedUnderDer, "Octet strings cannot be constructed under DER ruleset - ISO/IEC 8825-1:2021 10.2"); // @suppress(dscanner.style.long_line)
        }
        else
        {
            if(ident.encoding() == Asn1Identifier.Encoding.constructed)
                assert(false, "Constructed octet strings are not implemented yet");
        }

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading octet string contents");
    
        result = Asn1OctetString.fromUnownedBytes(data);
        return Result.noError;
    }

    const(ubyte)[] data() @nogc => this._data;
}

struct Asn1Null
{
    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Null result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.nullIsConstructed, "Null cannot be constructed - ISO/IEC 8825-1:2021 8.8.1"); // @suppress(dscanner.style.long_line)
        if(mem.bytesLeft != 0)
            return Result.make(Asn1DecodeError.nullHasContentBytes, "Null cannot be contain content bytes - ISO/IEC 8825-1:2021 8.8.2"); // @suppress(dscanner.style.long_line)
    
        return Result.noError;
    }
}

struct Asn1Primitive(string TypeName)
{
    private
    {
        const(ubyte)[] _data;
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    static typeof(this) fromUnownedBytes(const(ubyte)[] data) @nogc
    {
        return typeof(this)(data);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.constructed)
        {
            enum Error = TypeName ~ " cannot be constructed, it must be primitive";
            return Result.make(Asn1DecodeError.primitiveIsConstructed, Error); // @suppress(dscanner.style.long_line)
        }

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
        {
            enum Error = "Ran out of bytes when reading contents for primitive " ~ TypeName;
            return Result.make(Asn1DecodeError.eof, Error);
        }

        result = typeof(this).fromUnownedBytes(data);
        return Result.noError;
    }

    const(ubyte)[] data() @nogc => this._data;
}

struct Asn1Construction(string TypeName)
{
    private
    {
        const(ubyte)[] _data;
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    static typeof(this) fromUnownedBytes(const(ubyte)[] data) @nogc
    {
        return typeof(this)(data);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.primitive)
        {
            enum Error = TypeName ~ " cannot be primitive, it must be constructed";
            return Result.make(Asn1DecodeError.constructionIsPrimitive, Error); // @suppress(dscanner.style.long_line)
        }

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
        {
            enum Error = "Ran out of bytes when reading contents for construction " ~ TypeName;
            return Result.make(Asn1DecodeError.eof, Error);
        }

        result = typeof(this).fromUnownedBytes(data);
        return Result.noError;
    }

    const(ubyte)[] data() @nogc => this._data;
}

private struct Asn1ObjectIdentifierImpl(bool IsRelative)
{
    import std.typecons : Nullable;
    
    private
    {
        static if(IsRelative)
        {
            const(ubyte)[] _rest;
        }
        else
        {
            ubyte _first;
            ubyte _second;
            const(ubyte)[] _rest;
        }
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    static if(IsRelative)
    {
        static typeof(this) fromUnownedBytes(const(ubyte)[] ids) @nogc
        {
            return typeof(this)(ids);
        }
    }
    else
    {
        static typeof(this) fromUnownedBytes(ubyte firstId, ubyte secondId, const(ubyte)[] thirdOnwardIds) @nogc
        {
            return typeof(this)(firstId, secondId, thirdOnwardIds);
        }
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.oidIsConstructed, "Object Identifiers cannot be constructed - ISO/IEC 8825-1:2021 8.19.1");

        // It doesn't explicitly say how to handle when length == 0, so I guess allow it?
        if(mem.bytesLeft == 0)
            return Result.noError;

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading contents for Object Identifier");

        static if(!IsRelative)
        {
            ubyte first, second;
            if(data[0] >= 80)
            {
                first = 2;
                second = cast(ubyte)(data[0] - 80);
            }
            else
            {
                first = cast(ubyte)(data[0] / 40);
                second = cast(ubyte)(data[0] % 40);
            }
            result = typeof(this).fromUnownedBytes(first, second, data[1..$]);
            data = data[1..$];
        }
        else
            result = typeof(this).fromUnownedBytes(data);

        while(data.length > 0)
        {
            Nullable!ulong _;
            const slice = next7BitInt(data, _);
            if(slice[0] == 0x80)
                return Result.make(Asn1DecodeError.oidInvalidEncoding, "Object Identifier subidentifiers cannot start with 0x80 as the first byte - ISO/IEC 8825-1:2021 8.19.3"); // @suppress(dscanner.style.long_line)
            data = data[slice.length..$];
        }

        return Result.noError;
    }

    auto components() @nogc scope
    {
        alias OID = typeof(this);
        static struct R
        {
            OID id;
            size_t cursor;
            
            Nullable!ulong front;
            bool empty;

            static if(!IsRelative)
            {
                bool doneFirst;
                bool doneSecond;
            }

            @nogc @safe nothrow:

            this(OID id)
            {
                this.id = id;
                this.popFront();
            }

            void popFront()
            {
                static if(!IsRelative)
                {
                    if(!this.doneFirst)
                    {
                        this.front = this.id._first;
                        this.doneFirst = true;
                        return;
                    }
                    else if(!this.doneSecond)
                    {
                        this.front = this.id._second;
                        this.doneSecond = true;
                        return;
                    }
                }

                if(this.cursor >= this.id._rest.length)
                {
                    this.empty = true;
                    return;
                }

                const bytes = next7BitInt(this.id._rest[cursor..$], this.front);
                cursor += bytes.length;
            }
        }

        return R(this);
    }

    private static const(ubyte)[] next7BitInt(
        scope return const(ubyte)[] data, 
        scope out Nullable!ulong outResult,
    ) @nogc
    in(data.length > 0, "data is empty, likely a missing check from the caller's end")
    {
        size_t cursor;
        ulong result;
        
        do
        {
            result <<= 7;
            result |= (data[cursor] & 0b0111_1111);
        } while(cursor < data.length && (data[cursor++] & 0b1000_0000));

        if(cursor * 7 <= typeof(result).sizeof * 8)
            outResult = result;

        return data[0..cursor];
    }
}

alias Asn1ObjectIdentifier = Asn1ObjectIdentifierImpl!false;
alias Asn1RelativeObjectIdentifier = Asn1ObjectIdentifierImpl!true;

/**
    TODO TYPES:
        8.21 - Need to handle UTF support in @nogc?
        8.22 - ^^
**/

struct Asn1ComponentHeader
{
    Asn1Identifier identifier;
    Asn1Length length;
}

enum Asn1Ruleset
{
    der,
}

enum Asn1DecodeError
{
    none,
    eof,
    notImplemented,
    
    identifierTagTooLong,
    identifierTagInvalidEncoding,
    
    componentLengthReserved,
    componentLengthIndefiniteUnderDer,
    componentLengthInvalidDerEncoding,
    componentLengthOver64Bits,
    
    booleanInvalidEncoding,
    booleanInvalidDerEncoding,
    booleanIsConstructed,
    
    integerInvalidEncoding,
    integerInvalidDerEncoding,
    integerOverBits,
    integerIsConstructed,
    
    bitstringIsConstructedUnderDer,
    bitstringInvalidEncoding,

    realInvalidEncoding,
    realInvalidDerEncoding,
    realUnsupportedDecimalEncoding,
    realUnsupportedSpecialEncoding,

    octetstringIsConstructedUnderDer,

    nullIsConstructed,
    nullHasContentBytes,

    constructionIsPrimitive,
    primitiveIsConstructed,

    oidInvalidEncoding,
    oidIsConstructed,
}

Result asn1DecodeComponentHeader(Asn1Ruleset ruleset)(
    scope ref MemoryReader mem, 
    scope out Asn1ComponentHeader header
) @trusted @nogc nothrow
{
    auto error = asn1DecodeIdentifier!ruleset(mem, header.identifier);
    if(error.isError)
        return error;

    error = asn1DecodeLength!ruleset(mem, header.length);
    if(error.isError)
        return error;

    return Result.noError;
}

Result asn1DecodeIdentifier(Asn1Ruleset ruleset)(
    scope ref MemoryReader mem, 
    scope out Asn1Identifier ident
) @safe @nogc nothrow
{
    ubyte initialByte;
    if(!mem.readU8(initialByte))
        return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading initial byte of identifier");

    // ISO/IEC 8825-1:2021 8.1.2.2
    const class_    = cast(Asn1Identifier.Class)(initialByte >> 6);
    const encoding  = cast(Asn1Identifier.Encoding)((initialByte >> 5) & 1);
    const shortTag  = initialByte & 0b0001_1111;

    if(shortTag <= 30)
    {
        ident = Asn1Identifier(class_, encoding, shortTag);
        return Result.noError;
    }

    // ISO/IEC 8825-1:2021 8.1.2.4
    Asn1Identifier.Tag longTag = 0;
    ubyte tagByte;
    int counter;
    do
    {
        if(counter >= 9) // We can left shift by 7, 9 times before overflowing
            return Result.make(Asn1DecodeError.identifierTagTooLong, "Encoding of identifier long form tag is too long"); // @suppress(dscanner.style.long_line)
        if(!mem.readU8(tagByte))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading long form tag byte of identifier");
        if(counter == 0 && (tagByte & 0b0111_1111) == 0)
            return Result.make(Asn1DecodeError.identifierTagInvalidEncoding, "The first byte of the identifier long form tag must not have its first 7 bits as zero - ISO/IEC 8825-1:2021 8.1.2.4.2.c"); // @suppress(dscanner.style.long_line)

        longTag = (longTag << 7) | (tagByte & 0b0111_1111);
        counter++;
    } while(tagByte & 0b1000_0000);

    ident = Asn1Identifier(class_, encoding, longTag);
    return Result.noError;
}

Result asn1DecodeLength(Asn1Ruleset ruleset)(
    scope ref MemoryReader mem, 
    scope out Asn1Length length
) @trusted @nogc nothrow
{
    ubyte initialByte;
    if(!mem.readU8(initialByte))
        return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading initial byte of component length");
    if(initialByte == ubyte.max)
        return Result.make(Asn1DecodeError.componentLengthReserved, "Component length byte value is reserved - ISO/IEC 8825-1:2021 8.1.3.5.c"); // @suppress(dscanner.style.long_line)

    // ISO/IEC 8825-1:2021 8.1.3.4
    bool isShortForm = (initialByte & 0b1000_0000) == 0;
    if(isShortForm)
    {
        length = Asn1Length(initialByte);
        return Result.noError;
    }

    // ISO/IEC 8825-1:2021 8.1.3.6
    const isIndefinite = initialByte == 0x80;
    static if(ruleset == Asn1Ruleset.der)
    {
        if(isIndefinite)
            return Result.make(Asn1DecodeError.componentLengthIndefiniteUnderDer, "Indefinite lengths are not allowed under DER ruleset - ISO/IEC 8825-1:2021 10.1"); // @suppress(dscanner.style.long_line)
    }
    else
    {
        if(isIndefinite)
            assert(false, "Indefinite lengths are not implemented yet"); // since we currently only support DER, which forbids indefinite lengths
    }

    // ISO/IEC 8825-1:2021 8.1.3.5
    const(ubyte)[] lengthBytesResult;
    const lengthByteCount = initialByte & 0b0111_1111;
    if(!mem.readBytes(lengthByteCount, lengthBytesResult))
        return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading long form length bytes");

    static if(ruleset == Asn1Ruleset.der)
    {
        if(lengthByteCount == 1 && lengthBytesResult[0] <= 0x7F)
            return Result.make(Asn1DecodeError.componentLengthInvalidDerEncoding, "Invalid encoding of component length under DER ruleset, values of <=127 must use the short form of encoding - ISO/IEC 8825-1:2021 10.1"); // @suppress(dscanner.style.long_line)
    }

    length = Asn1Length(Asn1LongLength.fromUnownedBytes(lengthBytesResult));
    return Result.noError;
}

Result asn1ReadContentBytes(
    scope ref MemoryReader mem,
    const Asn1Length length,
    scope out MemoryReader contentReader,
) @safe @nogc nothrow
in(length != Asn1Length.init, "The length must be initialized")
{
    import std.sumtype : match;
    const(ubyte)[] contentBytes;

    // ISO/IEC 8825-1:2021 8.1.4
    return length.match!(
        (Asn1ShortLength shortLength) @trusted {
            if(!mem.readBytes(shortLength, contentBytes))
                return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading content bytes");
            contentReader = MemoryReader(contentBytes);
            return Result.noError;
        },
        (Asn1LongLength longLength) @trusted {
            if(!longLength.isAtMost64Bits)
                return Result.make(Asn1DecodeError.componentLengthOver64Bits, "Component length is too long to fit into a native ulong"); // @suppress(dscanner.style.long_line)
            if(!mem.readBytes(longLength.length, contentBytes))
                return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading content bytes");
            contentReader = MemoryReader(contentBytes);
            return Result.noError;
        }
    );
}

/++++ Unittests ++++/

@("Asn1Identifier - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Identifier expected;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1Identifier expected)
        {
            this.data = data;
            this.expected = expected;
        }

        this(ubyte[] data, Asn1DecodeError error)
        {
            this.data = data;
            this.expectedError = error;
        }
    }

    alias cl = Asn1Identifier.Class;
    alias en = Asn1Identifier.Encoding;
    alias err = Asn1DecodeError;
    const cases = [
        "class - universal": T(
            [0b0000_0000],
            Asn1Identifier(cl.universal, en.primitive, 0)
        ),
        "class - application": T(
            [0b0100_0000],
            Asn1Identifier(cl.application, en.primitive, 0)
        ),
        "class - contextSpecific": T(
            [0b1000_0000],
            Asn1Identifier(cl.contextSpecific, en.primitive, 0)
        ),
        "class - private": T(
            [0b1100_0000],
            Asn1Identifier(cl.private_, en.primitive, 0)
        ),

        "encoding - primitive": T(
            [0b1101_1101],
            Asn1Identifier(cl.private_, en.primitive, 0b1_1101)
        ),
        "encoding - constructed": T(
            [0b0010_0000],
            Asn1Identifier(cl.universal, en.constructed, 0)
        ),

        "tag - short 0": T(
            [0b0000_0000],
            Asn1Identifier(cl.universal, en.primitive, 0)
        ),
        "tag - short 15": T(
            [0b0000_1111],
            Asn1Identifier(cl.universal, en.primitive, 15)
        ),
        "tag - short 30": T(
            [0b0001_1110],
            Asn1Identifier(cl.universal, en.primitive, 30)
        ),

        "tag - long 31": T(
            [0b0001_1111, 0b0001_1111],
            Asn1Identifier(cl.universal, en.primitive, 31)
        ),
        "tag - long all ones, 1 byte": T(
            [0b0001_1111, 0b0111_1111],
            Asn1Identifier(cl.universal, en.primitive, 0b0111_1111)
        ),
        "tag - long all ones, 2 bytes": T(
            [0b0001_1111, 0b1111_1111, 0b0111_1111],
            Asn1Identifier(cl.universal, en.primitive, 0b0011_1111_1111_1111)
        ),
        "tag - long all ones, 3 bytes": T(
            [0b0001_1111, 0b1111_1111, 0b1111_1111, 0b0111_1111],
            Asn1Identifier(cl.universal, en.primitive, 0b0001_1111_1111_1111_1111_1111)
        ),
        "tag - long alternating, 3 bytes": T(
            [0b0001_1111, 0b1101_0101, 0b1010_1010, 0b0101_0101],
            Asn1Identifier(cl.universal, en.primitive, 0b0001_0101_0101_0101_0101_0101)
        ),

        "tag error - long form must be in minimal amount of octets - 8.1.2.4.2.c": T(
            [0b0001_1111, 0b1000_0000, 0b0111_1111],
            err.identifierTagInvalidEncoding
        ),
        "tag error - long form must fit into a native 64-bit int": T(
            [0b0001_1111, 0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b1000_0001,0b0000_0001], // @suppress(dscanner.style.long_line)
            err.identifierTagTooLong
        ),

        "eof error - initial read": T(
            [],
            err.eof
        ),
        "eof error - reading long tag": T(
            [0b0001_1111, 0b1000_0001],
            err.eof
        ),
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Identifier identifier;
            auto result = asn1DecodeIdentifier!(Asn1Ruleset.der)(mem, identifier);
            
            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(identifier == test.expected, format("\n  Got: %s\n  Expected: %s", identifier, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Length - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.sumtype       : match;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Length expected;
        Nullable!Asn1DecodeError expectedError;
        ulong expectedLongLength;

        this(ubyte[] data, Asn1ShortLength expected)
        {
            this.data = data;
            this.expected = expected;
        }

        this(ubyte[] data, Asn1LongLength expected, ulong expectedAsLong)
        {
            this.data = data;
            this.expected = expected;
            this.expectedLongLength = expectedAsLong;
        }

        this(ubyte[] data, Asn1DecodeError error, bool _compileIsStupid)
        {
            this.data = data;
            this.expectedError = error;
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "short - 8.1.3.4 example": T(
            [0b0010_0110],
            38
        ),
        "short - all 7 bits": T(
            [0b0111_1111],
            127
        ),

        "long - 8.1.3.5 example": T(
            [0b1000_0001, 0b1100_1001],
            Asn1LongLength.fromNumberGC(201u), 201u
        ),
        "long - DEADBEEF": T(
            [0b1000_0100, 0xDE, 0xAD, 0xBE, 0xEF],
            Asn1LongLength.fromNumberGC(0xDEADBEEFu), 0xDEADBEEFu
        ),
        "long - 128 should be ok": T(
            [0b1000_0001, 128],
            Asn1LongLength.fromNumberGC(128u), 128u
        ),

        "long error - all 1s can't be used": T(
            [0b1111_1111],
            err.componentLengthReserved, true
        ),
        "long error DER - bytes must be encoded in minimum amount of bytes": T(
            [0b1000_0001, 127], // The short form should've been used for a value <= 127
            err.componentLengthInvalidDerEncoding, true
        ),

        "eof - initial read": T(
            [],
            err.eof, true
        ),
        "eof - not enough long bytes": T(
            [0b1111_1110],
            err.eof, true
        ),
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Length length;
            auto result = asn1DecodeLength!(Asn1Ruleset.der)(mem, length);
            
            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(length == test.expected, format("\n  Got: %s\n  Expected: %s", length, test.expected));
            
            length.match!(
                (Asn1LongLength ll) { // Double checking that the decoder actually works
                    if(ll.isAtMost64Bits)
                        assert(ll.length == test.expectedLongLength);
                },
                (_){}
            );
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("asn1ReadContentBytes")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        ubyte[] expected;
        Asn1Length length;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, ubyte[] expected, Asn1ShortLength length)
        {
            this.data = data;
            this.expected = expected;
            this.length = length;
        }

        this(ubyte[] data, ubyte[] expected, Asn1LongLength length)
        {
            this.data = data;
            this.expected = expected;
            this.length = length;
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1ShortLength length)
        {
            this.data = data;
            this.expectedError = error;
            this.length = length;
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1LongLength length)
        {
            this.data = data;
            this.expectedError = error;
            this.length = length;
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "short - full": T([0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], 6),
        "short - partial": T([0, 1, 2, 3, 4, 5], [0, 1, 2], 3),
        "short error - too many": T([0], err.eof, 2),

        "long - full": T([0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5], Asn1LongLength.fromNumberGC(6u)),
        "long - partial": T([0, 1, 2, 3, 4, 5], [0, 1, 2], Asn1LongLength.fromNumberGC(3u)),
        "long error - too many": T([0], err.eof, Asn1LongLength.fromNumberGC(2u)),
        "long error - length too long": T([0], err.componentLengthOver64Bits, Asn1LongLength.fromUnownedBytes([0,0,0,0,0,0,0,0,0])), // @suppress(dscanner.style.long_line)
    ];

    foreach(name, test; cases)
    {
        try
        {
            MemoryReader content;
            auto mem = MemoryReader(test.data);
            auto result = asn1ReadContentBytes(mem, test.length , content);
            
            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            const(ubyte)[] gotContent;
            assert(content.readBytes(content.bytesLeft, gotContent));

            assert(gotContent == test.expected, format("\n  Got: %s\n  Expected: %s", gotContent, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Bool - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Bool expected;
        bool expectedBool;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1Bool expected, bool expectedBool)
        {
            this.data = data;
            this.expected = expected;
            this.expectedBool = expectedBool;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "false": T([0], Asn1Bool(0), false),
        "true": T([0xFF], Asn1Bool(0xFF), true),

        "error - bool must only be 1 byte long": T([0, 0], err.booleanInvalidEncoding),
        "error - bool must only be 1 byte long (0 case)": T([], err.booleanInvalidEncoding),
        "error - must not be constructed": T([0], err.booleanIsConstructed, Asn1Identifier.Encoding.constructed),
        "error DER - true can only be 0xFF": T([0xFE], err.booleanInvalidDerEncoding),
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Bool obj;
            auto result = Asn1Bool.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
            assert(obj.asBool == test.expectedBool);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Integer - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Integer expected;
        ulong expectedAsLong;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1Integer expected, ulong expectedAsLong)
        {
            this.data = data;
            this.expected = expected;
            this.expectedAsLong = expectedAsLong;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "1 byte": T([127], Asn1Integer.fromNumberGC(127), 127),
        "2 bytes": T([1, 0], Asn1Integer.fromNumberGC(256), 256),

        "error - eof on initial read": T([], err.integerInvalidEncoding),
        "error - must not be constructed": T([], err.integerIsConstructed, Asn1Identifier.Encoding.constructed),
        "error - must be encoded in minimum amount of bytes (0 case)": T([0, 0b0111_1111], err.integerInvalidEncoding),
        "error - must be encoded in minimum amount of bytes (1 case)": T([0xFF, 0b1000_0000], err.integerInvalidEncoding), // @suppress(dscanner.style.long_line)
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Integer obj;
            auto result = Asn1Integer.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
            
            ulong got;
            obj.asInt!ulong(got).resultAssert;
            assert(got == test.expectedAsLong, format("\n  Got: %s\n  Expected: %s", got, test.expectedAsLong));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1BitString - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1BitString expected;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1BitString expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "empty string": T([0], Asn1BitString.fromUnownedBytes([], 0)),
        "7 unused bits": T([0x07, 0b1000_0000], Asn1BitString.fromUnownedBytes([0b1000_0000], 1)),
        "multiple bytes": T([0x00, 0xDE, 0xAD, 0xBE, 0xEF], Asn1BitString.fromUnownedBytes([0xDE, 0xAD, 0xBE, 0xEF], 32)), // @suppress(dscanner.style.long_line)

        "error DER - must not be constructed": T([], err.bitstringIsConstructedUnderDer, Asn1Identifier.Encoding.constructed), // @suppress(dscanner.style.long_line)
        "error - must have at least one byte": T([], err.bitstringInvalidEncoding),
        "error - unused bits must be <= 7": T([0x08], err.bitstringInvalidEncoding),
        "error - unused bits must be 0 for empty strings": T([0x01], err.bitstringInvalidEncoding),
        "error DER - unused bits must be set to 0": T([0x07, 0xFF], err.bitstringInvalidEncoding),
        "error DER - the last byte must not be 0": T([0x00, 0x00], err.bitstringInvalidEncoding),
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto mem = MemoryReader(test.data);

            Asn1BitString obj;
            auto result = Asn1BitString.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Real - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Real expected;
        double expectedDouble;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1Real expected, double expectedAsDouble)
        {
            this.data = data;
            this.expected = expected;
            this.expectedDouble = expectedAsDouble;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    alias base = Asn1Real.Base;
    alias spec = Asn1Real.Special;
    const cases = [
        // https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/real.html
        "quick reference example (DER-ified)": T(
            [0x80, 0x01, 0x05], // DER requires the mantissa to be odd, so the example has to shift by 1
            Asn1Real(base.base2, false, 0, [1], [0x05], spec.notSpecial),
            10.0
        ),
        "negative sign": T(
            [0b1_1_00_00_00, 0x01, 0x05],
            Asn1Real(base.base2, true, 0, [1], [0x05], spec.notSpecial),
            -10.0
        ),

        "special - plus zero": T([], Asn1Real.plusZero, +0),
        "special - plus infinity": T(
            [0b0100_0000, 0b0100_0000],
            Asn1Real.plusInfinity,
            +double.infinity
        ),
        "special - minus infinity": T(
            [0b0100_0000, 0b0100_0001],
            Asn1Real.minusInfinity,
            -double.infinity
        ),
        "special - NaN": T(
            [0b0100_0000, 0b0100_0010],
            Asn1Real.notANumber,
            double.nan
        ),
        "special - minus zero": T(
            [0b0100_0000, 0b0100_0011],
            Asn1Real.minusZero,
            -0
        ),

        "error - must not be constructed": T([], err.realInvalidEncoding, Asn1Identifier.Encoding.constructed),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Real obj;
            auto result = Asn1Real.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            double value;
            obj.asDouble(value).resultAssert;
            
            if(!name.canFind("NaN")) // NaN can never equal NaN in D
                assert(value == test.expectedDouble, format("\n  Got: %s\n  Expected: %s", value, test.expectedDouble));
            
            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1OctetString - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1OctetString expected;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1OctetString expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "happy path": T(
            ['D', 'E', 'A', 'D', 'B', 'E', 'E', 'F'],
            Asn1OctetString.fromUnownedBytes(['D', 'E', 'A', 'D', 'B', 'E', 'E', 'F']),
        ),

        "error DER - must not be constructed": T([], err.octetstringIsConstructedUnderDer, Asn1Identifier.Encoding.constructed), // @suppress(dscanner.style.long_line)
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1OctetString obj;
            auto result = Asn1OctetString.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Null - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        ubyte[] data;
        Asn1Null expected;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Asn1Null expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "happy path": T([], Asn1Null()),
        "error - must not have content bytes": T([0], err.nullHasContentBytes),
        "error - must not be constructed": T([], err.nullIsConstructed, Asn1Identifier.Encoding.constructed),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Null obj;
            auto result = Asn1Null.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Primitive - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    alias Primivite = Asn1Primitive!"unittest";
    
    static struct T
    {
        ubyte[] data;
        Primivite expected;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Primivite expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "happy path": T([0xDE, 0xAD, 0xBE, 0xEF], Primivite.fromUnownedBytes([0xDE, 0xAD, 0xBE, 0xEF])),
        "error - must not be constructed": T([], err.primitiveIsConstructed, Asn1Identifier.Encoding.constructed),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind;

        try
        {
            auto mem = MemoryReader(test.data);

            Primivite obj;
            auto result = Primivite.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Construction - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    alias Construct = Asn1Construction!"unittest";
    
    static struct T
    {
        ubyte[] data;
        Construct expected;
        Asn1Identifier ident;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, Construct expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.constructed, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.constructed) // @suppress(dscanner.style.long_line)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "happy path": T([0xDE, 0xAD, 0xBE, 0xEF], Construct.fromUnownedBytes([0xDE, 0xAD, 0xBE, 0xEF])),
        "error - must not be primitive": T([], err.constructionIsPrimitive, Asn1Identifier.Encoding.primitive),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind;

        try
        {
            auto mem = MemoryReader(test.data);

            Construct obj;
            auto result = Construct.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj == test.expected, format("\n  Got: %s\n  Expected: %s", obj, test.expected));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1ObjectIdentifier - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        ulong[] expectedIds;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, ulong[] expectedIds)
        {
            this.data = data;
            this.expectedIds = expectedIds;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "quick reference example": T(
            [0x28, 0xC2, 0x7B, 0x02, 0x01], // https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/object-identifier.html
            [1, 0, 8571, 2, 1],
        ),

        // It doesn't make sense to me how this encoding is reached,
        // is the recommendation example wrong here? 
        // "recommendation example": T(
        //     [0x88, 0x37, 0x03],
        //     [2, 999, 3]
        // ),

        "internet example": T(
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D], // https://luca.ntop.org/Teaching/Appunti/asn1.html
            [1, 2, 840, 113_549]
        ),

        "error - must not be constructed": T([], err.oidIsConstructed, Asn1Identifier.Encoding.constructed),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1ObjectIdentifier obj;
            auto result = Asn1ObjectIdentifier.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.components.equal(test.expectedIds), format("\n  Got: %s\n  Expected: %s", obj.components, test.expectedIds)); // @suppress(dscanner.style.long_line)
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1RelativeObjectIdentifier - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        ulong[] expectedIds;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, ulong[] expectedIds)
        {
            this.data = data;
            this.expectedIds = expectedIds;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive)
        {
            this.data = data;
            this.expectedError = error;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                encoding, 
                0
            );
        }
    }

    alias err = Asn1DecodeError;
    const cases = [
        "recommendation example": T(
            [0xC2, 0x7B, 0x03, 0x02],
            [8571, 3, 2],
        ),

        "error - must not be constructed": T([], err.oidIsConstructed, Asn1Identifier.Encoding.constructed),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1RelativeObjectIdentifier obj;
            auto result = Asn1RelativeObjectIdentifier.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.components.equal(test.expectedIds), format("\n  Got: %s\n  Expected: %s", obj.components, test.expectedIds)); // @suppress(dscanner.style.long_line)
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}