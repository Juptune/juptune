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
    enum MIN_BYTES = 1;
    enum MAX_BYTES = 127;

    private
    {
        const(ubyte)[] _lengthBytes;
    }

    @safe @nogc nothrow pure:

    static Asn1LongLength fromUnownedBytes(const ubyte[] lengthBytes)
    in(lengthBytes.length >= MIN_BYTES && lengthBytes.length <= MAX_BYTES, "The amount of bytes must be between 1 and 127") // @suppress(dscanner.style.long_line)
    {
        return Asn1LongLength(lengthBytes);
    }

    const(ubyte)[] lengthBytes() const => _lengthBytes; // TODO: Note that this is always in big endian.
    
    bool isAtMost64Bits() const
    {
        return this._lengthBytes.length <= 8;
    }

    ulong length() const
    in(this.isAtMost64Bits(), "The amount of bytes is too large to represent as a ulong - please check with isAtMost64Bits or amountOfBytes") // @suppress(dscanner.style.long_line)
    {
        import std.bitmanip : swapEndian;

        ulong result = 0;
        foreach (ubyte b; _lengthBytes)
            result = (result << 8) | b;

        version(LittleEndian)
            result = swapEndian(result);
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

    static Result fromDecoding(Asn1Ruleset ruleset)(scope ref MemoryReader mem, scope out Asn1Bool result)
    {
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

    static Asn1Integer fromUnownedBytes(const(ubyte)[] bytes) @nogc @trusted nothrow
    {
        return Asn1Integer(bytes);
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Integer result
    )
    {
        if(mem.bytesLeft == 0)
            return Result.make(Asn1DecodeError.integerInvalidEncoding, "Integers require at least one byte under BER ruleset - ISO/IEC 8825-1:2021 8.3.1"); // @suppress(dscanner.style.long_line)

        const(ubyte)[] bytes;
        if(!mem.readBytes(mem.bytesLeft, bytes))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading integer value");

        result = Asn1Integer.fromUnownedBytes(bytes);
        return Result.noError;
    }

    Result asInt(IntT)(scope out IntT result) @nogc
    if(isIntegral!IntT)
    {
        import std.bitmanip : swapEndian;

        if(this._value.length > IntT.sizeof)
            return Result.make(Asn1DecodeError.integerOverBits, "Integer value is too large to fit into a native integer type"); // @suppress(dscanner.style.long_line)

        foreach(b; this._value)
            result = (result << 8) | b;

        version(LittleEndian)
            result = swapEndian(result);

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
            if(bytes.length > 1 && (bytes[$-1] & (0xFF >> unusedBits)) != 0)
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

    static Asn1Real plusZero() @nogc
    {
        Asn1Real fp;
        fp._special = Special.plusZeroNoContentBytes;
        return fp;
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Real result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.realInvalidEncoding, "Real numbers cannot be constructed under BER ruleset - ISO/IEC 8825-1:2021 8.5.1"); // @suppress(dscanner.style.long_line)

        if(mem.bytesLeft == 0)
            return Asn1Real.plusZero(); // I think this is how to interpret ISO/IEC 8825-1:2021 8.5.2?
        
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

    Result calculate(scope out double number) @nogc
    {
        import std.math : pow;
        import juptune.core.util.maths : checkedAdd, checkedMul;

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

    private Result fromDecodingBinary(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope ref Asn1Real result,
        const ubyte header,
    )
    {
        result._isNegative = (header & 0b0100_0000) == 1;
        result._base = cast(Base)(header & 0b0011_0000);
        result._scalingFactor = header & 0b0000_1100;
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
                if(!mem.readU8(exponentLength))
                    return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading real number exponent length"); // @suppress(dscanner.style.long_line)
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
                    return Result.make(Asn1DecodeError.realInvalidDerEncoding, "Under DER, the abstract mantissa either be 0 or odd when using base 2 binary encoding - ISO/IEC 8825-1:2021 11.3.2"); // @suppress(dscanner.style.long_line)
            }
        }

        return Result.noError;
    }

    private Result fromDecodingDecimal(Asn1Ruleset ruleset)(
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

    private Result fromSpecialEncoding(Asn1Ruleset ruleset)(
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
                this._special = plusInfinity;
                break;

            case minusInfinity:
                this._special = minusInfinity;
                break;

            case notANumber:
                this._special = notANumber;
                break;

            case minusZero:
                this._special = minusZero;
                break;

            default:
                return Result.make(Asn1DecodeError.realUnsupportedSpecialEncoding, "Unknown SpecialRealValue - ISO/IEC 8825-1:2021 8.5.9"); // @suppress(dscanner.style.long_line)
        }

        return Result.make(Asn1DecodeError.notImplemented, "Not implemented yet");
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
            return Result.make("Object Identifiers cannot be constructed - ISO/IEC 8825-1:2021 8.19.1");

        // It doesn't explicitly say how to handle when length == 0, so I guess allow it?
        if(mem.bytesLeft == 0)
            return Result.noError;

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading contents for Object Identifier");

        static if(!IsRelative)
        {
            const first = data[0] / 40;
            const second = data[0] % 40;
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
        import std.bitmanip : swapEndian;

        size_t cursor;
        ulong result;
        
        while(cursor < data.length && (data[cursor++] & 0b1000_0000))
        {
            result <<= 7;
            result |= (data[cursor-1] & 0b0111_1111);
        }

        if(cursor * 7 <= typeof(result).sizeof * 8)
        {
            version(LittleEndian)
                result = swapEndian(result);
            outResult = result;
        }

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
    identifierTagInvalidDerEncoding,
    
    componentLengthReserved,
    componentLengthIndefiniteUnderDer,
    componentLengthInvalidDerEncoding,
    componentLengthOver64Bits,
    
    booleanInvalidEncoding,
    booleanInvalidDerEncoding,
    
    integerInvalidEncoding,
    integerInvalidDerEncoding,
    integerOverBits,
    
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
    import std.bitmanip : swapEndian;

    ubyte initialByte;
    if(!mem.readU8(initialByte))
        return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading initial byte of identifier");

    // ISO/IEC 8825-1:2021 8.1.2.2
    const class_    = cast(Asn1Identifier.Class)(initialByte >> 6);
    const encoding  = cast(Asn1Identifier.Encoding)(initialByte & 0b0010_0000);
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
        if(counter++ >= 10) // We can left shift by 7, 9 times before overflowing
            return Result.make(Asn1DecodeError.identifierTagTooLong, "Encoding of identifier long form tag is too long"); // @suppress(dscanner.style.long_line)
        if(!mem.readU8(tagByte))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading long form tag byte of identifier");
        longTag = (longTag << 7) | (tagByte & 0b0111_1111);

        static if(ruleset == Asn1Ruleset.der)
        {
            if(tagByte == 0b1000_0000)
                return Result.make(Asn1DecodeError.identifierTagInvalidDerEncoding, "Invalid encoding of identifier long form tag under DER ruleset - ISO/IEC 8825-1:2021 10.1"); // @suppress(dscanner.style.long_line)
        }
    } while(tagByte & 0b1000_0000);

    version(LittleEndian)
        longTag = swapEndian(longTag);
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
            return Result.make(Asn1DecodeError.componentLengthInvalidDerEncoding, "Invalid encoding of component length under DER ruleset - ISO/IEC 8825-1:2021 10.1"); // @suppress(dscanner.style.long_line)
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