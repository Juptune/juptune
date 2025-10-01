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

/++
 + Represents the identifier byte(s) of an ASN.1 record.
 +
 + This type holds no references to external memory.
 + ++/
struct Asn1Identifier
{
    /// The class, as defined by ASN.1
    enum Class : ubyte // Note: NOT a flag enum - each value is distinct
    {
        /// The tag is well-defined across all ASN.1 encodings.
        universal = 0b00,

        /// The tag has a specific meaning to a specific/particular set of applications.
        application = 0b01,

        /// The tag has a unique meaning under a very specific context that isn't general enough for `application` or `private_`.
        contextSpecific = 0b10,

        /// The tag has a private organisation-wide meaning that's common across all of its tooling/applications.
        private_ = 0b11
    }

    /// How to interpet the content bytes.
    enum Encoding : ubyte
    {
        /// The content bytes are in a bespoke format, and likely need a specailised decoder.
        primitive = 0b0,

        /// The content bytes contain other ASN.1 records, and don't neccesarily need a decoder (beyond mapping them to D types properly).
        constructed = 0b1
    }
    
    /// Type used to store the tag number
    alias Tag = ulong;

    private
    {
        Class    _class;
        Encoding _encoding;
        Tag      _tag;
    }

    @safe @nogc nothrow pure const:

    /++ 
     + Params:
     +   _class   = The tag's class.
     +   encoding = The content bytes' encoding.
     +   tag      = The tag itself.
     +/
    this(Class _class, Encoding encoding, Tag tag)
    {
        this._class     = _class;
        this._encoding  = encoding;
        this._tag       = tag;
    }

    /// Returns: The tag's class.
    Class class_() => _class;

    /// Returns: The content byte's encoding.
    Encoding encoding() => _encoding;

    /// Returns: The numerical tag itself.
    Tag tag() => _tag;
}

/++
 + Represents the length of an ASN.1 record in the "long form", which can encode
 + very, very large numbers.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
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

    static Asn1LongLength fromNumberGC(T)(T number)
    if(isUnsigned!T)
    {
        import std.bitmanip : nativeToBigEndian;
        auto bytes = nativeToBigEndian(number).dup;
        while(bytes.length > 0 && bytes[0] == 0) // Encode in least amount of bytes
            bytes = bytes[1..$];

        return Asn1LongLength.fromUnownedBytes(bytes);
    }

    /++ 
     + Constructs an `Asn1LongLength` using a slice to external memory - this memory containing the raw length bytes
     + used within an encoded ASN.1 record.
     +
     + Notes:
     +  This constructor does NOT take ownership of the given memory slice. This means the returned struct
     +  MUST NOT outlive the underlying source of memory.
     + 
     + Params:
     +   lengthBytes = The raw length bytes.
     +
     + Returns: 
     +   An `Asn1LongLength` that uses the provided length bytes.
     +/
    static Asn1LongLength fromUnownedBytes(const ubyte[] lengthBytes) @nogc
    in(lengthBytes.length >= MIN_BYTES && lengthBytes.length <= MAX_BYTES, "The amount of bytes must be between 1 and 127") // @suppress(dscanner.style.long_line)
    {
        return Asn1LongLength(lengthBytes);
    }

    /++ 
     + Notes:
     +  As per the ASN.1 encoding, these bytes are always in big endian order.
     +
     + Returns:
     +  The raw length bytes for this length.
     +/
    const(ubyte)[] lengthBytes() const @nogc => _lengthBytes;
    
    /++
     + Determines whether this length can be converted into a native 64-bit number.
     +
     + User code should always check this, as ASN.1 lengths can go up to 1024 bits.
     + 
     + Returns:
     +  `true` if this length can be converted into a 64-bit number, or `false` if it's too large to do so.
     + ++/
    bool isAtMost64Bits() const @nogc
    {
        return this._lengthBytes.length <= 8;
    }

    /++
     + Converts the raw length bytes into a native ulong.
     +
     + Assertions:
     +  `isAtMost64Bits` must return `true`.
     +
     + Returns:
     +  The length as a native ulong.
     + ++/
    ulong length() const @nogc
    in(this.isAtMost64Bits(), "The amount of bytes is too large to represent as a ulong - please use isAtMost64Bits to check") // @suppress(dscanner.style.long_line)
    {
        ulong result = 0;
        foreach (ubyte b; _lengthBytes)
            result = (result << 8) | b;

        return result;
    }
}

/// Represents the length of an ASN.1 record in its "short form".
alias Asn1ShortLength = ubyte;

/// A SumType used to represent either version of an ASN.1 record's length.
alias Asn1Length = SumType!(Asn1ShortLength, Asn1LongLength);

/++
 + Represents an ASN.1 BOOLEAN.
 +
 + This type does not contain references to external memory.
 + ++/
struct Asn1Bool
{
    private
    {
        ubyte _value;
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[BOOLEAN]\n");
        putIndent();
        sink(this.asBool ? "TRUE\n" : "FALSE\n");
    }

    @safe @nogc nothrow:

    this(ubyte value) pure const
    {
        this._value = value;
    }

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.booleanIsConstructed` if the given `ident` describes a constructed encoding.
     +
     +  `Asn1DecodeError.booleanInvalidDerEncoding` for all all other DER spec violations.
     +
     +  `Asn1DecodeError.booleanInvalidEncoding` for all other BER spec violations.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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

    /// Returns: The `Asn1Boolean` as a native bool.
    bool asBool() pure const => _value != 0;

    /// Returns: The underlying byte as encoding within ASN.1
    ubyte value() pure const => _value;
}

/++
 + Represents an ASN.1 INTEGER.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
struct Asn1Integer
{
    import std.traits : isIntegral;

    private
    {
        const(ubyte)[] _value;
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[INTEGER]\n");
        putIndent();

        long value;
        auto result = this.asInt(value);
        if(result.isError)
        {
            import juptune.core.util.conv : toBase16, IntToHexCharBuffer;
            IntToHexCharBuffer buffer;

            foreach(i, byte_; this._value)
            {
                if(i != 0)
                    sink(", ");
                if((i % 16) == 0 && i > 0)
                {
                    sink("\n");
                    putIndent();
                }
                sink(toBase16(byte_, buffer));
            }
        }
        else
        {
            import juptune.core.util.conv : toBase10, IntToCharBuffer;
            IntToCharBuffer buffer;
            sink(toBase10(value, buffer));
        }
    }

    @trusted nothrow: // TODO: Look into why array's dtor is unsafe/untrusted // @suppress(dscanner.trust_too_much)

    static Asn1Integer fromNumberGC(T)(T number)
    if(isIntegral!T)
    {
        import std.bitmanip : nativeToBigEndian;
        auto bytes = nativeToBigEndian(number).dup;
        while(bytes.length > 0 && bytes[0] == 0) // Encode in least amount of bytes
            bytes = bytes[1..$];

        return Asn1Integer.fromUnownedBytes(bytes);
    }

    const(ubyte)[] rawBytes() @nogc nothrow const => this._value;

    /++ 
     + Constructs an `Asn1Integer` using a slice to external memory - this memory containing the raw bytes
     + used within an encoded ASN.1 record.
     +
     + Notes:
     +  This constructor does NOT take ownership of the given memory slice. This means the returned struct
     +  MUST NOT outlive the underlying source of memory.
     + 
     + Params:
     +   bytes = The raw bytes.
     +
     + Returns: 
     +   An `Asn1Integer` that uses the provided length bytes.
     +/
    static Asn1Integer fromUnownedBytes(const(ubyte)[] bytes) @nogc @trusted nothrow
    {
        return Asn1Integer(bytes);
    }

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.integerIsConstructed` if the given `ident` describes a constructed encoding.
     +
     +  `Asn1DecodeError.booleanInvalidEncoding` for all other BER spec violations.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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
    
    /++
     + Converts the raw bytes into a native integer.
     +
     + Params:
     +  result = The resulting integer.
     +
     + Throws:
     +  `Asn1DecodeError.integerOverBits` if the wanted `IntT` is too small to hold the decoded value.
     +
     + Returns:
     +  A `Result` depicting if the conversion was possible.
     + ++/
    Result asInt(IntT)(scope out IntT result) @nogc
    if(isIntegral!IntT)
    {
        if((this._value.length * 7) > (IntT.sizeof * 8))
        {
            enum Error = "Integer value is too large to fit into a native "~IntT.stringof;
            return Result.make(Asn1DecodeError.integerOverBits, Error);
        }

        foreach(b; this._value)
            result = (result << 8) | b;

        return Result.noError;
    }
}

// TODO: It'd be nice to have a generic BitString type. The one in Phobos uses the GC of course...

/++
 + Represents an ASN.1 BIT STRING.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
struct Asn1BitString
{
    private
    {
        const(ubyte)[]  _value;
        size_t          _bitCount;
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[BIT STRING]\n");
        putIndent();

        foreach(i, byte_; this._value)
        {
            import juptune.core.util : IntToHexCharBuffer, toBase16;

            if(i != 0)
                sink(", ");
            if((i % 16) == 0 && i > 0)
            {
                sink("\n");
                putIndent();
            }

            IntToHexCharBuffer buffer;
            sink(toBase16(byte_, buffer)[$-2..$]);
        }
        sink("\n");
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)
    
    /++ 
     + Constructs an `Asn1BitString` using a slice to external memory.
     +
     + Notes:
     +  This constructor does NOT take ownership of the given memory slice. This means the returned struct
     +  MUST NOT outlive the underlying source of memory.
     +
     +  Additional validation (e.g. those specified by DER) are not performed by this constructor.
     + 
     + Params:
     +   bytes    = The bytes containing the bit string.
     +   bitCount = The amount of bits contained within the bit string.
     +
     + Returns: 
     +   An `Asn1Integer` that uses the provided length bytes.
     +/
    static Asn1BitString fromUnownedBytes(const(ubyte)[] bytes, size_t bitCount) @nogc
    in(bytes.length * 8 >= bitCount, "The bit count must be less than or equal to the amount of bits in the byte array") // @suppress(dscanner.style.long_line)
    {
        return Asn1BitString(bytes, bitCount);
    }

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.bitstringIsConstructedUnderDer` if the given `ident` describes a constructed encoding when using DER encoding.
     +
     +  `Asn1DecodeError.bitstringInvalidDerEncoding` for all other DER spec violations.
     +
     +  `Asn1DecodeError.bitstringInvalidEncoding` for all other BER spec violations.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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
                return Result.make(Asn1DecodeError.bitstringInvalidDerEncoding, "The unused bits in a bit string must be zero - ISO/IEC 8825-1:2021 11.2.1"); // @suppress(dscanner.style.long_line)
            if(bytes.length > 1 && bytes[$-1] == 0)
                return Result.make(Asn1DecodeError.bitstringInvalidDerEncoding, "The last byte of a non-empty bit string must not be zero - ISO/IEC 8825-1:2021 11.2.2"); // @suppress(dscanner.style.long_line)
        }

        const bitCount = ((bytes.length - 1) * 8) - unusedBits; // @suppress(dscanner.suspicious.length_subtraction)
        result = Asn1BitString.fromUnownedBytes(bytes[1..$], bitCount);
        return Result.noError;
    }

    size_t bitCount() @nogc nothrow pure const => _bitCount;
    const(ubyte)[] bytes() @nogc nothrow pure const => _value;

    auto bits() @nogc nothrow
    {
        static struct R
        {
            const(ubyte)[] value;
            size_t bitCount;
            size_t bitIndex;

            bool front;
            bool empty;

            @nogc nothrow:

            this(const(ubyte)[] value, size_t bitCount)
            {
                this.value = value;
                this.bitCount = bitCount;
                this.popFront();
            }

            void popFront()
            {
                if(this.bitIndex >= this.bitCount)
                {
                    this.empty = true;
                    return;
                }

                this.front = (this.value[this.bitIndex / 8] & (1 << (7 - (this.bitIndex % 8)))) > 0;
                this.bitIndex++;
            }
        }

        return R(this._value, this._bitCount);
    }
}

/++
 + Represents an ASN.1 REAL.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
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

    /// Returns: a new `Asn1Real` that represents +0
    static Asn1Real plusZero() @nogc => fromSpecial(Special.plusZeroNoContentBytes);
    /// Returns: a new `Asn1Real` that represents +double.infinity
    static Asn1Real plusInfinity() @nogc => fromSpecial(Special.plusInfinity);
    /// Returns: a new `Asn1Real` that represents -double.infinity
    static Asn1Real minusInfinity() @nogc => fromSpecial(Special.minusInfinity);
    /// Returns: a new `Asn1Real` that represents double.nan
    static Asn1Real notANumber() @nogc => fromSpecial(Special.notANumber);
    /// Returns: a new `Asn1Real` that represents -0
    static Asn1Real minusZero() @nogc => fromSpecial(Special.minusZero);

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Notes:
     +  Currently no decimal encoding forms are supported due to lack of dev time spent on it.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.realIsConstructed` if the given `ident` describes a constructed encoding.
     +
     +  `Asn1DecodeError.realUnsupportedDecimalEncoding` if decimal encoding is used, and specifies a format that's not recognised.
     +
     +  `Asn1DecodeError.realUnsupportedSpecialEncoding` if special encoding is used, and specifies a special value that's not recognised.
     +
     +  `Asn1DecodeError.realInvalidDerEncoding` for all other DER spec violations.
     +
     +  `Asn1DecodeError.realInvalidEncoding` for all other BER spec violations.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out Asn1Real result,
        const Asn1Identifier ident
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.realIsConstructed, "Real numbers cannot be constructed under BER ruleset - ISO/IEC 8825-1:2021 8.5.1"); // @suppress(dscanner.style.long_line)

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
    
    /++
     + Converts the raw bytes into native double.
     +
     + Notes:
     +  ASN.1's `PLUS-INFINITY` is equal to `+double.infinity` in D.
     +
     +  ASN.1's `MINUS-INFINITY` is equal to `-double.infinity` in D.
     +
     +  This function uses checked maths in order to catch overflows (but not underflows... yet).
     +
     +  If you're getting the wrong value back, it's a lot more likely that this function is buggy rather than
     +  your input being incorrect, feel free to raise an issue since I'm not very good at proving my own maths.
     +
     + Params:
     +  number = The resulting number.
     +
     + Throws:
     +  `CheckedError.overflow` if there was an overflow when decoding the number.
     +
     +  Anything that `Asn1Integer.asInt` can throw, as it is used internally to decode parts of the real value.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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

/++
 + Represents an ASN.1 OCTET STRING.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
struct Asn1OctetString
{
    private
    {
        const(ubyte)[] _data;
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[OCTET STRING]\n");
        putIndent();

        foreach(i, byte_; this._data)
        {
            import juptune.core.util : IntToHexCharBuffer, toBase16;

            if(i != 0)
                sink(", ");
            if((i % 16) == 0 && i > 0)
            {
                sink("\n");
                putIndent();
            }

            IntToHexCharBuffer buffer;
            sink(toBase16(byte_, buffer)[$-2..$]);
        }
        sink("\n");
    }

    @trusted nothrow: // @suppress(dscanner.trust_too_much)

    /++ 
     + Constructs an `Asn1OctetString` using a slice to external memory.
     +
     + Notes:
     +  This constructor does NOT take ownership of the given memory slice. This means the returned struct
     +  MUST NOT outlive the underlying source of memory.
     + 
     + Params:
     +   data = The raw bytes of the octet string.
     +
     + Returns: 
     +   An `Asn1OctetString` that uses the provided length bytes.
     +/
    static Asn1OctetString fromUnownedBytes(const(ubyte)[] data) @nogc
    {
        return Asn1OctetString(data);
    }

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.octetstringIsConstructedUnderDer` if the given `ident` describes a constructed encoding when using DER.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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

    /// Returns: All the bytes making up the octet string
    const(ubyte)[] data() @nogc => this._data;
}

/++
 + Represents an ASN.1 NULL.
 +
 + This type holds no references to external memory.
 + ++/
struct Asn1Null
{    
    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.nullIsConstructed` if the given `ident` describes a constructed encoding.
     +
     +  `Asn1DecodeError.nullHasContentBytes` if `mem` contains any bytes.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
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

/++
 + Represents an ASN.1 primitive record with an unknown format.
 +
 + This type is templated so that custom types can be defined, to keep things type safe.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
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

/++
 + Represents an ASN.1 constructed record with an unknown format.
 +
 + This type is templated so that custom types can be defined, to keep things type safe.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
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

// Public for documentation generation, please use the aliases instead.
struct Asn1ObjectIdentifierImpl(bool IsRelative)
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

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[OBJECT IDENTIFIER]\n");
        putIndent();

        size_t i;
        foreach(component; this.components)
        {
            import juptune.core.util : IntToCharBuffer, toBase10;

            if(i++ != 0)
                sink(" ");
            if((i % 16) == 0 && i > 0)
            {
                sink("\n");
                putIndent();
            }

            IntToCharBuffer buffer;
            sink(toBase10(component.get, buffer));
        }
        sink("\n");
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

    /++
     + Decodes the passed in ASN.1 content bytes.
     +
     + Params:
     +  mem    = A MemoryReader *only* containing the content bytes for the ASN.1 record.
     +  result = The decoded result.
     +  ident  = The decoded ASN.1 identifier for this record.
     +
     + Throws:
     +  `Asn1DecodeError.oidIsConstructed` if the given `ident` describes a constructed encoding.
     +
     +  `Asn1DecodeError.oidInvalidEncoding` for all other BER spec violations.
     +
     + Returns:
     +  A `Result` depicting whether an error occured - the error string will contain verbose details.
     + ++/
    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.oidIsConstructed, "Object Identifiers cannot be constructed - ISO/IEC 8825-1:2021 8.19.1"); // @suppress(dscanner.style.long_line)

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

    /++
     + Creates a ulong InputRange where each item is an individual componet from
     + the decoded object identifier.
     +
     + e.g. For the identifier `1.2.4391.2`, you'd get a range of `[1, 2, 4391, 2]`.
     +
     + Notes:
     +  This range contains the same slice as the parent struct, so please make sure the range does not outlive
     +  the underlying memory source.
     + ++/
    auto components() @nogc scope return
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

/++
 + Represents an ASN.1 OBJECT IDENTIFIER.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
alias Asn1ObjectIdentifier = Asn1ObjectIdentifierImpl!false;

/++
 + Represents an ASN.1 RELATIVE-OID.
 +
 + This type contains slices to exteral memory, so please be aware of data lifetimes.
 + ++/
alias Asn1RelativeObjectIdentifier = Asn1ObjectIdentifierImpl!true;

// TODO: Document
// TODO: Mention that this type is specifically designed for dasn1's code generation, since it's a really
//       awkward issue to deal with.
// TODO: Also mention that yes, this is a really inefficient design, but allocating memory has some annoying
//       complications - especially around dasn1's code generation.
struct Asn1SetOfImpl(ElementT, bool IsSetOf) // @suppress(dscanner.suspicious.incomplete_operator_overloading)
{
    private
    {
        static struct FromDecoding
        {
            const(ubyte)[] data;
            size_t length;
        }

        static struct InMemory
        {
            ElementT[] elements;
        }

        enum ImplType
        {
            FAILSAFE,
            fromDecoding,
            inMemory,
        }

        ImplType _implType;
        union
        {
            FromDecoding _fromDecoding;
            InMemory _inMemory;
        }
    }

    alias foreachElement = foreachElementImpl!(
        Result delegate(ElementT) @nogc nothrow,
        Result delegate(scope ref MemoryReader, scope out ElementT, const Asn1Identifier) @nogc nothrow,
    );
    alias foreachElementGC = foreachElementImpl!(
        Result delegate(ElementT),
        Result delegate(scope ref MemoryReader, scope out ElementT, const Asn1Identifier),
    );
    alias foreachElementAuto = foreachElementAutoImpl!(Result delegate(ElementT) @nogc nothrow, Asn1Ruleset.der);
    alias foreachElementAutoGC = foreachElementAutoImpl!(Result delegate(ElementT), Asn1Ruleset.der);

    private Result foreachElementAutoImpl(HandlerT, Asn1Ruleset ruleset)(scope HandlerT handler)
    {
        scope decoder = (scope ref MemoryReader memory, scope out ElementT element, const Asn1Identifier identifier) {
            static if(__traits(isStaticFunction, ElementT.fromDecoding!ruleset))
                return ElementT.fromDecoding!ruleset(memory, element, identifier);
            else
                return element.fromDecoding!ruleset(memory, identifier);
        };
        return this.foreachElementImpl(handler, decoder);
    }

    private Result foreachElementImpl(HandlerT, DecoderT)(
        scope HandlerT handler,
        scope DecoderT decoder,
    )
    {
        final switch(this._implType) with(ImplType)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");

            case inMemory:
                foreach(element; this._inMemory.elements)
                {
                    auto result = handler(element);
                    if(result.isError)
                        return result;
                }
                return Result.noError;

            case fromDecoding:
                auto dataReader = MemoryReader(this._fromDecoding.data);
                while(dataReader.bytesLeft > 0)
                {
                    Asn1ComponentHeader header;
                    MemoryReader elementReader;
                    auto error = asn1DecodeComponentHeader!(Asn1Ruleset.der)(dataReader, header);
                    if(error.isError)
                        return error;
                    error = asn1ReadContentBytes(dataReader, header.length, elementReader);
                    if(error.isError)
                        return error;

                    ElementT element;
                    error = decoder(elementReader, element, header.identifier);
                    if(error.isError)
                        return error;
                    
                    error = handler(element);
                    if(error.isError)
                        return error;
                }
                return Result.noError;
        }
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        import juptune.core.util : resultAssert;

        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();

        static if(IsSetOf)
            sink("[SET OF "~ElementT.stringof~"]\n");
        else
            sink("[SEQUENCE OF "~ElementT.stringof~"]\n");
        
        depth++;
        scope handler = (ElementT element){
            static if(__traits(hasMember, ElementT, "toString"))
                element.toString(sink, depth);
            else
            {
                putIndent();
                sink("<no toString impl>");
            }
            return Result.noError;
        };
        this.foreachElementAutoImpl!(typeof(handler), Asn1Ruleset.der)(handler).resultAssert;
        depth--;
        sink("\n");
    }

    @trusted @nogc nothrow: // @suppress(dscanner.trust_too_much)

    size_t toHash() const @nogc @safe pure nothrow
    {
        // Nullable calls into toHash, and for some reason its __traits(compile) check *Passes* despite it generating errors.
        // So we have to have this dummy toHash here to make it all work right, lol.
        assert(false, "TODO: Support this I guess?");
        return 0;    
    }
    
    size_t elementCount()
    {
        final switch(this._implType) with(ImplType)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");
            case inMemory: return this._inMemory.elements.length;
            case fromDecoding: return this._fromDecoding.length;
        }
    }

    static typeof(this) fromInMemory(ElementT[] elements)
    {
        typeof(this) set;
        set._implType = ImplType.inMemory;
        set._inMemory.elements = elements;
        return set;
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.primitive)
        {
            enum Error = "Asn1SetOf!" ~ ElementT.stringof ~ " cannot be primitive, it must be constructed";
            return Result.make(Asn1DecodeError.setOfIsPrimitive, Error); // @suppress(dscanner.style.long_line)
        }

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
        {
            enum Error = "Ran out of bytes when reading contents for Asn1SetOf!" ~ ElementT.stringof;
            return Result.make(Asn1DecodeError.eof, Error);
        }

        result._implType = ImplType.fromDecoding;
        result._fromDecoding.data = data;

        static if(ruleset == Asn1Ruleset.der && IsSetOf)
        {{
            auto error = checkIsSorted(data);
            if(error.isError)
                return error;
        }}

        // TODO: Could technically just turn checkIsSorted into one-pass thing that can both validate and find the element length.
        auto dataReader = MemoryReader(data);
        while(dataReader.bytesLeft > 0)
        {
            Asn1ComponentHeader header;
            MemoryReader elementReader;
            auto error = asn1DecodeComponentHeader!(Asn1Ruleset.der)(dataReader, header);
            if(error.isError)
                return error;
            error = asn1ReadContentBytes(dataReader, header.length, elementReader);
            if(error.isError)
                return error;

            result._fromDecoding.length++;
        }

        return Result.noError;
    }

    static if(IsSetOf)
    private static Result checkIsSorted(const(ubyte)[] data)
    {
        /*
            Essentially:
                DER mandates that SET OF must be in a well known order - I can't actually find the part
                of the spec that mentions what this looks like, but other internet searches defines it
                to be the following:

                * SET OF elements must be ordered from "shortest" to "longest".
                * If the encoding of an element has less bytes than another, then the former element is "shorter".
                * If the encoding of two elements has the same amount of bytes, then:
                    * Search for the first byte that differs between the two encodings.
                    * The encoding where this different byte is a lower value than the other encoding, is the "shorter" one.
                    * I can't find any info on how to handle identical encodings.
        */

        if(data.length == 0)
            return Result.noError;

        auto memory = MemoryReader(data);
        Result getElementBytes(scope out const(ubyte)[] bytes)
        {
            Asn1ComponentHeader header;
            MemoryReader elementReader;
            auto result = asn1DecodeComponentHeader!(Asn1Ruleset.der)(memory, header);
            if(result.isError)
                return result;

            result = asn1ReadContentBytes(memory, header.length, elementReader);
            if(result.isError)
                return result;

            elementReader.readBytes(elementReader.bytesLeft, bytes);
            return Result.noError;
        }

        const(ubyte)[] prevBytes;
        auto result = getElementBytes(prevBytes);
        if(result.isError)
            return result;

        while(memory.bytesLeft > 0)
        {
            const(ubyte)[] bytes;
            result = getElementBytes(bytes);
            if(result.isError)
                return result;

            scope(exit) prevBytes = bytes;

            if(prevBytes.length < bytes.length)
                continue;
            else if(prevBytes.length > bytes.length)
            {
                enum Error = "DER encoded element is not in 'shortest' order for Asn1SetOf!" ~ ElementT.stringof;
                return Result.make(Asn1DecodeError.setOfDerIsUnordered, Error);
            }

            foreach(i, thisByte; bytes)
            {
                if(thisByte == prevBytes[i])
                    continue;
                else if(thisByte < prevBytes[i])
                {
                    enum Error = "DER encoded element is not in 'shortest' order for Asn1SetOf!" ~ ElementT.stringof;
                    return Result.make(Asn1DecodeError.setOfDerIsUnordered, Error);
                }
                break;
            }
        }

        return Result.noError;
    }
}

alias Asn1SetOf(ElementT) = Asn1SetOfImpl!(ElementT, true);
alias Asn1SequenceOf(ElementT) = Asn1SetOfImpl!(ElementT, false);

struct Asn1Utf8String // @suppress(dscanner.suspicious.incomplete_operator_overloading)
{
    private
    {
        static struct FromDecoding
        {
            const(ubyte)[] data;
        }

        enum ImplType
        {
            FAILSAFE,
            fromDecoding,
        }

        ImplType _implType;
        union
        {
            FromDecoding _fromDecoding;
        }
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        import juptune.core.util : resultAssert;

        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[UTF8String]\n");
        depth++;
        putIndent();
        sink(this.asSlice);
        sink("\n");
    }

    @trusted @nogc nothrow: // @suppress(dscanner.trust_too_much)

    size_t toHash() const @nogc @safe pure nothrow
    {
        // Nullable calls into toHash, and for some reason its __traits(compile) check *Passes* despite it generating errors.
        // So we have to have this dummy toHash here to make it all work right, lol.
        assert(false, "TODO: Support this I guess?");
        return 0;    
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        import juptune.data.utf8 : utf8Validate;

        if(ident.encoding() == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.utf8StringIsConstructedUnderDer, "Asn1Utf8String cannot be constructed under DER, it must be primitive"); // @suppress(dscanner.style.long_line)

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading contents for Asn1Utf8String");

        result._implType = ImplType.fromDecoding;
        result._fromDecoding.data = data;

        return utf8Validate(data);
    }

    const(char)[] asSlice()
    {
        final switch(this._implType) with(ImplType)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");
            case fromDecoding:
                // This is fine - D strings are UTF8 encoded, and .data has passed through utf8Validate.
                return cast(const(char)[])this._fromDecoding.data;
        }
    }
}

struct Asn1AsciiAlphabetString(string DebugName, string AlphaChars) // @suppress(dscanner.suspicious.incomplete_operator_overloading)
{
    import juptune.data.alphabet : AsciiAlphabet;
    alias Alphabet = AsciiAlphabet!AlphaChars;

    private
    {
        static struct FromDecoding
        {
            const(ubyte)[] data;
        }

        enum ImplType
        {
            FAILSAFE,
            fromDecoding,
        }

        ImplType _implType;
        union
        {
            FromDecoding _fromDecoding;
        }
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        import juptune.core.util : resultAssert;

        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("["~DebugName~"]\n");
        depth++;
        putIndent();
        sink(this.asSlice);
        sink("\n");
    }

    @trusted @nogc nothrow: // @suppress(dscanner.trust_too_much)

    size_t toHash() const @nogc @safe pure nothrow
    {
        // Nullable calls into toHash, and for some reason its __traits(compile) check *Passes* despite it generating errors.
        // So we have to have this dummy toHash here to make it all work right, lol.
        assert(false, "TODO: Support this I guess?");
        return 0;    
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.constructed)
        {
            enum Error = DebugName~" cannot be constructed under DER, it must be primitive";
            return Result.make(Asn1DecodeError.printableStringIsConstructedUnderDer, Error); // @suppress(dscanner.style.long_line)
        }

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
        {
            enum Error = "Ran out of bytes when reading contents for "~DebugName;
            return Result.make(Asn1DecodeError.eof, Error);
        }

        result._implType = ImplType.fromDecoding;
        result._fromDecoding.data = data;

        foreach(ch; cast(const(char)[])data)
        {
            if(!Alphabet().isAllowed(ch))
            {
                enum Error = DebugName~" contains invalid characters";
                return Result.make(Asn1DecodeError.printableStringHasInvalidChars, Error); // @suppress(dscanner.style.long_line)
            }
        }

        return Result.noError;
    }

    const(char)[] asSlice()
    {
        final switch(this._implType) with(ImplType)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");
            case fromDecoding:
                // This is fine - Printable strings are just a subset of ASCII.
                return cast(const(char)[])this._fromDecoding.data;
        }
    }
}

alias Asn1PrintableString = Asn1AsciiAlphabetString!("Asn1PrintableString", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+,-./:=? "); // @suppress(dscanner.style.long_line)
alias Asn1NumericString = Asn1AsciiAlphabetString!("Asn1NumericString", "0123456789 "); // @suppress(dscanner.style.long_line)
alias Asn1Ia5String = Asn1AsciiAlphabetString!("Asn1NumericString", (){
    char[127] alphabet;
    foreach(i, ref ch; alphabet)
        ch = cast(char)i;
    return alphabet[].idup;
}());

struct Asn1UtcTime
{
    private
    {
        ubyte _year;
        ubyte _month;
        ubyte _day;
        ubyte _hour;
        ubyte _minute;
        ubyte _second;
    }

    void toString(SinkT)(scope SinkT sink, int depth = 0) // @suppress(dscanner.suspicious.object_const)
    {
        import juptune.core.util : resultAssert, toBase10, IntToCharBuffer;

        void putIndent() { foreach(i; 0..depth) sink("  "); }
        putIndent();
        sink("[UTCTime]\n");
        putIndent();

        IntToCharBuffer buffer;
        sink(toBase10(this.year, buffer));
        sink("/");
        sink(toBase10(this.month, buffer));
        sink("/");
        sink(toBase10(this.day, buffer));
        sink(" ");
        sink(toBase10(this.hour, buffer));
        sink(":");
        sink(toBase10(this.minute, buffer));
        sink(":");
        sink(toBase10(this.second, buffer));
        sink(" (UTC)\n");
    }

    @trusted @nogc nothrow: // @suppress(dscanner.trust_too_much)

    static Result fromParsingLiteral(Asn1Ruleset ruleset)(scope const(char)[] literal, scope out typeof(this) result)
    {
        import juptune.core.util : fromBase10, IntToCharBuffer;

        static assert(ruleset == Asn1Ruleset.der, "TODO: Support non-DER");

        enum DER_LENGTH = "YYMMDDhhmmssZ".length;

        if(literal.length != DER_LENGTH)
        {
            import std.conv : to;
            enum Error = "UTCTime literal must be exactly "~DER_LENGTH.to!string~" characters long under DER";
            return Result.make(Asn1DecodeError.utcTimeIsWrongSize, Error);
        }

        if(literal[12] != 'Z')
            return Result.make(Asn1DecodeError.utcTimeHasTimezoneUnderDer, "UTCTime literals cannot contain a timezone under DER"); // @suppress(dscanner.style.long_line)

        string error;
        result._year = fromBase10!ubyte(literal[0..2], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);
        result._month = fromBase10!ubyte(literal[2..4], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);
        result._day = fromBase10!ubyte(literal[4..6], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);
        result._hour = fromBase10!ubyte(literal[6..8], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);
        result._minute = fromBase10!ubyte(literal[8..10], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);
        result._second = fromBase10!ubyte(literal[10..12], error);
        if(error !is null) return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, error);

        if(result._month < 1 || result._month > 12)
            return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, "UTCTime literal contains an invalid month - it must be a value between 1 and 12 (inclusive)"); // @suppress(dscanner.style.long_line)
        if(result._day < 1 || result._day > 31)
            return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, "UTCTime literal contains an invalid day - it must be a value between 1 and 31 (inclusive)"); // @suppress(dscanner.style.long_line)
        if(result._hour > 23)
            return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, "UTCTime literal contains an invalid hour - it must be a value between 0 and 23 (inclusive)"); // @suppress(dscanner.style.long_line)
        if(result._minute > 59)
            return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, "UTCTime literal contains an invalid minute - it must be a value between 0 and 59 (inclusive)"); // @suppress(dscanner.style.long_line)
        if(result._second > 59)
            return Result.make(Asn1DecodeError.utcTimeInvalidLiteral, "UTCTime literal contains an invalid second - it must be a value between 0 and 59 (inclusive)"); // @suppress(dscanner.style.long_line)

        return Result.noError;
    }

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        if(ident.encoding() == Asn1Identifier.Encoding.constructed)
            return Result.make(Asn1DecodeError.utcTimeIsConstructedUnderDer, "Asn1UtcTime cannot be constructed under DER, it must be primitive"); // @suppress(dscanner.style.long_line)

        const(ubyte)[] data;
        if(!mem.readBytes(mem.bytesLeft, data))
            return Result.make(Asn1DecodeError.eof, "Ran out of bytes when reading contents for Asn1UtcTime");

        return Asn1UtcTime.fromParsingLiteral!ruleset(cast(const(char)[])data, result);
    }

    // NOTE: Can't use Phobos' DateTime because the ctor can throw (and thus use the GC), lmfao.
    uint year() const pure => (this._year >= 50) ? 1950 + (this._year - 50) : 2000 + this._year;
    uint month() const pure => this._month;
    uint day() const pure => this._day;
    uint hour() const pure => this._hour;
    uint minute() const pure => this._minute;
    uint second() const pure => this._second;
}

/// A type like this needs to exist _somewhere_ for DASN.1 to work.
struct Asn1Any
{
    Asn1Identifier identifier;
    Asn1OctetString value;

    static Result fromDecoding(Asn1Ruleset ruleset)(
        scope ref MemoryReader mem, 
        scope out typeof(this) result,
        const Asn1Identifier ident,
    )
    {
        result.identifier = ident;
        return Asn1OctetString.fromDecoding!ruleset(mem, result.value, ident);
    }
}

/// Represents the decoded identifier and length bytes of an ASN.1 record.
struct Asn1ComponentHeader
{
    /// The identifier.
    Asn1Identifier identifier;
    
    /// The length, either short or long.
    Asn1Length length;
}

/// Used to describe which ruleset to apply during decoding.
enum Asn1Ruleset
{
    /// Use the DER binary ruleset - this ruleset ensures there is only ever one possible representation for any distinct value.
    der,
}

/// A `Result` error enum.
enum Asn1DecodeError
{
    none,
    eof,            /// Ran out of bytes.
    notImplemented, /// Functionality not implemented yet TODO: I need to replace some asserts with this.
    
    identifierTagTooLong,           /// Identifier tag has too many bytes.
    identifierTagInvalidEncoding,   /// Identifer violates the spec in some way.
    
    componentLengthReserved,            /// Content length uses a reserved value.
    componentLengthIndefiniteUnderDer,  /// Content length uses the indefinite form under DER, which is not allowed.
    componentLengthInvalidDerEncoding,  /// Content length violates a DER-specific constraint.
    componentLengthOver64Bits,          /// Content length is more than 64-bits, so can't be represented natively.
    
    booleanInvalidEncoding,     /// Boolean violates the spec in some way.
    booleanInvalidDerEncoding,  /// Boolean violates a DER-specific constraint.
    booleanIsConstructed,       /// Boolean is marked as constructed.
    
    integerInvalidEncoding,     /// Integer violates the spec in some way.
    integerInvalidDerEncoding,  /// Integer violates a DER-specific constraint.
    integerOverBits,            /// Integer is too large to be represented by a native D integral type.
    integerIsConstructed,       /// Integer is marked as constructed.
    
    bitstringIsConstructedUnderDer, /// Bit string is marked as constructed under DER, which is not allowed.
    bitstringInvalidEncoding,       /// Bit string violates the spec in some way.
    bitstringInvalidDerEncoding,    /// Bit string violates a DER-specific constraint.

    realIsConstructed,              /// Real is marked as constructed.
    realInvalidEncoding,            /// Real violates the spec in some way.
    realInvalidDerEncoding,         /// Real violates a DER-specific constraint.
    realUnsupportedDecimalEncoding, /// Real contains an unrecognised decimal encoding.
    realUnsupportedSpecialEncoding, /// Real contains an unrecognised special value.

    octetstringIsConstructedUnderDer, /// Octet string is marked as constructed under DER, which is not allowed.

    nullIsConstructed,      /// Null is marked as constructed under DER, which is not allowed.
    nullHasContentBytes,    /// Null contains content bytes.

    constructionIsPrimitive, /// Generic construction is marked as primitive.
    primitiveIsConstructed,  /// Generic primitive is marked as constructed.

    setOfIsPrimitive, /// Set of is marked as primitive.
    setOfDerIsUnordered, /// A DER-encoded SET OF is not properly encoded - elements must be encoded in 'shortest' order, but wasn't.

    oidInvalidEncoding, /// OID violates the spec in some way.
    oidIsConstructed,   /// OID is marked as constructed.

    utf8StringIsConstructedUnderDer, /// A UTF8String was marked as constructed under DER, which is not allowed.

    printableStringIsConstructedUnderDer, /// A PrintableString was marked as constructed under DER, which is not allowed.
    printableStringHasInvalidChars, /// A PrintableString contains characters that are not allowed.

    utcTimeIsConstructedUnderDer, /// A UTCTime was marked as constructed under DER, which is not allowed.
    utcTimeIsWrongSize, /// A UTCTime literal is not the right size.
    utcTimeHasTimezoneUnderDer, /// A UTCTime literal was given a timezone under DER, which is not allowed.
    utcTimeInvalidLiteral, /// A UTCTime literal is invalid for some non-specific reason (e.g. invalid characters).

    // NOTE: The following errors are only used by the decoder generated by dasn1 - they're put here since it's a very logical
    //       place to have them.

    identifierHasInvalidClass, /// An identifier has a class that was unexpected for the decoding type.
    identifierHasInvalidTag,   /// An identifier has a tag value that was unexpected for the decoding type.

    choiceHasNoMatch, /// An CHOICE type is unable to select a value while decoding the data stream.

    sequenceMissingField, /// A SEQUENCE type is missing a non-optional field.
    sequenceHasExtraData, /// A non-extensible SEQUENCE type has unread content bytes after attempted decoding of all known fields.

    setMissingField, /// A SET type is missing a non-optional field.
    setHasExtraData, /// A non-extensible SET type has unread content bytes after attempted decoding of all known fields.

    constraintFailed, /// A value was decoded that did not match a constraint from the source schema
}

/++
 + Decodes a component header from the given ASN.1 data stream.
 +
 + Params:
 +  mem    = The ASN.1 data stream. It will automatically be advanced to the content bytes.
 +  header = The decoded header.
 +
 + Throws:
 +  Anything that `asn1DecodeIdentifier` and `asn1DecodeLength` can throw.
 +
 + Returns:
 +  A `Result` if decoding failed.
 + ++/
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

/++
 + Decodes an identifier from the given ASN.1 data stream.
 +
 + Params:
 +  mem   = The ASN.1 data stream. It will automatically be advanced to the length bytes.
 +  ident = The decoded identifier.
 +
 + Throws:
 +  `Asn1DecodeError.eof` if there are less bytes than expected.
 +
 +  `Asn1DecodeError.identifierTagTooLong` if the long-form tag contains too many bytes to fit into a ulong.
 +
 +  `Asn1DecodeError.identifierTagInvalidEncoding` for any other violations.
 +
 + Returns:
 +  A `Result` if decoding failed.
 + ++/
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

/++
 + Decodes a record length from the given ASN.1 data stream.
 +
 + Params:
 +  mem    = The ASN.1 data stream. It will automatically be advanced to the content bytes.
 +  length = The decoded length.
 +
 + Throws:
 +  `Asn1DecodeError.eof` if there are less bytes than expected.
 +
 +  `Asn1DecodeError.componentLengthReserved` if the length contains a reserved value.
 +
 +  `Asn1DecodeError.componentLengthIndefiniteUnderDer` when the indefinite length form is used under DER.
 +
 +  `Asn1DecodeError.componentLengthInvalidDerEncoding` for any other DER-specific violations.
 +
 + Returns:
 +  A `Result` if decoding failed.
 + ++/
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

/++
 + Creates a new memory reader, from the parent ASN.1 data stream, that contains
 + the content bytes for a record.
 +
 + This new reader is suitable for passing into the various `fromDecoding` functions provided by the primitive types
 + in this module.
 +
 + Notes:
 +  The new reader is created from a non-copied slice from the parent reader, so the new reader must not outlive the
 +  parent reader.
 +
 + Params:
 +  mem           = The ASN.1 data stream. It will automatically be advanced to the next non-nested record.
 +  length        = The length of the current record to read in.
 +  contentReader = The newly made reader which will only contain the content bytes of the current record.
 +
 + Throws:
 +  `Asn1DecodeError.eof` if there are less bytes than expected.
 +
 +  `Asn1DecodeError.componentLengthOver64Bits` if the length is long-form and does not fit into a native D integer.
 +
 + Returns:
 +  A `Result` if reading failed.
 + ++/
Result asn1ReadContentBytes(
    scope ref MemoryReader mem,
    const Asn1Length length,
    scope out MemoryReader contentReader,
) @safe @nogc nothrow
// in(length != Asn1Length.init, "The length must be initialized") // Annoying: A length of 0 matches Asn1Length.init because the SumType doesn't treat .init as an invalid state... *sigh*
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
        "error DER - unused bits must be set to 0": T([0x07, 0xFF], err.bitstringInvalidDerEncoding),
        "error DER - the last byte must not be 0": T([0x00, 0x00], err.bitstringInvalidDerEncoding),
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

        "error - must not be constructed": T([], err.realIsConstructed, Asn1Identifier.Encoding.constructed),
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

@("Asn1SetOf - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        ulong[] expectedValues;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, ulong[] expectedValues)
        {
            this.data = data;
            this.expectedValues = expectedValues;
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
        "empty": T([], []),
        "1 element": T([0x02, 0x01, 0x0A], [10]),
        "2 elements": T([
            0x02, 0x01, 0x0A,
            0x02, 0x01, 0x0C,
        ], [10, 12]),

        "error - unordered due to size": T([
            0x02, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x0A,
        ], err.setOfDerIsUnordered),
        "error - unordered due to bytes": T([
            0x02, 0x01, 0x0C,
            0x02, 0x01, 0x0A,
        ], err.setOfDerIsUnordered),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1SetOf!Asn1Integer obj;
            auto result = Asn1SetOf!Asn1Integer.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.elementCount == test.expectedValues.length);
            
            size_t i;
            obj.foreachElement((Asn1Integer element){
                ulong value;
                element.asInt(value).resultAssert;
                assert(value == test.expectedValues[i++]);
                return Result.noError;
            }, (scope ref reader, scope out number, const identifier){
                return Asn1Integer.fromDecoding!(Asn1Ruleset.der)(reader, number, identifier);
            }).resultAssert;
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1Utf8String - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        string expected;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, string expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive) // @suppress(dscanner.style.long_line)
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
        "empty": T([], ""),
        "ASCII": T(['a', 'b', 'c'], "abc"),
        "Unicode": T([0xEC, 0x9C, 0x84], "위"),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1Utf8String obj;
            auto result = Asn1Utf8String.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.asSlice == test.expected);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1PrintableString - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        string expected;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, string expected)
        {
            this.data = data;
            this.expected = expected;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive) // @suppress(dscanner.style.long_line)
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
        "empty": T([], ""),
        "ASCII": T(['a', 'b', 'c'], "abc"),

        "error - invalid chars": T(['@'], err.printableStringHasInvalidChars),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1PrintableString obj;
            auto result = Asn1PrintableString.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.asSlice == test.expected);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}

@("Asn1UtcTime - General Conformance")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.format        : format;
    import std.typecons      : Nullable;

    static struct T
    {
        ubyte[] data;
        Asn1Identifier ident;
        uint expectedYear, expectedMonth, expectedDay, expectedHour, expectedMinute, expectedSecond;
        Nullable!Asn1DecodeError expectedError;

        this(ubyte[] data, uint expectedYear, uint expectedMonth, uint expectedDay, uint expectedHour, uint expectedMinute, uint expectedSecond) // @suppress(dscanner.style.long_line)
        {
            this.data = data;
            this.expectedYear = expectedYear;
            this.expectedMonth = expectedMonth;
            this.expectedDay = expectedDay;
            this.expectedHour = expectedHour;
            this.expectedMinute = expectedMinute;
            this.expectedSecond = expectedSecond;
            this.ident = Asn1Identifier(
                Asn1Identifier.Class.universal, 
                Asn1Identifier.Encoding.primitive, 
                0
            );
        }

        this(ubyte[] data, Asn1DecodeError error, Asn1Identifier.Encoding encoding = Asn1Identifier.Encoding.primitive) // @suppress(dscanner.style.long_line)
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
        "recommendation 1": T(cast(ubyte[])"920521000000Z", 1992, 05, 21, 00, 00, 00),
        "recommendation 2": T(cast(ubyte[])"920622123421Z", 1992, 06, 22, 12, 34, 21),
        "recommendation 3": T(cast(ubyte[])"920722132100Z", 1992, 07, 22, 13, 21, 00),

        // Don't ask... just don't - ASN.1's UTCTime is insane.
        "year for 2000": T(cast(ubyte[])"000101000000Z", 2000, 01, 01, 00, 00, 00),
        "year for 2049": T(cast(ubyte[])"490101000000Z", 2049, 01, 01, 00, 00, 00),
        "year for 1950": T(cast(ubyte[])"500101000000Z", 1950, 01, 01, 00, 00, 00),
        "year for 1999": T(cast(ubyte[])"990101000000Z", 1999, 01, 01, 00, 00, 00),

        "error - wrong size under DER": T(cast(ubyte[])"000102000060+0500", err.utcTimeIsWrongSize),
        "error - invalid chars": T(cast(ubyte[])"ab0102000060Z", err.utcTimeInvalidLiteral),
        "error - no Z at the end": T(cast(ubyte[])"000102000060+", err.utcTimeHasTimezoneUnderDer),
        "error - invalid month - cannot be 0": T(cast(ubyte[])"000001000000Z", err.utcTimeInvalidLiteral),
        "error - invalid month - too large": T(cast(ubyte[])"003101000000Z", err.utcTimeInvalidLiteral),
        "error - invalid day - cannot be 0": T(cast(ubyte[])"000100000000Z", err.utcTimeInvalidLiteral),
        "error - invalid day - too large": T(cast(ubyte[])"000132000000Z", err.utcTimeInvalidLiteral),
        "error - invalid hour - too large": T(cast(ubyte[])"000102240000Z", err.utcTimeInvalidLiteral),
        "error - invalid minute - too large": T(cast(ubyte[])"000102006000Z", err.utcTimeInvalidLiteral),
        "error - invalid second - too large": T(cast(ubyte[])"000102000060Z", err.utcTimeInvalidLiteral),
    ];

    foreach(name, test; cases)
    {
        import std.algorithm : canFind, equal;

        try
        {
            auto mem = MemoryReader(test.data);

            Asn1UtcTime obj;
            auto result = Asn1UtcTime.fromDecoding!(Asn1Ruleset.der)(mem, obj, test.ident);

            if(result.isError)
            {
                if(test.expectedError.isNull)
                    result.resultAssert();
                resultAssertSameCode!err(result, Result.make(test.expectedError.get));
                continue;
            }
            else if(!test.expectedError.isNull)
                assert(false, "Expected an error, but didn't get one.");

            assert(obj.year == test.expectedYear);
            assert(obj.month == test.expectedMonth);
            assert(obj.day == test.expectedDay);
            assert(obj.hour == test.expectedHour);
            assert(obj.minute == test.expectedMinute);
            assert(obj.second == test.expectedSecond);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]: "~err.msg);
    }
}