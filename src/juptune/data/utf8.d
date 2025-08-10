/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.utf8;

import juptune.core.util.result;

/++
 + A `Result` error enum.
 + ++/
enum Utf8Error
{
    none,
    
    invalid,    /// A leading byte is simply just invalid, and can never be used to represent a valid codepoint.
    tooShort,   /// A leading byte has too little continuation bytes.
    tooLong,    /// A continuation byte was found when a leading byte was expected - too many continuation bytes were used in the previous codepoint.
    overlong,   /// The codepoint must be above U+7F when two bytes; U+7FF when three bytes, and U+FFFF when four bytes long.
    tooLarge,   /// The codepoint must be <= U+10FFFF.
    surrogate,  /// The codepoint must not be in the range U+D800..U+DFFF.
    eof         /// Ran out of bytes while decoding a codepoint.
}

alias Utf8EncodeCharBuffer = ubyte[4];

/++
 + Validates that the entirety of the given input is a correct, well-formed UTF-8 string.
 +
 + Params:
 +  AlgorithmT = The particular algorithm to use to perform validation.
 +  input      = The input to validate.
 +
 + Throws:
 +  `Utf8Error.invalid`, `Utf8Error.tooShort`, `Utf8Error.tooLong`, `Utf8Error.overlong`, `Utf8Error.tooLarge`,
 +  `Utf8Error.surrogate`, and `Utf8Error.eof`. Please see their documentation on what conditions trigger them.
 +
 + Returns:
 +  A non-errorful `Result` if `input` is a valid UTF-8 string, otherwise a `Result` roughly specifying why `input` is invalid.
 + ++/
Result utf8Validate(alias AlgorithmT = Utf8DefaultAlgorithm)(scope const(void)[] input) @nogc nothrow @safe
{
    return AlgorithmT.validate(input);
}

/++
 + Validates and decodes the next UTF-8 codepoint from the given input.
 +
 + Notes:
 +  After calling this function on success, the `cursor` will be advanced to the
 +  position of the next codepoint to decode.
 +
 +  The value of `decoded` and `cursor` is undefined if an error is thrown.
 +
 + Params:
 +  AlgorithmT = The particular algorithm to use to perform validation & decoding.
 +  input      = The input to validate and decode.
 +  cursor     = The cursor into `input` to decode the next codepoint from.
 +  decoded    = The decoded codepoint.
 +
 + Throws:
 +  `Utf8Error.invalid`, `Utf8Error.tooShort`, `Utf8Error.tooLong`, `Utf8Error.overlong`, `Utf8Error.tooLarge`,
 +  `Utf8Error.surrogate`, and `Utf8Error.eof`. Please see their documentation on what conditions trigger them.
 +
 + Returns:
 +  A non-errorful `Result` if `input` is a valid UTF-8 string, otherwise a `Result` roughly specifying why `input` is invalid.
 + ++/
Result utf8DecodeNext(alias AlgorithmT = Utf8DefaultAlgorithm)(
    scope const(void)[] input,
    scope ref size_t cursor,
    scope ref dchar decoded,
) @nogc nothrow @safe
{
    return AlgorithmT.decodeNext(input, cursor, decoded);
}

/++
 + Encodes (but does not validate) the given Unicode codepoint into UTF-8 codeunits.
 +
 + Notes:
 +  This function does not validate that `ch` is a valid codepoint. It is up to the caller
 +  the use the other validation functions when appropriate to confirm the encoding is valid.
 +
 +  For `buffer`, just initialise an empty `Utf8EncodeCharBuffer` and pass it in - it's just to make
 +  handling the variable-lengthiness of UTF-8 easier.
 +
 + Params:
 +  ch          = The codepoint to encode.
 +  buffer      = A buffer to store the encoded codepoint into.
 +  outSlice    = A slice of `buffer` containing the bytes that were used for encoding `ch`.
 +
 + Throws:
 +  `Utf8Error.invalid` if `ch` is greater than 0x10FFFF - as any value above that number is not allowed
 +  to be encoded under UTF-8.
 +
 + Returns:
 +  A `Result` indicating whether encoding was succesful or not.
 + ++/
Result utf8Encode(
    dchar ch,
    scope ref Utf8EncodeCharBuffer buffer,
    scope ref ubyte[] outSlice,
) @safe @nogc nothrow
{
    if(ch <= 0x7F) // ASCII
    {
        buffer[0] = cast(ubyte)ch;
        outSlice = buffer[0..1];
        return Result.noError;
    }
    else if(ch <= 0x7FF) // Two bytes
    {
        buffer[0] = 0b110_00000 | ((ch & 0b0111_1100_0000) >> 6);
        buffer[1] = 0b10_000000 | ( ch & 0b0000_0011_1111);
        outSlice = buffer[0..2];
        return Result.noError;
    }
    else if(ch <= 0xFFFF) // Three bytes
    {
        buffer[0] = 0b1110_0000 | ((ch & 0b1111_0000_0000_0000) >> 12);
        buffer[1] = 0b10_000000 | ((ch & 0b0000_1111_1100_0000) >> 6);
        buffer[2] = 0b10_000000 | ( ch & 0b0000_0000_0011_1111);
        outSlice = buffer[0..3];
        return Result.noError;
    }
    else if(ch <= 0x10FFFF) // Four bytes
    {
        buffer[0] = 0b11110_000 | ((ch & 0b1_1100_0000_0000_0000_0000) >> 18);
        buffer[1] = 0b10_000000 | ((ch & 0b0_0011_1111_0000_0000_0000) >> 12);
        buffer[2] = 0b10_000000 | ((ch & 0b0_0000_0000_1111_1100_0000) >> 6);
        buffer[3] = 0b10_000000 | ( ch & 0b0_0000_0000_0000_0011_1111);
        outSlice = buffer[0..4];
        return Result.noError;
    }

    return Result.make(Utf8Error.invalid, "Attempted to encode an invalid UTF-8 codepoint");
}

/++++ Algorithms ++++/

/// The default set of UTF-8 algorithms for this platform.
alias Utf8DefaultAlgorithm = Utf8FallbackAlgorithm;

private template Utf8FallbackAlgorithm_()
{
    import juptune.core.util : Result;

    private static @nogc nothrow:

    // Implements the "Branchy Range Validator" described in https://arxiv.org/pdf/2010.03090
    Result validate(scope const(void)[] input) @trusted // @safe - the long* cast is protected by a bounds check.
    {
        scope const bytes = cast(const(ubyte)[])input;

        size_t i = 0;
        dchar ignore;
        while(i < bytes.length)
        {
            // ASCII fast path as described in the linked paper.
            if(
                bytes.length >= 8
                && i <= bytes.length-8 // @suppress(dscanner.suspicious.length_subtraction)
                && (*cast(long*)&bytes[i] & 0x8080808080808080) == 0
            )
            {
                i += 8;
                continue;
            }

            auto result = next!false(bytes, i, ignore);
            if(result.isError)
                return result;
        }

        return Result.noError; 
    }

    Result decodeNext(scope const(void)[] input, scope ref size_t cursor, scope ref dchar decoded) @safe
    {
        return next!true(cast(const(ubyte)[])input, cursor, decoded);
    }

    pragma(inline, true)
    Result next(bool DoDecode)(scope const(ubyte[]) bytes, scope ref size_t i, scope ref dchar decoded)
    {
        switch(bytes[i])
        {
            // ASCII
            case 0b00000000: .. case 0b01111111:
                static if(DoDecode)
                    decoded = cast(dchar)bytes[i];
                i++;
                break;

            // 2 bytes
            case 0b11000010: .. case 0b11011111:
                if(i + 1 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 2-byte UTF-8 codepoint.");
                if((bytes[i+1] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 2-byte UTF-8 codepoint, the next byte isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00011111) << 6) | (bytes[i+1] & 0b00111111);
                i += 2;
                break;

            // 3 bytes (Lower end of allowed values)
            case 0b11100000:
                if(i + 2 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 3-byte (lower) UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                
                const byte1 = bytes[i+1];
                if((byte1 & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 3-byte (lower) UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                if(byte1 >= 0b10000000 && byte1 <= 0b10011111)
                    return Result.make(Utf8Error.overlong, "For 3-byte (lower) UTF-8 codepoint, value is <= U+7FF");
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00001111) << 12) | ((bytes[i+1] & 0b00111111) << 6) | (bytes[i+2] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 3;
                break;

            // 3 bytes (potential surrogate)
            case 0b11101101:
                if(i + 2 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 3-byte (surrogate) UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                
                const byte1 = bytes[i+1];
                if((byte1 & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 3-byte (surrogate) UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                if(byte1 >= 0b10100000 && byte1 <= 0b10111111)
                    return Result.make(Utf8Error.surrogate, "For 3-byte (surrogate) UTF-8 codepoint, value could be confused as a UTF-16 surrogate."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00001111) << 12) | ((bytes[i+1] & 0b00111111) << 6) | (bytes[i+2] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 3;
                break;

            // 3 bytes (rest of the potential values)
            case 0b11100001: .. case 0b11101100:
            case 0b11101110: .. case 0b11101111:
                if(i + 2 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 3-byte UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                if((bytes[i+1] & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 3-byte UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00001111) << 12) | ((bytes[i+1] & 0b00111111) << 6) | (bytes[i+2] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 3;
                break;

            // 4 bytes (potentially too small)
            case 0b11110000:
                if(i + 3 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 4-byte (lower) UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                
                const byte1 = bytes[i+1];
                if((byte1 & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80 || (bytes[i+3] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 4-byte (lower) UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                if(byte1 >= 0b10000000 && byte1 <= 0b10001111)
                    return Result.make(Utf8Error.overlong, "For 4-byte (lower) UTF-8 codepoint, value is <= U+FFFF."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00000111) << 18) | ((bytes[i+1] & 0b00111111) << 12) | ((bytes[i+2] & 0b00111111) << 6) | (bytes[i+3] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 4;
                break;

            // 4 bytes (no potential for being too large or small)
            case 0b11110001: .. case 0b11110011:
                if(i + 3 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 4-byte UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                if((bytes[i+1] & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80 || (bytes[i+3] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 4-byte UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00000111) << 18) | ((bytes[i+1] & 0b00111111) << 12) | ((bytes[i+2] & 0b00111111) << 6) | (bytes[i+3] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 4;
                break;

            // 4 bytes (potentially too large)
            case 0b11110100:
                if(i + 3 >= bytes.length)
                    return Result.make(Utf8Error.eof, "Ran out of bytes when decoding 4-byte (upper) UTF-8 codepoint."); // @suppress(dscanner.style.long_line)
                
                const byte1 = bytes[i+1];
                if((byte1 & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80 || (bytes[i+3] & 0xC0) != 0x80)
                    return Result.make(Utf8Error.tooShort, "For 4-byte (upper) UTF-8 codepoint, one of the next bytes isn't a continuation byte."); // @suppress(dscanner.style.long_line)
                if(byte1 >= 0b10100000 && byte1 <= 0b10111111)
                    return Result.make(Utf8Error.tooLarge, "For 4-byte (upper) UTF-8 codepoint, value is > U+10FFFF."); // @suppress(dscanner.style.long_line)
                static if(DoDecode)
                    decoded = ((bytes[i] & 0b00000111) << 18) | ((bytes[i+1] & 0b00111111) << 12) | ((bytes[i+2] & 0b00111111) << 6) | (bytes[i+3] & 0b00111111); // @suppress(dscanner.style.long_line)
                i += 4;
                break;

            default:
                return Result.make(Utf8Error.invalid, "UTF-8 leading byte contains 5 or more header bits.");
        }

        return Result.noError;
    }
}

/++
 + A fallback set of algorithms that should work on any platform. This'll usually be the slowest
 + implementation, but that should generally still be fast enough for most cases.
 + ++/
alias Utf8FallbackAlgorithm = Utf8FallbackAlgorithm_!();

/++++ Unittests ++++/

version(unittest):

import std.meta : AliasSeq;

private alias AllAlgorithms = AliasSeq!(Utf8FallbackAlgorithm);

@("utf8Validate - Tests cases from https://github.com/flenniken/utf8tests (shoutout!)")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import std.typecons : Nullable;

    static struct T
    {
        const(ubyte)[] input;
        Nullable!Utf8Error expectedError;

        this(const(ubyte)[] input)
        {
            this.input = input;
        }

        this(const(ubyte)[] input, Utf8Error error)
        {
            this.input = input;
            this.expectedError = error;
        }
    }

    T[string] cases = [
        "1.0.1": T([0x31]),
        "1.1.0": T(cast(const(ubyte)[])"abc"),
        "2.1.0": T([0xC2, 0xA9]),
        "3.0": T([0xE2, 0x80, 0x90]),
        "4.0": T([0xF0, 0x9D, 0x92, 0x9C]),
        "5.1": T([0xC2, 0x80]),
        "5.2": T([0xE0, 0xA0, 0x80]),
        "5.3": T([0xF0, 0x90, 0x80, 0x80]),
        "7.1": T([0xC2, 0x80]),
        "7.2": T([0xC2, 0x81]),
        "7.3": T([0xC2, 0x82]),
        "8.0": T([0x7F]),
        "8.1": T([0xDF, 0xBF]),
        "8.2": T([0xEF, 0xBF, 0xBF]),
        "8.3": T([0xF4, 0x8F, 0xBF, 0xBF]),
        "10.1": T([0xEE, 0x80, 0x80]),
        "10.2": T([0xEF, 0xBF, 0xBD]),
        "22.0": T(cast(const(ubyte)[])"/"),
        "22.1": T([0x2F]),
        "22.2": T([0xE0, 0xA0, 0x80]),

        "6.0": T([0xF7, 0xBF, 0xBF, 0xBF], Utf8Error.invalid),
        // "6.0.1": T([0xF4, 0x90, 0x80, 0x80], Utf8Error.invalid),
        "6.1": T([0xF8, 0x88, 0x80, 0x80], Utf8Error.invalid),
        "6.2": T([0xF7, 0xBF, 0xBF, 0xBF], Utf8Error.invalid),
        "6.3": T([0xFC, 0x84, 0x80, 0x80], Utf8Error.invalid),
        "9.0": T([0xF7, 0xBF, 0xBF], Utf8Error.invalid),
        
        "11.0": T([0x80], Utf8Error.invalid),
        "11.1": T([0xBF], Utf8Error.invalid),
        "11.2": T([0x80, 0xBF], Utf8Error.invalid),
        "11.3": T([0x80, 0xBF, 0x80], Utf8Error.invalid),
        "11.4": T([0x80, 0xBF, 0x80, 0xBF], Utf8Error.invalid),

        "11.4": T([0x80, 0xBF, 0x80, 0xBF], Utf8Error.invalid),

        "13.0.0": T([0xC0, 0x20], Utf8Error.invalid),
        "13.0.1": T([0xC1, 0x20], Utf8Error.invalid),

        "16.0": T([0xF8], Utf8Error.invalid),
        "16.1": T([0xF9], Utf8Error.invalid),
        "16.2": T([0xFA], Utf8Error.invalid),
        "16.3": T([0xFB], Utf8Error.invalid),
        "17.0": T([0xFC], Utf8Error.invalid),
        "17.1": T([0xFD], Utf8Error.invalid),

        "18.0": T([0xC2], Utf8Error.eof),
        "18.1": T([0xE0, 0x80], Utf8Error.eof),
        "18.2": T([0xF0, 0x80, 0x80], Utf8Error.eof),
        
        "21.0": T([0x80], Utf8Error.invalid),
        "21.1": T([0x81], Utf8Error.invalid),
        "21.2": T([0xFE], Utf8Error.invalid),
        "21.3": T([0xFF], Utf8Error.invalid),
        "21.4": T([0x37, 0xFF], Utf8Error.invalid),
        "21.5": T([0x37, 0x38, 0xFF], Utf8Error.invalid),
        "21.6": T([0x37, 0x38, 0x39, 0xFF], Utf8Error.invalid),

        "22.3": T([0xE0, 0x80, 0xAF], Utf8Error.overlong),
        "22.4": T([0xF0, 0x80, 0x80, 0xAF], Utf8Error.overlong),
        "23.1": T([0xE0, 0x9F, 0xBF], Utf8Error.overlong),
        "23.2": T([0xF0, 0x8F, 0xBF, 0xBF], Utf8Error.overlong),
        
        "24.0": T([0xED, 0xA0, 0x80], Utf8Error.surrogate),
        "24.0.1": T([0xED, 0xA0, 0x80, 0x35], Utf8Error.surrogate),
        "24.0.2": T([0x31, 0x32, 0x33, 0xED, 0xA0, 0x80, 0x31], Utf8Error.surrogate),
        "24.2": T([0xED, 0xAD, 0xBF], Utf8Error.surrogate),
        "24.3": T([0xED, 0xAE, 0x80], Utf8Error.surrogate),
        "24.4": T([0xED, 0xAF, 0xBF], Utf8Error.surrogate),
        "24.5": T([0xED, 0xB0, 0x80], Utf8Error.surrogate),
        "24.6": T([0xED, 0xBE, 0x80], Utf8Error.surrogate),
        "24.7": T([0xED, 0xBF, 0xBF], Utf8Error.surrogate),

        "37.1": T([0xE0, 0x80, 0x80], Utf8Error.overlong),
        "37.2": T([0xF0, 0x80, 0x80, 0x80], Utf8Error.overlong),
    ];

    // 12.0 -> 12.7
    foreach(i; 0x80..0xC0)
    {
        import std.conv : to;
        cases["12.0."~i.to!string(16)] = T([cast(ubyte)i], Utf8Error.invalid);
    }

    // 13.0 -> 13.7
    foreach(i; 0xC2..0xE0)
    {
        import std.conv : to;
        cases["13.1."~i.to!string(16)] = T([cast(ubyte)i, 0x20], Utf8Error.tooShort);
    }

    // 14.0 -> 14.3
    foreach(i; 0xE0..0xF0)
    {
        import std.conv : to;
        cases["14.0."~i.to!string(16)] = T([cast(ubyte)i, 0x20, 0x00], Utf8Error.tooShort);
    }

    // 15.0 -> 15.2
    foreach(i; 0xF0..0xF5)
    {
        import std.conv : to;
        cases["15.0."~i.to!string(16)] = T([cast(ubyte)i, 0x20, 0x00, 0x00], Utf8Error.tooShort);
    }

    static foreach(AlgorithmT; AllAlgorithms)
    foreach(testName, testCase; cases)
    {
        try
        {
            auto result = utf8Validate!AlgorithmT(testCase.input);
            if(testCase.expectedError.isNull)
                result.resultAssert;
            else
                resultAssertSameCode!Utf8Error(result, Result.make(testCase.expectedError.get));
        }
        catch(Error ex) // @suppress(dscanner.suspicious.catch_em_all)
        {
            assert(false, "["~testName~"] "~ex.msg);
        }
    }
}

@("utf8DecodeNext - General success")
unittest
{
    import juptune.core.util : resultAssert;
    import std.typecons : Nullable;

    static struct T
    {
        const(ubyte)[] input;
        dchar expected;
    }

    T[string] cases = [
        // Cases from: https://en.wikipedia.org/wiki/UTF-8
        "Ascii W": T([0x57], 'W'),
        "Greek Beta": T([0xCE, 0x92], 'Β'),
        "Korean Wi": T([0xEC, 0x9C, 0x84], '위'),
        "Some Gothic character": T([0xF0, 0x90, 0x8D, 0x85], '𐍅'),
    ];

    static foreach(AlgorithmT; AllAlgorithms)
    foreach(testName, testCase; cases)
    {
        try
        {
            dchar decoded;
            size_t cursor;
            utf8DecodeNext!AlgorithmT(testCase.input, cursor, decoded).resultAssert;
            assert(cursor == testCase.input.length, "cursor is not at the end of the given input?");
            assert(decoded == testCase.expected);
        }
        catch(Error ex) // @suppress(dscanner.suspicious.catch_em_all)
        {
            assert(false, "["~testName~"] "~ex.msg);
        }
    }
}

@("utf8Encode - General success")
unittest
{
    import juptune.core.util : resultAssert;
    import std.typecons : Nullable;

    static struct T
    {
        dchar input;
        const(ubyte)[] expected;
    }

    T[string] cases = [
        // Cases from: https://en.wikipedia.org/wiki/UTF-8
        "Ascii W": T('W', [0x57]),
        "Greek Beta": T('Β', [0xCE, 0x92]),
        "Korean Wi": T('위', [0xEC, 0x9C, 0x84]),
        "Some Gothic character": T('𐍅', [0xF0, 0x90, 0x8D, 0x85]),

        "Max ASCII": T(cast(dchar)0x7F, [0x7F]),
        "Max Two Byte": T(cast(dchar)0x7FF, [0xDF, 0xBF]),
        "Max Three Byte": T(cast(dchar)0xFFFF, [0xEF, 0xBF, 0xBF]),
        "Max Four Byte": T(cast(dchar)0x10FFFF, [0xF4, 0x8F, 0xBF, 0xBF]),
    ];

    static foreach(AlgorithmT; AllAlgorithms)
    foreach(testName, testCase; cases)
    {
        try
        {
            Utf8EncodeCharBuffer buffer;
            ubyte[] usedBuffer;
            utf8Encode(testCase.input, buffer, usedBuffer).resultAssert;
            assert(usedBuffer == testCase.expected);

            utf8Validate(usedBuffer).resultAssert;
        }
        catch(Error ex) // @suppress(dscanner.suspicious.catch_em_all)
        {
            assert(false, "["~testName~"] "~ex.msg);
        }
    }
}