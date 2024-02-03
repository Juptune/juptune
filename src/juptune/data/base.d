/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.base;

import std.typecons : Flag;
import juptune.core.util : Result;

private
{
    enum INVALID_BASE64 = 0xFF;
    immutable g_base64BaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
}

/// Used with an Alphabet to describe how padding is handled.
enum Base64Padding
{
    /// No padding is allowed in both encoding and decoding.
    none,

    /// Padding is optional in both encoding and decoding; and the encoder should always output padding where possible.
    optionalPrefer,

    /// Padding is optional in both encoding and decoding; and the encoder should never output padding.
    optionalNoPrefer,

    /// Padding is required in both encoding and decoding.
    required,
}

/// Used with an Alphabet to describe whether line breaks are supported.
alias Base64AllowLines = Flag!"base64AllowLines";

/++
 + Describes a base64 alphabet. You may want to use the aliases instead of using this directly.
 +
 + Pretty much all base64 alphabets are the same beyond the 62nd and 63rd characters, and the padding character,
 + so those are the only ones that are configurable.
 + ++/
struct Base64Alphabet(
    char Char62,                  char Char63, 
    Base64Padding Padding_,       char CharPad,
    Base64AllowLines AllowLines_, string LineBreak_, uint MaxLineLength_
) 
{
    @safe @nogc nothrow pure static:

    enum      Pad1          = CharPad;
    enum      Padding       = Padding_;
    enum      AllowLines    = AllowLines_;
    enum      MaxLineLength = MaxLineLength_;
    immutable Pad2          = [CharPad, CharPad];
    immutable LineBreak     = LineBreak_;

    static assert(!AllowLines || MaxLineLength >= 4, "MaxLineLength must be at least 4 when AllowLines is set");

    char sextetToChar(uint sextet)
    in(sextet < 64, "bug: sextet must be less than 64 - caller has bad logic")
    {
        switch(sextet)
        {
            case 63: return Char63;
            case 62: return Char62;
            default: return g_base64BaseAlphabet[sextet];
        }
    }

    uint charToSextet(char c)
    {
        switch(c)
        {
            case 'A':..case 'Z':
                return (c - 'A');

            case 'a':..case 'z':
                return (c - 'a') + 26;

            case '0':..case '9':
                return (c - '0') + 52;

            case Char62: return 62;
            case Char63: return 63;
            default: return INVALID_BASE64;
        }
    }
}

alias Base64Rfc4648Alphabet = Base64Alphabet!(
    '+',                            '/', 
    Base64Padding.optionalPrefer,   '=',
    Base64AllowLines.no,            "", 0
);

alias Base64Rfc4648UrlAlphabet = Base64Alphabet!(
    '-',                            '_', 
    Base64Padding.optionalNoPrefer, '=',
    Base64AllowLines.no,            "", 0
);

alias Base64Rfc2045Alphabet = Base64Alphabet!(
    '+',                            '/', 
    Base64Padding.required,         '=',
    Base64AllowLines.yes,           "\r\n", 76
);

struct Base64Encoder(Alphabet)
{
    private
    {
        enum BufferState
        {
            empty,
            one,
            two
        }

        ubyte[3]    _buffer;
        BufferState _bufferState;

        static if(Alphabet.AllowLines) size_t _lineLength;
    }

    @trusted: // This can't be @safe due to the compiler temporaries causing dumb errors // @suppress(dscanner.trust_too_much)

    @disable this(this); // Mainly to stop accidental copies.

    Result encode(OutStreamFunc)(scope const(ubyte)[] input, scope OutStreamFunc outStream)
    in(input.length > 0, "input must have at least 1 byte - caller has bad logic")
    in(outStream !is null, "outStream must not be null")
    {
        final switch(this._bufferState) with(BufferState)
        {
            case empty: break;
            case one:
                this._buffer[1] = input[0];
                if(input.length == 1)
                {
                    this._bufferState = two;
                    return Result.noError;
                }

                this._bufferState = empty;
                this._buffer[2] = input[1];

                auto result = this.writeToStream(this.encodeGroup(this._buffer), outStream);
                if(result != Result.noError)
                    return result;

                input = input[2..$];
                break;
            case two:
                this._buffer[2] = input[0];
                this._bufferState = empty;
                input = input[1..$];

                auto result = this.writeToStream(this.encodeGroup(this._buffer), outStream);
                if(result != Result.noError)
                    return result;
                break;
        }
        if(input.length == 0)
            return Result.noError;

        while(input.length >= 3)
        {
            auto result = this.writeToStream(this.encodeGroup(input[0..3]), outStream);
            if(result != Result.noError)
                return result;
            input = input[3..$];
        }

        final switch(input.length)
        {
            case 0: break;
            case 1:
                this._buffer[0] = input[0];
                this._bufferState = BufferState.one;
                break;
            case 2:
                this._buffer[0] = input[0];
                this._buffer[1] = input[1];
                this._bufferState = BufferState.two;
                break;
        }

        return Result.noError;
    }

    Result finish(OutStreamFunc)(scope OutStreamFunc outStream)
    in(outStream !is null, "outStream must not be null")
    {
        final switch(this._bufferState) with(BufferState)
        {
            case empty: return Result.noError;
            case one:
                this._buffer[1] = 0;
                this._buffer[2] = 0;

                auto encoded = this.encodeGroup(this._buffer);
                auto slice   = encoded[];
                if(Alphabet.Padding == Base64Padding.required || Alphabet.Padding == Base64Padding.optionalPrefer)
                    slice[2..$] = Alphabet.Pad2;
                else
                    slice = slice[0..2];

                this._bufferState = empty;
                return this.writeToStream(slice, outStream);
            case two:
                this._buffer[2] = 0;

                auto encoded = this.encodeGroup(this._buffer);
                auto slice   = encoded[];
                if(Alphabet.Padding == Base64Padding.required || Alphabet.Padding == Base64Padding.optionalPrefer)
                    slice[3] = Alphabet.Pad1;
                else
                    slice = slice[0..3];

                this._bufferState = empty;
                return this.writeToStream(slice, outStream);
        }
    }

    private Result writeToStream(OutStreamFunc)(scope const char[] chars, scope OutStreamFunc outStream)
    {
        static if(Alphabet.AllowLines)
        {
            if(this._lineLength + chars.length > Alphabet.MaxLineLength)
            {
                auto slice = chars[];
                if(this._lineLength < Alphabet.MaxLineLength)
                {
                    auto result = outStream(slice[0..(Alphabet.MaxLineLength - this._lineLength)]);
                    if(result != Result.noError)
                        return result;

                    slice = slice[(Alphabet.MaxLineLength - this._lineLength)..$];
                }

                auto result = outStream(Alphabet.LineBreak);
                if(result != Result.noError)
                    return result;

                assert(slice.length <= Alphabet.MaxLineLength, "bug: slice must be less than or equal to MaxLineLength"); // @suppress(dscanner.style.long_line)
                result = outStream(slice);
                if(result != Result.noError)
                    return result;

                this._lineLength = slice.length;
                return Result.noError;
            }

            this._lineLength += chars.length;
            return outStream(chars[]);
        }
        else return outStream(chars[]);
    }

    private char[4] encodeGroup(scope const ubyte[3] group) @safe @nogc nothrow pure const
    {
        return [
            Alphabet.sextetToChar(group[0] >> 2),
            Alphabet.sextetToChar(((group[0] & 0b0000_0011) << 4) | (group[1] >> 4)),
            Alphabet.sextetToChar(((group[1] & 0b0000_1111) << 2) | (group[2] >> 6)),
            Alphabet.sextetToChar(group[2] & 0b0011_1111)
        ];
    }
}

/++++ Unittests ++++/

version(unittest) import juptune.core.util : resultAssert;

@("Base64Encoder - exactly 3 chars")
@nogc nothrow unittest
{
    bool lambdaCalled = false;
    scope(success) assert(lambdaCalled);
    
    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    encoder.encode([0x00, 0x00, 0x00], (scope const char[] chars){
        lambdaCalled = true;
        assert(chars == "AAAA");
        return Result.noError;
    }).resultAssert;

    enum Error { _ }
    encoder.finish((scope const char[] chars) => Result.make(Error._)).resultAssert;
}

@("Base64Encoder - correctly splitting groups")
@nogc nothrow unittest
{
    int lambdaCalled;
    scope(success) assert(lambdaCalled == 3);
    
    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    encoder.encode([0, 0, 0, 1, 1, 1, 2, 2, 2], (scope const char[] chars){
        lambdaCalled++;

        final switch(lambdaCalled)
        {
            case 1: assert(chars == "AAAA"); break;
            case 2: assert(chars == "AQEB"); break;
            case 3: assert(chars == "AgIC"); break;
        }

        return Result.noError;
    }).resultAssert;

    enum Error { _ }
    encoder.finish((scope const char[] chars) => Result.make(Error._)).resultAssert;
}

@("Base64Encoder - correctly handling partial groups")
@nogc nothrow unittest
{
    enum Error { _ }
    int lambdaCalled;
    
    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    scope check = (scope const char[] chars){
        lambdaCalled++;
        assert(chars == "AQEB");
        return Result.noError;
    };

    /** one -> empty **/
    encoder.encode([1], (scope const char[] chars) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.encode([1, 1], (scope const char[] chars){
        lambdaCalled++;
        assert(chars == "AQEB");
        return Result.noError;
    }).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 1);

    /** one -> two **/
    encoder.encode([1], (scope const char[] chars) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.encode([1], (scope const char[] chars) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.two);

    /** two -> empty **/
    encoder.encode([1], check).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 2);

    /** empty -> one **/
    encoder.encode([1, 1, 1, 1], check).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);
    assert(lambdaCalled == 3);

    encoder.encode([1, 1], check).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 4);

    /** empty -> two **/
    encoder.encode([1, 1, 1, 1, 1], check).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.two);
    assert(lambdaCalled == 5);
}

@("Base64Encoder - correctly handling partial groups with finish")
@nogc nothrow unittest
{
    enum Error { _ }
    int lambdaCalled;
    
    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    scope checkPad1 = (scope const char[] chars){
        lambdaCalled++;
        assert(chars == "AQ==");
        return Result.noError;
    };
    scope checkPad2 = (scope const char[] chars){
        lambdaCalled++;
        assert(chars == "AQE=");
        return Result.noError;
    };

    /** one **/
    encoder.encode([1], (scope const char[] chars) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.finish(checkPad1).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 1);

    /** two **/
    encoder.encode([1, 1], (scope const char[] chars) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.two);

    encoder.finish(checkPad2).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 2);
}

@("Base64Encoder - can use any byte as input")
unittest
{
    import std.algorithm : map;
    import std.array     : array;
    import std.range     : iota;

    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    encoder.encode(
        iota(0, ubyte.max+1).map!(b => cast(ubyte)b).array, 
        (scope const char[] chars) => Result.noError
    ).resultAssert;
    encoder.finish((scope const char[] chars) => Result.noError).resultAssert;
}

@("Base64Encoder - example")
unittest
{
    string result;
    scope append = (scope const char[] chars){
        result ~= chars;
        return Result.noError;
    };

    auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
    encoder.encode(cast(const ubyte[])"Many hands make light work.", append).resultAssert;
    encoder.finish(append).resultAssert;

    assert(result == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
}

@("Base64Encoder - example with lines")
unittest
{
    string result;
    scope append = (scope const char[] chars){
        result ~= chars;
        return Result.noError;
    };

    alias Alphabet = Base64Alphabet!(
        '+',                            '/', 
        Base64Padding.optionalPrefer,   '=',
        Base64AllowLines.yes,           "\r\n", 4
    );

    auto encoder = Base64Encoder!Alphabet();
    encoder.encode(cast(const ubyte[])"Many hands make light work.", append).resultAssert;
    encoder.finish(append).resultAssert;

    assert(result == "TWFu\r\neSBo\r\nYW5k\r\ncyBt\r\nYWtl\r\nIGxp\r\nZ2h0\r\nIHdv\r\ncmsu");
}