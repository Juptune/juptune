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

/// A `Result` error enum.
enum Base64Error
{
    none,

    /// Produced when padding is detected during decoding, but not enough padding is present.
    invalidPadding,

    /// Produced when too much padding is found during decoding.
    tooMuchPadding,

    /// A message was succesfully decoded, however there was still input left over.
    tooMuchInput,

    /// Produced when `finish` is called during decoding; there's data left over in the decode buffer,
    /// and the provided Alphabet either doesn't allow padding, or has padding that is not optional.
    notEnoughInput,

    /// Produced when a character is found that is not part of the alphabet during decoding.
    invalidCharacter,

    /// Produced when a line break is found that is not valid/incomplete during decoding.
    invalidNewLine,

    /// Produced when the decoder is done and the `decode` function is called again before a call to `finish`.
    decoderIsDone,
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
    enum      Zero          = 'A';
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
                static if(Alphabet.Padding == Base64Padding.required || Alphabet.Padding == Base64Padding.optionalPrefer) // @suppress(dscanner.style.long_line)
                    slice[2..$] = Alphabet.Pad2;
                else
                    slice = slice[0..2];

                this._bufferState = empty;
                return this.writeToStream(slice, outStream);
            case two:
                this._buffer[2] = 0;

                auto encoded = this.encodeGroup(this._buffer);
                auto slice   = encoded[];
                static if(Alphabet.Padding == Base64Padding.required || Alphabet.Padding == Base64Padding.optionalPrefer) // @suppress(dscanner.style.long_line)
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

struct Base64Decoder(Alphabet)
{
    import juptune.core.util : StateMachineTypes;

    private
    {
        alias Machine = StateMachineTypes!(State, void*);
        alias StateMachine = Machine.Static!([
            Machine.Transition(State.buffer,  State.newLine, (scope ref _) => Alphabet.AllowLines),
            Machine.Transition(State.buffer,  State.padding, (scope ref _) => Alphabet.Padding != Base64Padding.none),
            Machine.Transition(State.newLine, State.buffer),
            Machine.Transition(State.padding, State.newLineMidPadding, (scope ref _) => Alphabet.AllowLines),
            Machine.Transition(State.padding, State.done),
            Machine.Transition(State.done,    State.buffer),
            Machine.Transition(State.newLineMidPadding, State.padding),
        ]);

        enum State
        {
            buffer,
            newLine,
            newLineMidPadding,
            padding,
            done,
        }

        StateMachine _state;
        char[4] _buffer;
        ubyte _bufferLength;
        
        static if(Alphabet.Padding != Base64Padding.none) 
            ubyte _paddingCount; // Padding may occur over multiple lines, so we need to keep track of it separately.

        static if(Alphabet.AllowLines)
        {
            static assert(Alphabet.LineBreak.length <= _buffer.length, "LineBreak must fit into the internal buffer.");

            // Length of the current line.
            // Note: When we're parsing the new line separator, this variable is used to track how many characters of the
            //       separator we've seen so far, before resetting to 0.
            size_t _lineLength;
        }
    }

    @trusted: // This can't be @safe due to the compiler temporaries causing dumb errors // @suppress(dscanner.trust_too_much)

    @disable this(this); // Mainly to stop accidental copies.

    Result decode(OutStreamFunc)(scope const(char)[] input, scope OutStreamFunc outStream)
    in(input.length > 0, "input must have at least 1 byte - caller has bad logic")
    in(outStream !is null, "outStream must not be null")
    {
        size_t cursor;

        while(cursor < input.length)
        {
            final switch(this._state.current) with(State)
            {
                case buffer:
                    const ch = input[cursor];
                    
                    static if(Alphabet.Padding != Base64Padding.none)
                    if(ch == Alphabet.Pad1)
                    {
                        this._state.mustTransition!(State.buffer, State.padding);
                        break;
                    }

                    static if(Alphabet.AllowLines)
                    {
                        this._lineLength++;
                        if(this._lineLength > Alphabet.MaxLineLength || ch == Alphabet.LineBreak[0])
                        {
                            this._lineLength = 0;
                            this._state.mustTransition!(State.buffer, State.newLine);
                            break;
                        }
                    }

                    cursor++;
                    this._buffer[this._bufferLength++] = ch;
                    if(this._bufferLength != this._buffer.length)
                        break;
                    this._bufferLength = 0;

                    ubyte[3] group;
                    auto result = this.decodeGroup(group);
                    if(result != Result.noError)
                        return result;

                    result = outStream(group);
                    if(result != Result.noError)
                        return result;
                    break;

                static if(Alphabet.Padding != Base64Padding.none)
                {
                    case padding:
                        const ch = input[cursor];
                            
                        static if(Alphabet.AllowLines)
                        {
                            this._lineLength++;
                            if(this._lineLength > Alphabet.MaxLineLength || ch == Alphabet.LineBreak[0])
                            {
                                this._lineLength = 0;
                                this._state.mustTransition!(State.padding, State.newLineMidPadding);
                                break;
                            }
                        }

                        this._paddingCount++;
                        cursor++;
                        if(ch != Alphabet.Pad1)
                            return Result.make(Base64Error.invalidPadding, "Unexpected character in padding");
                        if(this._paddingCount >= 3)
                            return Result.make(Base64Error.tooMuchPadding, "More than 2 padding characters found");
                        break;
                }
                else
                {
                    case padding:
                        assert(false, "bug: padding should not be possible without Padding != none");
                }

                static if(Alphabet.AllowLines)
                {
                    case newLineMidPadding:
                    case newLine:
                        const ch = input[cursor++];
                        if(ch != Alphabet.LineBreak[this._lineLength])
                            return Result.make(Base64Error.invalidNewLine, "Unexpected character in line break sequence"); // @suppress(dscanner.style.long_line)

                        this._lineLength++;
                        if(this._lineLength == Alphabet.LineBreak.length)
                        {
                            this._lineLength = 0;

                            if(this._state.current == State.newLineMidPadding)
                                this._state.mustTransition!(State.newLineMidPadding, State.padding);
                            else
                                this._state.mustTransition!(State.newLine, State.buffer);
                        }
                        break;
                }
                else
                {
                    case newLineMidPadding:
                    case newLine:
                        assert(false, "bug: newLine and newLineMidPadding should not be possible without AllowLines");
                }

                case done:
                    return Result.make(Base64Error.decoderIsDone, "Decode was called again before finish");
            }
        }

        return Result.noError;
    }

    Result finish(OutStreamFunc)(scope OutStreamFunc outStream)
    in(outStream !is null, "outStream must not be null")
    {
        final switch(this._state.current) with(State)
        {
            case buffer:
                if(this._bufferLength == 0)
                    break;
                else if(this._bufferLength == 1)
                    return Result.make(Base64Error.notEnoughInput, "Not enough input to decode. only 1 char in buffer");

                assert(this._bufferLength < 4, "bug: bufferLength being >= 4 should not be possible here");
                static if(Alphabet.Padding == Base64Padding.required)
                {
                    // Due to the break we have to put at the end, we now need to make the compiler
                    // think this is potentially optional.
                    bool _thecompilerisstupid = true;
                    if(_thecompilerisstupid)
                        return Result.make(Base64Error.invalidPadding, "Unexpected end of input");
                }
                else static if(Alphabet.Padding == Base64Padding.none)
                {
                    bool _thecompilerisstupid = true;
                    if(_thecompilerisstupid)
                        return Result.make(Base64Error.notEnoughInput, "Not enough input to decode when using Padding.none"); // @suppress(dscanner.style.long_line)
                }
                else
                {
                    this._buffer[this._bufferLength..$] = Alphabet.Zero;

                    static if(Alphabet.Padding != Base64Padding.none)
                    {
                        const implicitPadding = this._buffer.length - this._bufferLength - this._paddingCount;
                        const end = 3 - (this._paddingCount + implicitPadding);
                    }
                    else
                        const end = 3;

                    ubyte[3] group;
                    auto result = this.decodeGroup(group);
                    if(result != Result.noError)
                        return result;

                    result = outStream(group[0..end]);
                    if(result != Result.noError)
                        return result;
                }
                break; // Must be here otherwise the compiler gets confused.

            static if(Alphabet.Padding == Base64Padding.required)
            {
                case padding:
                    return Result.make(Base64Error.invalidPadding, "Unexpected end of input");
            }
            else static if(Alphabet.Padding != Base64Padding.none)
            {
                case padding:
                    goto case buffer;
            }
            else
            {
                case padding:
                    assert(false, "bug: padding should not be possible when Padding != none");
            }

            static if(Alphabet.AllowLines)
            {
                case newLine:
                case newLineMidPadding:
                    return Result.make(Base64Error.invalidNewLine, "Unexpected end of input");
            }
            else
            {
                case newLine:
                case newLineMidPadding:
                    assert(false, "bug: newLine and newLineMidPadding should not be possible without AllowLines");
            }

            case done:
                this._state.mustTransition!(State.done, State.buffer);
                break;
        }

        this._buffer[] = 0;
        this._bufferLength = 0;
        static if(Alphabet.AllowLines)
            this._lineLength = 0;
        static if(Alphabet.Padding != Base64Padding.none)
            this._paddingCount = 0;

        return Result.noError;
    }

    Result decodeGroup(scope out ubyte[3] group) @nogc nothrow
    {
        uint[4] sextets = [
            Alphabet.charToSextet(this._buffer[0]),
            Alphabet.charToSextet(this._buffer[1]),
            Alphabet.charToSextet(this._buffer[2]),
            Alphabet.charToSextet(this._buffer[3])
        ];
        foreach(i, sextet; sextets)
        {
            if(sextet == INVALID_BASE64)
                return Result.make(Base64Error.invalidCharacter, "Invalid character in input");
        }

        group[0] = cast(ubyte)((sextets[0] << 2) | (sextets[1] >> 4));
        group[1] = cast(ubyte)((sextets[1] << 4) | (sextets[2] >> 2));
        group[2] = cast(ubyte)((sextets[2] << 6) | sextets[3]);

        return Result.noError;
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
    encoder.finish((scope const char[] _) => Result.make(Error._)).resultAssert;
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
    encoder.finish((scope const char[] _) => Result.make(Error._)).resultAssert;
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
    encoder.encode([1], (scope const char[] _) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.encode([1, 1], (scope const char[] chars){
        lambdaCalled++;
        assert(chars == "AQEB");
        return Result.noError;
    }).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 1);

    /** one -> two **/
    encoder.encode([1], (scope const char[] _) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.encode([1], (scope const char[] _) => Result.make(Error._)).resultAssert;
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
    encoder.encode([1], (scope const char[] _) => Result.make(Error._)).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.one);

    encoder.finish(checkPad1).resultAssert;
    assert(encoder._bufferState == encoder.BufferState.empty);
    assert(lambdaCalled == 1);

    /** two **/
    encoder.encode([1, 1], (scope const char[] _) => Result.make(Error._)).resultAssert;
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
        (scope const char[] _) => Result.noError
    ).resultAssert;
    encoder.finish((scope const char[] _) => Result.noError).resultAssert;
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

@("Base64Decoder - Exactly 4 chars")
unittest
{
    bool lambdaCalled = false;
    scope(success) assert(lambdaCalled);
    
    auto decoder = Base64Decoder!Base64Rfc4648Alphabet();
    decoder.decode("YWJj", (scope const ubyte[] bytes){
        lambdaCalled = true;
        assert(bytes == ['a', 'b', 'c']);
        return Result.noError;
    }).resultAssert;

    enum Error { _ }
    decoder.finish((scope const ubyte[] _) => Result.make(Error._)).resultAssert;
}

@("Base64Decoder - correctly splitting groups")
unittest
{
    int lambdaCalled;
    scope(success) assert(lambdaCalled == 3);
    
    auto decoder = Base64Decoder!Base64Rfc2045Alphabet();
    decoder.decode("YWJjZGVmZ2hp", (scope const ubyte[] bytes){
        lambdaCalled++;

        final switch(lambdaCalled)
        {
            case 1: assert(bytes == ['a', 'b', 'c']); break;
            case 2: assert(bytes == ['d', 'e', 'f']); break;
            case 3: assert(bytes == ['g', 'h', 'i']); break;
        }

        return Result.noError;
    }).resultAssert;

    enum Error { _ }
    decoder.finish((scope const ubyte[] _) => Result.make(Error._)).resultAssert;
}

@("Base64Decoder - correctly handling partial groups")
unittest
{
    enum Error { _ }
    int lambdaCalled;
    
    auto decoder = Base64Decoder!Base64Rfc2045Alphabet();
    scope error = (scope const ubyte[] _) => Result.make(Error._);
    scope check = (scope const ubyte[] bytes){
        lambdaCalled++;
        assert(bytes == ['a', 'b', 'c']);
        return Result.noError;
    };

    /** 0 -> 2 **/
    decoder.decode("YW", error).resultAssert;
    assert(decoder._bufferLength == 2);

    /** 2 -> 3 **/
    decoder.decode("J", error).resultAssert;
    assert(decoder._bufferLength == 3);

    /** 3 -> 0 **/
    decoder.decode("j", check).resultAssert;
    assert(decoder._bufferLength == 0);
    assert(lambdaCalled == 1);

    /** 3 -> 1 **/
    decoder.decode("YWJ", error).resultAssert;
    assert(decoder._bufferLength == 3);

    decoder.decode("jY", check).resultAssert;
    assert(decoder._bufferLength == 1);
    assert(lambdaCalled == 2);
}

@("Base64Decoder - correctly handling partial groups with finish - Padding.required")
unittest
{
    enum Error { _ }
    alias Alphabet = Base64Alphabet!(
        '+',                    '/', 
        Base64Padding.required, '=',
        Base64AllowLines.no,    "", 0
    );

    auto decoder = Base64Decoder!Alphabet();
    decoder.decode("YW=", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.padding);
    assert(
        decoder.finish((scope const ubyte[] _) { assert(false); })
        .isError(Base64Error.invalidPadding)
    );
}

@("Base64Decoder - correctly handling partial groups with finish - Padding.optionalXXX")
unittest
{
    enum Error { _ }
    alias Alphabet = Base64Alphabet!(
        '+',                            '/', 
        Base64Padding.optionalPrefer,   '=',
        Base64AllowLines.no,            "", 0
    );

    // Implicit padding (3)
    auto decoder = Base64Decoder!Alphabet();
    decoder.decode("Y", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.buffer);
    assert(
        decoder.finish((scope const ubyte[] bytes) { return Result.noError; })
            .isError(Base64Error.notEnoughInput)
    );

    // Explicit padding (2)
    decoder = Base64Decoder!Alphabet();
    decoder.decode("YW==", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.padding);
    decoder.finish((scope const ubyte[] bytes) {
        assert(bytes == ['a']);
        return Result.noError; 
    }).resultAssert;

    // Implicit padding (2)
    decoder = Base64Decoder!Alphabet();
    decoder.decode("YW=", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.padding);
    decoder.finish((scope const ubyte[] bytes) {
        assert(bytes == ['a']);
        return Result.noError; 
    }).resultAssert;

    // Explicit padding (1)
    decoder = Base64Decoder!Alphabet();
    decoder.decode("YWJ=", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.padding);
    decoder.finish((scope const ubyte[] bytes) {
        assert(bytes == ['a', 'b']);
        return Result.noError; 
    }).resultAssert;

    // Implicit padding (1)
    decoder = Base64Decoder!Alphabet();
    decoder.decode("YWJ", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.buffer);
    decoder.finish((scope const ubyte[] bytes) {
        assert(bytes == ['a', 'b']);
        return Result.noError; 
    }).resultAssert;
}

@("Base64Decoder - correctly handling partial groups with finish - Padding.none")
unittest
{
    enum Error { _ }
    alias Alphabet = Base64Alphabet!(
        '+',                    '/', 
        Base64Padding.none,     '=',
        Base64AllowLines.no,    "", 0
    );

    auto decoder = Base64Decoder!Alphabet();
    decoder.decode("YWJ", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.buffer);
    assert(
        decoder.finish((scope const ubyte[] _) { return Result.noError; })
            .isError(Base64Error.notEnoughInput)
    );
}

@("Base64Decoder - correctly handling partial groups with finish - AllowLines")
unittest
{
    enum Error { _ }
    alias Alphabet = Base64Alphabet!(
        '+',                    '/', 
        Base64Padding.none,     '=',
        Base64AllowLines.yes,   "\r\n", 4
    );

    auto decoder = Base64Decoder!Alphabet();
    decoder.decode("\r", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.newLine);
    assert(
        decoder.finish((scope const ubyte[] _) { return Result.noError; })
            .isError(Base64Error.invalidNewLine)
    );
}

@("Base64Decoder - correctly handle new lines")
unittest
{
    enum Error { _ }
    alias Alphabet = Base64Alphabet!(
        '+',                            '/', 
        Base64Padding.optionalPrefer,   '=',
        Base64AllowLines.yes,           "\r\n", 4
    );

    int lambdaCalled;

    auto decoder = Base64Decoder!Alphabet();
    decoder.decode("YWJj\r\nYWJj\r\nYWJj", (scope const ubyte[] bytes) {
        lambdaCalled++;
        assert(bytes == ['a', 'b', 'c']);
        return Result.noError;
    }).resultAssert;
    assert(lambdaCalled == 3);

    decoder = Base64Decoder!Alphabet();
    decoder.decode("Y\r\nW\r\nJ\r\nj", (scope const ubyte[] bytes) {
        lambdaCalled++;
        assert(bytes == ['a', 'b', 'c']);
        return Result.noError;
    }).resultAssert;
    assert(lambdaCalled == 4);

    decoder = Base64Decoder!Alphabet();
    assert(
        decoder.decode("YW\rJj", (scope const ubyte[] _) => Result.make(Error._))
            .isError(Base64Error.invalidNewLine)
    );

    decoder = Base64Decoder!Alphabet();
    assert(
        decoder.decode("YWJjYWJj", (scope const ubyte[] _) => Result.noError)
            .isError(Base64Error.invalidNewLine)
    );

    decoder = Base64Decoder!Alphabet();
    decoder.decode("YW=\r", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder._state.mustBeIn(decoder.State.newLineMidPadding);
    decoder.decode("\n=", (scope const ubyte[] _) => Result.make(Error._)).resultAssert;
    decoder.finish((scope const ubyte[] bytes) {
        lambdaCalled++;
        assert(bytes == ['a']);
        return Result.noError; 
    }).resultAssert;
    assert(lambdaCalled == 5);
}

@("Base64Decoder - example")
unittest
{
    string result;
    scope append = (scope const ubyte[] bytes){
        result ~= cast(string)bytes;
        return Result.noError;
    };

    auto decoder = Base64Decoder!Base64Rfc4648Alphabet();
    decoder.decode("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu", append).resultAssert;
    decoder.finish(append).resultAssert;

    assert(result == "Many hands make light work.");
}
