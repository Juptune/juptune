/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.pem;

import juptune.core.util : Result;

enum PemError
{
    none,

    eof,
    invalidStartBoundary,
    invalidEndBoundary,
    invalidBase64Line,
    labelMismatch,
}

struct PemParser
{
    private
    {
        const(char)[] _input;
        size_t _cursor;
    }

    @disable this(this);

    this(const(char)[] input) @nogc nothrow
    {
        this._input = input;
    }

    Result parseNext(
        scope Result delegate(const(char)[] label) @nogc nothrow onStart,
        scope Result delegate(scope const(ubyte)[] data) @nogc nothrow onData,
        scope Result delegate() @nogc nothrow onEnd,
    ) @nogc nothrow
        => this.parseNextImpl(onStart, onData, onEnd);

    /// ditto
    Result parseNextGC(
        scope Result delegate(const(char)[] label) onStart,
        scope Result delegate(scope const(ubyte)[] data) onData,
        scope Result delegate() onEnd,
    )
        => this.parseNextImpl(onStart, onData, onEnd);

    private Result parseNextImpl(OnStartT, OnDataT, OnEndT)(
        scope OnStartT onStart,
        scope OnDataT onData,
        scope OnEndT onEnd,
    )
    in(onStart !is null, "onStart is null")
    in(onData !is null, "onData is null")
    in(onEnd !is null, "onEnd is null")
    {
        import juptune.data.base : Base64Decoder, Base64Rfc4648Alphabet;

        while(!this.eof && this._input[this._cursor] != '-')
        {
            While: while(!this.eof)
            {
                const ch = this._input[this._cursor];
                switch(ch)
                {
                    case '\n', '\r':
                        this.eatNewLine();
                        break While;

                    default:
                        this._cursor++;
                        break;
                }
            }
        }

        const(char)[] label;
        auto result = this.readDataBoundaryLine!("-----BEGIN ", PemError.invalidStartBoundary, true)(label);
        if(result.isError)
            return result;

        result = onStart(label);
        if(result.isError)
            return result;

        For: for(; this._cursor < this._input.length; this._cursor++)
        {
            switch(this._input[this._cursor])
            {
                case ' ', '\t', '\n', '\v', '\r': break;
                default: break For;
            }
        }

        Base64Decoder!Base64Rfc4648Alphabet decoder;
        while(true)
        {
            if(this.eof)
                return Result.make(PemError.eof, "Hit EOF when trying to read next base64 line");

            if(this._input[this._cursor] == '-')
                break;

            const(char)[] line;
            result = this.nextLine(line);
            if(result.isError)
                return result;

            result = decoder.decode(line, onData);
            if(result.isError)
                return result;
        }

        const(char)[] endLabel;
        result = this.readDataBoundaryLine!("-----END ", PemError.invalidEndBoundary, false)(endLabel);
        if(result.isError)
            return result;
        if(endLabel != label)
            return Result.make(PemError.labelMismatch, "Start and End boundary labels are different");

        result = decoder.finish(onData);
        if(result.isError)
            return result;

        return onEnd();
    }

    bool eof() @nogc nothrow const => this._cursor >= this._input.length;
    
    size_t charsLeft() @nogc nothrow const
    in(this._cursor <= this._input.length)
        => this._input.length - this._cursor;

    private Result nextLine(out scope const(char)[] line) @nogc nothrow
    {
        const start = this._cursor;
        foreach(i; 0..65)
        {
            if(this.eof)
                return Result.make(PemError.eof, "Hit EOF when trying to read next base64 line");

            const ch = this._input[this._cursor];
            if(ch == '\n' || ch == '\r')
                break;
            this._cursor++;

            if(i == 64)
                return Result.make(PemError.invalidBase64Line, "Expected new line after 64 chars of base64 data");
        }
        const end = this._cursor;

        const foundNewLine = this.eatNewLine();
        if(!foundNewLine)
            return Result.make(PemError.invalidBase64Line, "Expected new line after base64 data - (I'm not sure this can even trigger?)"); // @suppress(dscanner.style.long_line)

        line = this._input[start..end];
        return Result.noError;
    }

    private Result readDataBoundaryLine(
        string prefix, 
        PemError invalidError,
        bool expectNewLine,
    )(out scope const(char)[] label)
    {
        import std.conv : to;
        enum prefixLength = prefix.length.to!string;

        if(this.charsLeft < prefix.length)
            return Result.make(PemError.eof, "Expected at least "~prefixLength~" chars left when reading data boundary"); // @suppress(dscanner.style.long_line)
        if(this._input[this._cursor..this._cursor+prefix.length] != prefix)
            return Result.make(invalidError, "Data boundary does not begin with '"~prefix~"'"); // @suppress(dscanner.style.long_line)
        this._cursor += prefix.length;

        const labelStart = this._cursor;
        bool foundEnd;
        For: for(; this._cursor < this._input.length; this._cursor++)
        {
            switch(this._input[this._cursor])
            {
                case '-':
                    if(this.charsLeft >= 2 && this._input[this._cursor+1] != '-')
                        break;
                    if(this._input[this._cursor-1] == '-')
                        return Result.make(invalidError, "Data boundary labels cannot contain consecutive hyphens");

                    if(this.charsLeft >= 5)
                    {
                        if(this._input[this._cursor..this._cursor+5] != "-----")
                            return Result.make(invalidError, "Expected 5 hyphens to end data boundary label");

                        label = this._input[labelStart..this._cursor];
                        this._cursor += 5;
                        foundEnd = true;
                        break For;
                    }
                    break;

                case ' ':
                    if(this._input[this._cursor-1] == ' ')
                        return Result.make(invalidError, "Data boundary labels cannot contain consecutive spaces");
                    break;
                
                case 'a':..case 'z':
                case 'A':..case 'Z':
                case '0':..case '9':
                    break;

                default:
                    return Result.make(
                        invalidError,
                        "Encountered a character that isn't alphanumeric or whitespace when reading data boundary label"
                    );
            }
        }

        if(!foundEnd)
            return Result.make(PemError.eof, "Hit EOF when reading data boundary");

        const foundNewLine = this.eatNewLine();
        if(expectNewLine && !foundNewLine)
            return Result.make(invalidError, "Expected new line after data boundary start");

        return Result.noError;
    }

    private bool eatNewLine() @nogc nothrow
    {
        if(this.eof)
            return false;

        switch(this._input[this._cursor])
        {
            case '\n':
                this._cursor++;
                return true;

            case '\r':
                if(this.charsLeft >= 2 && this._input[this._cursor + 1] == '\n')
                    this._cursor += 2;
                else
                    this._cursor++;
                return true;

            default: return false;
        }
    }
}
///
unittest
{
    import juptune.core.util : resultAssertSameCode, resultAssert;
    import std.typecons : Nullable;

    static struct T
    {
        string input;
        string label;
        string expected;
        Nullable!PemError error;

        this(string label, string expected, string input)
        {
            this.input = input;
            this.label = label;
            this.expected = expected;
        }

        this(PemError error, string input)
        {
            this.input = input;
            this.error = error;
        }
    }

    T[string] testCases = [
        "Hello, World!": T(
            "HELLO WORLD",
            "Hello, World!",
`-----BEGIN HELLO WORLD-----
SGVsbG8sIFdvcmxkIQ==
-----END HELLO WORLD-----
`
        ),
        
        "Multiline data": T(
            "MULTILINE",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
`-----BEGIN MULTILINE-----
YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh
YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh
YWFhYWFhYWE=
-----END MULTILINE-----`,
        ),

        "Empty data": T(
            "EMPTY",
            "",
            "-----BEGIN EMPTY-----\n\n-----END EMPTY-----"
        ),

        "Empty label": T(
            "",
            "",
            "-----BEGIN -----\n\n-----END -----"
        ),

        "error - label mismatch": T(
            PemError.labelMismatch,
            "-----BEGIN A-----\n\n-----END B-----"
        ),
        "error - invalid label char": T(
            PemError.invalidStartBoundary,
            "-----BEGIN \0-----\n\n-----END -----"
        ),
        "error - invalid label char (end)": T(
            PemError.invalidEndBoundary,
            "-----BEGIN -----\n\n-----END \0-----"
        ),
        "error - eof in start boundary": T(
            PemError.eof,
            "-----BEGIN "
        ),
        "error - eof in data": T(
            PemError.eof,
            "-----BEGIN -----\n"
        ),
        "error - eof in end boundary": T(
            PemError.eof,
            "-----BEGIN -----\n\n-----END "
        ),
        "error - double spaces": T(
            PemError.invalidStartBoundary,
            "-----BEGIN  -----\n\n-----END ----"
        ),
        "error - double hyphens": T(
            PemError.invalidStartBoundary,
            "-----BEGIN A--B-----\n\n-----END ----"
        ),
    ];

    foreach(name, test; testCases)
    {
        try
        {
            auto parser = PemParser(test.input);
            
            string label;
            string got;
            auto result = parser.parseNextGC(
                onStart: (lab){ label = lab.idup; return Result.noError; },
                onData: (scope data){ got ~= cast(char[])data; return Result.noError; },
                onEnd: () => Result.noError,
            );

            if(test.error.isNull)
            {
                resultAssert(result);
                assert(label == test.label, "Expected label '"~test.label~"' but got label '"~label~"'");
                assert(got == test.expected, "Expected output '"~test.expected~"' but got output '"~got~"'");
            }
            else
                resultAssertSameCode!PemError(result, Result.make(test.error.get));
        }
        catch(Exception ex)
            assert(false, "["~name~"] "~ex.msg);
    }
}