/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.lexer;

import juptune.data.asn1.lang.common : Asn1Location;

struct Asn1Token
{
    private static struct Compound { string chars; Type type; }
    private static struct Singular { char ch; Type type; }

    private static immutable COMPOUND_OPS = [
        // NOTE: Keep in order by chars length.
        // NOTE: Unittests are automatically generated.
        Compound("::=", Type.assignment),
        Compound("...", Type.ellipsis),
        Compound("..", Type.rangeSeparator),
        Compound("[[", Type.leftVersionBrackets),
        Compound("]]", Type.rightVersionBrackets),
    ];

    private static immutable SINGULAR_OPS = [
        // NOTE: Unittests are automatically generated.
        Singular('{', Type.leftBracket),
        Singular('}', Type.rightBracket),
        Singular('<', Type.leftArrow),
        Singular('>', Type.rightArrow),
        Singular(',', Type.comma),
        Singular('.', Type.dot),
        Singular('(', Type.leftParenthesis),
        Singular(')', Type.rightParenthesis),
        Singular('[', Type.leftSquare),
        Singular(']', Type.rightSquare),
        Singular('-', Type.hyphenMinus),
        Singular(':', Type.colon),
        Singular(';', Type.semicolon),
        Singular('@', Type.at),
        Singular('|', Type.pipe),
        Singular('!', Type.exclamation),
        Singular('^', Type.toBach), // I don't actually know what we call this in English... so Welsh it is.
        Singular('*', Type.asterisk), // Oddity: Not defined as a lexical token, yet is used within productions?
    ];

    private static immutable RESERVED_WORDS = [
        // NOTE: Unittests are automatically generated.
        "ABSENT": Type.rABSENT,
        "ABSTRACT-SYNTAX": Type.rABSTRACT_SYNTAX,
        "ALL": Type.rALL,
        "APPLICATION": Type.rAPPLICATION,
        "AUTOMATIC": Type.rAUTOMATIC,
        "BEGIN": Type.rBEGIN,
        "BIT": Type.rBIT,
        "BMPString": Type.rBMPString,
        "BOOLEAN": Type.rBOOLEAN,
        "BY": Type.rBY,
        "CHARACTER": Type.rCHARACTER,
        "CHOICE": Type.rCHOICE,
        "CLASS": Type.rCLASS,
        "COMPONENT": Type.rCOMPONENT,
        "COMPONENTS": Type.rCOMPONENTS,
        "CONSTRAINED": Type.rCONSTRAINED,
        "CONTAINING": Type.rCONTAINING,
        "DEFAULT": Type.rDEFAULT,
        "DEFINITIONS": Type.rDEFINITIONS,
        "EMBEDDED": Type.rEMBEDDED,
        "ENCODED": Type.rENCODED,
        "END": Type.rEND,
        "ENUMERATED": Type.rENUMERATED,
        "EXCEPT": Type.rEXCEPT,
        "EXPLICIT": Type.rEXPLICIT,
        "EXPORTS": Type.rEXPORTS,
        "EXTENSIBILITY": Type.rEXTENSIBILITY,
        "EXTERNAL": Type.rEXTERNAL,
        "FALSE": Type.rFALSE,
        "FROM": Type.rFROM,
        "GeneralizedTime": Type.rGeneralizedTime,
        "GeneralString": Type.rGeneralString,
        "GraphicString": Type.rGraphicString,
        "IA5String": Type.rIA5String,
        "IDENTIFIER": Type.rIDENTIFIER,
        "IMPLICIT": Type.rIMPLICIT,
        "IMPLIED": Type.rIMPLIED,
        "IMPORTS": Type.rIMPORTS,
        "INCLUDES": Type.rINCLUDES,
        "INSTANCE": Type.rINSTANCE,
        "INTEGER": Type.rINTEGER,
        "INTERSECTION": Type.rINTERSECTION,
        "ISO646String": Type.rISO646String,
        "MAX": Type.rMAX,
        "MIN": Type.rMIN,
        "MINUS-INFINITY": Type.rMINUS_INFINITY,
        "NULL": Type.rNULL,
        "NumericString": Type.rNumericString,
        "OBJECT": Type.rOBJECT,
        "ObjectDescriptor": Type.rObjectDescriptor,
        "OCTET": Type.rOCTET,
        "OF": Type.rOF,
        "OPTIONAL": Type.rOPTIONAL,
        "PATTERN": Type.rPATTERN,
        "PDV": Type.rPDV,
        "PLUS-INFINITY": Type.rPLUS_INFINITY,
        "PRESENT": Type.rPRESENT,
        "PrintableString": Type.rPrintableString,
        "PRIVATE": Type.rPRIVATE,
        "REAL": Type.rREAL,
        "RELATIVE-OID": Type.rRELATIVE_OID,
        "SEQUENCE": Type.rSEQUENCE,
        "SET": Type.rSET,
        "SIZE": Type.rSIZE,
        "STRING": Type.rSTRING,
        "SYNTAX": Type.rSYNTAX,
        "T61String": Type.rT61String,
        "TAGS": Type.rTAGS,
        "TeletexString": Type.rTeletexString,
        "TRUE": Type.rTRUE,
        "TYPE-INDENTIFIER": Type.rTYPE_INDENTIFIER,
        "UNION": Type.rUNION,
        "UNIQUE": Type.rUNIQUE,
        "UNIVERSAL": Type.rUNIVERSAL,
        "UniversalString": Type.rUniversalString,
        "UTCTime": Type.rUTCTime,
        "UTF8String": Type.rUTF8String,
        "VideotexString": Type.rVideotexString,
        "VisibleString": Type.rVisibleString,
        "WITH": Type.rWITH,
    ];

    enum Type
    {
        FAILSAFE,
        eof,

        identifier,
        typeReference,

        number,
        realNumber,

        whiteSpace,
        oneLineComment,
        multiLineComment,

        // Compound operators
        assignment,
        rangeSeparator,
        ellipsis,
        leftVersionBrackets,
        rightVersionBrackets,

        // Single character operators
        leftBracket,
        rightBracket,
        leftArrow,
        rightArrow,
        comma,
        dot,
        leftParenthesis,
        rightParenthesis,
        leftSquare,
        rightSquare,
        hyphenMinus,
        colon,
        quotationMark,
        apostrophe,
        semicolon,
        at,
        pipe,
        exclamation,
        toBach,
        asterisk,

        // NOTE: For all string types, the starting quote, ending quote, and any type info attached to the ending quote,
        //       will all be preserved within `text`. You may want to use `asSubString.slice` to strip this off.
        bstring,
        hstring,
        cstring,

        // Reserved words - helpful to mark them early rather than doing a bunch of string compares later.
        // 'r' prefix means "reserved", naming matches ASN.1 notation syntax rather than Juptune's naming scheme.
        // 11.27 ISO/IEC 8824-1:2003
        rABSENT,
        rABSTRACT_SYNTAX,
        rALL,
        rAPPLICATION,
        rAUTOMATIC,
        rBEGIN,
        rBIT,
        rBMPString,
        rBOOLEAN,
        rBY,
        rCHARACTER,
        rCHOICE,
        rCLASS,
        rCOMPONENT,
        rCOMPONENTS,
        rCONSTRAINED,
        rCONTAINING,
        rDEFAULT,
        rDEFINITIONS,
        rEMBEDDED,
        rENCODED,
        rEND,
        rENUMERATED,
        rEXCEPT,
        rEXPLICIT,
        rEXPORTS,
        rEXTENSIBILITY,
        rEXTERNAL,
        rFALSE,
        rFROM,
        rGeneralizedTime,
        rGeneralString,
        rGraphicString,
        rIA5String,
        rIDENTIFIER,
        rIMPLICIT,
        rIMPLIED,
        rIMPORTS,
        rINCLUDES,
        rINSTANCE,
        rINTEGER,
        rINTERSECTION,
        rISO646String,
        rMAX,
        rMIN,
        rMINUS_INFINITY,
        rNULL,
        rNumericString,
        rOBJECT,
        rObjectDescriptor,
        rOCTET,
        rOF,
        rOPTIONAL,
        rPATTERN,
        rPDV,
        rPLUS_INFINITY,
        rPRESENT,
        rPrintableString,
        rPRIVATE,
        rREAL,
        rRELATIVE_OID,
        rSEQUENCE,
        rSET,
        rSIZE,
        rSTRING,
        rSYNTAX,
        rT61String,
        rTAGS,
        rTeletexString,
        rTRUE,
        rTYPE_INDENTIFIER,
        rUNION,
        rUNIQUE,
        rUNIVERSAL,
        rUniversalString,
        rUTCTime,
        rUTF8String,
        rVideotexString,
        rVisibleString,
        rWITH,

        // Aliases
        valueReference = identifier,
        moduleReference = typeReference,
        objectReference = valueReference,
        objectSetReference = typeReference,
        todo,
    }

    static struct Number
    {
        // The spec is a little confusing - I think negative numbers are supposed to be constructed during syntax analysis
        // from seeing HYPHEN-MINUS and NUMBER together?
        //
        // Hence why this is always unsigned.
        private ulong _value;
        bool canFitNatively;

        ulong value() @safe @nogc nothrow pure const
        in(this.canFitNatively, "cannot call value() when canFitNatively is false, please add a check!")
        {
            return this._value;
        }
    }

    static struct Real
    {
        ulong integer;
        ulong fraction;
        ulong exponent;
    }

    static struct SubString
    {
        const(char)[] slice;
    }

    static union InnerValue
    {
        Number asNumber;
        Real asReal;
        SubString asSubString;
    }

    Type type;
    Asn1Location location;
    const(char)[] text;
    InnerValue value;

    version(unittest) this(Type type, string text, size_t start, size_t end, InnerValue value = InnerValue.init)
    {
        this.type = type;
        this.text = text;
        this.location.start = start;
        this.location.end = end;
        this.value = value;
    }

    version(unittest) this(Type type, string text, size_t start, size_t end, Real value)
    {
        this.type = type;
        this.text = text;
        this.location.start = start;
        this.location.end = end;
        this.value.asReal = value;
    }

    version(unittest) this(Type type, string text, size_t start, size_t end, SubString value)
    {
        this.type = type;
        this.text = text;
        this.location.start = start;
        this.location.end = end;
        this.value.asSubString = value;
    }
    
    version(unittest) bool opEquals(const typeof(this) other)
    {
        if(!this.type == other.type)
            return false;

        switch(this.type) with(Type)
        {
            case number:
                if(this.asNumber != other.asNumber)
                    return false;
                break;

            case realNumber:
                if(this.asReal != other.asReal)
                    return false;
                break;

            case bstring:
            case hstring:
            case cstring:
                if(this.asSubString != other.asSubString)
                    return false;
                break;

            default: break;
        }

        return this.text == other.text && this.location == other.location;
    }

    Number asNumber() @trusted @nogc nothrow pure const
    in(this.type == Type.number, "cannot call asNumber when token's type is not number")
    {
        return this.value.asNumber;
    }

    Real asReal() @trusted @nogc nothrow pure const
    in(this.type == Type.realNumber, "cannot call asReal when token's type is not realNumber")
    {
        return this.value.asReal;
    }

    SubString asSubString() @trusted @nogc nothrow pure const
    in(
        this.type == Type.bstring || this.type == Type.hstring || this.type == Type.cstring, 
        "cannot call asSubString when token's type is not bstring, hstring, or cstring"
    )
    {
        return this.value.asSubString;
    }

    Asn1BstringRange asBstringRange() @safe @nogc nothrow
    in(this.type == Type.bstring, "cannot call asBstringRange when token's type is not bstring")
    {
        return Asn1BstringRange(this.asSubString.slice);
    }

    Asn1HstringRange asHstringRange() @safe @nogc nothrow
    in(this.type == Type.hstring, "cannot call asHstringRange when token's type is not hstring")
    {
        return Asn1HstringRange(this.asSubString.slice);
    }

    static string suggestionForType(Type type) @safe @nogc nothrow
    {
        final switch(type) with(Type)
        {
            case FAILSAFE: assert(false, "bug: attempted to use FAILSAFE");
            case eof: return "EOF";

            case identifier: return "my-identifier";
            case typeReference: return "My-Type-Reference";
            case number: return "12345";
            case realNumber: return "3.14";
            case whiteSpace: return "\\t";
            case oneLineComment: return "-- comment";
            case multiLineComment: return "/* comment */";
            case quotationMark: return "\"";
            case apostrophe: return "'";
            case bstring: return "'1010'B";
            case hstring: return "'F00'H";
            case cstring: return "'Foo'";

            static foreach(name, value; RESERVED_WORDS)
            {
                case value: return name;
            }

            static foreach(name, value; SINGULAR_OPS)
            {
                case value.type:
                    enum Str = ""~value.ch;
                    return Str;
            }

            static foreach(name, value; COMPOUND_OPS)
            {
                case value.type: return value.chars;
            }
        }
    }
}

enum Asn1LexerError
{
    none,

    invalidCharacter,
    eof,

    identifierEndsWithHyphen,

    integerStartsWithZero,
    
    stringHasUnknownType,
    bstringHasInvalidChars,
    hstringHasInvalidChars,
}

struct Asn1Lexer
{
    import std.typecons : Flag;
    import juptune.core.util : Result;
    import juptune.data.alphabet : AsciiAlphabet;
    
    static immutable Alphabet           = AsciiAlphabet!"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"&'()*,-./:;<=>@[]^_{|}\t\n\v\f\r "(); // @suppress(dscanner.style.long_line)
    static immutable IdentifierAlphabet = AsciiAlphabet!"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"(); // @suppress(dscanner.style.long_line)
    static immutable WhiteSpace         = AsciiAlphabet!"\t\n\v\f\r "(); // NOTE: Is a superset of NewLine, so we only need to check this one
    static immutable NewLine            = AsciiAlphabet!"\n\v\f\r"();
    static immutable BitStringAlphabet  = AsciiAlphabet!"\t\n\v\f\r 01"();
    static immutable HexStringAlphabet  = AsciiAlphabet!"\t\n\v\f\r 0123456789ABCDEF"();

    enum MAX_LOOKAHEAD = 3;

    private alias AllowEof = Flag!"allowEof";

    private
    {
        const(char)[] _input;
        size_t _cursor;
        ulong _tokensRead;

        Asn1Token[MAX_LOOKAHEAD] _lookahead;
        size_t _lookaheadCursor;
    }

    @nogc nothrow:

    this(const(char)[] input)
    in(input.length < size_t.max - 1, "To help avoid overflow errors, the input is not allowed to be size_t.max long")
    {
        this._input = input;
    }

    Result lookahead(size_t offset, scope out Asn1Token token)
    in(offset < MAX_LOOKAHEAD, "offset is too high")
    {
        if(offset < this._lookaheadCursor)
        {
            token = this._lookahead[offset];
            return Result.noError;
        }

        while(this._lookaheadCursor <= offset)
        {
            auto result = this.lexNext(token);
            if(result.isError)
                return result;

            this._lookahead[this._lookaheadCursor++] = token;
        }

        // token should now be set by the while loop.
        return Result.noError;
    }

    Result next(scope out Asn1Token token)
    {
        if(this._lookaheadCursor > 0)
        {
            this._lookaheadCursor--;
            token = this._lookahead[0];
            foreach(i, tok; this._lookahead[1..$])
                this._lookahead[i] = tok;
            return Result.noError;
        }

        return this.lexNext(token);
    }

    size_t cursor()
    {
        return this._cursor;
    }

    ulong tokensRead()
    {
        return this._tokensRead;
    }

    /**** Lex functions ****/

    private Result lexNext(scope out Asn1Token token)
    {
        import std.ascii : isAlpha, isDigit;
        import juptune.core.ds : String2, Array;
    
        if(this.eof)
        {
            token = this.makeToken(Asn1Location(this._cursor, this._cursor), Asn1Token.Type.eof);
            return Result.noError;
        }
        this._tokensRead++;

        const left = this.charsLeft;
        const ch0 = this.peekAt(0);
        const ch1 = (left > 1) ? this.peekAt(1) : char.init;

        if(WhiteSpace.isAllowed(ch0))
            return this.lexNextWhiteSpace(token);
        else if(ch0.isAlpha && IdentifierAlphabet.isAllowed(ch0))
            return this.lexNextIdentifier(token);
        else if(left >= 2 && ch0 == '-' && ch1 == '-')
            return this.lexNextSingleComment(token);
        else if(left >= 2 && ch0 == '/' && ch1 == '*')
            return this.lexNextMultiComment(token);
        else if(ch0.isDigit)
            return this.lexNextNumber(token);
        else if(ch0 == '\'')
            return this.lexNextTypedString(token);
        else if(ch0 == '"')
            return this.lexNextCharString(token);
        else if(this.tryLexNextCompoundOperator(token))
            return Result.noError;
        else if(this.tryLexNextSingularOperator(token))
            return Result.noError;

        this._tokensRead--;
        
        Array!char context;
        this.buildError(context, Asn1Location(this._cursor));
        return Result.make(Asn1LexerError.invalidCharacter, "Invalid character found - it's not the start character for any known token", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
    }

    private Result lexNextWhiteSpace(scope ref Asn1Token token)
    {
        Asn1Location location;

        auto whiteSpaceResult = this.readUntil!((ch) => !WhiteSpace.isAllowed(ch), "When reading in white space")(this, location, AllowEof.yes); // @suppress(dscanner.style.long_line)
        if(whiteSpaceResult.isError)
            return whiteSpaceResult;

        token = this.makeToken(location, Asn1Token.Type.whiteSpace);
        return Result.noError;
    }

    private Result lexNextIdentifier(scope ref Asn1Token token)
    {
        import std.ascii : isUpper;
        import juptune.core.ds : String2, Array;

        Asn1Location location;
        auto result = this.readUntil!(
            (ch) => !IdentifierAlphabet.isAllowed(ch), "only letter; digits, and hyphens can be used in identifiers/typeReferences - 11.2.1 & 11.3 ISO/IEC 8824-1:2003" // @suppress(dscanner.style.long_line)
        )(this, location, AllowEof.yes); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        if(this._input[location.end-1] == '-')
        {
            Array!char context;
            this.buildError(context, location);
            return Result.make(Asn1LexerError.identifierEndsWithHyphen, "Identifiers/typeReferences cannot end with a hyphen - 11.2.1 & 11.3 ISO/IEC 8824-1:2003", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
        }

        const text = this._input[location.start..location.end];
        const reserved = ((cast(string)text) in Asn1Token.RESERVED_WORDS); // Should be @safe still, the lookup shouldn't preserve token.text in any way.
        token = this.makeToken(
            location, 
            (reserved !is null)
                ? *reserved
                : (this._input[location.start].isUpper) 
                    ? Asn1Token.Type.typeReference 
                    : Asn1Token.Type.identifier
        );

        return Result.noError;
    }

    private Result lexNextSingleComment(scope ref Asn1Token token)
    in(this.charsLeft >= 2 && this.peekAt(0) == '-' && this.peekAt(1) == '-')
    {
        // Comments have different enough logic that readUntil is too hard to use.

        Asn1Location location;
        location.start = this._cursor;
        this.advance(2); // Skip --

        while(!this.eof)
        {
            if(NewLine.isAllowed(this.peekAt(0)))
            {
                this.advance(1);
                break;
            }

            if(this.peekAt(0) != '-' || this.charsLeft < 2)
            {
                this.advance(1);
                continue;
            }

            if(this.peekAt(1) != '-')
            {
                this.advance(1);
                continue;
            }

            this.advance(2); // Skip --
            break;
        }

        location.end = this._cursor;
        token = this.makeToken(location, Asn1Token.Type.oneLineComment);
        return Result.noError;
    }

    private Result lexNextMultiComment(scope ref Asn1Token token)
    in(this.charsLeft >= 2 && this.peekAt(0) == '/' && this.peekAt(1) == '*')
    {
        import juptune.core.ds : String2, Array;
        // Comments have different enough logic that readUntil is too hard to use.

        Asn1Location location;
        location.start = this._cursor;
        this.advance(2); // Skip /*

        size_t nestLevel = 1; // size_t to make overflows a non-issue.

        while(!this.eof)
        {
            if(this.charsLeft < 2)
            {
                this.advance(1);
                continue;
            }

            if(this.peekAt(0) == '*' && this.peekAt(1) == '/')
            {
                nestLevel--;
                this.advance(2); // */

                if(nestLevel == 0)
                {
                    location.end = this._cursor;
                    token = this.makeToken(location, Asn1Token.Type.multiLineComment);
                    return Result.noError;
                }

                continue;
            }

            if(this.peekAt(0) == '/' && this.peekAt(1) == '*')
            {
                this.advance(2); // /*
                nestLevel++;
                continue;
            }

            this.advance(1);
        }

        Array!char context;
        this.buildError(context, Asn1Location(this._cursor));
        return Result.make(Asn1LexerError.eof, "Unterminated multi-line comment - unlike single-line comments, multi-line comments MUST be terminated - 11.6.4 ISO/IEC 8824-1:2003", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
    }

    private Result lexNextNumber(scope ref Asn1Token token)
    {
        import std.ascii       : isDigit;
        import juptune.core.ds : String2, Array;

        Asn1Location location;
        location.start = this._cursor;

        while(!this.eof)
        {
            const ch = this.peekAt(0);
            if(!ch.isDigit)
                break;
            this.advance(1);
        }
        const integerPart = Asn1Location(location.start, this._cursor);
        Asn1Location fractionalPart, exponentPart;
        bool isReal = false;

        if(!this.eof)
        {
            if(this.peekAt(0) == '.' && (this.charsLeft <= 1 || this.peekAt(1) != '.'))
            {
                this.advance(1); // Skip .
                isReal = true;
                
                fractionalPart.start = this._cursor;
                while(!this.eof)
                {
                    const ch = this.peekAt(0);
                    if(!ch.isDigit)
                        break;
                    this.advance(1);
                }
                fractionalPart.end = this._cursor;
            }

            if(!this.eof && (this.peekAt(0) == 'e' || this.peekAt(0) == 'E'))
            {
                this.advance(1); // Skip E
                isReal = true;
                
                exponentPart.start = this._cursor;
                while(!this.eof)
                {
                    const ch = this.peekAt(0);
                    if(!ch.isDigit)
                        break;
                    this.advance(1);
                }
                exponentPart.end = this._cursor;
            }
        }

        location.end = this._cursor;

        if(!isReal)
        {
            import juptune.core.util : fromBase10;
            token = this.makeToken(location, Asn1Token.Type.number);
        
            if(token.text.length > 1 && token.text[0] == '0')
            {
                Array!char context;
                this.buildError(context, location);
                return Result.make(Asn1LexerError.integerStartsWithZero, "Multi-digit integers cannot start with a 0 - 11.8 ISO/IEC 8824-1:2003", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
            }

            string error;
            token.value.asNumber._value = fromBase10!ulong(token.text, error);
            token.value.asNumber.canFitNatively = error.length == 0; // Kinda yucky since it doesn't account for non-overflow errors, but fromBase10 needs fixing to use Result >:(
        }
        else
        {
            import juptune.core.util : fromBase10;
            token = this.makeToken(location, Asn1Token.Type.realNumber);

            // TODO: Add error checking - I'm not bothering since I'm kind of brushing reals to the side for now

            // TODO: This needs to be a lot better - but real support in Juptune is too shoddy right now
            string error;
            token.value.asReal.integer = fromBase10!ulong(this._input[integerPart.start..integerPart.end], error);

            if(fractionalPart != Asn1Location.init)
                token.value.asReal.fraction = fromBase10!ulong(this._input[fractionalPart.start..fractionalPart.end], error); // @suppress(dscanner.style.long_line)
            
            if(exponentPart.start != exponentPart.end)
                token.value.asReal.exponent = fromBase10!ulong(this._input[exponentPart.start..exponentPart.end], error); // @suppress(dscanner.style.long_line)
            else
                token.value.asReal.exponent = 1;
        }

        return Result.noError;
    }

    private Result lexNextTypedString(scope ref Asn1Token token)
    in(this.charsLeft >= 1 && this.peekAt(0) == '\'')
    {
        import juptune.core.ds : String2, Array;
        /* Note: I'm not sure if typed strings can contain escape characters, so for now I'm avoiding readUntil */

        Asn1Location location;
        location.start = this._cursor;
        this.advance(1); // Skip start quote

        while(!this.eof)
        {
            // TODO: be wary of escape chars here? Need to find clarity on the syntax...
            const ch = this.peekAt(0);
            if(ch == '\'')
                break;
            this.advance(1);
        }

        if(this.eof)
        {
            Array!char context;
            this.buildError(context, Asn1Location(location.start, this._cursor));
            return Result.make(Asn1LexerError.eof, "Unterminated typed string, hit EOF before finding closing quote", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
        }

        this.advance(1); // Skip closing quote

        if(this.eof)
        {
            Array!char context;
            this.buildError(context, Asn1Location(this._cursor));
            return Result.make(Asn1LexerError.eof, "Invalid typed string, expected type character after closing quote (e.g. B, H), but found EOF", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
        }

        const type = this.peekAt(0);
        this.advance(1);
        location.end = this._cursor;

        token = this.makeToken(location, Asn1Token.Type.FAILSAFE);
        token.value.asSubString.slice = token.text[1..$-2];

        switch(type)
        {
            case 'B':
                return this.validateBitString(token);
            
            case 'H':
                return this.validateHexString(token);

            default:
                Array!char context;
                this.buildError(context, Asn1Location(this._cursor));
                return Result.make(Asn1LexerError.stringHasUnknownType, "Invalid typed string, unknown type character after closing quote", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
        }
    }

    private Result lexNextCharString(scope ref Asn1Token token)
    in(this.charsLeft >= 1 && this.peekAt(0) == '"')
    {
        import juptune.core.ds : String2, Array;
        /* Note: I'm not sure if typed strings can contain escape characters, so for now I'm avoiding readUntil */

        Asn1Location location;
        location.start = this._cursor;
        this.advance(1); // Skip start quote

        while(!this.eof)
        {
            const ch = this.peekAt(0);
            if(ch == '"')
            {
                if(this.charsLeft > 1 && this.peekAt(1) == '"') // Two quotes next to eachother == singular escaped quote
                {
                    this.advance(2);
                    continue;
                }
                break;
            }
            this.advance(1);
        }

        if(this.eof)
        {
            Array!char context;
            this.buildError(context, Asn1Location(this._cursor));
            return Result.make(Asn1LexerError.eof, "Unterminated character string, hit EOF before finding closing quote", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
        }

        this.advance(1); // Skip closing quote
        location.end = this._cursor;

        token = this.makeToken(location, Asn1Token.Type.cstring);
        token.value.asSubString.slice = token.text[1..$-1];

        return Result.noError; // Further error checks have to happen once a character set is known, i.e. not during lexing.
    }

    private bool tryLexNextCompoundOperator(scope ref Asn1Token token)
    {
        const left = this.charsLeft();
        char[3] chars = [
            this.peekAt(0),
            (left > 1) ? this.peekAt(1) : char.init,
            (left > 2) ? this.peekAt(2) : char.init,
        ];

        // Not the fastest implementation, but it should barely matter.
        static foreach(op; Asn1Token.COMPOUND_OPS)
        {
            if(left >= op.chars.length && chars[0..op.chars.length] == op.chars)
            {
                Asn1Location location;
                location.start = this._cursor;
                this.advance(op.chars.length);
                location.end = this._cursor;

                token = this.makeToken(location, op.type);
                return true;
            }
        }

        return false;
    }

    private bool tryLexNextSingularOperator(scope ref Asn1Token token)
    {
        const ch = this.peekAt(0);

        static foreach(op; Asn1Token.SINGULAR_OPS)
        {
            // NOTE: I want to use a switch statement, but switches and static foreach have historically caused me bugs.
            if(ch == op.ch)
            {
                Asn1Location location;
                location.start = this._cursor;
                this.advance(1);
                location.end = this._cursor;

                token = this.makeToken(location, op.type);
                return true;
            }
        }

        return false;
    }

    private Result validateBitString(scope ref Asn1Token token)
    {
        import juptune.core.ds : String2, Array;

        foreach(i, ch; token.value.asSubString.slice)
        {
            if(!BitStringAlphabet.isAllowed(ch))
            {
                Array!char context;
                this.buildError(context, Asn1Location(this._cursor),
                    "char: ", ch, " (base10 ", cast(int)ch, ") @ index ", i,
                );
                return Result.make(Asn1LexerError.bstringHasInvalidChars, "Bitstring contains an invalid character, only 0; 1, and white space is allowed - 11.10 ISO/IEC 8824-1:2003", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
            }
        }

        token.type = Asn1Token.Type.bstring;
        return Result.noError;
    }

    private Result validateHexString(scope ref Asn1Token token)
    {
        import juptune.core.ds : String2, Array;

        foreach(i, ch; token.value.asSubString.slice)
        {
            if(!HexStringAlphabet.isAllowed(ch))
            {
                Array!char context;
                this.buildError(context, Asn1Location(this._cursor),
                    "char: ", ch, " (base10 ", cast(int)ch, ") @ index ", i,
                );
                return Result.make(Asn1LexerError.hstringHasInvalidChars, "Hexstring contains an invalid character, only 0-9, A-F, and white space is allowed - 11.12 ISO/IEC 8824-1:2003", String2.fromDestroyingArray(context)); // @suppress(dscanner.style.long_line)
            }
        }

        token.type = Asn1Token.Type.hstring;
        return Result.noError;
    }

    /**** Input reading helpers ****/

    private bool eof() const pure
    {
        return this._cursor >= this._input.length;
    }

    private size_t charsLeft() const pure
    in(this._cursor <= this._input.length, "bug: cursor is greater than input length?")
    {
        return this._input.length - this._cursor;
    }

    private char peekAt(size_t offset) const pure
    in(this.charsLeft() > offset, "bug: attempted to peek past EOF")
    {
        return this._input[this._cursor + offset];
    }

    private void advance(size_t offset)
    in(this.charsLeft() >= offset, "bug: attempted to advance past EOF")
    {
        this._cursor += offset;
    }

    // Reads up to the next `Target` - cursor will be LEFT on the Target if found.
    // The compiler thinks it needs a dual context without being static... *sigh*
    private static Result readUntil(
        alias IsTarget,
        string ErrorContext,
        alias IsValidCharacter = (ch) => Alphabet.isAllowed(ch),
        string ValidCharacterError = "encountered character not considered part of ASN.1's character set - 10.1 ISO/IEC 8824-1:2003", // @suppress(dscanner.style.long_line)
    )(
        scope ref typeof(this) This,
        scope out Asn1Location range,
        AllowEof allowEof = AllowEof.no,
    )
    {
        import juptune.core.ds : String2, Array;

        range.start = This._cursor;
        while(!This.eof)
        {
            const ch = This.peekAt(0);
            if(IsTarget(ch))
            {
                range.end = This._cursor;
                assert(range.start != range.end, "bug: No characters were read, the caller likely missed a check");
                assert(range.start <= range.end, "bug: Start is greater than end?");
                return Result.noError;
            }

            if(!IsValidCharacter(ch))
            {
                Array!char context;
                This.buildError(context, range);

                enum Error = ErrorContext~" - "~ValidCharacterError;
                return Result.make(Asn1LexerError.invalidCharacter, Error, String2.fromDestroyingArray(context));
            }

            This.advance(1);
        }

        if(allowEof)
        {
            range.end = This._cursor;
            return Result.noError;
        }

        Array!char context;
        This.buildError(context, range);

        enum Error = ErrorContext~" - unexpected EOF";
        return Result.make(Asn1LexerError.eof, Error, String2.fromDestroyingArray(context));
    }

    /**** Other helpers ****/

    Result makeError(ErrorT, Args...)(
        ErrorT error,
        string message,
        const Asn1Location location, 
        scope const Args args,
    )
    {
        import juptune.core.ds : Array, String2;

        Array!char buffer;
        this.buildError(buffer, location, args);
        auto result = Result.make(error, message, String2.fromDestroyingArray(buffer));

        // version(unittest) debug
        // {
        //     import std.stdio : writeln;
        //     writeln(result.error, " -> ", result.context.sliceMaybeFromStack);
        // }

        return result;
    }

    void buildError(Range, Args...)(
        scope ref Range range,
        const Asn1Location location, 
        scope const Args args,
    )
    {
        import juptune.core.util : toStringSink;

        range.put("input[");
        if(location.start >= this._input.length)
        {
            range.put("eof]");
        }
        else if(location.end <= location.start)
        {
            toStringSink(location.start, range);
            range.put("] -> `");
            range.put(this._input[location.start..location.start+1]);
        }
        else
        {
            toStringSink(location.start, range);
            range.put("..");
            toStringSink(location.end, range);
            range.put("] -> `");
            range.put(this._input[location.start..location.end]);
        }

        static if(Args.length == 0)
            range.put("`");
        else
            range.put("`: ");

        foreach(arg; args)
            toStringSink(arg, range);
    }

    Asn1Token makeToken(
        Asn1Location location, 
        Asn1Token.Type type, 
        Asn1Token.InnerValue value = Asn1Token.InnerValue.init
    )
    {
        Asn1Token token;

        token.location = location;
        token.text = this._input[location.start..location.end];
        token.type = type;
        token.value = value;

        return token;
    }
}

struct Asn1BstringRange
{
    private
    {
        const(char)[] _bstring;
        size_t        _cursor;
        bool          _empty;
        bool          _front;
    }

    @safe @nogc nothrow:

    this(const(char)[] bstring)
    {
        this._bstring = bstring;
        this.popFront();
    }

    bool empty() pure const
    {
        return this._empty;
    }

    bool front() pure const
    {
        return this._front;
    }

    void popFront()
    {
        while(this._cursor < this._bstring.length && Asn1Lexer.WhiteSpace.isAllowed(this._bstring[this._cursor]))
            this._cursor++;

        if(this._cursor >= this._bstring.length)
        {
            this._empty = true;
            return;
        }

        const ch = this._bstring[this._cursor++];
        if(ch == '0')
            this._front = false;
        else if(ch == '1')
            this._front = true;
        else
            assert(false, "Unexpected character in bstring. Expected 0, 1, or white space. PLEASE ensure you only pass data that's already been through the Asn1Lexer to this range."); // @suppress(dscanner.style.long_line)
    }
}

struct Asn1HstringRange
{
    private
    {
        const(char)[] _hstring;
        size_t        _cursor;
        bool          _empty;
        ubyte         _front;
    }

    @safe @nogc nothrow:

    this(const(char)[] hstring)
    {
        this._hstring = hstring;
        this.popFront();
    }

    bool empty() pure const
    {
        return this._empty;
    }

    ubyte front() pure const
    {
        return this._front;
    }

    void popFront()
    {
        while(this._cursor < this._hstring.length && Asn1Lexer.WhiteSpace.isAllowed(this._hstring[this._cursor]))
            this._cursor++;

        if(this._cursor >= this._hstring.length)
        {
            this._empty = true;
            return;
        }

        const ch = this._hstring[this._cursor++];
        if(!Asn1Lexer.HexStringAlphabet.isAllowed(ch))
            assert(false, "Unexpected character in bstring. Expected 0-9, A-F, or white space. PLEASE ensure you only pass data that's already been through the Asn1Lexer to this range."); // @suppress(dscanner.style.long_line)

        if(ch >= '0' && ch <= '9')
            this._front = cast(ubyte)(ch - '0');
        else if(ch >= 'A' && ch <= 'F')
            this._front = cast(ubyte)(10 + (ch - 'A'));
        else
            assert(false, "bug: Invalid hex digit, this should've been caught earlier.");
    }
}

/**** Unittests ****/

@("Asn1Lexer - Single Token Tests")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode, Result;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        string input;
        Asn1Token expected;
        Nullable!Asn1LexerError expectedError;

        this(string input, Asn1Token expected)
        {
            this.input = input;
            this.expected = expected;
        }

        this(string input, Asn1LexerError error)
        {
            this.input = input;
            this.expectedError = error;
        }
    }

    alias tok = Asn1Token;
    alias typ = Asn1Token.Type;
    alias err = Asn1LexerError;
    alias iv  = Asn1Token.InnerValue;
    alias num = Asn1Token.Number;
    alias rum = Asn1Token.Real;
    alias str = Asn1Token.SubString;
    auto cases = [
        "whitespace - space": T(" ", tok(typ.whiteSpace, " ", 0, 1)),
        "whitespace - line": T("\n", tok(typ.whiteSpace, "\n", 0, 1)),
        "whitespace - \\t": T("\t", tok(typ.whiteSpace, "\t", 0, 1)),
        "whitespace - \\v": T("\v", tok(typ.whiteSpace, "\v", 0, 1)),
        "whitespace - \\f": T("\f", tok(typ.whiteSpace, "\f", 0, 1)),
        "whitespace - \\r": T("\r", tok(typ.whiteSpace, "\r", 0, 1)),
        "whitespace - all": T(" \t\v\n\f\r ", tok(typ.whiteSpace, " \t\v\n\f\r ", 0, 7)),

        "typeReference - letters": T("Foo", tok(typ.typeReference, "Foo", 0, 3)),
        "typeReference - numbers": T("F00", tok(typ.typeReference, "F00", 0, 3)),
        "typeReference - hyphens": T("F00-bAR-b4z", tok(typ.typeReference, "F00-bAR-b4z", 0, 11)),
        "typeReference error - ends with hyphen": T("F-", err.identifierEndsWithHyphen),

        "identifier - letters": T("foo", tok(typ.identifier, "foo", 0, 3)),
        "identifier - numbers": T("f00", tok(typ.identifier, "f00", 0, 3)),
        "identifier - hyphens": T("f00-bAR-b4z", tok(typ.identifier, "f00-bAR-b4z", 0, 11)),
        "identifier error - ends with hyphen": T("f-", err.identifierEndsWithHyphen),

        "comment single - empty, eof terminated": T("--", tok(typ.oneLineComment, "--", 0, 2)),
        "comment single - empty, hyphen terminated": T("----", tok(typ.oneLineComment, "----", 0, 4)),
        "comment single - non-empty, eof terminated": T("--this is a story", tok(typ.oneLineComment, "--this is a story", 0, 17)), // @suppress(dscanner.style.long_line)
        "comment single - non-empty, hyphen terminated": T("-- this is a story--", tok(typ.oneLineComment, "-- this is a story--", 0, 20)), // @suppress(dscanner.style.long_line)
        "comment single - no early termination": T("-- a-b-c - --", tok(typ.oneLineComment, "-- a-b-c - --", 0, 13)), // @suppress(dscanner.style.long_line)
        
        "comment multi - empty": T("/**/", tok(typ.multiLineComment, "/**/", 0, 4)),
        "comment multi - one line": T("/*this is a story*/", tok(typ.multiLineComment, "/*this is a story*/", 0, 19)),
        "comment multi - multiple lines": T("/*this is a story\nall about how*/", tok(typ.multiLineComment, "/*this is a story\nall about how*/", 0, 33)), // @suppress(dscanner.style.long_line)
        "comment multi - multiple levels 1": T("/*/**/*/", tok(typ.multiLineComment, "/*/**/*/", 0, 8)),
        "comment multi - multiple levels 2": T("/*/*/*/*----*/*/*/*/", tok(typ.multiLineComment, "/*/*/*/*----*/*/*/*/", 0, 20)), // @suppress(dscanner.style.long_line)
        "comment multi error - unterminated": T("/*", err.eof),
        "comment multi error - unterminated multiple levels": T("/*/**/", err.eof),

        "number - success": T("1234567890987654321", tok(typ.number, "1234567890987654321", 0, 19, iv(num(1234567890987654321, true)))), // @suppress(dscanner.style.long_line) // @suppress(dscanner.style.number_literals)
        "number - too large": T("111111111111111111111111111111111111111111", tok(typ.number, "111111111111111111111111111111111111111111", 0, 42, iv(num(0, false)))), // @suppress(dscanner.style.long_line) // @suppress(dscanner.style.number_literals)
        "number - zero": T("0", tok(typ.number, "0", 0, 1, iv(num(0, true)))),
        "number error - starts with zero": T("01", err.integerStartsWithZero),

        // NOTE: Real support is superficial right now.
        "real - only integer": T("123.", tok(typ.realNumber, "123.", 0, 4, rum(123, 0, 1))),
        "real - fraction": T("123.321", tok(typ.realNumber, "123.321", 0, 7, rum(123, 321, 1))),
        "real - empty exponent": T("123E", tok(typ.realNumber, "123E", 0, 4, rum(123, 0, 1))),
        "real - exponent": T("123E321", tok(typ.realNumber, "123E321", 0, 7, rum(123, 0, 321))),
        "real - everything": T("123.321e20", tok(typ.realNumber, "123.321e20", 0, 10, rum(123, 321, 20))),
    
        "typed string error - unterminated": T("'", err.eof),
        "typed string error - no type": T("''", err.eof),
        "typed string error - invalid type": T("''b", err.stringHasUnknownType),
        
        "bstring - empty": T("''B", tok(typ.bstring, "''B", 0, 3, str(null))),
        "bstring - no spaces": T("'1010'B", tok(typ.bstring, "'1010'B", 0, 7, str("1010"))),
        "bstring - white space": T("'1010 1111\n0000'B", tok(typ.bstring, "'1010 1111\n0000'B", 0, 17, str("1010 1111\n0000"))), // @suppress(dscanner.style.long_line)
        "bstring error - invalid chars": T("'a'B", err.bstringHasInvalidChars),
        
        "hstring - empty": T("''H", tok(typ.hstring, "''H", 0, 3, str(null))),
        "hstring - no spaces": T("'DEAD'H", tok(typ.hstring, "'DEAD'H", 0, 7, str("DEAD"))),
        "hstring - white space": T("'DEAD BEEF\nC4F3'H", tok(typ.hstring, "'DEAD BEEF\nC4F3'H", 0, 17, str("DEAD BEEF\nC4F3"))), // @suppress(dscanner.style.long_line)
        "hstring error - invalid chars": T("'a'H", err.hstringHasInvalidChars),
        
        "cstring - empty": T(`""`, tok(typ.cstring, `""`, 0, 2, str(null))),
        "cstring - one line": T(`"abc 123"`, tok(typ.cstring, `"abc 123"`, 0, 9, str("abc 123"))),
        "cstring - escaped speech mark": T(`""""`, tok(typ.cstring, `""""`, 0, 4, str(`""`))),
        "cstring error - unterminated": T(`"`, err.eof),
        "cstring error - unterminated 2": T(`"""`, err.eof),
    ];

    foreach(op; Asn1Token.COMPOUND_OPS)
        cases["compound op - "~op.chars] = T(op.chars, tok(op.type, op.chars, 0, op.chars.length));
    foreach(op; Asn1Token.SINGULAR_OPS)
        cases["single op - "~op.ch] = T("" ~ op.ch, tok(op.type, "" ~ op.ch, 0, 1));
    foreach(word, type; Asn1Token.RESERVED_WORDS)
        cases["reserved word - "~word] = T(word, tok(type, word, 0, word.length));

    foreach(name, test; cases)
    {
        try
        {
            auto lexer = Asn1Lexer(test.input);
            
            Asn1Token token;
            auto result = lexer.lexNext(token);
            if(test.expectedError.isNull)
            {
                resultAssert(result);
                assert(token == test.expected, format("Expected:\n\t%s\nGot:\n\t%s", test.expected, token));
            }
            else
                resultAssertSameCode!err(Result.make(test.expectedError.get), result);

            if(test.expectedError.isNull)
            {
                lexer.lexNext(token).resultAssert;
                assert(token.type == typ.eof, format("Lexer did not generate an EoF token, but instead %s", token));
            }
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1Lexer - Multi Token Tests")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode, Result;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        string input;
        Asn1Token[] expected;
        Nullable!Asn1LexerError expectedError;

        this(string input, Asn1Token[] expected)
        {
            this.input = input;
            this.expected = expected;
        }

        this(string input, Asn1LexerError error)
        {
            this.input = input;
            this.expectedError = error;
        }
    }

    alias tok = Asn1Token;
    alias typ = Asn1Token.Type;
    alias err = Asn1LexerError;
    alias iv  = Asn1Token.InnerValue;
    alias num = Asn1Token.Number;
    alias rum = Asn1Token.Real;
    alias str = Asn1Token.SubString;
    const cases = [
        // The spec doesn't seem to ever mention this as valid, but this particular syntax
        // is used in several official examples, lol
        "number - range separator edge case": T(
            "1..2", [
                tok(typ.number, "1", 0, 1, iv(num(1, true))),
                tok(typ.rangeSeparator, "..", 1, 3),
                tok(typ.number, "2", 3, 4, iv(num(2, true))),
            ]
        )
    ];

    foreach(name, test; cases)
    {
        try
        {
            auto lexer = Asn1Lexer(test.input);
            
            Asn1Token[] tokens;
            Asn1Token token;
            while(token.type != Asn1Token.Type.eof)
            {
                auto result = lexer.lexNext(token);
                if(result.isError)
                {
                    if(test.expectedError.isNull)
                        resultAssert(result);
                    else
                        resultAssertSameCode!err(Result.make(test.expectedError.get), result);
                }

                tokens ~= token;
            }

            assert(test.expectedError.isNull, "No error occurred");
            assert(tokens.length != test.expected.length, format(
                "Expected %s tokens but got %s.\nGot:\n\t%s\nExpected:\n\t%s",
                tokens.length, test.expected.length,
                tokens, test.expected,
            ));
            assert(tokens[$-1].type == Asn1Token.type.eof, "Last token wasn't eof?");
            tokens = tokens[0..$-1];

            foreach(i, got; tokens)
            {
                assert(got == test.expected[i], format(
                    "Token #%s is incorrect.\nGot:\n\t%s\nExpected:\n\t%s",
                    i,
                    got, test.expected[i]
                ));
            }
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1BstringRange")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode, Result;
    import core.exception    : AssertError;
    import std.array         : array;
    import std.algorithm     : equal;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        string input;
        bool[] expected;
        bool expectedError;

        this(string input, bool[] expected)
        {
            this.input = input;
            this.expected = expected;
        }

        this(string input, bool error)
        {
            this.input = input;
            this.expectedError = error;
        }
    }

    const cases = [
        "empty": T("", []),
        "no spaces": T("10101", [true, false, true, false, true]),
        "spaces": T("10 \n\t 101", [true, false, true, false, true]),
        "error - invalid chars": T("a", true),
    ];

    foreach(name, test; cases)
    {
        try
        {
            bool[] got;

            try
                got = Asn1BstringRange(test.input).array;
            catch(AssertError err)
            {
                if(!test.expectedError)
                    throw err;
                continue;
            }

            assert(!test.expectedError, "No error was thrown");
            assert(got.equal(test.expected), format(
                "Got:\n\t%s\nExpected:\n\t%s",
                got, test.expected
            ));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1HstringRange")
unittest
{
    import juptune.core.util : resultAssert, resultAssertSameCode, Result;
    import core.exception    : AssertError;
    import std.array         : array;
    import std.algorithm     : equal, map;
    import std.format        : format;
    import std.typecons      : Nullable;
    
    static struct T
    {
        string input;
        ubyte[] expected;
        bool expectedError;

        this(string input, int[] expected)
        {
            this.input = input;
            this.expected = expected.map!(i => cast(ubyte)i).array;
        }

        this(string input, bool error)
        {
            this.input = input;
            this.expectedError = error;
        }
    }

    const cases = [
        "empty": T("", []),
        "no spaces": T("01DE", [0, 1, 0xD, 0xE]),
        "spaces": T("01 \n\t DE", [0, 1, 0xD, 0xE]),
        "error - invalid chars": T("a", true),
    ];

    foreach(name, test; cases)
    {
        try
        {
            ubyte[] got;

            try
                got = Asn1HstringRange(test.input).array;
            catch(AssertError err)
            {
                if(!test.expectedError)
                    throw err;
                continue;
            }

            assert(!test.expectedError, "No error was thrown");
            assert(got.equal(test.expected), format(
                "Got:\n\t%s\nExpected:\n\t%s",
                got, test.expected
            ));
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1Lexer - next and lookahead")
unittest
{
    import juptune.core.util : resultAssert;

    auto lexer = Asn1Lexer("0 2 4");

    // Lookahead that need to lex
    Asn1Token token;
    lexer.lookahead(0, token).resultAssert;
    assert(token.text == "0");
    assert(lexer._lookaheadCursor == 1);

    // Lookahead that doen't need to lex
    lexer.lookahead(0, token).resultAssert;
    assert(token.text == "0");
    assert(lexer._lookaheadCursor == 1);

    // Lookahead that isn't the first one that needs to lex
    lexer.lookahead(1, token).resultAssert;
    assert(token.text == " ");
    assert(lexer._lookaheadCursor == 2);

    // Lookahead that isn't the first one that doesn't need to lex
    lexer.lookahead(1, token).resultAssert;
    assert(token.text == " ");
    assert(lexer._lookaheadCursor == 2);

    // Lookahead multiple at a time
    lexer._cursor = 0;
    lexer._lookaheadCursor = 0;
    lexer.lookahead(2, token).resultAssert;
    assert(lexer._lookaheadCursor == 3);
    assert(token.text == "2");

    // Next with lookahead
    lexer.next(token).resultAssert;
    assert(token.text == "0");
    lexer.next(token).resultAssert;
    assert(token.text == " ");
    lexer.next(token).resultAssert;
    assert(token.text == "2");

    // Next without lookahead
    lexer.next(token).resultAssert;
    assert(token.text == " ");
    lexer.next(token).resultAssert;
    assert(token.text == "4");
}