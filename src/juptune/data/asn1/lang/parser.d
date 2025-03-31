/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.parser;

import std.typecons : Nullable;

import juptune.core.util             : Result, resultAssert;
import juptune.data.asn1.lang.common : Asn1ParserContext, Asn1Location;
import juptune.data.asn1.lang.lexer  : Asn1Lexer, Asn1Token;
import juptune.data.asn1.lang.ast; // Intentionally everything

enum Asn1ParserError
{
    none,
    tokenNotFound,
    nonInitialTokenNotFound,
    oneOfNoMatches,
    listMustNotBeEmpty,
    bug,
    invalidSyntax,
}

// Some parsers are also subparsers of other parsers! So we need a shortcut
// to more finely control whether an "initial token not found" error is reported or not.
private Result notInitial(Result result)
{
    if(result.isError(Asn1ParserError.tokenNotFound))
        result.changeErrorType(Asn1ParserError.nonInitialTokenNotFound);
    return result;
}

/++
 + TODO, Organise:
 +  Two ways to signal a missing token: initial and non-initial.
 +      - Initial is useful for checking whether a particular parser is even suitable.
 +      - Non-initial is useful for signalling that there's a syntax error, since a particular parser was able to start - but not finish - parsing.
 +      - The `.notInitial` function is used to make it easier to control subparser results.
 +
 +  To make it easier to debug certain cases, all parsers will backtrack to their original position on failure.
 +
 +  Yes, the lexer's lookahead functionality is unused, mainly because of the infinite amount of whitespace and comments
 +  that can be between actually useful tokens making things complicated to deal with.
 +
 +  The code structure doesn't try to break things into 1:1 function:node as it becomes _very_ unweidly and somehow harder to read,
 +  instead it tries to only DRY common subparsers. It actively avoids the use of helper functions where possible to make
 +  debugging less of a PITA (not worth the DRYness).
 +
 +  Currently doesn't even attempt to preserve comments or original formatting - parser isn't completely suitable
 +  for all kinds of tooling due to this (adds complexity I don't want to tackle yet).
 +
 +  Yes, the AST is inefficient and parts are unused due to ambiguity that requires a semantic pass - I want to keep
 +  syntax and semantic analysis separate for my own sanity. Yes, this does waste a lot more memory than it should.
 + ++/
struct Asn1Parser
{
    private
    {
        Asn1ParserContext* _context;
        Asn1Lexer          _lexer;
        ulong              _level;
    }

    this(Asn1Lexer lexer, Asn1ParserContext* context) @nogc nothrow
    in(context !is null, "context cannot be null")
    {
        this._context = context;
        this._lexer   = lexer;
    }

    /++++ Standard parsing functions/helpers ++++/

    Result peek(scope out Asn1Token token) @nogc nothrow
    {
        TailCall:

        if(auto r = this._lexer.lookahead(0, token)) return r;

        if(token.type == Asn1Token.Type.whiteSpace
        || token.type == Asn1Token.Type.oneLineComment
        || token.type == Asn1Token.Type.multiLineComment)
        {
            this._lexer.next(token).resultAssert;
            goto TailCall;
        }

        return Result.noError;
    }

    Result consume(scope out Asn1Token token) @nogc nothrow
    {
        if(auto r = this.peek(token)) return r;
        this._lexer.next(token).resultAssert;
        return Result.noError;
    }

    Result consume() @nogc nothrow
    {
        Asn1Token _;
        return this.consume(_);
    }

    /++++ Parsers (can you tell I'm suicidal) ++++/

    Result NamedType(out Asn1NamedTypeNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.identifier) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected identifier to begin a NamedType",
            token.location, "encountered token of type ", token.type
        );

        Asn1TypeNode type;
        if(auto r = Type(type)) return r.notInitial;

        node = _context.allocNode!Asn1NamedTypeNode(
            _context.allocNode!Asn1IdentifierTokenNode(token),
            type
        );
        return Result.noError;
    }

    Result NamedNumber(out Asn1NamedNumberNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.identifier) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected identifier to begin a NamedNumber",
            token.location, "encountered token of type ", token.type
        );

        const identifierToken = token;

        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.leftParenthesis) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected opening parenthesis as part of a NamedNumber",
            token.location, "encountered token of type ", token.type
        );

        Result checkEnd()
        {
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.rightParenthesis) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected closing parenthesis as part of a NamedNumber",
                token.location, "encountered token of type ", token.type
            );
            return Result.noError;
        }

        Asn1SignedNumberNode signedNumber;
        if(auto snr = SignedNumber(signedNumber))
        {
            if(!snr.isError(Asn1ParserError.tokenNotFound)) return snr;

            Asn1DefinedValueNode definedValue;
            if(auto r = DefinedValue(definedValue)) return r.notInitial;
            if(auto r = checkEnd()) return r;
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(typeof(node).Defined)(
                    _context.allocNode!Asn1IdentifierTokenNode(identifierToken),
                    definedValue
                )
            );
        }
        else
        {
            if(auto r = checkEnd()) return r;
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(typeof(node).Signed)(
                    _context.allocNode!Asn1IdentifierTokenNode(identifierToken),
                    signedNumber
                )
            );
        }

        return Result.noError;
    }

    Result SignedNumber(out Asn1SignedNumberNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;

        switch(token.type) with(Asn1Token.Type)
        {
            case hyphenMinus:
                if(auto r = consume(token)) return r;
                if(token.type != number) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected number following hyphen when looking for a SignedNumber",
                    token.location, "encountered token of type ", token.type
                );
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1SignedNumberNode.Negative)(
                        _context.allocNode!Asn1NumberTokenNode(
                            token
                        )
                    )
                );
                return Result.noError;

            case number:
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1NumberTokenNode(
                        token
                    )
                );
            return Result.noError;

            default: return _lexer.makeError(
                Asn1ParserError.tokenNotFound,
                "expected hyphen or number when looking for a SignedNumber",
                token.location, "encountered token of type ", token.type
            );
        }
    }

    Result DefinedValue(out Asn1DefinedValueNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        
        if(token.type == Asn1Token.Type.moduleReference)
        {
            const moduleToken = token;
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.dot) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected `.` following module reference when parsing a DefinedValue",
                token.location, "encountered token of type ", token.type
            );

            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.valueReference) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected identifier following module reference when parsing a DefinedValue",
                token.location, "encountered token of type ", token.type
            );

            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ExternalValueReferenceNode(
                    _context.allocNode!Asn1ModuleReferenceTokenNode(moduleToken),
                    _context.allocNode!Asn1ValueReferenceTokenNode(token)
                )
            );
            return Result.noError;
        }
        else if (token.type == Asn1Token.Type.valueReference)
        {
            Asn1Token lookahead;
            if(auto r = peek(lookahead)) return r;
            if(lookahead.type == Asn1Token.Type.leftBracket)
            {
                assert(false, "TODO: Support ParameterizedValue");
            }

            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ValueReferenceTokenNode(token)
            );
            return Result.noError;
        }

        return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected identifier or module reference when attempting to parse a DefinedValue",
            token.location, "encountered token of type ", token.type
        );
    }

    Result DefinedObjectClass(out Asn1DefinedObjectClassNode node)
    {
        assert(false, "TODO: Implement");
    }

    Result ComponentType(out Asn1ComponentTypeNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;

        if(token.type == Asn1Token.Type.rCOMPONENTS)
        {
            consume().resultAssert;
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.rOF) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected `OF` to denote `COMPONENTS OF` for a ComponenType within a ComponentTypeList",
                token.location, "encountered token of type ", token.type
            );

            Asn1TypeNode type;
            if(auto r = Type(type)) return r.notInitial;
            node = _context.allocNode!(typeof(node))(type);

            return Result.noError;
        }

        if(token.type != Asn1Token.Type.identifier) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected identifier or `COMPONENTS` when attemping to parse a ComponentTypeList",
            token.location, "encountered token of type ", token.type
        );

        Asn1NamedTypeNode namedType;
        if(auto r = NamedType(namedType)) return r.notInitial;
        if(auto r = peek(token)) return r;
        
        if(token.type == Asn1Token.Type.rOPTIONAL)
        {
            consume().resultAssert;
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(typeof(node).Optional)(namedType),
            );
        }
        else if(token.type == Asn1Token.Type.rDEFAULT)
        {
            consume().resultAssert;
            Asn1ValueNode value;
            if(auto r = Value(value)) return r.notInitial;
            
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(typeof(node).Default)(
                    namedType,
                    value
                ),
            );
        }
        else
            node = _context.allocNode!(typeof(node))(namedType);

        return Result.noError;
    }

    Result ComponentTypeList(out Asn1ComponentTypeListNode outNode)
    {
        auto savedLexer = _lexer;
        scope(exit) if(outNode is null)
            _lexer = savedLexer;

        Asn1Token token;
        Asn1Lexer savedBeforeComma = _lexer;
        auto list = _context.allocNode!Asn1ComponentTypeListNode();
        while(true)
        {
            Asn1ComponentTypeNode typeNode;
            if(auto r = ComponentType(typeNode))
            {
                if(r.isError(Asn1ParserError.tokenNotFound))
                {
                    _lexer = savedBeforeComma;
                    break;
                }
                return r;
            }
            list.items.put(typeNode);

            savedBeforeComma = _lexer;
            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.comma) break;
            consume().resultAssert;
        }

        if(list.items.length == 0) return _lexer.makeError(
            Asn1ParserError.listMustNotBeEmpty,
            "type list is not allowed to empty",
            token.location
        );

        outNode = list;
        return Result.noError;
    }

    Result ComponentTypeLists(out Asn1ComponentTypeListsNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;

        Asn1ComponentTypeListNode rootTypeList;
        if(token.type != Asn1Token.Type.ellipsis)
        {
            if(auto r = ComponentTypeList(rootTypeList)) return r;
            if(auto r = peek(token)) return r;

            if(token.type != Asn1Token.Type.comma)
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1RootComponentTypeListNode)(
                        rootTypeList
                    ),
                );
                return Result.noError;
            }
            consume().resultAssert;
        }

        Asn1ExtensionAndExceptionNode extAndExc;
        Asn1ExtensionAdditionsNode extAdditions;
        if(auto r = ExtensionAndException(extAndExc)) return r.notInitial;
        if(auto r = ExtensionAdditions(extAdditions)) return r.notInitial;

        if(auto r = peek(token)) return r;
        if(token.type != Asn1Token.Type.comma)
        {
            if(rootTypeList !is null)
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1ComponentTypeListsNode.Case1)(
                        _context.allocNode!Asn1RootComponentTypeListNode(
                            rootTypeList,
                        ),
                        extAndExc,
                        extAdditions,
                        _context.allocNode!Asn1OptionalExtensionMarkerNode(
                            _context.allocNode!Asn1EmptyNode(token)
                        ),
                    ),
                );
            }
            else
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1ComponentTypeListsNode.Case4)(
                        extAndExc,
                        extAdditions,
                        _context.allocNode!Asn1OptionalExtensionMarkerNode(
                            _context.allocNode!Asn1EmptyNode(token)
                        ),
                    ),
                );
            }
            return Result.noError;
        }

        Asn1ExtensionEndMarkerNode endMarker;
        if(auto r = ExtensionEndMarker(endMarker)) return r.notInitial;
        if(auto r = peek(token)) return r;
        if(token.type != Asn1Token.Type.comma)
        {
            if(rootTypeList !is null)
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1ComponentTypeListsNode.Case1)(
                        _context.allocNode!Asn1RootComponentTypeListNode(
                            rootTypeList,
                        ),
                        extAndExc,
                        extAdditions,
                        _context.allocNode!Asn1OptionalExtensionMarkerNode(
                            _context.allocNode!Asn1ElipsisNode(endMarker.token)
                        ),
                    ),
                );
            }
            else
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!(Asn1ComponentTypeListsNode.Case4)(
                        extAndExc,
                        extAdditions,
                        _context.allocNode!Asn1OptionalExtensionMarkerNode(
                            _context.allocNode!Asn1ElipsisNode(endMarker.token)
                        ),
                    ),
                );
            }
            return Result.noError;
        }
        consume().resultAssert;

        Asn1ComponentTypeListNode additionalList;
        if(auto r = ComponentTypeList(additionalList)) return r.notInitial;

        if(rootTypeList !is null)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(Asn1ComponentTypeListsNode.Case2)(
                    _context.allocNode!Asn1RootComponentTypeListNode(
                        rootTypeList,
                    ),
                    extAndExc,
                    extAdditions,
                    endMarker,
                    _context.allocNode!(Asn1ComponentTypeListsNode.Case2.Additional)(
                        _context.allocNode!Asn1RootComponentTypeListNode(
                            additionalList,
                        ),
                    )
                ),
            );
        }
        else
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!(Asn1ComponentTypeListsNode.Case3)(
                    extAndExc,
                    extAdditions,
                    endMarker,
                    _context.allocNode!Asn1RootComponentTypeListNode(
                        additionalList,
                    ),
                ),
            );
        }
        return Result.noError;
    }

    Result ExceptionSpec(out Asn1ExceptionSpecNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;

        if(token.type != Asn1Token.Type.exclamation)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1EmptyNode(token),
            );
            return Result.noError;
        }
        consume().resultAssert;

        Asn1ExceptionIdentificationNode identification;

        Asn1SignedNumberNode number;
        auto result = SignedNumber(number);
        if(!result.isError)
        {
            identification = _context.allocNode!(typeof(identification))(number);
            node = _context.allocNode!(typeof(node))(identification);
            return Result.noError;
        }

        Asn1DefinedValueNode definedValue;
        result = DefinedValue(definedValue);
        if(!result.isError)
        {
            identification = _context.allocNode!(typeof(identification))(definedValue);
            node = _context.allocNode!(typeof(node))(identification);
            return Result.noError;
        }

        Asn1TypeNode type;
        Asn1ValueNode value;
        if(auto r = Type(type)) return r.notInitial;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.colon) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `:` following type when parsing an ExceptionSpec",
            token.location, "encountered token of type ", token.type
        );
        if(auto r = Value(value)) return r.notInitial;
        
        identification = _context.allocNode!(typeof(identification))(
            _context.allocNode!(typeof(identification).TypeValue)(
                type,
                value
            ),
        );
        node = _context.allocNode!(typeof(node))(identification);
        return Result.noError;
    }

    Result ExtensionAndException(out Asn1ExtensionAndExceptionNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.ellipsis) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected `...` when looking for ExtensionAndException",
            token.location, "encountered token of type ", token.type
        );

        Asn1Token auxToken;
        if(auto r = peek(auxToken)) return r;
        if(auxToken.type != Asn1Token.Type.exclamation)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ElipsisNode(token)
            );
            return Result.noError;
        }

        Asn1ExceptionSpecNode exception;
        if(auto r = ExceptionSpec(exception)) return r.notInitial;
        assert(!exception.isNode!Asn1EmptyNode, "bug: to match the ASN.1 syntax notation, we need to catch the empty condition ourselves"); // @suppress(dscanner.style.long_line)

        node = _context.allocNode!(typeof(node))(exception);
        return Result.noError;
    }

    Result VersionNumber(out Asn1VersionNumberNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;
        if(token.type != Asn1Token.Type.number)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1EmptyNode(token)
            );
            return Result.noError;
        }
        consume().resultAssert;

        Asn1Token auxToken;
        if(auto r = consume(auxToken)) return r;
        if(auxToken.type != Asn1Token.Type.colon) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `:` following number consisting a VersionNumber",
            auxToken.location, "encountered token of type ", auxToken.type
        );
        
        node = _context.allocNode!(typeof(node))(
            _context.allocNode!Asn1NumberTokenNode(token)
        );
        return Result.noError;
    }

    Result ExtensionEndMarker(out Asn1ExtensionEndMarkerNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.comma)return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected `, ` to denote `, ...` (an extension end marker)",
            token.location, "encountered token of type ", token.type
        );

        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.ellipsis) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `...` to denote `, ...` (an extension end marker)",
            token.location, "encountered token of type ", token.type
        );
        
        node = _context.allocNode!(typeof(node))(token);
        return Result.noError;
    }

    Result ExtensionAdditions(out Asn1ExtensionAdditionsNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;
        if(token.type != Asn1Token.Type.comma)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1EmptyNode(token)
            );
            return Result.noError;
        }

        Asn1Lexer savedBeforeComma = _lexer;
        consume().resultAssert;

        auto list = _context.allocNode!Asn1ExtensionAdditionListNode();
        while(true)
        {
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.leftVersionBrackets)
            {
                consume().resultAssert;

                Asn1VersionNumberNode versionNumber;
                Asn1ComponentTypeListNode typeList;
                if(auto r = VersionNumber(versionNumber)) return r.notInitial;
                if(auto r = ComponentTypeList(typeList)) return r.notInitial;
                list.items.put(_context.allocNode!Asn1ExtensionAdditionNode(
                    _context.allocNode!Asn1ExtensionAdditionGroupNode(
                        versionNumber,
                        typeList
                    )
                ));

                if(auto r = consume(token)) return r;
                if(token.type != Asn1Token.Type.rightVersionBrackets) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `]]` to mark end of an extension addition group",
                    token.location, "encountered token of type ", token.type
                );
            }
            else
            {
                Asn1ComponentTypeNode typeNode;
                if(auto r = ComponentType(typeNode))
                {
                    if(r.isError(Asn1ParserError.tokenNotFound))
                    {
                        _lexer = savedBeforeComma;
                        break;
                    }
                    return r;
                }
                list.items.put(_context.allocNode!Asn1ExtensionAdditionNode(typeNode));
            }

            savedBeforeComma = _lexer;
            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.comma) break;
            consume().resultAssert;
        }

        if(list.items.length == 0) // This can happen when ExtensionAdditions is placed before another comma-starting production.
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1EmptyNode(token)
            );
        }
        else
            node = _context.allocNode!(typeof(node))(list);
        return Result.noError;
    }

    Result Type(out Asn1TypeNode node)
    {
        // TODO: ConstrainedType
        return PlainType(node);
    }

    Result PlainType(out Asn1TypeNode node)
    {
        import std.meta : AliasSeq;
        static struct StringType(NodeT_)
        {
            alias NodeT = NodeT_;
            Asn1Token.Type type;
        }

        static struct TypeListType(string Name_, ListT_, OfT_)
        {
            static immutable Name = Name_;
            alias ListT = ListT_;
            alias OfT = OfT_;

            static immutable BeginErrorMsg = "expected opening bracket to begin `"~Name_~"` type list";
            static immutable EndErrorMsg = "expected closing bracket to end `"~Name_~"` type list";

            Asn1Token.Type type;
        }

        void makeBuiltin(NodeT, Args...)(Args args)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1BuiltinTypeNode(
                    _context.allocNode!NodeT(args)
                ),
            );
        }

        // TODO: ObjectClassFieldType
        // TODO: ReferencedType

        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token, auxToken;
        if(auto r = consume(token)) return r;

        switch(token.type) with(Asn1Token.Type)
        {
            case rBIT:
                if(auto r = consume(token)) return r;
                if(token.type != rSTRING)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `STRING` to denote `BIT STRING`",
                        token.location, "encountered token of type ", token.type
                    );

                if(auto r = peek(auxToken)) return r;
                if(auxToken.type != leftBracket)
                {
                    makeBuiltin!Asn1BitStringTypeNode(
                        _context.allocNode!(Asn1BitStringTypeNode.Plain)(token)
                    );
                }
                else
                {
                    consume().resultAssert;

                    auto bitList = _context.allocNode!Asn1NamedBitListNode();
                    while(true)
                    {
                        Asn1Token id;
                        if(auto r = peek(id)) return r;
                        if(id.type != identifier) break;
                        consume().resultAssert;

                        if(auto r = consume(auxToken)) return r;
                        if(auxToken.type != leftParenthesis) return _lexer.makeError(
                            Asn1ParserError.nonInitialTokenNotFound,
                            "expected `(` following name of named bit within a `BIT STRING` component list",
                            auxToken.location, "encountered token of type ", auxToken.type
                        );

                        Asn1Token bitNumber;
                        if(auto r = peek(bitNumber)) return r;
                        if(bitNumber.type == number)
                        {
                            consume().resultAssert;
                            auto bit = _context.allocNode!Asn1NamedBitNode(
                                _context.allocNode!(Asn1NamedBitNode.Number)(
                                    _context.allocNode!Asn1IdentifierTokenNode(id),
                                    _context.allocNode!Asn1NumberTokenNode(bitNumber)
                                )
                            );
                            bitList.items.put(bit);
                        }
                        else
                        {
                            Asn1DefinedValueNode value;
                            if(auto r = DefinedValue(value)) return r.notInitial;

                            auto bit = _context.allocNode!Asn1NamedBitNode(
                                _context.allocNode!(Asn1NamedBitNode.DefinedValue)(
                                    _context.allocNode!Asn1IdentifierTokenNode(id),
                                    value
                                )
                            );
                            bitList.items.put(bit);
                        }

                        if(auto r = consume(auxToken)) return r;
                        if(auxToken.type != rightParenthesis) return _lexer.makeError(
                            Asn1ParserError.nonInitialTokenNotFound,
                            "expected `)` following value of named bit within a `BIT STRING` component list",
                            auxToken.location, "encountered token of type ", auxToken.type
                        );

                        if(auto r = peek(auxToken)) return r;
                        if(auxToken.type != comma) break;
                        consume().resultAssert;
                    }

                    if(bitList.items.length == 0) return _lexer.makeError(
                        Asn1ParserError.listMustNotBeEmpty,
                        "component list for `BIT STRING` is not allowed to empty - `BIT STRING { }` is forbidden",
                        token.location
                    );

                    if(auto r = consume(auxToken)) return r;
                    if(auxToken.type != rightBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected closing bracket to complete `BIT STRING` component list",
                        auxToken.location, "encountered token of type ", auxToken.type
                    );

                    makeBuiltin!Asn1BitStringTypeNode(bitList);
                }
                return Result.noError;

            case rBOOLEAN:
                makeBuiltin!Asn1BooleanTypeNode(token);
                return Result.noError;

            static foreach(StringT; AliasSeq!(
                StringType!Asn1BMPStringNode(rBMPString),
                StringType!Asn1GeneralStringNode(rGeneralString),
                StringType!Asn1GraphicStringNode(rGraphicString),
                StringType!Asn1IA5StringNode(rIA5String),
                StringType!Asn1ISO646StringNode(rISO646String),
                StringType!Asn1NumericStringNode(rNumericString),
                StringType!Asn1PrintableStringNode(rPrintableString),
                StringType!Asn1TeletexStringNode(rTeletexString),
                StringType!Asn1T61StringNode(rT61String),
                StringType!Asn1UniversalStringNode(rUniversalString),
                StringType!Asn1UTF8StringNode(rUTF8String),
                StringType!Asn1VideotexStringNode(rVideotexString),
                StringType!Asn1VisibleStringNode(rVisibleString),
            ))
            {
                case StringT.type:
                    makeBuiltin!Asn1CharacterStringTypeNode(
                        _context.allocNode!Asn1RestrictedCharacterStringTypeNode(
                            _context.allocNode!(StringT.NodeT)(token)
                        )
                    );
                    return Result.noError;
            }

            case rCHARACTER:
                if(auto r = consume(token)) return r;
                if(token.type != rSTRING)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `STRING` to denote `CHARACTER STRING`",
                        token.location, "encountered token of type ", token.type
                    );
                makeBuiltin!Asn1CharacterStringTypeNode(
                    _context.allocNode!Asn1UnrestrictedCharacterStringTypeNode(token)
                );
                return Result.noError;

            case rCHOICE:
                if(auto r = consume(token)) return r;
                if(token.type != leftBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected opening bracket to begin `CHOICE` alternative type list",
                    token.location, "encountered token of type ", token.type
                );

                Result checkEnd()
                {
                    if(auto r = consume(token)) return r;
                    if(token.type != rightBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected closing bracket to end `CHOICE` alternative type list",
                        token.location, "encountered token of type ", token.type
                    );
                    return Result.noError;
                }

                Result AlternativeTypeList(out Asn1AlternativeTypeListNode typeList, out bool endingComma)
                {
                    typeList = _context.allocNode!Asn1AlternativeTypeListNode();
                    while(true)
                    {
                        if(auto r = peek(token)) return r;
                        if(token.type != identifier) break;
                        endingComma = false;

                        Asn1NamedTypeNode namedType;
                        if(auto r = NamedType(namedType)) return r.notInitial;
                        typeList.items.put(namedType);

                        if(auto r = peek(token)) return r;
                        if(token.type != comma) break;
                        consume().resultAssert;
                        endingComma = true;
                    }

                    if(typeList.items.length == 0) return _lexer.makeError(
                        Asn1ParserError.listMustNotBeEmpty,
                        "alternative type list for `CHOICE` is not allowed to empty - `CHOICE { }` is forbidden",
                        token.location
                    );
                    return Result.noError;
                }
                
                Asn1AlternativeTypeListNode typeList;
                bool endingComma;
                if(auto r = AlternativeTypeList(typeList, endingComma)) return r;
                
                if(!endingComma)
                {
                    if(auto r = checkEnd()) return r;

                    makeBuiltin!Asn1ChoiceTypeNode(
                        _context.allocNode!Asn1AlternativeTypeListsNode(
                            _context.allocNode!Asn1RootAlternativeTypeListNode(
                                typeList
                            )
                        )
                    );
                    return Result.noError;
                }

                Asn1ExtensionAndExceptionNode extAndExc;
                if(auto r = ExtensionAndException(extAndExc)) return r.notInitial;
                if(auto r = peek(token)) return r;
                if(token.type != comma)
                {
                    if(auto r = checkEnd()) return r;

                    makeBuiltin!Asn1ChoiceTypeNode(
                        _context.allocNode!Asn1AlternativeTypeListsNode(
                            _context.allocNode!(Asn1AlternativeTypeListsNode.Case1)(
                                _context.allocNode!Asn1RootAlternativeTypeListNode(
                                    typeList
                                ),
                                extAndExc,
                                _context.allocNode!Asn1ExtensionAdditionAlternativesNode(
                                    _context.allocNode!Asn1EmptyNode(token)
                                ),
                                _context.allocNode!Asn1OptionalExtensionMarkerNode(
                                    _context.allocNode!Asn1EmptyNode(token)
                                )
                            )
                        )
                    );
                    return Result.noError;
                }
                consume().resultAssert;

                Asn1ExtensionAdditionAlternativesListNode addList;
                if(auto r = peek(token)) return r;
                if(token.type != ellipsis)
                {
                    addList = _context.allocNode!(typeof(addList))();
                    while(true)
                    {
                        if(auto r = peek(token)) return r;
                        if(token.type == Asn1Token.Type.leftVersionBrackets)
                        {
                            consume().resultAssert;

                            Asn1VersionNumberNode versionNumber;
                            if(auto r = VersionNumber(versionNumber)) return r;

                            Asn1AlternativeTypeListNode altTypeList;
                            if(auto r = AlternativeTypeList(altTypeList, endingComma)) return r;

                            if(endingComma) return _lexer.makeError(
                                Asn1ParserError.nonInitialTokenNotFound,
                                "expected alternative type following comma within a `CHOICE` alternative type list",
                                token.location, "encountered token of type ", token.type
                            );

                            if(auto r = consume(token)) return r;
                            if(token.type != rightVersionBrackets) return _lexer.makeError(
                                Asn1ParserError.nonInitialTokenNotFound,
                                "expected `]]` to close alternative group within a `CHOICE` alternative type list",
                                token.location, "encountered token of type ", token.type
                            );

                            auto group = _context.allocNode!Asn1ExtensionAdditionAlternativesGroupNode(
                                versionNumber,
                                altTypeList
                            );
                            addList.items.put(_context.allocNode!Asn1ExtensionAdditionAlternativeNode(group));
                        }
                        else
                        {
                            Asn1NamedTypeNode namedType;
                            if(auto r = NamedType(namedType)) return r;
                            addList.items.put(_context.allocNode!Asn1ExtensionAdditionAlternativeNode(namedType));
                        }

                        if(auto r = peek(token)) return r;
                        if(token.type != comma) break;
                        consume().resultAssert;

                        if(auto r = peek(token)) return r;
                        if(token.type == ellipsis) break;
                    }
                }

                Asn1OptionalExtensionMarkerNode optionalEnd;
                if(auto r = peek(token)) return r;
                if(token.type == ellipsis)
                {
                    consume().resultAssert;
                    optionalEnd = _context.allocNode!(typeof(optionalEnd))(
                        _context.allocNode!Asn1ElipsisNode(token)
                    );
                }
                else
                {
                    optionalEnd = _context.allocNode!(typeof(optionalEnd))(
                        _context.allocNode!Asn1EmptyNode(token)
                    );
                }

                Asn1ExtensionAdditionAlternativesNode alternatives;
                if(addList is null || addList.items.length == 0)
                {
                    alternatives = _context.allocNode!(typeof(alternatives))(
                        _context.allocNode!Asn1EmptyNode(token)
                    );
                }
                else
                {
                    alternatives = _context.allocNode!(typeof(alternatives))(
                        addList
                    );
                }

                if(auto r = checkEnd()) return r;

                makeBuiltin!Asn1ChoiceTypeNode(
                    _context.allocNode!Asn1AlternativeTypeListsNode(
                        _context.allocNode!(Asn1AlternativeTypeListsNode.Case1)(
                            _context.allocNode!Asn1RootAlternativeTypeListNode(
                                typeList
                            ),
                            extAndExc,
                            alternatives,
                            optionalEnd
                        ),
                    )
                );
                return Result.noError;

            case rEMBEDDED:
                if(auto r = consume(token)) return r;
                if(token.type != rPDV)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `PDV` to denote `EMBEDDED PDV`",
                        token.location, "encountered token of type ", token.type
                    );
                makeBuiltin!Asn1EmbeddedPDVTypeNode(token);
                return Result.noError;

            case rENUMERATED:
                if(auto r = consume(token)) return r;
                if(token.type != leftBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected opening bracket to begin `ENUMERATED` enumerations",
                    token.location, "encountered token of type ", token.type
                );

                Result checkEnd()
                {
                    if(auto r = consume(token)) return r;
                    if(token.type != rightBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected closing bracket to end `ENUMERATED` enumerations",
                        token.location, "encountered token of type ", token.type
                    );
                    return Result.noError;
                }

                Result Enumeration(out Asn1EnumerationNode enumeration, out bool endingComma)
                {
                    enumeration = _context.allocNode!Asn1EnumerationNode();
                    endingComma = false;
                    while(true)
                    {
                        if(auto r = peek(token)) return r;
                        if(token.type != identifier) break;
                        endingComma = false;

                        Asn1NamedNumberNode namedNumber;
                        if(auto r = NamedNumber(namedNumber))
                        {
                            consume().resultAssert;
                            enumeration.items.put(_context.allocNode!Asn1EnumerationItemNode(
                                _context.allocNode!Asn1IdentifierTokenNode(token)
                            ));
                        }
                        else
                            enumeration.items.put(_context.allocNode!Asn1EnumerationItemNode(namedNumber));

                        if(auto r = peek(token)) return r;
                        if(token.type != comma) break;
                        consume().resultAssert;
                        endingComma = true;
                    }
                    if(enumeration.items.length == 0) return _lexer.makeError(
                        Asn1ParserError.listMustNotBeEmpty,
                        "enumerations for `ENUMERATED` is not allowed to empty - `ENUMERATED { }` is forbidden",
                        token.location
                    );
                    return Result.noError;
                }

                Asn1EnumerationNode enumeration;
                bool endingComma;
                if(auto r = Enumeration(enumeration, endingComma)) return r;
                
                if(!endingComma)
                {
                    if(auto r = checkEnd()) return r;

                    makeBuiltin!Asn1EnumeratedTypeNode(
                        _context.allocNode!Asn1EnumerationsNode(
                            _context.allocNode!Asn1RootEnumerationNode(
                                enumeration
                            )
                        )
                    );
                    return Result.noError;
                }

                if(auto r = consume(token)) return r;
                if(token.type != ellipsis) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `...` following comma within an `ENUMERATED` enumerations list",
                    token.location, "encountered token of type ", token.type
                );

                Asn1ExceptionSpecNode excSpec;
                if(auto r = ExceptionSpec(excSpec)) return r;
                if(auto r = peek(token)) return r;
                if(token.type != comma)
                {
                    if(auto r = checkEnd()) return r;

                    makeBuiltin!Asn1EnumeratedTypeNode(
                        _context.allocNode!Asn1EnumerationsNode(
                            _context.allocNode!(Asn1EnumerationsNode.Case1)(
                                _context.allocNode!Asn1RootEnumerationNode(
                                    enumeration
                                ),
                                excSpec
                            )
                        )
                    );
                    return Result.noError;
                }
                consume().resultAssert;

                Asn1EnumerationNode addEnumeration;
                if(auto r = Enumeration(addEnumeration, endingComma)) return r;
                if(endingComma) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected enumeration following comma at end of an `ENUMERATED` enumerations list",
                    token.location, "encountered token of type ", token.type
                );
                if(auto r = checkEnd()) return r;

                makeBuiltin!Asn1EnumeratedTypeNode(
                    _context.allocNode!Asn1EnumerationsNode(
                        _context.allocNode!(Asn1EnumerationsNode.Case2)(
                            _context.allocNode!Asn1RootEnumerationNode(
                                enumeration
                            ),
                            excSpec,
                            _context.allocNode!Asn1AdditionalEnumerationNode(
                                addEnumeration
                            ),
                        )
                    )
                );
                return Result.noError;

            case rEXTERNAL:
                makeBuiltin!Asn1ExternalTypeNode(token);
                return Result.noError;

            case rINSTANCE:
                if(auto r = consume(token)) return r;
                if(token.type != rOF)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `OF` to denote `INSTANCE OF`",
                        token.location, "encountered token of type ", token.type
                    );

                Asn1DefinedObjectClassNode definedObjectClass;
                if(auto r = DefinedObjectClass(definedObjectClass)) return r.notInitial;
                makeBuiltin!Asn1InstanceOfTypeNode(definedObjectClass);
                return Result.noError;

            case rINTEGER:
                if(auto r = peek(token)) return r;
                if(token.type != leftBracket)
                {
                    makeBuiltin!Asn1IntegerTypeNode(
                        _context.allocNode!(Asn1IntegerTypeNode.Plain)(token)
                    );
                    return Result.noError;
                }
                consume().resultAssert;

                auto numberList = _context.allocNode!Asn1NamedNumberListNode();
                while(true)
                {
                    Asn1NamedNumberNode namedNumber;
                    if(auto r = NamedNumber(namedNumber)) return r.notInitial;
                    numberList.items.put(namedNumber);

                    if(auto r = peek(token)) return r;
                    if(token.type != comma) break;
                    consume().resultAssert;
                }

                if(numberList.items.length == 0) return _lexer.makeError(
                    Asn1ParserError.listMustNotBeEmpty,
                    "named number list for `INTEGER` is not allowed to empty - `INTEGER { }` is forbidden",
                    token.location
                );

                if(auto r = consume(token)) return r;
                if(token.type != rightBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected closing bracket to end `INTEGER` named number list",
                    token.location, "encountered token of type ", token.type
                );
                
                makeBuiltin!Asn1IntegerTypeNode(numberList);
                return Result.noError;

            case rNULL:
                makeBuiltin!Asn1NullTypeNode(token);
                return Result.noError;

            case rOBJECT:
                if(auto r = consume(token)) return r;
                if(token.type != rIDENTIFIER)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `IDENTIFIER` to denote `OBJECT IDENTIFIER`",
                        token.location, "encountered token of type ", token.type
                    );

                makeBuiltin!Asn1ObjectIdentifierTypeNode(token);
                return Result.noError;

            case rOCTET:
                if(auto r = consume(token)) return r;
                if(token.type != rSTRING)
                    return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `STRING` to denote `OCTET STRING`",
                        token.location, "encountered token of type ", token.type
                    );

                makeBuiltin!Asn1OctetStringTypeNode(token);
                return Result.noError;

            case rREAL:
                makeBuiltin!Asn1RealTypeNode(token);
                return Result.noError;

            case rRELATIVE_OID:
                makeBuiltin!Asn1RelativeOIDTypeNode(token);
                return Result.noError;

            // SET and SEQUENCE are identical, so we can do a simple subtitution
            static foreach(Case; AliasSeq!(
                TypeListType!("SEQUENCE", Asn1SequenceTypeNode, Asn1SequenceOfTypeNode)(rSEQUENCE),
                TypeListType!("SET", Asn1SetTypeNode, Asn1SetOfTypeNode)(rSET),
            ))
            {
                case Case.type:
                    if(auto r = consume(token)) return r;
                    if(token.type == rOF)
                    {
                        if(auto r = peek(token)) return r;
                        if(token.type == identifier)
                        {
                            Asn1NamedTypeNode namedType;
                            if(auto r = NamedType(namedType)) return r;
                            makeBuiltin!(Case.OfT)(namedType);
                        }
                        else
                        {
                            Asn1TypeNode type;
                            if(auto r = Type(type)) return r;
                            makeBuiltin!(Case.OfT)(type);
                        }

                        return Result.noError;
                    }

                    if(token.type != leftBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        Case.BeginErrorMsg,
                        token.location, "encountered token of type ", token.type
                    );

                    if(auto r = peek(token)) return r;
                    if(token.type == rightBracket)
                    {
                        consume().resultAssert;
                        makeBuiltin!(Case.ListT)(
                            _context.allocNode!(Case.ListT.Empty)(token)
                        );
                        return Result.noError;
                    }

                    Asn1ComponentTypeListsNode typeLists;
                    if(auto r = ComponentTypeLists(typeLists)) return r.notInitial;

                    if(auto r = consume(token)) return r;
                    if(token.type != rightBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        Case.EndErrorMsg,
                        token.location, "encountered token of type ", token.type
                    );

                    makeBuiltin!(Case.ListT)(typeLists);
                    return Result.noError;
            }

            case leftSquare:
                Asn1ClassNode class_;
                if(auto r = peek(token)) return r;
                switch(token.type)
                {
                    case rUNIVERSAL:  
                        class_ = _context.allocNode!Asn1ClassNode(_context.allocNode!Asn1UniversalNode(token));
                        consume().resultAssert;
                        break;
                    case rAPPLICATION:  
                        class_ = _context.allocNode!Asn1ClassNode(_context.allocNode!Asn1ApplicationNode(token));
                        consume().resultAssert;
                        break;
                    case rPRIVATE:  
                        class_ = _context.allocNode!Asn1ClassNode(_context.allocNode!Asn1PrivateNode(token));
                        consume().resultAssert;
                        break;
                    default:
                        class_ = _context.allocNode!Asn1ClassNode(_context.allocNode!Asn1EmptyNode(token));
                        break;
                }

                Asn1ClassNumberNode classNumber;
                if(auto r = peek(token)) return r;
                if(token.type == number)
                {
                    consume().resultAssert;
                    classNumber = _context.allocNode!(typeof(classNumber))(
                        _context.allocNode!Asn1NumberTokenNode(token)
                    );
                }
                else
                {
                    Asn1DefinedValueNode value;
                    if(auto r = DefinedValue(value)) return r.notInitial;
                    classNumber = _context.allocNode!(typeof(classNumber))(value);
                }

                if(auto r = consume(token)) return r;
                if(token.type != rightSquare) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `]` to mark end of Tag, as part of a TaggedType",
                    token.location, "encountered token of type ", token.type
                );

                auto tag = _context.allocNode!Asn1TagNode(class_, classNumber);
                if(auto r = peek(token)) return r;

                Asn1Token tagTypeToken;
                if(token.type == rEXPLICIT || token.type == rIMPLICIT)
                {
                    tagTypeToken = token;
                    consume().resultAssert;
                }

                Asn1TypeNode type;
                if(auto r = Type(type)) return r;

                switch(tagTypeToken.type)
                {
                    case rEXPLICIT:
                        makeBuiltin!Asn1TaggedTypeNode(
                            _context.allocNode!(Asn1TaggedTypeNode.Explicit)(
                                tag, type
                            ),
                        );
                        break;
                    
                    case rIMPLICIT:
                        makeBuiltin!Asn1TaggedTypeNode(
                            _context.allocNode!(Asn1TaggedTypeNode.Implicit)(
                                tag, type
                            ),
                        );
                        break;

                    default:
                        makeBuiltin!Asn1TaggedTypeNode(
                            _context.allocNode!(Asn1TaggedTypeNode.Default)(
                                tag, type
                            ),
                        );
                        break;
                }

                return Result.noError;

            default: return _lexer.makeError(
                Asn1ParserError.oneOfNoMatches,
                "expected Type",
                token.location, "encountered token of type ", token.type
            );
        }
    }

    Result ValueList(out Asn1ValueListNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        node = _context.allocNode!(typeof(node))();
        while(true)
        {
            Asn1ValueNode value;
            if(auto r = Value(value)) return r;
            node.items.put(value);

            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.comma) break;
            consume().resultAssert;
        }

        return Result.noError;
    }

    Result NamedValueList(out Asn1NamedValueListNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        node = _context.allocNode!(typeof(node))();
        while(true)
        {
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.identifier) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected identifier when looking for a NamedValue",
                token.location, "encountered token of type ", token.type
            );

            Asn1ValueNode value;
            if(auto r = Value(value)) return r;
            node.items.put(_context.allocNode!Asn1NamedValueNode(
                _context.allocNode!Asn1IdentifierTokenNode(token),
                value
            ));

            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.comma) break;
            consume().resultAssert;
        }

        return Result.noError;
    }

    Result ObjIdComponentsList(out Asn1ObjIdComponentsListNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        node = _context.allocNode!(typeof(node))();
        while(true)
        {
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.identifier)
            {
                Asn1Token lookahead;
                const savedLexerLookahead = _lexer;
                consume().resultAssert;

                if(auto r = consume(lookahead)) return r;
                if(lookahead.type == Asn1Token.Type.leftParenthesis)
                {
                    const identifierToken = token;
                    if(auto r = peek(token)) return r;
                    
                    if(token.type == Asn1Token.Type.number)
                    {
                        consume().resultAssert;
                        node.items.put(_context.allocNode!Asn1ObjIdComponentsNode(
                            _context.allocNode!Asn1NameAndNumberFormNode(
                                _context.allocNode!Asn1IdentifierTokenNode(identifierToken),
                                _context.allocNode!Asn1NumberFormNode(
                                    _context.allocNode!Asn1NumberTokenNode(token)
                                )
                            )
                        ));
                    }
                    else
                    {
                        Asn1DefinedValueNode definedValue;
                        if(auto r = DefinedValue(definedValue)) return r.notInitial;
                        
                        node.items.put(_context.allocNode!Asn1ObjIdComponentsNode(
                            _context.allocNode!Asn1NameAndNumberFormNode(
                                _context.allocNode!Asn1IdentifierTokenNode(identifierToken),
                                _context.allocNode!Asn1NumberFormNode(definedValue)
                            )
                        ));
                    }

                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.rightParenthesis) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `)` to denote end of named object identifier part",
                        token.location, "encountered token of type ", token.type
                    );
                }
                else
                {
                    _lexer = savedLexerLookahead;
                    Asn1DefinedValueNode definedValue;
                    if(auto r = DefinedValue(definedValue)) return r.notInitial;
                    node.items.put(_context.allocNode!Asn1ObjIdComponentsNode(
                        definedValue
                    ));
                }
            }
            else return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected identifier when reading object identifier component list",
                token.location, "encountered token of type ", token.type
            );

            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.rightBracket) break; // Intentionally not consumed, left for the parent parser
        }

        return Result.noError;
    }

    Result Value(out Asn1ValueNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;

        void makeBuiltin(NodeT, Args...)(Args args)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1BuiltinValueNode(
                    _context.allocNode!NodeT(args)
                ),
            );
        }

        switch(token.type) with(Asn1Token.Type)
        {
            case cstring:
                makeBuiltin!Asn1UnresolvedStringValueNode(
                    _context.allocNode!Asn1CstringTokenNode(token)
                );
                return Result.noError;
            case hstring:
                makeBuiltin!Asn1UnresolvedStringValueNode(
                    _context.allocNode!Asn1HstringTokenNode(token)
                );
                return Result.noError;
            case bstring:
                makeBuiltin!Asn1UnresolvedStringValueNode(
                    _context.allocNode!Asn1BstringTokenNode(token)
                );
                return Result.noError;
            case rCONTAINING:
                Asn1ValueNode value;
                if(auto r = Value(value)) return r;
                makeBuiltin!Asn1UnresolvedStringValueNode(
                    _context.allocNode!(Asn1UnresolvedStringValueNode.Containing)(value)
                );
                return Result.noError;

            case rTRUE:
                makeBuiltin!Asn1BooleanValueNode(
                    _context.allocNode!(Asn1BooleanValueNode.True)(token),
                );
                return Result.noError;
            case rFALSE:
                makeBuiltin!Asn1BooleanValueNode(
                    _context.allocNode!(Asn1BooleanValueNode.False)(token),
                );
                return Result.noError;

            case rNULL:
                makeBuiltin!Asn1NullValueNode(token);
                return Result.noError;

            case number:
                makeBuiltin!Asn1IntegerValueNode(
                    _context.allocNode!Asn1SignedNumberNode(
                        _context.allocNode!Asn1NumberTokenNode(token)
                    )
                );
                return Result.noError;

            case realNumber:
                makeBuiltin!Asn1RealValueNode(
                    _context.allocNode!Asn1NumericRealValueNode(
                        _context.allocNode!Asn1RealNumberTokenNode(token)
                    )
                );
                return Result.noError;

            case hyphenMinus:
                Asn1Token numberToken;
                if(auto r = consume(numberToken)) return r;
                
                if(numberToken.type == number)
                {
                    makeBuiltin!Asn1IntegerValueNode(
                        _context.allocNode!Asn1SignedNumberNode(
                            _context.allocNode!(Asn1SignedNumberNode.Negative)(
                                _context.allocNode!Asn1NumberTokenNode(numberToken)
                            )
                        )
                    );
                }
                else if(numberToken.type == realNumber)
                {
                    makeBuiltin!Asn1RealValueNode(
                        _context.allocNode!Asn1NumericRealValueNode(
                            _context.allocNode!(Asn1NumericRealValueNode.Negative)(
                                _context.allocNode!Asn1RealNumberTokenNode(numberToken)
                            )
                        )
                    );
                }
                else return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected number or realNumber following hyphen to denote a negative SignedNumber",
                    numberToken.location, "encountered token of type ", numberToken.type
                );

                return Result.noError;

            case rPLUS_INFINITY:
                makeBuiltin!Asn1RealValueNode(
                    _context.allocNode!Asn1SpecialRealValueNode(
                        _context.allocNode!Asn1PlusInfinityNode(token)
                    )
                );
                return Result.noError;
            case rMINUS_INFINITY:
                makeBuiltin!Asn1RealValueNode(
                    _context.allocNode!Asn1SpecialRealValueNode(
                        _context.allocNode!Asn1MinusInfinityNode(token)
                    )
                );
                return Result.noError;

            case identifier:
            case typeReference:
                _lexer = savedLexer;
                
                Asn1DefinedValueNode value;
                if(auto r = DefinedValue(value)) return r;
                
                node = _context.allocNode!Asn1ValueNode(
                    _context.allocNode!Asn1ReferencedValueNode(value)
                );
                return Result.noError;

            case leftBracket:
                Result checkEnd(string Context)()
                {
                    static immutable ErrorMsg = "expected `}` to close "~Context;

                    if(auto r = consume(token)) return r;
                    if(token.type != rightBracket) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        ErrorMsg,
                        token.location, "encountered token of type ", token.type
                    );
                    return Result.noError;
                }

                if(auto r = peek(token)) return r;
                if(token.type == rightBracket)
                {
                    makeBuiltin!Asn1UnresolvedSequenceValueNode(
                        _context.allocNode!Asn1EmptyNode(token)
                    );
                    consume().resultAssert;
                    return Result.noError;
                }

                // Figure out which type of value list we're dealing with by
                // performing a lookahead. Not efficient but it's so much more
                // simpler than figuring it on-the-fly.
                    const savedLexerSeq = _lexer;

                // If a left parenthesis shows up directly after any identifier, then it's an OBJECT IDENTIFIER sequence,
                // as no other sequence-looking value syntax allows for NameAndNumberForm.
                //      { iso-yada(123) }
                //      { iso-yada-123 asn1(123) }
                //
                // If no commas show up and there's only 1 value, then it's ambiguous, so will default to
                // a ValueList.
                //      { my-integer }
                //
                // (Values in the form of `a { yada }` are ambiguous between a named Sequence value and a
                //  parameterised value)
                //
                // If no commas show up and there's 1 ambiguous value, then assume it's a NamedValueList.
                //      { iso-yada-123 asn1 }
                //
                // If a comma is found; multiple non-named values exist, and any number
                // of ambiguous values exist then it's a ValueList.
                //      { my, value }
                //      { my, ambiguous {} }
                //
                // If a comma is found, and only ambiguous values exists, assume it's a NamedValueList.
                //      { ambiguous {} }
                //      { ambiguous {}, twobiguous {} }
                //
                // If a comma is found, and any amount of non-ambiguous named values exist, it's a NamedValueList.
                //      { ambiguous {}, except this }
                //
                // DefinedValue allows for a ParameterizedValue, which uses `{}` to define parameters, 
                // so we need to keep track of whether we're in a parameter list or not and ignore everything inside one.
                //      { some { template, params }, here }
                //
                // This loop also keeps track of how many identifiers show up side-by-side, but it's
                // currently (and probably never) needed as a way to sort out ambiguity.
                //
                // Semantic Analysis will perform the rest of the validation, e.g. sometimes what looks like a
                // NamedValueList is also a valid OBJECT IDENTIFIER sequence, so type information will be used to
                // clear up ambiguity.
                ulong bracketNesting;
                ulong soloValues;
                ulong ambiguousNamedValues;
                ulong definiteNamedValues;
                ulong longestIdChain;
                ulong idChain;
                bool foundComma;

                Result skipParams()
                {
                    Asn1Token tok;
                    if(auto r = peek(tok)) return r;
                    if(tok.type == leftBracket)
                    {
                        bracketNesting++;
                        consume.resultAssert();
                    }

                    while(bracketNesting > 0)
                    {
                        if(auto r = consume(tok)) return r;
                        if(tok.type == leftBracket)
                            bracketNesting++;
                        else if(tok.type == rightBracket)
                            bracketNesting--;
                        else if(tok.type == eof) return _lexer.makeError(
                            Asn1ParserError.nonInitialTokenNotFound,
                            "hit eof when looking for `}` to close sequence when performing lookahead - unterminated sequence list",
                            token.location, "encountered token of type ", token.type
                        );
                    }

                    return Result.noError;
                }

                void resetIdChain()
                {
                    if(idChain > longestIdChain)
                        longestIdChain = idChain;
                    idChain = 0;
                }

                while(true)
                {
                    Asn1Token lookahead;
                    if(auto r = consume(lookahead)) return r;

                    if(lookahead.type == identifier)
                    {
                        idChain++;
                        if(auto r = consume(lookahead)) return r;
                        if(lookahead.type == leftBracket)
                        {
                            bracketNesting++;
                            if(auto r = skipParams()) return r;
                            ambiguousNamedValues++;
                        }
                        else if(lookahead.type == comma)
                        {
                            foundComma = true;
                            soloValues++;
                        }
                        else if(lookahead.type == leftParenthesis)
                        {
                            _lexer = savedLexerSeq;
                            Asn1ObjIdComponentsListNode componentList;
                            if(auto r = ObjIdComponentsList(componentList)) return r.notInitial;
                            makeBuiltin!Asn1UnresolvedSequenceValueNode(componentList);
                            return checkEnd!"object identifier component list sequence"();
                        }
                        else if(lookahead.type == rightBracket)
                        {
                            soloValues++;
                            break;
                        }
                        else
                        {
                            resetIdChain();
                            definiteNamedValues++;
                        }
                    }
                    else if(lookahead.type == leftBracket)
                    {
                        resetIdChain();
                        bracketNesting++;
                        if(auto r = skipParams()) return r;
                    }
                    else if(lookahead.type == comma)
                        foundComma = true;
                    else if(lookahead.type == typeReference)
                        assert(false, "TODO: Short circuit into a parameterised value's parameter list");
                    else if(lookahead.type == rightBracket)
                        break;
                    else if(lookahead.type == eof) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "hit eof when looking for `}` to close sequence when performing lookahead - unterminated sequence list",
                        token.location, "encountered token of type ", token.type
                    );
                    else
                    {
                        resetIdChain();
                        soloValues++;
                    }
                }
                _lexer = savedLexerSeq;

                if(
                    (soloValues == 1 && ambiguousNamedValues == 0 && definiteNamedValues == 0)
                    || (soloValues > 1 && ambiguousNamedValues >= 0 && definiteNamedValues == 0 && foundComma)
                )
                {
                    Asn1ValueListNode valueList;
                    if(auto r = ValueList(valueList)) return r.notInitial;
                    makeBuiltin!Asn1UnresolvedSequenceValueNode(valueList);
                    return checkEnd!"value list sequence"();
                }
                else if(
                    (soloValues == 0 && ambiguousNamedValues + definiteNamedValues == 1)
                    || (soloValues == 0 && ambiguousNamedValues + definiteNamedValues > 1 && foundComma)
                )
                {
                    Asn1NamedValueListNode valueList;
                    if(auto r = NamedValueList(valueList)) return r.notInitial;
                    makeBuiltin!Asn1UnresolvedSequenceValueNode(valueList);
                    return checkEnd!"named value list sequence"();
                }
                else if(!foundComma) // NOTE: No comma but (potentially) multiple values exist
                {
                    Asn1ObjIdComponentsListNode componentList;
                    if(auto r = ObjIdComponentsList(componentList)) return r.notInitial;
                    makeBuiltin!Asn1UnresolvedSequenceValueNode(componentList);
                    return checkEnd!"object identifier component list sequence"();
                }
                else if(soloValues > 0 && definiteNamedValues > 0) return _lexer.makeError(
                    Asn1ParserError.invalidSyntax,
                    "sequence value appears to consist of both Values and NamedValues, this is never a valid construction",
                    token.location, 
                    "soloValues=", soloValues, 
                    " definiteNamedValue=", definiteNamedValues,
                    " ambiguousNamedValues=", ambiguousNamedValues
                );

                return _lexer.makeError(
                    Asn1ParserError.bug,
                    "bug: Unable to determine what type of sequence is formed",
                    token.location,
                    "soloValues=", soloValues, 
                    " definiteNamedValue=", definiteNamedValues,
                    " ambiguousNamedValues=", ambiguousNamedValues,
                );

            default: return _lexer.makeError(
                Asn1ParserError.oneOfNoMatches,
                "expected Value",
                token.location, "encountered token of type ", token.type
            );
        }
    }
}

/++++ Unittests ++++/

version(unittest)
{
    import std.meta : AliasSeq;
    import juptune.core.util : resultAssert, resultAssertSameCode;
}

@("Asn1Parser - Type - General Success")
unittest
{
    static struct T
    {
        string input;
        void function(Asn1TypeNode node) verify;
    }

    auto cases = [
        "BIT STRING": T("BIT STRING", (n){ 
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1BitStringTypeNode.isNode!(Asn1BitStringTypeNode.Plain)); 
        }),
        "BIT STRING - named": T("BIT STRING { a(0), b(1) }", (n){ 
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1BitStringTypeNode.isNode!Asn1NamedBitListNode); 
        }),
        "BOOLEAN": T("BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1BooleanTypeNode);
        }),
        "BMPString": T("BMPString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1BMPStringNode);
        }),
        "GeneralString": T("GeneralString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1GeneralStringNode);
        }),
        "GraphicString": T("GraphicString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1GraphicStringNode);
        }),
        "IA5String": T("IA5String", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1IA5StringNode);
        }),
        "ISO646String": T("ISO646String", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1ISO646StringNode);
        }),
        "NumericString": T("NumericString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1NumericStringNode);
        }),
        "PrintableString": T("PrintableString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1PrintableStringNode);
        }),
        "TeletexString": T("TeletexString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1TeletexStringNode);
        }),
        "T61String": T("T61String", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1T61StringNode);
        }),
        "UniversalString": T("UniversalString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1UniversalStringNode);
        }),
        "UTF8String": T("UTF8String", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1UTF8StringNode);
        }),
        "VideotexString": T("VideotexString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1VideotexStringNode);
        }),
        "VisibleString": T("VisibleString", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.asNode!Asn1RestrictedCharacterStringTypeNode
                .isNode!Asn1VisibleStringNode);
        }),
        "CHARACTER STRING": T("CHARACTER STRING", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode.isNode!Asn1UnrestrictedCharacterStringTypeNode);
        }),
        "CHOICE - RootAlternativeTypeList - Single": T(
            "CHOICE { a BOOLEAN }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.asNode!Asn1RootAlternativeTypeListNode.getNode!Asn1AlternativeTypeListNode
                    .items.length == 1
                );
            }
        ),
        "CHOICE - RootAlternativeTypeList - Multiple": T(
            "CHOICE { a BOOLEAN, b BIT STRING, c CHOICE { a BOOLEAN } }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.asNode!Asn1RootAlternativeTypeListNode.getNode!Asn1AlternativeTypeListNode
                    .items.length == 3
                );
            }
        ),
        "CHOICE - Case1 - Alternative": T(
            "CHOICE { a BOOLEAN, ... !20 }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.isNode!(Asn1AlternativeTypeListsNode.Case1));
            }
        ),
        "CHOICE - Case1 - Alternative 2": T(
            "CHOICE { a BOOLEAN, ... !20, ... }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.isNode!(Asn1AlternativeTypeListsNode.Case1));
            }
        ),
        "CHOICE - Case1 - Alternative 3": T(
            "CHOICE { a BOOLEAN, ... !20, b BOOLEAN, [[ 20: c INTEGER ]] }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.isNode!(Asn1AlternativeTypeListsNode.Case1));
            }
        ),
        "CHOICE - Case1 - Alternative 4": T(
            "CHOICE { a BOOLEAN, ..., [[ 20: b BOOLEAN, c INTEGER ]], ... }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode.getNode!Asn1AlternativeTypeListsNode.isNode!(Asn1AlternativeTypeListsNode.Case1));
            }
        ),
        "EMBEDDED PDV": T("EMBEDDED PDV", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1EmbeddedPDVTypeNode);
        }),
        "ENUMERATED - RootEnumeration - Single": T(
            "ENUMERATED { a }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode.getNode!Asn1EnumerationsNode.asNode!Asn1RootEnumerationNode.getNode!Asn1EnumerationNode
                    .items.length == 1
                );
            }
        ),
        "ENUMERATED - RootEnumeration - Multiple": T(
            "ENUMERATED { a, b(1), c(-2) }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode.getNode!Asn1EnumerationsNode.asNode!Asn1RootEnumerationNode.getNode!Asn1EnumerationNode
                    .items.length == 3
                );
            }
        ),
        "ENUMERATED - Case1": T(
            "ENUMERATED { a, ... !20 }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode.getNode!Asn1EnumerationsNode.isNode!(Asn1EnumerationsNode.Case1));
            }
        ),
        "ENUMERATED - Case2": T(
            "ENUMERATED { a, ... !20, b }", (n){
                assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode.getNode!Asn1EnumerationsNode.isNode!(Asn1EnumerationsNode.Case2));
            }
        ),
        "EXTERNAL": T("EXTERNAL", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1ExternalTypeNode);
        }),
        "INTEGER - Plain": T("INTEGER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1IntegerTypeNode.isNode!(Asn1IntegerTypeNode.Plain));
        }),
        "INTEGER - NamedNumberList - Single": T("INTEGER { a(1) }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1IntegerTypeNode.asNode!Asn1NamedNumberListNode
                .items.length == 1
            );
        }),
        "INTEGER - NamedNumberList - Multiple": T("INTEGER { a(1), b(2), c(3) }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1IntegerTypeNode.asNode!Asn1NamedNumberListNode
                .items.length == 3
            );
        }),
        "NULL": T("NULL", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1NullTypeNode);
        }),
        "OBJECT IDENTIFIER": T("OBJECT IDENTIFIER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1ObjectIdentifierTypeNode);
        }),
        "OCTET STRING": T("OCTET STRING", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1OctetStringTypeNode);
        }),
        "REAL": T("REAL", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1RealTypeNode);
        }),
        "RELATIVE-OID": T("RELATIVE-OID", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.isNode!Asn1RelativeOIDTypeNode);
        }),
        "SEQUENCE - Empty": T("SEQUENCE {}", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.isNode!(Asn1SequenceTypeNode.Empty));
        }),
        "SEQUENCE - Single - ComponentType - Plain": T("SEQUENCE { a BOOLEAN }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SEQUENCE - Single - ComponentType - Optional": T("SEQUENCE { a BOOLEAN OPTIONAL }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SEQUENCE - Single - ComponentType - COMPONENTS OF": T("SEQUENCE { COMPONENTS OF INTEGER }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SEQUENCE - Multiple": T("SEQUENCE { a BOOLEAN, b INTEGER OPTIONAL, COMPONENTS OF INTEGER }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 3
            );
        }),
        "SEQUENCE - Case1": T("SEQUENCE { a BOOLEAN, ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case1);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SEQUENCE - Case1 - Alternative": T("SEQUENCE { a BOOLEAN, ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case1);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ElipsisNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1EmptyNode);
        }),
        "SEQUENCE - Case2": T("SEQUENCE { a BOOLEAN, ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ..., d BIT STRING, e INTEGER }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case2);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!(Asn1ComponentTypeListsNode.Case2.Additional).getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 2
            );
        }),
        "SEQUENCE - Case3": T("SEQUENCE { ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ..., d BIT STRING, e INTEGER }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case3);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 2
            );
        }),
        "SEQUENCE - Case4": T("SEQUENCE { ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SEQUENCE - Case4 - Alternative": T("SEQUENCE { ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ElipsisNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1EmptyNode);
        }),
        "SEQUENCE - Redudant case": T("SEQUENCE { ... !20, ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ExceptionSpecNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SEQUENCE OF - Type": T("SEQUENCE OF INTEGER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceOfTypeNode.isNode!Asn1TypeNode);
        }),
        "SEQUENCE OF - NamedType": T("SEQUENCE OF i INTEGER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceOfTypeNode.isNode!Asn1NamedTypeNode);
        }),
        "SET - Empty": T("SET {}", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.isNode!(Asn1SetTypeNode.Empty));
        }),
        "SET - Single - ComponentType - Plain": T("SET { a BOOLEAN }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SET - Single - ComponentType - Optional": T("SET { a BOOLEAN OPTIONAL }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SET - Single - ComponentType - COMPONENTS OF": T("SET { COMPONENTS OF INTEGER }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
        }),
        "SET - Multiple": T("SET { a BOOLEAN, b INTEGER OPTIONAL, COMPONENTS OF INTEGER }", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 3
            );
        }),
        "SET - Case1": T("SET { a BOOLEAN, ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case1);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SET - Case1 - Alternative": T("SET { a BOOLEAN, ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case1);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ElipsisNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1EmptyNode);
        }),
        "SET - Case2": T("SET { a BOOLEAN, ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ..., d BIT STRING, e INTEGER }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case2);
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 1
            );
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!(Asn1ComponentTypeListsNode.Case2.Additional).getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 2
            );
        }),
        "SET - Case3": T("SET { ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ..., d BIT STRING, e INTEGER }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case3);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode
                .items.length == 2
            );
        }),
        "SET - Case4": T("SET { ... !-20, b BOOLEAN, [[ 20: c INTEGER ]], ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.asNode!Asn1ExceptionSpecNode.asNode!Asn1ExceptionIdentificationNode.asNode!Asn1SignedNumberNode.asNode!(Asn1SignedNumberNode.Negative).getNode!Asn1NumberTokenNode
                .token.asNumber.value == 20
            );
            assert(node.getNode!Asn1ExtensionAdditionsNode.asNode!Asn1ExtensionAdditionListNode
                .items.length == 2
            );
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SET - Case4 - Alternative": T("SET { ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ElipsisNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1EmptyNode);
        }),
        "SET - Redudant case": T("SET { ... !20, ... }", (n){
            auto node = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetTypeNode.asNode!Asn1ComponentTypeListsNode.asNode!(Asn1ComponentTypeListsNode.Case4);
            assert(node.getNode!Asn1ExtensionAndExceptionNode.isNode!Asn1ExceptionSpecNode);
            assert(node.getNode!Asn1ExtensionAdditionsNode.isNode!Asn1EmptyNode);
            assert(node.getNode!Asn1OptionalExtensionMarkerNode.isNode!Asn1ElipsisNode);
        }),
        "SET OF - Type": T("SET OF INTEGER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetOfTypeNode.isNode!Asn1TypeNode);
        }),
        "SET OF - NamedType": T("SET OF i INTEGER", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1SetOfTypeNode.isNode!Asn1NamedTypeNode);
        }),
        "TAG - Default": T("[UNIVERSAL 0] BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode.isNode!(Asn1TaggedTypeNode.Default));
        }),
        "TAG - Explicit": T("[APPLICATION 0] EXPLICIT BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode.isNode!(Asn1TaggedTypeNode.Explicit));
        }),
        "TAG - Implicit": T("[PRIVATE 0] IMPLICIT BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode.isNode!(Asn1TaggedTypeNode.Implicit));
        }),
        "TAG - No tag class": T("[0] BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode.isNode!(Asn1TaggedTypeNode.Default));
        }),
    ];

    foreach(name, test; cases)
    {
        try
        {
            import std.conv : to;

            Asn1ParserContext context;
            auto lexer = Asn1Lexer(test.input);
            auto parser = Asn1Parser(lexer, &context);

            Asn1TypeNode node;
            parser.Type(node).resultAssert;
            test.verify(node);

            Asn1Token token;
            parser.consume(token).resultAssert;
            assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1Parser - Value - General Success")
unittest
{
    static struct T
    {
        string input;
        void function(Asn1ValueNode node) verify;
    }

    auto cases = [
        "UnresolvedString - bstring": T("'0101'B", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedStringValueNode.isNode!Asn1BstringTokenNode); 
        }),
        "UnresolvedString - hstring": T("'DEAD'H", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedStringValueNode.isNode!Asn1HstringTokenNode); 
        }),
        "UnresolvedString - cstring": T(`"foo"`, (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedStringValueNode.isNode!Asn1CstringTokenNode); 
        }),
        "UnresolvedString - CONTAINING value": T(`CONTAINING "boo"`, (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedStringValueNode.isNode!(Asn1UnresolvedStringValueNode.Containing)); 
        }),
        "boolean - FALSE": T("TRUE", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1BooleanValueNode.isNode!(Asn1BooleanValueNode.True)); 
        }),
        "boolean - FALSE": T("FALSE", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1BooleanValueNode.isNode!(Asn1BooleanValueNode.False)); 
        }),
        "NULL": T("NULL", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.isNode!Asn1NullValueNode); 
        }),
        "integer - positive": T("20", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1IntegerValueNode.asNode!Asn1SignedNumberNode.isNode!Asn1NumberTokenNode); 
        }),
        "integer - negative": T("-20", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1IntegerValueNode.asNode!Asn1SignedNumberNode.isNode!(Asn1SignedNumberNode.Negative)); 
        }),
        "real - positive": T("20.0", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1RealValueNode.asNode!Asn1NumericRealValueNode.isNode!Asn1RealNumberTokenNode); 
        }),
        "real - negative": T("-20.0", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1RealValueNode.asNode!Asn1NumericRealValueNode.isNode!(Asn1NumericRealValueNode.Negative)); 
        }),
        "real - PLUS-INFINITY": T("PLUS-INFINITY", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1RealValueNode.asNode!Asn1SpecialRealValueNode.isNode!Asn1PlusInfinityNode); 
        }),
        "real - MINUS-INFINITY": T("MINUS-INFINITY", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1RealValueNode.asNode!Asn1SpecialRealValueNode.isNode!Asn1MinusInfinityNode); 
        }),
        "UnresolvedSequence - Empty": T("{}", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.isNode!Asn1EmptyNode); 
        }),
        "UnresolvedSequence - ValueList - Single": T("{ 1 }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ValueListNode
                .items.length == 1
            ); 
        }),
        "UnresolvedSequence - ValueList - Multiple": T("{ 1, TRUE, 'DEADBEEF'H }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ValueListNode
                .items.length == 3
            ); 
        }),
        // "UnresolvedSequence - ValueList - Multiple w/ Ambiguous": T("{ 1, value {}, 'DEADBEEF'H }", (n){ 
        //     assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ValueListNode
        //         .items.length == 3
        //     ); 
        // }),
        "UnresolvedSequence - NamedValueList - Single": T("{ a 1 }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 1
            ); 
        }),
        "UnresolvedSequence - NamedValueList - Multiple": T("{ a 1, b 12, c 42 }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 3
            ); 
        }),
        "UnresolvedSequence - NamedValueList - Ambiguous Single": T("{ a {} }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 1
            ); 
        }),
        "UnresolvedSequence - NamedValueList - Ambiguous Multiple": T("{ a {}, b {} }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 2
            ); 
        }),
        "UnresolvedSequence - NamedValueList - Ambiguous mixed": T("{ a {}, except 2 }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 2
            ); 
        }),
        "UnresolvedSequence - NamedValueList - Ambiguous Multiple 2": T("{ a b }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1NamedValueListNode
                .items.length == 1
            ); 
        }),
        "UnresolvedSequence - ObjIdComponentsList - Unambiguous Single": T("{ a (1) }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ObjIdComponentsListNode
                .items.length == 1
            );
        }),
        "UnresolvedSequence - ObjIdComponentsList - Unambiguous Single Alternative": T("{ a (def) }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ObjIdComponentsListNode
                .items.length == 1
            );
        }),
        "UnresolvedSequence - ObjIdComponentsList - Unambiguous Single Alternative 2": T("{ a (MODULE.def) }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ObjIdComponentsListNode
                .items.length == 1
            );
        }),
        "UnresolvedSequence - ObjIdComponentsList - Unambiguous Multiple": T("{ a b c }", (n){ 
            assert(n.asNode!Asn1BuiltinValueNode.asNode!Asn1UnresolvedSequenceValueNode.asNode!Asn1ObjIdComponentsListNode
                .items.length == 3
            );
        }),
    ];

    foreach(name, test; cases)
    {
        try
        {
            import std.conv : to;

            Asn1ParserContext context;
            auto lexer = Asn1Lexer(test.input);
            auto parser = Asn1Parser(lexer, &context);

            Asn1ValueNode node;
            parser.Value(node).resultAssert;
            test.verify(node);

            Asn1Token token;
            parser.consume(token).resultAssert;
            assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}