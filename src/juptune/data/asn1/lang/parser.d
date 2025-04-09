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
    listMustNotBeEmpty,
    bug,
    invalidSyntax,
}

// Some parsers are also subparsers of other parsers! So we need a shortcut
// to more finely control whether an "initial token not found" error is reported or not.
private Result notInitial(Result result) @nogc nothrow
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
 +
 +  As most of this file is very, _very_ similar, verbose code, this file is free to take liberties in the name
 +  of terseness. i.e. no `this.` spam; usage of the `if(auto r = ...)` pattern; less whitespace usage, etc.
 + ++/
struct Asn1Parser
{
    private
    {
        Asn1ParserContext* _context;
        Asn1Lexer          _lexer;
        ulong              _level;
    }

    @nogc nothrow:

    this(Asn1Lexer lexer, Asn1ParserContext* context)
    in(context !is null, "context cannot be null")
    {
        this._context = context;
        this._lexer   = lexer;
    }

    /++++ Standard parsing functions/helpers ++++/

    Result peek(scope out Asn1Token token)
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

    Result consume(scope out Asn1Token token)
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

    Result ModuleDefinition(out Asn1ModuleDefinitionNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;

        Asn1ModuleIdentifierNode identifier;
        if(auto r = ModuleIdentifier(identifier)) return r;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rDEFINITIONS) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `DEFINITIONS` when parsing ModuleDefinition",
            token.location, "encountered token of type ", token.type
        );

        Asn1TagDefaultNode tagDefault;
        if(auto r = peek(token)) return r;
        switch(token.type) with(Asn1Token.Type)
        {
            case rEXPLICIT:
            case rIMPLICIT:
            case rAUTOMATIC:
                consume().resultAssert;

                const typeToken = token;
                if(auto r = consume(token)) return r;
                if(token.type != rTAGS) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `TAGS` when parsing ModuleDefinition",
                    token.location, "encountered token of type ", token.type
                );

                if(typeToken.type == rEXPLICIT)
                    tagDefault = _context.allocNode!(typeof(tagDefault))(_context.allocNode!Asn1ExplicitTagsNode(typeToken));
                else if(typeToken.type == rIMPLICIT)
                    tagDefault = _context.allocNode!(typeof(tagDefault))(_context.allocNode!Asn1ImplicitTagsNode(typeToken));
                else if(typeToken.type == rAUTOMATIC)
                    tagDefault = _context.allocNode!(typeof(tagDefault))(_context.allocNode!Asn1AutomaticTagsNode(typeToken));
                break;

            default:
                tagDefault = _context.allocNode!(typeof(tagDefault))(
                    _context.allocNode!Asn1EmptyNode(token)
                );
                break;
        }

        Asn1ExtensionDefaultNode extensionDefault;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rEXTENSIBILITY)
        {
            consume().resultAssert;
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.rIMPLIED) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected `IMPLIED` to denote `EXTENSIBILITY IMPLIED` when parsing ModuleDefinition",
                token.location, "encountered token of type ", token.type
            );
            extensionDefault = _context.allocNode!(typeof(extensionDefault))(
                _context.allocNode!Asn1ExtensibilityImpliedNode(token)
            );
        }
        else
        {
            extensionDefault = _context.allocNode!(typeof(extensionDefault))(
                _context.allocNode!Asn1EmptyNode(token)
            );
        }

        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.assignment) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `::=` when parsing ModuleDefinition",
            token.location, "encountered token of type ", token.type
        );
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rBEGIN) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `BEGIN` when parsing ModuleDefinition",
            token.location, "encountered token of type ", token.type
        );

        Asn1ModuleBodyNode modBod;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rEND)
        {
            modBod = _context.allocNode!(typeof(modBod))(
                _context.allocNode!Asn1EmptyNode(token)
            );
        }
        else if(auto r = ModuleBody(modBod)) return r.notInitial;

        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rEND) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `END` when parsing ModuleDefinition",
            token.location, "encountered token of type ", token.type
        );
        
        node = _context.allocNode!(typeof(node))(
            identifier,
            tagDefault,
            extensionDefault,
            modBod
        );
        return Result.noError;
    }

    Result ModuleBody(out Asn1ModuleBodyNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;
        
        Asn1Token token;

        Asn1ExportsNode exports;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rEXPORTS)
        {
            consume().resultAssert;
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.rALL)
            {
                consume().resultAssert;
                if(auto r = consume(token)) return r;
                if(token.type != Asn1Token.Type.semicolon) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `;` to denote `EXPORT ALL ;` when parsing ModuleDefinition",
                    token.location, "encountered token of type ", token.type
                );
                exports = _context.allocNode!(typeof(exports))(
                    _context.allocNode!Asn1ExportsAllNode(token)
                );
            }
            else
            {
                Asn1SymbolListNode symbols;
                if(auto r = peek(token)) return r;
                if(token.type != Asn1Token.Type.semicolon)
                {
                    if(auto r = SymbolList(symbols)) return r.notInitial;
                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.semicolon) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `;` to denote end of `EXPORT` when parsing ModuleDefinition",
                        token.location, "encountered token of type ", token.type
                    );
                    exports = _context.allocNode!(typeof(exports))(
                        _context.allocNode!Asn1SymbolsExportedNode(symbols)
                    );
                }
                else
                {
                    consume().resultAssert;
                    exports = _context.allocNode!(typeof(exports))(
                        _context.allocNode!Asn1SymbolsExportedNode(
                            _context.allocNode!Asn1EmptyNode(token)
                        )
                    );
                }
            }
        }
        else
        {
            exports = _context.allocNode!(typeof(exports))(
                _context.allocNode!Asn1EmptyNode(token)
            );
        }

        Asn1ImportsNode imports;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rIMPORTS)
        {
            consume().resultAssert;
            if(auto r = peek(token)) return r;

            if(token.type != Asn1Token.Type.semicolon)
            {
                auto importsList = _context.allocNode!Asn1SymbolsFromModuleListNode();
                while(true)
                {
                    Asn1SymbolListNode symbols;
                    if(auto r = SymbolList(symbols)) return r.notInitial;
                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.rFROM) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `;` to denote of `IMPORT ... FROM` when parsing Imports",
                        token.location, "encountered token of type ", token.type
                    );

                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.moduleReference) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected module reference after `FROM` when parsing an import",
                        token.location, "encountered token of type ", token.type
                    );
                    const modRefToken = token;

                    Asn1AssignedIdentifierNode assId;
                    if(auto r = peek(token)) return r;
                    if(token.type == Asn1Token.Type.leftBracket)
                    {
                        consume().resultAssert;
                        Asn1ObjIdComponentsListNode idList;
                        if(auto r = ObjIdComponentsList(idList)) return r.notInitial;
                        if(auto r = consume(token)) return r;
                        if(token.type != Asn1Token.Type.rightBracket) return _lexer.makeError(
                            Asn1ParserError.nonInitialTokenNotFound,
                            "expected `}` after module reference for `FROM` when parsing an import",
                            token.location, "encountered token of type ", token.type
                        );

                        assId = _context.allocNode!(typeof(assId))(
                            _context.allocNode!Asn1ObjectIdentifierValueNode(idList)
                        );
                    }
                    else
                    {
                        Asn1DefinedValueNode definedValue;
                        if(auto r = DefinedValue(definedValue))
                        {
                            if(!r.notInitial.isError(Asn1ParserError.nonInitialTokenNotFound))
                                return r;
                            assId = _context.allocNode!(typeof(assId))(
                                _context.allocNode!Asn1EmptyNode(token)
                            );
                        }
                        else
                            assId = _context.allocNode!(typeof(assId))(definedValue);
                    }

                    importsList.items.put(_context.allocNode!Asn1SymbolsFromModuleNode(
                        symbols,
                        _context.allocNode!Asn1GlobalModuleReferenceNode(
                            _context.allocNode!Asn1ModuleReferenceTokenNode(modRefToken),
                            assId
                        )
                    ));
                    
                    if(auto r = peek(token)) return r;
                    if(token.type == Asn1Token.Type.semicolon)
                    {
                        consume().resultAssert;
                        break;
                    }
                }
                imports = _context.allocNode!(typeof(imports))(
                    _context.allocNode!Asn1SymbolsImportedNode(importsList)
                );
            }
            else
            {
                consume().resultAssert;
                imports = _context.allocNode!(typeof(imports))(
                    _context.allocNode!Asn1SymbolsImportedNode(
                        _context.allocNode!Asn1EmptyNode(token)
                    )
                );
            }
        }
        else
        {
            imports = _context.allocNode!(typeof(imports))(
                _context.allocNode!Asn1EmptyNode(token)
            );
        }

        auto assList = _context.allocNode!Asn1AssignmentListNode();
        while(true)
        {
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.rEND) break;

            Asn1AssignmentNode ass;
            if(auto r = Assignment(ass)) return r;
            assList.items.put(ass); // Modern Poetry
        }

        node = _context.allocNode!(typeof(node))(
            _context.allocNode!(typeof(node).Case1)(
                exports,
                imports,
                assList
            )
        );
        return Result.noError;
    }

    Result SymbolList(out Asn1SymbolListNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;
        
        Asn1Token token;

        node = _context.allocNode!(typeof(node))();
        while(true)
        {
            Asn1ReferenceNode refNode;
            if(auto r = Reference(refNode)) return r;
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.leftBracket)
            {
                consume().resultAssert;
                if(auto r = consume(token)) return r;
                if(token.type != Asn1Token.Type.rightBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `}` to close parameter list for Symbol",
                    token.location, "encountered token of type ", token.type
                );

                node.items.put(_context.allocNode!Asn1SymbolNode(
                    _context.allocNode!Asn1ParameterizedReferenceNode(refNode)
                ));
            }
            else
                node.items.put(_context.allocNode!Asn1SymbolNode(refNode));

            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.comma) break;
            consume().resultAssert;
        }

        return Result.noError;
    }

    Result Reference(out Asn1ReferenceNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;
        
        Asn1Token token;
        if(auto r = consume(token)) return r;

        if(token.type == Asn1Token.Type.typeReference)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1TypeReferenceTokenNode(token)
            );
        }
        else if(token.type == Asn1Token.Type.valueReference)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ValueReferenceTokenNode(token)
            );
        }
        else return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected module or type reference when parsing Reference",
            token.location, "encountered token of type ", token.type
        ); 

        return Result.noError;
    }

    Result ModuleIdentifier(out Asn1ModuleIdentifierNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;
        
        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.moduleReference) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected module reference (starts with a capital) when parsing ModuleIdentifier",
            token.location, "encountered token of type ", token.type
        );
        const modRefToken = token;

        if(auto r = peek(token)) return r;
        if(token.type != Asn1Token.Type.leftBracket)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ModuleReferenceTokenNode(modRefToken),
                _context.allocNode!Asn1DefinitiveIdentifierNode(
                    _context.allocNode!Asn1EmptyNode(token)
                ),
            );
            return Result.noError;
        }
        consume().resultAssert;

        auto idList = _context.allocNode!Asn1DefinitiveObjIdComponentListNode();
        while(true)
        {
            if(auto r = consume(token)) return r;
            
            if(token.type == Asn1Token.Type.number)
            {
                idList.items.put(_context.allocNode!Asn1DefinitiveObjIdComponentNode(
                    _context.allocNode!Asn1DefinitiveNumberFormNode(
                        _context.allocNode!Asn1NumberTokenNode(token)
                    )
                ));
            }
            else if(token.type == Asn1Token.Type.identifier)
            {
                const identifierToken = token;
                if(auto r = peek(token)) return r;
                if(token.type == Asn1Token.Type.leftParenthesis)
                {
                    consume().resultAssert;
                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.number) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected number when parsing named module object identifier component",
                        token.location, "encountered token of type ", token.type
                    );

                    idList.items.put(_context.allocNode!Asn1DefinitiveObjIdComponentNode(
                        _context.allocNode!Asn1DefinitiveNameAndNumberFormNode(
                            _context.allocNode!Asn1IdentifierTokenNode(identifierToken),
                            _context.allocNode!Asn1DefinitiveNumberFormNode(
                                _context.allocNode!Asn1NumberTokenNode(token)
                            ),
                        )
                    ));

                    if(auto r = consume(token)) return r;
                    if(token.type != Asn1Token.Type.rightParenthesis) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `)` to close a named module object identifier component",
                        token.location, "encountered token of type ", token.type
                    );
                }
                else
                {
                    idList.items.put(_context.allocNode!Asn1DefinitiveObjIdComponentNode(
                        _context.allocNode!Asn1NameFormNode(
                            _context.allocNode!Asn1IdentifierTokenNode(identifierToken)
                        )
                    ));
                }
            }
            else return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected identifier or number when parsing module object identifier component",
                token.location, "encountered token of type ", token.type
            );

            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.rightBracket) break;
        }

        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rightBracket) return _lexer.makeError(
            Asn1ParserError.nonInitialTokenNotFound,
            "expected `}` to denote end of module object identifier component list",
            token.location, "encountered token of type ", token.type
        );

        node = _context.allocNode!(typeof(node))(
            _context.allocNode!Asn1ModuleReferenceTokenNode(modRefToken),
            _context.allocNode!Asn1DefinitiveIdentifierNode(idList),
        );
        return Result.noError;
    }

    Result Assignment(out Asn1AssignmentNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;

        if(token.type == Asn1Token.Type.typeReference)
        {
            const typeRefToken = token;

            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.assignment)
            {
                assert(false, "TODO: ValueSetTypeAssignment");

                Asn1TypeNode type;
                if(auto r = Type(type)) return r;
                if(auto r = consume(token)) return r;
                if(token.type != Asn1Token.Type.assignment) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `::=` following type when parsing a ValueSetAssignment",
                    token.location, "encoutered token of type ", token.type
                );

                Asn1ValueSetNode valueSet;
                if(auto r = false) return Result.noError;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1ValueSetTypeAssignmentNode(
                        _context.allocNode!Asn1TypeReferenceTokenNode(typeRefToken),
                        type,
                        valueSet
                    )
                );
            }
            else
            {
                consume().resultAssert;
                Asn1TypeNode type;
                if(auto r = Type(type)) return r;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1TypeAssignmentNode(
                        _context.allocNode!Asn1TypeReferenceTokenNode(typeRefToken),
                        type
                    )
                );
            }
        }
        else if(token.type == Asn1Token.Type.valueReference)
        {
            const valueRefToken = token;

            Asn1TypeNode type;
            if(auto r = Type(type)) return r;

            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.assignment) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected `::=` following value name when parsing a ValueAssignment",
                token.location, "encoutered token of type ", token.type
            );

            Asn1ValueNode value;
            if(auto r = Value(value)) return r;
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ValueAssignmentNode(
                    _context.allocNode!Asn1ValueReferenceTokenNode(valueRefToken),
                    type,
                    value
                )
            );
        }
        else return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected type or identifier when parsing Assignment",
            token.location, "encoutered token of type ", token.type
        );
        assert(node !is null, "Forgot to set node to a value");

        return Result.noError();
    }

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
            "expected `...` when looking for ExtensionAndException - did you add an extra comma within a SEQUENCE/SET/CHOICE?",
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
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;
        
        Asn1TypeNode plainType;
        if(auto r = PlainType(plainType)) return r;

        Asn1Token token;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.leftParenthesis)
        {
            Asn1ConstraintNode constraint;
            if(auto r = Constraint(constraint)) return r;
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ConstrainedTypeNode(
                    _context.allocNode!(Asn1ConstrainedTypeNode.Case1)(
                        plainType,
                        constraint
                    )
                )
            );
        }
        else
            node = plainType;

        return Result.noError;
    }

    Result PlainType(out Asn1TypeNode node)
    {
        import std.meta : AliasSeq;
        static struct StringType(NodeT_)
        {
            alias NodeT = NodeT_;
            Asn1Token.Type type;
        }

        static struct TypeListType(
            string Name_, 
            ListT_, 
            OfT_,
            ConstraintOfTypeT_,
            SizeConstraintOfTypeT_,
            ConstraintOfNamedTypeT_,
            SizeConstraintOfNamedTypeT_,
        )
        {
            static immutable Name = Name_;
            alias ListT = ListT_;
            alias OfT = OfT_;
            alias ConstraintOfTypeT = ConstraintOfTypeT_;
            alias SizeConstraintOfTypeT = SizeConstraintOfTypeT_;
            alias ConstraintOfNamedTypeT = ConstraintOfNamedTypeT_;
            alias SizeConstraintOfNamedTypeT = SizeConstraintOfNamedTypeT_;

            static immutable BeginErrorMsg = "expected opening bracket to begin `"~Name_~"` type list";
            static immutable EndErrorMsg = "expected closing bracket to end `"~Name_~"` type list";
            static immutable ConstraintMissingOfErrorMsg = "expected `OF` following constraint for `"~Name_~"`";

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

        void makeTypeWithConstraint(NodeT, Args...)(Args args)
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1ConstrainedTypeNode(
                    _context.allocNode!Asn1TypeWithConstraintNode(
                        _context.allocNode!NodeT(args)
                    )
                ),
            );
        }

        // TODO: ObjectClassFieldType

        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token, auxToken;
        if(auto r = consume(token)) return r;

        switch(token.type) with(Asn1Token.Type)
        {
            case identifier:
                const idToken = token;
                if(auto r = consume(token)) return r;
                if(token.type != leftArrow) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `<` after identifier when parsing selection type",
                    token.location, "encountered token of type ", token.type
                );

                Asn1TypeNode type;
                if(auto r = Type(type)) return r;

                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1ReferencedTypeNode(
                        _context.allocNode!Asn1SelectionTypeNode(
                            _context.allocNode!Asn1IdentifierTokenNode(
                                idToken
                            ),
                            type
                        )
                    )
                );
                return Result.noError;

            case typeReference:
                const typeRefToken = token;
                if(auto r = peek(token)) return r;
                if(token.type == dot)
                {
                    consume().resultAssert;
                    if(auto r = consume(token)) return r;
                    if(token.type != typeReference) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected typereference after `.` when parsing external type reference",
                        token.location, "encountered token of type ", token.type
                    );
                    node = _context.allocNode!(typeof(node))(
                        _context.allocNode!Asn1ReferencedTypeNode(
                            _context.allocNode!Asn1DefinedTypeNode(
                                _context.allocNode!Asn1ExternalTypeReferenceNode(
                                    _context.allocNode!Asn1ModuleReferenceTokenNode(
                                        typeRefToken
                                    ),
                                    _context.allocNode!Asn1TypeReferenceTokenNode(
                                        token
                                    )
                                )
                            )
                        )
                    );
                    return Result.noError;
                }

                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1ReferencedTypeNode(
                        _context.allocNode!Asn1DefinedTypeNode(
                            _context.allocNode!Asn1TypeReferenceTokenNode(
                                typeRefToken
                            )
                        )
                    )
                );
                return Result.noError;

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

            static foreach(UsefulT; [rGeneralizedTime, rUTCTime, rObjectDescriptor])
            {
                case UsefulT:
                    token.type = typeReference; // Forcefully coerce, since for all intents and purposes this is how it gets treated.
                    node = _context.allocNode!(typeof(node))(
                        _context.allocNode!Asn1ReferencedTypeNode(
                            _context.allocNode!Asn1UsefulTypeNode(
                                _context.allocNode!Asn1TypeReferenceTokenNode(token)
                            )
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
                TypeListType!(
                    "SEQUENCE", 
                    Asn1SequenceTypeNode, 
                    Asn1SequenceOfTypeNode,
                    Asn1TypeWithConstraintNode.SequenceConstraintType,
                    Asn1TypeWithConstraintNode.SequenceSizeConstraintType,
                    Asn1TypeWithConstraintNode.SequenceConstraintNamedType,
                    Asn1TypeWithConstraintNode.SequenceSizeConstraintNamedType,
                )(rSEQUENCE),
                TypeListType!(
                    "SET", 
                    Asn1SetTypeNode, 
                    Asn1SetOfTypeNode,
                    Asn1TypeWithConstraintNode.SetConstraintType,
                    Asn1TypeWithConstraintNode.SetSizeConstraintType,
                    Asn1TypeWithConstraintNode.SetConstraintNamedType,
                    Asn1TypeWithConstraintNode.SetSizeConstraintNamedType,
                )(rSET),
            ))
            {
                case Case.type:
                    Asn1ConstraintNode sizeConstraint;
                    Asn1ConstraintNode otherConstraint;
                    if(auto r = peek(token)) return r;
                    if(token.type == rSIZE)
                    {
                        consume().resultAssert;
                        if(auto r = Constraint(sizeConstraint)) return r.notInitial;
                    }
                    else if(token.type == leftParenthesis)
                    {
                        if(auto r = Constraint(otherConstraint)) return r.notInitial;
                    }
                    
                    if(auto r = consume(token)) return r;
                    if(token.type == rOF)
                    {
                        if(auto r = peek(token)) return r;
                        if(token.type == identifier)
                        {
                            Asn1NamedTypeNode namedType;
                            if(auto r = NamedType(namedType)) return r;

                            if(sizeConstraint !is null)
                            {
                                makeTypeWithConstraint!(Case.SizeConstraintOfNamedTypeT)(
                                    _context.allocNode!Asn1SizeConstraintNode(sizeConstraint),
                                    namedType
                                );
                            }
                            else if(otherConstraint !is null)
                            {
                                makeTypeWithConstraint!(Case.ConstraintOfNamedTypeT)(
                                    otherConstraint,
                                    namedType
                                );
                            }
                            else
                                makeBuiltin!(Case.OfT)(namedType);
                        }
                        else
                        {
                            Asn1TypeNode type;
                            if(auto r = Type(type)) return r;

                            if(sizeConstraint !is null)
                            {
                                makeTypeWithConstraint!(Case.SizeConstraintOfTypeT)(
                                    _context.allocNode!Asn1SizeConstraintNode(sizeConstraint),
                                    type
                                );
                            }
                            else if(otherConstraint !is null)
                            {
                                makeTypeWithConstraint!(Case.ConstraintOfTypeT)(
                                    otherConstraint,
                                    type
                                );
                            }
                            else
                                makeBuiltin!(Case.OfT)(type);
                        }

                        return Result.noError;
                    }
                    else if(sizeConstraint !is null || otherConstraint !is null) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        Case.ConstraintMissingOfErrorMsg,
                        token.location, "encountered token of type ", token.type
                    );

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
                Asn1ParserError.tokenNotFound,
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
            else if(token.type == Asn1Token.Type.number)
            {
                consume().resultAssert;
                node.items.put(_context.allocNode!Asn1ObjIdComponentsNode(
                    _context.allocNode!Asn1NumberFormNode(
                        _context.allocNode!Asn1NumberTokenNode(
                            token
                        )
                    )
                ));
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
                Asn1ParserError.tokenNotFound,
                "expected Value",
                token.location, "encountered token of type ", token.type
            );
        }
    }

    Result Constraint(out Asn1ConstraintNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.leftParenthesis) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected `(` to denote start of constraint",
            token.location, "encountered token of type ", token.type
        );

        Asn1ConstraintSpecNode constraintSpec;
        // TODO: Asn1GeneralConstraintNode

        Asn1ElementSetSpecNode rootSetSpec;
        if(auto r = ElementSetSpec(rootSetSpec)) return r;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.comma)
        {
            consume().resultAssert;
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.ellipsis) return _lexer.makeError(
                Asn1ParserError.tokenNotFound,
                "expected `...` to denote `, ...` as part of constraint spec",
                token.location, "encountered token of type ", token.type
            );
            
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.comma)
            {
                consume().resultAssert;
                Asn1ElementSetSpecNode additionalSetSpec;
                if(auto r = ElementSetSpec(additionalSetSpec)) return r;
                constraintSpec = _context.allocNode!(typeof(constraintSpec))(
                    _context.allocNode!Asn1SubtypeConstraintNode(
                        _context.allocNode!Asn1ElementSetSpecsNode(
                            _context.allocNode!(Asn1ElementSetSpecsNode.Case2)(
                                _context.allocNode!Asn1RootElementSetSpecNode(
                                    rootSetSpec
                                ),
                                _context.allocNode!Asn1AdditionalElementSetSpecNode(
                                    additionalSetSpec
                                )
                            )
                        )
                    )
                );
            }
            else
            {
                constraintSpec = _context.allocNode!(typeof(constraintSpec))(
                    _context.allocNode!Asn1SubtypeConstraintNode(
                        _context.allocNode!Asn1ElementSetSpecsNode(
                            _context.allocNode!(Asn1ElementSetSpecsNode.Case1)(
                                _context.allocNode!Asn1RootElementSetSpecNode(
                                    rootSetSpec
                                )
                            )
                        )
                    )
                );
            }
        }
        else
        {
            constraintSpec = _context.allocNode!(typeof(constraintSpec))(
                _context.allocNode!Asn1SubtypeConstraintNode(
                    _context.allocNode!Asn1ElementSetSpecsNode(
                        _context.allocNode!Asn1RootElementSetSpecNode(
                            rootSetSpec
                        )
                    )
                )
            );
        }

        Asn1ExceptionSpecNode excSpec;
        if(auto r = ExceptionSpec(excSpec)) return r;
        
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rightParenthesis) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected `)` to denote end of constraint",
            token.location, "encountered token of type ", token.type
        );

        node = _context.allocNode!(typeof(node))(
            constraintSpec,
            excSpec
        );
        return Result.noError;
    }

    Result ElementSetSpec(out Asn1ElementSetSpecNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rALL)
        {
            consume().resultAssert;
            Asn1ExclusionsNode exclusions;
            if(auto r = Exclusions(exclusions)) return r;
            node = _context.allocNode!(typeof(node))(exclusions);
            return Result.noError;
        }

        auto unions = _context.allocNode!Asn1UnionsNode();
        while(true)
        {
            auto intersections = _context.allocNode!Asn1IntersectionsNode();
            while(true)
            {
                Asn1ElementsNode elements;
                if(auto r = Elements(elements)) return r;
                if(auto r = peek(token)) return r;
                if(token.type == Asn1Token.Type.rEXCEPT)
                {
                    Asn1ExclusionsNode exclusions;
                    if(auto r = Exclusions(exclusions)) return r;
                    
                    intersections.items.put(_context.allocNode!Asn1IntersectionElementsNode(
                        _context.allocNode!(Asn1IntersectionElementsNode.Case1)(
                            _context.allocNode!Asn1ElemsNode(elements),
                            exclusions
                        )
                    ));
                }
                else
                {
                    intersections.items.put(_context.allocNode!Asn1IntersectionElementsNode(
                        elements
                    ));
                }

                if(auto r = peek(token)) return r;
                if(token.type != Asn1Token.Type.rINTERSECTION
                && token.type != Asn1Token.Type.toBach) break;
                consume().resultAssert;
            }
            unions.items.put(intersections);

            if(auto r = peek(token)) return r;
            if(token.type != Asn1Token.Type.rUNION
            && token.type != Asn1Token.Type.pipe) break;
            consume().resultAssert;
        }

        node = _context.allocNode!(typeof(node))(unions);
        return Result.noError;
    }

    Result Exclusions(out Asn1ExclusionsNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = consume(token)) return r;
        if(token.type != Asn1Token.Type.rEXCEPT) return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected `EXCEPT` to denote `ALL EXCEPT` when parsing Exclusions",
            token.location, "encountered token of type ", token.type
        );

        Asn1ElementsNode elements;
        if(auto r = Elements(elements)) return r;

        node = _context.allocNode!(typeof(node))(elements);
        return Result.noError;
    }

    // NOTE: Does not parse
    //      - TypeConstraint as it is special cased for `ObjectClassFieldType`, so must be handled specially there.
    Result Elements(out Asn1ElementsNode node)
    {
        auto savedLexer = _lexer;
        scope(exit) if(node is null)
            _lexer = savedLexer;

        Asn1Token token;
        if(auto r = peek(token)) return r;

        // Start off with the easy ones.
        switch(token.type) with(Asn1Token.Type)
        {
            case rINCLUDES:
                consume().resultAssert;
                
                Asn1TypeNode type;
                if(auto r = Type(type)) return r.notInitial;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1ContainedSubtypeNode(
                            _context.allocNode!Asn1IncludesNode(
                                _context.allocNode!Asn1IncludesMarkNode(token)
                            ),
                            type
                        ),
                    )
                );
                return Result.noError;

            case rFROM:
                consume().resultAssert;

                Asn1ConstraintNode constraint;
                if(auto r = Constraint(constraint)) return r.notInitial;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1PermittedAlphabetNode(
                            constraint
                        ),
                    )
                );
                return Result.noError;

            case rSIZE:
                consume().resultAssert;

                Asn1ConstraintNode constraint;
                if(auto r = Constraint(constraint)) return r.notInitial;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1SizeConstraintNode(
                            constraint
                        ),
                    )
                );
                return Result.noError;

            case rPATTERN:
                consume().resultAssert;

                Asn1ValueNode value;
                if(auto r = Value(value)) return r.notInitial;
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1PatternConstraintNode(
                            value
                        ),
                    )
                );
                return Result.noError;

            case rWITH:
                consume().resultAssert;
                if(auto r = consume(token)) return r;
                if(token.type == rCOMPONENT)
                {
                    Asn1ConstraintNode constraint;
                    if(auto r = Constraint(constraint)) return r;
                    node = _context.allocNode!(typeof(node))(
                        _context.allocNode!Asn1SubtypeElementsNode(
                            _context.allocNode!Asn1InnerTypeConstraintsNode(
                                _context.allocNode!Asn1SingleTypeConstraintNode(
                                    constraint
                                ),
                            ),
                        )
                    );
                    return Result.noError;
                }
                else if(token.type != rCOMPONENTS) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `COMPONENTS` to denote `WITH COMPONENTS` when parsing constraint",
                    token.location, "encountered token of type ", token.type
                );

                if(auto r = consume(token)) return r;
                if(token.type != leftBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `{` to denote start of `WITH COMPONENTS` constraint list",
                    token.location, "encountered token of type ", token.type
                );

                bool isPartial;
                if(auto r = peek(token)) return r;
                if(token.type == ellipsis)
                {
                    consume().resultAssert;
                    isPartial = true;
                    if(auto r = consume(token)) return r;
                    if(token.type != comma) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected `,` following `...` within `WITH COMPONENTS` constraint list",
                        token.location, "encountered token of type ", token.type
                    );
                }

                auto typeConstraints = _context.allocNode!Asn1TypeConstraintsNode();
                while(true)
                {
                    if(auto r = consume(token)) return r;
                    if(token.type != identifier) return _lexer.makeError(
                        Asn1ParserError.nonInitialTokenNotFound,
                        "expected identifier within `WITH COMPONENTS` constraint list to begin next NamedConstraint",
                        token.location, "encountered token of type ", token.type
                    );
                    const idToken = token;

                    Asn1ValueConstraintNode valueConstraint;
                    Asn1ConstraintNode constraint;
                    if(auto r = Constraint(constraint))
                    {
                        if(!r.isError(Asn1ParserError.tokenNotFound))
                            return r;
                        valueConstraint = _context.allocNode!(typeof(valueConstraint))(
                            _context.allocNode!Asn1EmptyNode(token)
                        );
                    }
                    else
                    {
                        valueConstraint = _context.allocNode!(typeof(valueConstraint))(
                            constraint
                        );
                    }

                    Asn1PresenceConstraintNode presence;
                    if(auto r = peek(token)) return r;
                    switch(token.type)
                    {
                        case rPRESENT:
                            consume().resultAssert;
                            presence = _context.allocNode!(typeof(presence))(
                                _context.allocNode!Asn1PresentNode(token)
                            );
                            break;
                        case rABSENT:
                            consume().resultAssert;
                            presence = _context.allocNode!(typeof(presence))(
                                _context.allocNode!Asn1AbsentNode(token)
                            );
                            break;
                        case rOPTIONAL:
                            consume().resultAssert;
                            presence = _context.allocNode!(typeof(presence))(
                                _context.allocNode!Asn1OptionalNode(token)
                            );
                            break;
                        default:
                            presence = _context.allocNode!(typeof(presence))(
                                _context.allocNode!Asn1EmptyNode(token)
                            );
                            break;
                    }

                    typeConstraints.items.put(_context.allocNode!Asn1NamedConstraintNode(
                        _context.allocNode!Asn1IdentifierTokenNode(idToken),
                        _context.allocNode!Asn1ComponentConstraintNode(
                            valueConstraint,
                            presence
                        )
                    ));

                    if(auto r = peek(token)) return r;
                    if(token.type != comma) break;
                    consume().resultAssert;
                }

                Asn1MultipleTypeConstraintsNode constraints;
                if(isPartial)
                {
                    constraints = _context.allocNode!(typeof(constraints))(
                        _context.allocNode!Asn1PartialSpecificationNode(
                            typeConstraints
                        )
                    );
                }
                else
                {
                    constraints = _context.allocNode!(typeof(constraints))(
                        _context.allocNode!Asn1FullSpecificationNode(
                            typeConstraints
                        )
                    );
                }

                if(auto r = consume(token)) return r;
                if(token.type != rightBracket) return _lexer.makeError(
                    Asn1ParserError.nonInitialTokenNotFound,
                    "expected `}` to denote end of `WITH COMPONENTS` constraint list",
                    token.location, "encountered token of type ", token.type
                );
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1InnerTypeConstraintsNode(
                            constraints
                        ),
                    )
                );
                return Result.noError;

            default: break;
        }

        Asn1TypeNode type;
        if(auto r = Type(type))
        {
            // Since we're prioritising Types before Values, we need to allow
            // identifiers to pass through to the Value case, since 99% of the time
            // they won't be signalling something like a SelectionType
            if(r.isError(Asn1ParserError.nonInitialTokenNotFound))
            {
                if(auto r2 = peek(token)) return r2;
                if(token.type != Asn1Token.Type.identifier) return r;
            }
            else if(!r.isError(Asn1ParserError.tokenNotFound))
                return r;
        }
        else
        {
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1SubtypeElementsNode(
                    _context.allocNode!Asn1ContainedSubtypeNode(
                        _context.allocNode!Asn1IncludesNode(
                            _context.allocNode!Asn1EmptyNode(token)
                        ),
                        type
                    ),
                )
            );
            return Result.noError;
        }

        Result ValueRange(out Asn1ValueRangeNode node, Asn1LowerEndpointNode lower)
        {
            if(auto r = consume(token)) return r;
            if(token.type != Asn1Token.Type.rangeSeparator) return _lexer.makeError(
                Asn1ParserError.nonInitialTokenNotFound,
                "expected `..` following lower end of range constraint",
                token.location, "encountered token of type ", token.type
            );

            if(auto r = peek(token)) return r;
            
            bool hasLeftArrow;
            if(token.type == Asn1Token.Type.leftArrow)
            {
                hasLeftArrow = true;
                consume().resultAssert;
            }

            Asn1UpperEndValueNode upper;
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.rMAX)
            {
                consume().resultAssert;
                upper = _context.allocNode!(typeof(upper))(
                    _context.allocNode!Asn1MaxNode(token)
                );
            }
            else
            {
                Asn1ValueNode upperValue;
                if(auto r = Value(upperValue)) return r.notInitial;
                upper = _context.allocNode!(typeof(upper))(
                    upperValue
                );
            }

            Asn1UpperEndpointNode upperEndpoint;
            if(hasLeftArrow)
                upperEndpoint = _context.allocNode!Asn1UpperEndpointNode(_context.allocNode!(Asn1UpperEndpointNode.Case1)(upper));
            else
                upperEndpoint = _context.allocNode!Asn1UpperEndpointNode(upper);

            node = _context.allocNode!(typeof(node))(
                lower,
                upperEndpoint
            );
            return Result.noError;
        }

        if(auto r = peek(token)) return r;
        if(token.type == Asn1Token.Type.rMIN)
        {
            Asn1LowerEndpointNode lower;

            consume().resultAssert;
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.leftArrow)
            {
                consume().resultAssert;
                lower = _context.allocNode!(typeof(lower))(
                    _context.allocNode!(typeof(lower).Case1)(
                        _context.allocNode!Asn1LowerEndValueNode(
                            _context.allocNode!Asn1MinNode(token)
                        )
                    )
                );
            }
            else
            {
                lower = _context.allocNode!(typeof(lower))(
                    _context.allocNode!Asn1LowerEndValueNode(
                        _context.allocNode!Asn1MinNode(token)
                    )
                );
            }

            Asn1ValueRangeNode valueRange;
            if(auto r = ValueRange(valueRange, lower)) return r;
            
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1SubtypeElementsNode(
                    valueRange
                )
            );
            return Result.noError;
        }

        Asn1ValueNode value;
        if(auto r = Value(value))
        {
            if(!r.isError(Asn1ParserError.tokenNotFound))
                return r;
        }
        else
        {
            Asn1LowerEndpointNode lower;
            if(auto r = peek(token)) return r;
            if(token.type == Asn1Token.Type.leftArrow)
            {
                consume().resultAssert;
                lower = _context.allocNode!(typeof(lower))(
                    _context.allocNode!(typeof(lower).Case1)(
                        _context.allocNode!Asn1LowerEndValueNode(
                            value
                        )
                    )
                );
            }
            else if(token.type == Asn1Token.Type.rangeSeparator)
            {
                lower = _context.allocNode!(typeof(lower))(
                    _context.allocNode!Asn1LowerEndValueNode(
                        value
                    )
                );
            }

            if(lower is null) // We're not in a range constraint
            {
                node = _context.allocNode!(typeof(node))(
                    _context.allocNode!Asn1SubtypeElementsNode(
                        _context.allocNode!Asn1SingleValueNode(
                            value
                        ),
                    )
                );
                return Result.noError;
            }

            Asn1ValueRangeNode valueRange;
            if(auto r = ValueRange(valueRange, lower)) return r;
            
            node = _context.allocNode!(typeof(node))(
                _context.allocNode!Asn1SubtypeElementsNode(
                    valueRange
                )
            );
            return Result.noError;
        }

        return _lexer.makeError(
            Asn1ParserError.tokenNotFound,
            "expected constraint element",
            token.location, "encountered token of type ", token.type,
        );
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
                auto items = n.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode.getNode!Asn1EnumerationsNode.asNode!Asn1RootEnumerationNode.getNode!Asn1EnumerationNode
                            .items;
                assert(items.length == 3);
                assert(items[1].asNode!Asn1NamedNumberNode.asNode!(Asn1NamedNumberNode.Signed).getNode!Asn1SignedNumberNode
                    .isNode!Asn1NumberTokenNode
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
        "SEQUENCE OF - SizeConstraint - Type": T("SEQUENCE SIZE (0..1) OF INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SequenceSizeConstraintType));
        }),
        "SEQUENCE OF - SizeConstraint - NamedType": T("SEQUENCE SIZE (0..1) OF i INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SequenceSizeConstraintNamedType));
        }),
        "SEQUENCE OF - Constraint - Type": T("SEQUENCE (0) OF INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SequenceConstraintType));
        }),
        "SEQUENCE OF - Constraint - NamedType": T("SEQUENCE (0) OF i INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SequenceConstraintNamedType));
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
        "SET OF - SizeConstraint - Type": T("SET SIZE (0..1) OF INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SetSizeConstraintType));
        }),
        "SET OF - SizeConstraint - NamedType": T("SET SIZE (0..1) OF i INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SetSizeConstraintNamedType));
        }),
        "SET OF - Constraint - Type": T("SET (0) OF INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SetConstraintType));
        }),
        "SET OF - Constraint - NamedType": T("SET (0) OF i INTEGER", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!Asn1TypeWithConstraintNode.isNode!(Asn1TypeWithConstraintNode.SetConstraintNamedType));
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
        "TAG - No tag class": T("[0] BOOLEAN", (n){
            assert(n.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode.isNode!(Asn1TaggedTypeNode.Default));
        }),
        "Constraint - SingleValue": T("INTEGER (1)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1SingleValueNode
            );
        }),
        "Constraint - ContainedSubtype": T("INTEGER (BOOLEAN)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ContainedSubtypeNode
            );
        }),
        "Constraint - ContainedSubtype Alternative": T("INTEGER (INCLUDES BOOLEAN)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ContainedSubtypeNode
            );
        }),
        "Constraint - ValueRange": T("INTEGER (0..1)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - ValueRange MIN": T("INTEGER (MIN..1)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - ValueRange MIN<": T("INTEGER (MIN<..1)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - ValueRange MAX": T("INTEGER (0..MAX)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - ValueRange MAX<": T("INTEGER (0..<MAX)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - ValueRange Lower<": T("INTEGER (0<..1)", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1ValueRangeNode
            );
        }),
        "Constraint - PermittedAlphabet": T(`INTEGER (FROM ("abc"))`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1PermittedAlphabetNode
            );
        }),
        "Constraint - Size": T("INTEGER (SIZE (1))", (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1SizeConstraintNode
            );
        }),
        "Constraint - Pattern": T(`INTEGER (PATTERN "[012]")`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .isNode!Asn1PatternConstraintNode
            );
        }),
        "Constraint - Intersections": T(`INTEGER (1 INTERSECTION 2 ^ 3)`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0]
                .items.length == 3
            );
        }),
        "Constraint - Union": T(`INTEGER (1 UNION 2 | 3)`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode
                .items.length == 3
            );
        }),
        "Constraint - Mixed union & intersection": T(`INTEGER (1 ^ 2 | 3 EXCEPT 4)`, (n){
            auto unions = n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode;
            assert(unions.items.length == 2);
            assert(unions.items[0].items.length == 2);
            assert(unions.items[1].items.length == 1);
        }),
        "Constraint - InnerTypeConstraints Single": T(`INTEGER (WITH COMPONENT (1))`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .asNode!Asn1InnerTypeConstraintsNode.isNode!Asn1SingleTypeConstraintNode
            );
        }),
        "Constraint - InnerTypeConstraints Multiple": T(`INTEGER (WITH COMPONENTS { a })`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .asNode!Asn1InnerTypeConstraintsNode.isNode!Asn1MultipleTypeConstraintsNode
            );
        }),
        "Constraint - InnerTypeConstraints Multiple w/ Value Constraint": T(
            `INTEGER (WITH COMPONENTS { a (1) })`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .asNode!Asn1InnerTypeConstraintsNode.isNode!Asn1MultipleTypeConstraintsNode
            );
        }),
        "Constraint - InnerTypeConstraints Multiple w/ Presence": T(
            `INTEGER (WITH COMPONENTS { a PRESENT, b OPTIONAL, c ABSENT })`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .asNode!Asn1InnerTypeConstraintsNode.isNode!Asn1MultipleTypeConstraintsNode
            );
        }),
        "Constraint - InnerTypeConstraints Multiple Partial": T(
            `INTEGER (WITH COMPONENTS { ..., a })`, (n){
            assert(n.asNode!Asn1ConstrainedTypeNode.asNode!(Asn1ConstrainedTypeNode.Case1).getNode!Asn1ConstraintNode.getNode!Asn1ConstraintSpecNode.asNode!Asn1SubtypeConstraintNode.getNode!Asn1ElementSetSpecsNode.asNode!Asn1RootElementSetSpecNode.getNode!Asn1ElementSetSpecNode.asNode!Asn1UnionsNode.items[0].items[0].asNode!Asn1ElementsNode.asNode!Asn1SubtypeElementsNode
                .asNode!Asn1InnerTypeConstraintsNode.isNode!Asn1MultipleTypeConstraintsNode
            );
        }),
        "ReferencedType - TypeReference": T(`MyType`, (n) {
            assert(n.asNode!Asn1ReferencedTypeNode.asNode!Asn1DefinedTypeNode.isNode!Asn1TypeReferenceTokenNode);
        }),
        "ReferencedType - ExternalTypeReference": T(`MyMod.TypeRef`, (n) {
            assert(n.asNode!Asn1ReferencedTypeNode.asNode!Asn1DefinedTypeNode.isNode!Asn1ExternalTypeReferenceNode);
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
        "UnresolvedSequence - NamedValueList - Ambiguous Mixed": T("{ a {}, except 2 }", (n){ 
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

@("Asn1Parser - ModuleDefinition - General Success")
unittest
{
    static struct T
    {
        string input;
        void function(Asn1ModuleDefinitionNode node) verify;
    }

    auto cases = [
        "minimal": T("MyMod DEFINITIONS ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1TagDefaultNode.isNode!Asn1EmptyNode);
            assert(n.getNode!Asn1ExtensionDefaultNode.isNode!Asn1EmptyNode);
            assert(n.getNode!Asn1ModuleBodyNode.isNode!Asn1EmptyNode);
        }),
        "ModuleIdentifier - All Types": T("MyMod { nameForm 20 nameAndNumber(20) } DEFINITIONS ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1ModuleIdentifierNode.getNode!Asn1DefinitiveIdentifierNode.asNode!Asn1DefinitiveObjIdComponentListNode
                .items.length == 3
            );
        }),
        "TagDefault - EXPLICIT": T("MyMod DEFINITIONS EXPLICIT TAGS ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1TagDefaultNode.isNode!Asn1ExplicitTagsNode);
        }),
        "TagDefault - IMPLICIT": T("MyMod DEFINITIONS IMPLICIT TAGS ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1TagDefaultNode.isNode!Asn1ImplicitTagsNode);
        }),
        "TagDefault - AUTOMATIC": T("MyMod DEFINITIONS AUTOMATIC TAGS ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1TagDefaultNode.isNode!Asn1AutomaticTagsNode);
        }),
        "ExtensionDefault - IMPLIED": T("MyMod DEFINITIONS EXTENSIBILITY IMPLIED ::= BEGIN END", (n){ 
            assert(n.getNode!Asn1ExtensionDefaultNode.isNode!Asn1ExtensibilityImpliedNode);
        }),
        "Imports - Empty": T(`
            MyMod DEFINITIONS ::= BEGIN
                IMPORTS;
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1ImportsNode.asNode!Asn1SymbolsImportedNode.isNode!Asn1EmptyNode);
        }),
        "Imports - Multiple": T(`
            MyMod DEFINITIONS ::= BEGIN
                IMPORTS
                    A, b FROM Mod1
                    C FROM Mod2 { iso foo(123) }
                    D FROM Mod3 definedValue
                    E FROM Mod4 ThisTechnically.shouldntWork
                ;
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1ImportsNode.asNode!Asn1SymbolsImportedNode.asNode!Asn1SymbolsFromModuleListNode
                .items.length == 4
            );
        }),
        "Exports - Empty": T(`
            MyMod DEFINITIONS ::= BEGIN
                EXPORTS;
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1ExportsNode.asNode!Asn1SymbolsExportedNode.isNode!Asn1EmptyNode);
        }),
        "Exports - ALL": T(`
            MyMod DEFINITIONS ::= BEGIN
                EXPORTS ALL;
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1ExportsNode.isNode!Asn1ExportsAllNode);
        }),
        "Exports - Multiple": T(`
            MyMod DEFINITIONS ::= BEGIN
                EXPORTS
                    Foo, bar
                ;
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1ExportsNode.asNode!Asn1SymbolsExportedNode.asNode!Asn1SymbolListNode
                .items.length == 2
            );
        }),
        "TypeAssignment": T(`
            MyMod DEFINITIONS ::= BEGIN
                T ::= SEQUENCE {
                    a BOOLEAN,
                    b SET OF INTEGER
                }
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1AssignmentListNode
                .items.length == 1
            );
        }),
        "ValueAssignment": T(`
            MyMod DEFINITIONS ::= BEGIN
                t SEQUENCE { a BOOLEAN, b SET OF INTEGER } ::= {
                    a TRUE,
                    b { 1, 2, 3 }
                }
            END
        `, (n){
            assert(n.getNode!Asn1ModuleBodyNode.asNode!(Asn1ModuleBodyNode.Case1).getNode!Asn1AssignmentListNode
                .items.length == 1
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

            Asn1ModuleDefinitionNode node;
            parser.ModuleDefinition(node).resultAssert;
            test.verify(node);

            Asn1Token token;
            parser.consume(token).resultAssert;
            assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

@("Asn1Parser - Examples from ISO/IEC 8824-1:2003")
unittest
{
    // Just testing that they fully parse. Examples are modified to fit into a full
    // ModuleDefinition syntax if needed.
    auto cases = [
        "14.10": `
            M DEFINITIONS ::= BEGIN
                T ::= SEQUENCE {
                    a BOOLEAN,
                    b SET OF INTEGER
                }
            END
        `,
        "19.5": `
            M DEFINITIONS ::= BEGIN
                A ::= ENUMERATED {a, b, ..., c(0)} -- invalid, since both 'a' and 'c' equal 0
                B ::= ENUMERATED {a, b, ..., c, d(2)} -- invalid, since both 'c' and 'd' equal 2
                C ::= ENUMERATED {a, b(3), ..., c(1)} -- valid, 'c' = 1
                D ::= ENUMERATED {a, b, ..., c(2)} -- valid, 'c' = 2
            END
        `,
        "19.6": `
            M DEFINITIONS ::= BEGIN
                A ::= ENUMERATED {a, b, ..., c} -- c = 2
                B ::= ENUMERATED {a, b, c(0), ..., d} -- d = 3
                C ::= ENUMERATED {a, b, ..., c(3), d} -- d = 4
                D ::= ENUMERATED {a, z(25), ..., d} -- d = 1
            END
        `,
        "28.8": `
            M DEFINITIONS ::= BEGIN
                A ::= CHOICE {
                    b B,
                    c NULL}
                B ::= CHOICE {
                    d [0] NULL,
                    e [1] NULL}

                A ::= CHOICE {
                    b B,
                    c C}
                B ::= CHOICE {
                    d [0] NULL,
                    e [1] NULL}
                C ::= CHOICE {
                    f [2] NULL,
                    g [3] NULL}

                A ::= CHOICE {
                    b B,
                    c C}
                B ::= CHOICE {
                    d [0] NULL,
                    e [1] NULL}
                C ::= CHOICE {
                    f [0] NULL,
                    g [1] NULL}
            END
        `,
        "31.12": `
            M DEFINITIONS ::= BEGIN
                a OBJECT IDENTIFIER ::= { iso standard 8571 pci (1) }
                ftam OBJECT IDENTIFIER ::= { iso standard 8571 }
                ftom2 OBJECT IDENTIFIER ::= { ftma pci(1) }
            END
        `,
        "32.6": `
            M DEFINITIONS ::= BEGIN
                thisUniversity OBJECT IDENTIFIER ::=
                    {iso member-body country(29) universities(56) thisuni(32)}
                firstgroup RELATIVE-OID ::= {science-fac(4) maths-dept(3)}
            END
        `,
        "33.5": `
            M DEFINITIONS ::= BEGIN
                T ::= SEQUENCE {
                    identification CHOICE {
                        syntaxes SEQUENCE {
                            abstract OBJECT IDENTIFIER,
                            transfer OBJECT IDENTIFIER }
                        -- Abstract and transfer syntax object identifiers --,
                        syntax OBJECT IDENTIFIER
                        -- A single object identifier for identification of the abstract
                        -- and transfer syntaxes --,
                        presentation-context-id INTEGER
                        -- (Applicable only to OSI environments)
                        -- The negotiated OSI presentation context identifies the
                        -- abstract and transfer syntaxes --,
                        context-negotiation SEQUENCE {
                            presentation-context-id INTEGER,
                            transfer-syntax OBJECT IDENTIFIER }
                        -- (Applicable only to OSI environments)
                        -- Context-negotiation in progress, presentation-context-id
                        -- identifies only the abstract syntax
                        -- so the transfer syntax shall be specified --,
                        transfer-syntax OBJECT IDENTIFIER
                        -- The type of the value (for example, specification that it is
                        -- the value of an ASN.1 type)
                        -- is fixed by the application designer (and hence known to both
                        -- sender and receiver). This
                        -- case is provided primarily to support
                        -- selective-field-encryption (or other encoding
                        -- transformations) of an ASN.1 type --,
                        fixed NULL
                        -- The data value is the value of a fixed ASN.1 type (and hence
                        -- known to both sender
                        -- and receiver) -- },
                        --data-value-descriptor ObjectDescriptor OPTIONAL
                        -- This provides human-readable identification of the class of the
                        -- value --
                        data-value OCTET STRING }
                    ( WITH COMPONENTS {
                    ... ,
                    data-value-descriptor ABSENT } )
            END
        `,
        "33.8": `
            M DEFINITIONS ::= BEGIN
                T ::= EMBEDDED PDV (WITH COMPONENTS {
                        ... ,
                        identification (WITH COMPONENTS {
                        syntaxes PRESENT } ) } )
            END
        `,
        "37.8": `
            M DEFINITIONS ::= BEGIN
                IMPORTS BasicLatin, greekCapitalLetterSigma FROM ASN1-CHARACTER-MODULE
                    { joint-iso-itu-t asn1(1) specification(0) modules(0) iso10646(0) };
                MyAlphabet ::= UniversalString (FROM (BasicLatin | greekCapitalLetterSigma))
                mystring MyAlphabet ::= { "abc" , greekCapitalLetterSigma , "def" }
            END
        `,
        "38.1.3": `
            M DEFINITIONS ::= BEGIN
                space BMPString ::= {0, 0, 0, 32}
                exclamationMark BMPString ::= {0, 0, 0, 33}
                quotationMark BMPString ::= {0, 0, 0, 34}
                -- ... and so on
                tilde BMPString ::= {0, 0, 0, 126}
                BasicLatin ::= BMPString
                (FROM (space
                | exclamationMark
                | quotationMark
                --| ...  and so on
                | tilde)
                )
            END
        `,
        "38.1.4": `
            M DEFINITIONS ::= BEGIN
                Level1 ::= BMPString (FROM (ALL EXCEPT CombiningCharacters))
                Level2 ::= BMPString (FROM (ALL EXCEPT CombiningCharactersType-2))
                Level3 ::= BMPString
            END
        `,
        "45.2": `
            M DEFINITIONS ::= BEGIN
                NamesOfMemberNations ::= SEQUENCE OF VisibleString (SIZE(1..64))
            END
        `,
        "45.3": `
            M DEFINITIONS ::= BEGIN
                T ::= CHOICE {
                    a SEQUENCE {
                        a INTEGER OPTIONAL,
                        b BOOLEAN
                    },
                    b NULL
                }
                V ::= a < T (WITH COMPONENTS {..., a ABSENT})
            END
        `,
        "E.1.2": `
            M DEFINITIONS ::= BEGIN
                PersonnelRecord ::= [APPLICATION 0] SET
                {   name Name,
                    title VisibleString,
                    number EmployeeNumber,
                    dateOfHire Date,
                    nameOfSpouse Name,
                    children SEQUENCE OF ChildInformation DEFAULT {}
                }
                ChildInformation ::= SET
                {   name Name,
                    dateOfBirth Date
                }
                Name ::= [APPLICATION 1] SEQUENCE
                {   givenName VisibleString,
                    initial VisibleString,
                    familyName VisibleString
                }
                EmployeeNumber ::= [APPLICATION 2] INTEGER
                Date ::= [APPLICATION 3] VisibleString -- YYYY MMDD
            END
        `,
    ];

    foreach(name, test; cases)
    {
        try
        {
            import std.conv : to;

            Asn1ParserContext context;
            auto lexer = Asn1Lexer(test);
            auto parser = Asn1Parser(lexer, &context);

            Asn1ModuleDefinitionNode node;
            parser.ModuleDefinition(node).resultAssert;

            Asn1Token token;
            parser.consume(token).resultAssert;
            assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}