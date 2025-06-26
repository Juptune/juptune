/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// Provides a ton of convenience types/functions that tooling may find useful, as it simplifies
/// usage of this package.
module juptune.data.asn1.lang.tooling;

import juptune.core.ds                  : String2;
import juptune.core.util                : Result;
import juptune.data.asn1.lang.common    : Asn1ParserContext, Asn1Location, Asn1ErrorHandler, Asn1NullErrorHandler;
import juptune.data.asn1.lang.ir        : Asn1ModuleIr, Asn1BaseIr, Asn1ModuleRegistry;

/++
 + A simple semantic error handler that will always fail an assert if any function is called.
 +
 + This is mainly intended to be used for always-success cases, such as certain types of unittests.
 + ++/
final class Asn1AlwaysCrashErrorHandler : Asn1ErrorHandler
{
    override void startLine(Asn1Location location) { assert(false, "Something tried to generate an error"); }
    override void putInLine(scope const(char)[] slice) { assert(false, "Something tried to generate an error"); }
    override void endLine() { assert(false, "Something tried to generate an error"); }
    override void indent() { assert(false, "Something tried to generate an error"); }
    override void dedent() { assert(false, "Something tried to generate an error"); }
}

/++
 + A semantic error handler that immediately passes data into `printf`.
 +
 + This is useful for @nogc tools, or other applications where only one thread can write to stdout.
 + ++/
final class Asn1PrintfErrorHandler : Asn1ErrorHandler
{
    import core.stdc.stdio : printf;

    @nogc nothrow:

    private
    {
        uint _indentLevel;
        bool _wasCalled;
    }

    /// Returns: Whether `startLine` was called at least once - can be used to detect if an error occurred or not.
    bool wasCalled() => this._wasCalled;

    override void startLine(Asn1Location location)
    {
        this._wasCalled = true;
        printf("[%lld..%lld]: ", location.start, location.end);
        foreach(i; 0..this._indentLevel)
            printf("  ");
    }

    override void putInLine(scope const(char)[] slice)
    in(slice.length <= uint.max, "slice is too large to write")
    {
        printf("%.*s", cast(uint)slice.length, slice.ptr);
    }

    override void endLine()
    {
        printf("\n");
    }

    override void indent() { this._indentLevel++; }
    override void dedent() { this._indentLevel--; }
}

// TODO: document that this is an easy to use "just fucking parse" function
Result asn1Parse(
    scope ref Asn1ParserContext context,
    out Asn1ModuleIr modIr,
    scope const(char)[] rawSourceCode,
    scope Asn1ErrorHandler errorHandler,
) @nogc nothrow
{
    import juptune.data.asn1.lang.ast       : Asn1ModuleDefinitionNode;
    import juptune.data.asn1.lang.ast2ir    : asn1AstToIr;
    import juptune.data.asn1.lang.lexer     : Asn1Lexer;
    import juptune.data.asn1.lang.parser    : Asn1Parser;

    auto lexer = Asn1Lexer(rawSourceCode);
    auto parser = Asn1Parser(lexer, &context);
    
    Asn1ModuleDefinitionNode modDef;
    auto result = parser.ModuleDefinition(modDef);
    if(result.isError)
        return result;

    result = asn1AstToIr(modDef, modIr, context, errorHandler);
    if(result.isError)
        return result;

    return Result.noError;
}

// TODO: document that this is an easy to use "just fucking typecheck" function
Result asn1Semantics(
    scope ref Asn1ParserContext context,
    scope Asn1ModuleIr modIr,
    scope Asn1ErrorHandler errorHandler,
) @nogc nothrow
{
    import std.traits : EnumMembers;
    
    import juptune.data.asn1.lang.ir        : Asn1BaseIr;
    import juptune.data.asn1.lang.typecheck : Asn1TypeCheckVisitor;

    foreach(semanticStage; EnumMembers!(Asn1BaseIr.SemanticStageBit))
    {
        auto result = modIr.doSemanticStage(
            semanticStage,
            (_) => Asn1ModuleIr.LookupItemT.init,
            context,
            Asn1BaseIr.SemanticInfo(),
            errorHandler
        );
        if(result.isError)
            return result;
    }

    scope visitor = new Asn1TypeCheckVisitor(errorHandler);
    return modIr.visit(visitor);
}

Result asn1ParseWithSemantics(
    scope ref Asn1ParserContext context,
    out Asn1ModuleIr modIr,
    scope const(char)[] rawSourceCode,
    scope Asn1ModuleRegistry registry,
    scope Asn1ErrorHandler errorHandler,
) @nogc nothrow
{
    auto result = asn1Parse(context, modIr, rawSourceCode, errorHandler);
    if(result.isError)
        return result;

    result = registry.register(modIr, errorHandler);
    if(result.isError)
        return result;

    return asn1Semantics(context, modIr, errorHandler);
}

/++
 + Convenience function for converting any IR node into a string.
 +
 + Notes:
 +  If `ir` is an `Asn1ModuleIr`, then certain settings such as the
 +  `tagDefault` will be fetched directly from the IR node, and the
 +  settings provided directly to this function will be ignored.
 +
 + Params:
 +  ir         = The IR node to convert into ASN.1 notation.
 +  tagDefault = The default tag encoding.
 +
 + Returns:
 +  `ir` as a `String2`.
 + ++/
String2 asn1ToString(IrT : Asn1BaseIr)(
    IrT ir,
    Asn1ModuleIr.TagDefault tagDefault = Asn1ModuleIr.TagDefault.explicit
) @nogc nothrow
in(ir !is null, "ir is null")
{
    import juptune.core.util              : resultAssert;
    import juptune.data.asn1.lang.printer : Asn1PrinterVisitor, Asn1StringPrinterHandler;

    scope handler = new Asn1StringPrinterHandler();
    scope visitor = new Asn1PrinterVisitor(handler, tagDefault);
    ir.visit(visitor).resultAssert; // There shouldn't be any error results from the printer visitor

    return String2.fromDestroyingArray(handler.buffer);
}

/// Same as `asn1ToString` but creates a GC string instead.
string asn1ToStringGC(IrT : Asn1BaseIr)(
    IrT ir,
    Asn1ModuleIr.TagDefault tagDefault = Asn1ModuleIr.TagDefault.explicit
)
in(ir !is null, "ir is null")
{
    import juptune.core.util              : resultAssert;
    import juptune.data.asn1.lang.printer : Asn1PrinterVisitor, Asn1StringPrinterHandler;

    scope handler = new Asn1StringPrinterHandler();
    scope visitor = new Asn1PrinterVisitor(handler, tagDefault);
    ir.visit(visitor).resultAssert; // There shouldn't be any error results from the printer visitor

    return handler.buffer.slice.idup;
}

/++++ Unittests ++++/
version(unittest):

@("asn1ParseWithSemantics - basic")
unittest
{
    import juptune.core.util : resultAssert;
    import juptune.data.asn1.lang.ir;

    const code = `
        MyMod DEFINITIONS ::= BEGIN
            foo UTF8String ::= "bar"
        END
    `;

    Asn1ModuleIr modIr;
    Asn1ParserContext context;
    scope registry = new Asn1ModuleRegistry();
    asn1ParseWithSemantics(context, modIr, code, registry, new Asn1AlwaysCrashErrorHandler()).resultAssert;

    Asn1ValueAssignmentIr fooAss;
    modIr.getAssignmentByName("foo", fooAss).resultAssert;

    auto fooValue = cast(Asn1CstringValueIr)fooAss.getSymbolValue();
    assert(fooValue !is null);
    assert(fooValue.asString() == "bar");
}