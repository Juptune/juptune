/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.tooling;

import juptune.core.ds                  : String2;
import juptune.core.util                : Result;
import juptune.data.asn1.lang.common    : Asn1ParserContext, Asn1Location;
import juptune.data.asn1.lang.ir        : Asn1ModuleIr, Asn1SemanticErrorHandler, Asn1NullSemanticErrorHandler, Asn1BaseIr; // @suppress(dscanner.style.long_line)

/++
 + A simple semantic error handler that will always fail an assert if any function is called.
 +
 + This is mainly intended to be used for always-success cases, such as certain types of unittests.
 + ++/
final class Asn1AlwaysCrashErrorHandler : Asn1SemanticErrorHandler
{
    override void startLine(Asn1Location location) { assert(false, "Something tried to generate an error"); }
    override void putInLine(scope const(char)[] slice) { assert(false, "Something tried to generate an error"); }
    override void endLine() { assert(false, "Something tried to generate an error"); }
    override void indent() { assert(false, "Something tried to generate an error"); }
    override void dedent() { assert(false, "Something tried to generate an error"); }
}

// TODO: document that this is an easy to use "just fucking parse" function
// TODO: Needs functionality in the future to handle imports, but imports right now are barely implemented
Result asn1ParseWithSemantics(
    scope ref Asn1ParserContext context,
    out Asn1ModuleIr modIr,
    scope const(char)[] rawSourceCode,
    scope Asn1SemanticErrorHandler errorHandler = Asn1NullSemanticErrorHandler.instance,
)
{
    import std.traits : EnumMembers;
    
    import juptune.data.asn1.lang.ast       : Asn1ModuleDefinitionNode;
    import juptune.data.asn1.lang.ast2ir    : asn1AstToIr;
    import juptune.data.asn1.lang.ir        : Asn1BaseIr;
    import juptune.data.asn1.lang.lexer     : Asn1Lexer;
    import juptune.data.asn1.lang.parser    : Asn1Parser;
    import juptune.data.asn1.lang.typecheck : Asn1TypeCheckVisitor;

    auto lexer = Asn1Lexer(rawSourceCode);
    auto parser = Asn1Parser(lexer, &context);
    
    Asn1ModuleDefinitionNode modDef;
    auto result = parser.ModuleDefinition(modDef);
    if(result.isError)
        return result;

    result = asn1AstToIr(modDef, modIr, context, errorHandler);
    if(result.isError)
        return result;

    foreach(semanticStage; EnumMembers!(Asn1BaseIr.SemanticStageBit))
    {
        result = modIr.doSemanticStage(
            semanticStage,
            (_) => Asn1ModuleIr.LookupItemT.init,
            context,
            Asn1BaseIr.SemanticInfo()
        );
        if(result.isError)
            return result;
    }

    scope visitor = new Asn1TypeCheckVisitor(errorHandler);
    return modIr.visit(visitor);
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
)
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
    asn1ParseWithSemantics(context, modIr, code, new Asn1AlwaysCrashErrorHandler()).resultAssert;

    Asn1ValueAssignmentIr fooAss;
    modIr.getAssignmentByName("foo", fooAss).resultAssert;

    auto fooValue = cast(Asn1CstringValueIr)fooAss.getSymbolValue();
    assert(fooValue !is null);
    assert(fooValue.asString() == "bar");
}