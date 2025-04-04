/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.ast2ir;

import juptune.core.util : Result;
import juptune.data.asn1.lang.ast; // Intentionally everything
import juptune.data.asn1.lang.ir;  // Intentionally everything
import juptune.data.asn1.lang.common : Asn1ParserContext;
import juptune.data.asn1.lang.parser : Asn1Parser, Asn1ParserError;

/++++ Types ++++/

Result asn1AstToIr(
    scope Asn1TypeNode node,
    scope out Asn1TypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1BuiltinTypeNode type) {
            return type.match(
                (Asn1BitStringTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1BooleanTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1CharacterStringTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1ChoiceTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1EmbeddedPDVTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1EnumeratedTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1ExternalTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1InstanceOfTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1IntegerTypeNode subtype) {
                    Asn1IntegerTypeIr intIr;
                    if(auto r = asn1AstToIr(subtype, intIr, context, errors))
                        return r;
                    ir = intIr;
                    return Result.noError;
                },
                (Asn1NullTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1ObjectClassFieldTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1ObjectIdentifierTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1OctetStringTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1RealTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1RelativeOIDTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1SequenceTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1SequenceOfTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1SetTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1SetOfTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1TaggedTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
            ); 
        },
        (Asn1ReferencedTypeNode type) { assert(false, "Not implemented"); return Result.noError; },
        (Asn1ConstrainedTypeNode type) { assert(false, "Not implemented"); return Result.noError; },
    );
}

Result asn1AstToIr(
    scope Asn1IntegerTypeNode node,
    scope out Asn1IntegerTypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1IntegerTypeNode.Plain plain) {
            ir = context.allocNode!(typeof(ir))(plain.token.location);
            return Result.noError;
        },
        (Asn1NamedNumberListNode list) {
            assert(list.items.length, "List is empty? The parser should've caught this!");

            foreach(item; list.items)
            {
                auto result = item.match(
                    (Asn1NamedNumberNode.Signed signed) {
                        auto id = signed.getNode!Asn1IdentifierTokenNode;
                        auto value = signed.getNode!Asn1SignedNumberNode;
                        if(ir is null)
                            ir = context.allocNode!(typeof(ir))(id.token.location);
                        
                        Asn1IntegerValueIr intValue;
                        if(auto r = asn1AstToIr(value, intValue, context, errors))
                            return r;

                        if(auto r = ir.addNamedNumber(id.token.text, intValue, errors))
                            return r;
                        return Result.noError;
                    },
                    (Asn1NamedNumberNode.Defined defined) {
                        auto id = defined.getNode!Asn1IdentifierTokenNode;
                        auto value = defined.getNode!Asn1DefinedValueNode;
                        if(ir is null)
                            ir = context.allocNode!(typeof(ir))(id.token.location);
                        
                        Asn1ValueReferenceIr reference;
                        if(auto r = asn1AstToIr(value, reference, context, errors))
                            return r;

                        if(auto r = ir.addNamedNumber(id.token.text, reference, errors))
                            return r;
                        return Result.noError;
                    }
                );
                if(result.isError)
                    return result;
            }
            return Result.noError;
        },
    );
}
@("asn1AstToIr - Asn1IntegerTypeNode > Asn1IntegerTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1IntegerTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1IntegerTypeNode;
    });
    
    with(Harness) run([
        "Plain": T("INTEGER", (ir){ assert(ir !is null); }),
        "NamedNumberList": T("INTEGER { a (-12), b (valueRef), c (MyMod.valueRef) }", (ir){
            long value;
            ir.getByName!Asn1IntegerValueIr("a").asSigned(value).resultAssert;
            assert(value == -12);
            assert(ir.getByName!Asn1ValueReferenceIr("b").getFullString() == "valueRef");
            assert(ir.getByName!Asn1ValueReferenceIr("c").getFullString() == "MyMod.valueRef");
        }),
        "Error - duplicate keys": T("INTEGER { a(1), a(2) }", Asn1SemanticError.duplicateKey)
    ]);
}

/++++ Values ++++/

Result asn1AstToIr(
    scope Asn1SignedNumberNode node,
    scope out Asn1IntegerValueIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1NumberTokenNode unsigned) {
            ir = context.allocNode!(typeof(ir))(unsigned.token, false);
            return Result.noError;
        },
        (Asn1SignedNumberNode.Negative signed) {
            auto token = signed.getNode!Asn1NumberTokenNode.token;
            if(token.asNumber.canFitNatively && token.asNumber.value == 0)
            {
                return Result.make(
                    Asn1SemanticError.numberCannotBeNegativeZero,
                    "number cannot be negative as per ISO/IEC 8824-1:2003 - 18.2",
                    errors.errorAndString(token.location, "-0 is an invalid value")
                );
            }

            ir = context.allocNode!(typeof(ir))(token, true);
            return Result.noError;
        }
    );
}
@("asn1AstToIr - Asn1SignedNumberNode > Asn1IntegerValueIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1IntegerValueIr, (ref parser){
        Asn1SignedNumberNode node;
        parser.SignedNumber(node).resultAssert;
        return node;
    });
    
    with(Harness) run([
        "Unsigned": T("200", (ir){
            ulong value;
            ir.asUnsigned(value).resultAssert;
            assert(value == 200);
        }),
        "Signed": T("-200", (ir){
            long value;
            ir.asSigned(value).resultAssert;
            assert(value == -200);
        }),
        "Error - Negative zero": T("-0", Asn1SemanticError.numberCannotBeNegativeZero),
    ]);
}

Result asn1AstToIr(
    scope Asn1DefinedValueNode node,
    scope out Asn1ValueReferenceIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1ExternalValueReferenceNode extRef) { 
            auto mod = extRef.getNode!Asn1ModuleReferenceTokenNode;
            ir = context.allocNode!(typeof(ir))(
                mod.token.location,
                mod.token.text,
                extRef.getNode!Asn1ValueReferenceTokenNode.token.text
            );
            return Result.noError;
        },
        (Asn1ValueReferenceTokenNode value) {
            ir = context.allocNode!(typeof(ir))(
                value.token.location,
                value.token.text,
            );
            return Result.noError;
        },
        (Asn1ParameterizedValueNode) { assert(false, "Not Implemented"); return Result.noError; }
    );
}
@("asn1AstToIr - Asn1DefinedValueNode > Asn1ValueReferenceIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1ValueReferenceIr, (ref parser){
        Asn1DefinedValueNode node;
        parser.DefinedValue(node).resultAssert;
        return node;
    });
    
    with(Harness) run([
        "ValueReference": T("valueRef", (ir){ assert(ir.getFullString() == "valueRef"); }),
        "ExternalValueReference": T("MyMod.valueRef", (ir){ assert(ir.getFullString() == "MyMod.valueRef"); }),
    ]);
}

version(unittest)
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import juptune.data.asn1.lang.lexer; // Intentionally everything

    template GenericTestHarness(IrT, alias ParseFunc)
    {
        static struct T
        {
            string input;
            void function(IrT ir) validate;
            Asn1SemanticError expectedError;

            this(string input, typeof(validate) validate)
            {
                this.input = input;
                this.validate = validate;
            }

            this(string input, Asn1SemanticError error)
            {
                this.input = input;
                this.expectedError = error;
            }
        }

        void run(T[string] cases)
        {
            import std.conv : to;
            foreach(name, test; cases)
            {
                try
                {
                    Asn1ParserContext context;
                    auto lexer = Asn1Lexer(test.input);
                    auto parser = Asn1Parser(lexer, &context);

                    auto node = ParseFunc(parser);
                    IrT ir;
                    auto result = asn1AstToIr(node, ir, context, Asn1NullSemanticErrorHandler.instance);

                    if(test.validate !is null)
                    {
                        resultAssert(result);
                        Asn1Token token;
                        parser.consume(token).resultAssert;
                        assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);

                        test.validate(ir);
                    }
                    else
                    {
                        resultAssertSameCode!Asn1SemanticError(result, Result.make(test.expectedError));
                    }
                }
                catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
                    assert(false, "\n["~name~"]:\n"~err.msg);
            }
        }
    }
}