/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.ast2ir;

import juptune.core.util : Result, resultAssert;
import juptune.data.asn1.lang.ast; // Intentionally everything
import juptune.data.asn1.lang.ir;  // Intentionally everything
import juptune.data.asn1.lang.common : Asn1ParserContext, Asn1Location;
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
                (Asn1BitStringTypeNode subtype) {
                    Asn1BitStringTypeIr bitStringIr;
                    if(auto r = asn1AstToIr(subtype, bitStringIr, context, errors))
                        return r;
                    ir = bitStringIr;
                    return Result.noError;
                },
                (Asn1BooleanTypeNode subtype) {
                    ir = context.allocNode!Asn1BooleanTypeIr(subtype.token.location);
                    return Result.noError; 
                },
                (Asn1CharacterStringTypeNode subtype) {
                    Asn1TypeIr typeIr;
                    if(auto r = asn1AstToIr(subtype, typeIr, context, errors))
                        return r;
                    ir = typeIr;
                    return Result.noError;
                },
                (Asn1ChoiceTypeNode subtype) {
                    Asn1ChoiceTypeIr choiceIr;
                    if(auto r = asn1AstToIr(subtype, choiceIr, context, errors))
                        return r;
                    ir = choiceIr;
                    return Result.noError;
                },
                (Asn1EmbeddedPDVTypeNode subtype) {
                    ir = context.allocNode!Asn1EmbeddedPdvTypeIr(subtype.token.location);
                    return Result.noError; 
                },
                (Asn1EnumeratedTypeNode subtype) {
                    Asn1EnumeratedTypeIr enumIr;
                    if(auto r = asn1AstToIr(subtype, enumIr, context, errors))
                        return r;
                    ir = enumIr;
                    return Result.noError;
                },
                (Asn1ExternalTypeNode subtype) {
                    ir = context.allocNode!Asn1ExternalTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1InstanceOfTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1IntegerTypeNode subtype) {
                    Asn1IntegerTypeIr intIr;
                    if(auto r = asn1AstToIr(subtype, intIr, context, errors))
                        return r;
                    ir = intIr;
                    return Result.noError;
                },
                (Asn1NullTypeNode subtype) {
                    ir = context.allocNode!Asn1NullTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1ObjectClassFieldTypeNode subtype) { assert(false, "Not implemented"); return Result.noError; },
                (Asn1ObjectIdentifierTypeNode subtype) { 
                    ir = context.allocNode!Asn1ObjectIdentifierTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1OctetStringTypeNode subtype) { 
                    ir = context.allocNode!Asn1OctetStringTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1RealTypeNode subtype) {
                    ir = context.allocNode!Asn1RealTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1RelativeOIDTypeNode subtype) {
                    ir = context.allocNode!Asn1RelativeOidTypeIr(subtype.token.location);
                    return Result.noError;
                },
                (Asn1SequenceTypeNode subtype) { 
                    Asn1SequenceTypeIr sequenceIr;
                    if(auto r = asn1AstToIrForSequence(subtype, sequenceIr, context, errors))
                        return r;
                    ir = sequenceIr;
                    return Result.noError;
                },
                (Asn1SequenceOfTypeNode subtype) {
                    Asn1SequenceOfTypeIr sequenceIr;
                    if(auto r = asn1AstToIrForSequenceOf(subtype, sequenceIr, context, errors))
                        return r;
                    ir = sequenceIr;
                    return Result.noError;
                },
                (Asn1SetTypeNode subtype) { 
                    Asn1SetTypeIr setIr;
                    if(auto r = asn1AstToIrForSequence(subtype, setIr, context, errors))
                        return r;
                    ir = setIr;
                    return Result.noError;
                },
                (Asn1SetOfTypeNode subtype) {
                    Asn1SetOfTypeIr setIr;
                    if(auto r = asn1AstToIrForSequenceOf(subtype, setIr, context, errors))
                        return r;
                    ir = setIr;
                    return Result.noError;
                },
                (Asn1TaggedTypeNode subtype) {
                    Asn1TaggedTypeIr taggedIr;
                    if(auto r = asn1AstToIr(subtype, taggedIr, context, errors))
                        return r;
                    ir = taggedIr;
                    return Result.noError;
                },
            ); 
        },
        (Asn1ReferencedTypeNode type) { assert(false, "Not implemented"); return Result.noError; },
        (Asn1ConstrainedTypeNode type) { assert(false, "Not implemented"); return Result.noError; },
    );
}

Result asn1AstToIr(
    scope Asn1BitStringTypeNode node,
    scope out Asn1BitStringTypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1BitStringTypeNode.Plain plain) {
            ir = context.allocNode!(typeof(ir))(plain.token.location);
            return Result.noError;
        },
        (Asn1NamedBitListNode list) {
            assert(list.items.length, "Asn1NamedBitListNode is empty? The parser should've caught this!");

            foreach(item; list.items)
            {
                auto result = item.match(
                    (Asn1NamedBitNode.Number number) {
                        auto id = number.getNode!Asn1IdentifierTokenNode;
                        auto value = number.getNode!Asn1NumberTokenNode;
                        if(ir is null)
                            ir = context.allocNode!(typeof(ir))(id.token.location);
                        
                        auto intValue = context.allocNode!Asn1IntegerValueIr(value.token, false);
                        if(auto r = ir.addNamedBit(id.token.text, intValue, errors))
                            return r;
                        return Result.noError;
                    },
                    (Asn1NamedBitNode.DefinedValue defined) {
                        auto id = defined.getNode!Asn1IdentifierTokenNode;
                        auto value = defined.getNode!Asn1DefinedValueNode;
                        if(ir is null)
                            ir = context.allocNode!(typeof(ir))(id.token.location);
                        
                        Asn1ValueReferenceIr reference;
                        if(auto r = asn1AstToIr(value, reference, context, errors))
                            return r;

                        if(auto r = ir.addNamedBit(id.token.text, reference, errors))
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
@("asn1AstToIr - Asn1BitStringTypeNode > Asn1BitStringTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1BitStringTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1BitStringTypeNode;
    });
    
    with(Harness) run([
        "Plain": T("BIT STRING", (ir){ assert(ir !is null); }),
        "NamedBitList": T("BIT STRING { a (12), b (valueRef), c (MyMod.valueRef) }", (ir){
            ulong value;
            ir.getByName!Asn1IntegerValueIr("a").asUnsigned(value).resultAssert;
            assert(value == 12);
            assert(ir.getByName!Asn1ValueReferenceIr("b").getFullString() == "valueRef");
            assert(ir.getByName!Asn1ValueReferenceIr("c").getFullString() == "MyMod.valueRef");
        }),
        "Error - duplicate keys": T("BIT STRING { a(1), a(2) }", Asn1SemanticError.duplicateKey)
    ]);
}

Result asn1AstToIr(
    scope Asn1CharacterStringTypeNode node,
    scope out Asn1TypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1RestrictedCharacterStringTypeNode stringType){
            return stringType.match(
                (Asn1BMPStringNode sub) {
                    ir = context.allocNode!Asn1BMPStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1GeneralStringNode sub) {
                    ir = context.allocNode!Asn1GeneralStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1GraphicStringNode sub) {
                    ir = context.allocNode!Asn1GraphicStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1IA5StringNode sub) {
                    ir = context.allocNode!Asn1IA5StringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1ISO646StringNode sub) {
                    ir = context.allocNode!Asn1ISO646StringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1NumericStringNode sub) {
                    ir = context.allocNode!Asn1NumericStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1PrintableStringNode sub) {
                    ir = context.allocNode!Asn1PrintableStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1TeletexStringNode sub) {
                    ir = context.allocNode!Asn1TeletexStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1T61StringNode sub) {
                    ir = context.allocNode!Asn1T61StringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1UniversalStringNode sub) {
                    ir = context.allocNode!Asn1UniversalStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1UTF8StringNode sub) {
                    ir = context.allocNode!Asn1UTF8StringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1VideotexStringNode sub) {
                    ir = context.allocNode!Asn1VideotexStringTypeIr(sub.token.location);
                    return Result.noError;
                },
                (Asn1VisibleStringNode sub) {
                    ir = context.allocNode!Asn1VisibleStringTypeIr(sub.token.location);
                    return Result.noError;
                },
            );
        },
        (Asn1UnrestrictedCharacterStringTypeNode stringType){
            ir = context.allocNode!Asn1CharacterStringTypeIr(stringType.token.location);
            return Result.noError;
        },
    );
}
@("asn1AstToIr - Asn1CharacterStringTypeNode > Asn1Ir")
unittest
{
    alias Harness = GenericTestHarness!(Asn1TypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1CharacterStringTypeNode;
    });
    
    with(Harness) run([
        "Unrestricted": T("CHARACTER STRING", (ir){ assert(cast(Asn1CharacterStringTypeIr)ir); }),
        "BMPString": T("BMPString", (ir){ assert(cast(Asn1BMPStringTypeIr)ir); }),
        "GeneralString": T("GeneralString", (ir){ assert(cast(Asn1GeneralStringTypeIr)ir); }),
        "GraphicString": T("GraphicString", (ir){ assert(cast(Asn1GraphicStringTypeIr)ir); }),
        "IA5String": T("IA5String", (ir){ assert(cast(Asn1IA5StringTypeIr)ir); }),
        "ISO646String": T("ISO646String", (ir){ assert(cast(Asn1ISO646StringTypeIr)ir); }),
        "NumericString": T("NumericString", (ir){ assert(cast(Asn1NumericStringTypeIr)ir); }),
        "PrintableString": T("PrintableString", (ir){ assert(cast(Asn1PrintableStringTypeIr)ir); }),
        "TeletexString": T("TeletexString", (ir){ assert(cast(Asn1TeletexStringTypeIr)ir); }),
        "T61String": T("T61String", (ir){ assert(cast(Asn1T61StringTypeIr)ir); }),
        "UniversalString": T("UniversalString", (ir){ assert(cast(Asn1UniversalStringTypeIr)ir); }),
        "UTF8String": T("UTF8String", (ir){ assert(cast(Asn1UTF8StringTypeIr)ir); }),
        "VideotexString": T("VideotexString", (ir){ assert(cast(Asn1VideotexStringTypeIr)ir); }),
        "VisibleString": T("VisibleString", (ir){ assert(cast(Asn1VisibleStringTypeIr)ir); }),
    ]);
}

Result asn1AstToIr(
    scope Asn1ChoiceTypeNode node,
    scope out Asn1ChoiceTypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Result append(Asn1NamedTypeNode item)
    {
        Asn1TypeIr typeIr;
        auto convResult = asn1AstToIr(item.getNode!Asn1TypeNode, typeIr, context, errors);
        if(convResult.isError)
            return convResult;

        auto result = ir.addChoice(
            item.getNode!Asn1IdentifierTokenNode.token.text,
            typeIr,
            errors
        );
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result appendAll(Asn1AlternativeTypeListNode typeList)
    {
        foreach(item; typeList.items)
        {
            if(auto r = append(item))
                return r;
        }
        return Result.noError;
    }

    ir = context.allocNode!(typeof(ir))(Asn1Location.init); // TODO: Easy way to get a rough location?
    return node.getNode!Asn1AlternativeTypeListsNode.match(
        (Asn1RootAlternativeTypeListNode typeList){
            return appendAll(typeList.getNode!Asn1AlternativeTypeListNode);
        },
        (Asn1AlternativeTypeListsNode.Case1 case1){
            if(auto r = appendAll(case1.getNode!Asn1RootAlternativeTypeListNode.getNode!Asn1AlternativeTypeListNode))
                return r;
            
            ir.markAsExtensible();

            if(auto typeList = case1.getNode!Asn1ExtensionAdditionAlternativesNode
                                    .maybeNode!Asn1ExtensionAdditionAlternativesListNode
            )
            {
                foreach(item; typeList.items)
                {
                    auto result = item.match(
                        (Asn1ExtensionAdditionAlternativesGroupNode group){
                            // TODO: Double check whether version numbers are even used for anything significant?
                            //       (Might be relevant to PER, which I can safely ignore for the next decade)
                            // TODO: Implement check for 24.15
                            return appendAll(group.getNode!Asn1AlternativeTypeListNode);
                        },
                        (Asn1NamedTypeNode namedType) => append(namedType)
                    );
                    if(result.isError)
                        return result;
                }
            }

            return Result.noError;
        }
    );
}
@("asn1AstToIr - Asn1ChoiceTypeNode > Asn1ChoiceTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1ChoiceTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1ChoiceTypeNode;
    });
    
    with(Harness) run([
        "Plain": T("CHOICE { a INTEGER, b BOOLEAN }", (ir){
            uint length;
            ir.foreachChoice((name, choice, isExtensible){
                if(name == "a")
                {
                    length++;
                    assert(cast(Asn1IntegerTypeIr)choice);
                }
                else if(name == "b")
                {
                    length++;
                    assert(cast(Asn1BooleanTypeIr)choice);
                }
                else
                    assert(false, name);
                assert(!isExtensible);
                return Result.noError;
            }).resultAssert;
            assert(length == 2);
        }),
        "Extensible - no following types": T("CHOICE { a INTEGER, b BOOLEAN, ... }", (ir){
            uint length;
            ir.foreachChoice((name, choice, isExtensible){
                length++;
                assert(!isExtensible);
                return Result.noError;
            }).resultAssert;
            assert(length == 2);
            assert(ir.isExtensible);
        }),
        "Extensible - with following types": T("CHOICE { a INTEGER, b BOOLEAN, ..., c INTEGER, [[2: d BOOLEAN, e BOOLEAN]] }", (ir){ // @suppress(dscanner.style.long_line)
            uint length;
            ir.foreachChoice((name, choice, isExtensible){
                length++;

                if(length > 2)
                    assert(isExtensible);
                else
                    assert(!isExtensible);

                return Result.noError;
            }).resultAssert;
            assert(length == 5);
            assert(ir.isExtensible);
        }),
    ]);
}

Result asn1AstToIr(
    scope Asn1EnumeratedTypeNode node,
    scope out Asn1EnumeratedTypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Result appendAll(Asn1EnumerationNode enumerations)
    {
        foreach(item; enumerations.items)
        {
            auto result = item.match(
                (Asn1IdentifierTokenNode identifier) {
                    return ir.addEnumerationImplicit(identifier.token.text, errors);
                },
                (Asn1NamedNumberNode number) {
                    return number.match(
                        (Asn1NamedNumberNode.Signed signed){
                            Asn1IntegerValueIr intValue;
                            if(auto r = asn1AstToIr(signed.getNode!Asn1SignedNumberNode, intValue, context, errors))
                                return r;

                            return ir.addEnumerationExplicit(
                                signed.getNode!Asn1IdentifierTokenNode.token.text,
                                intValue
                            );
                        },
                        (Asn1NamedNumberNode.Defined defined){
                            Asn1ValueReferenceIr valueRef;
                            if(auto r = asn1AstToIr(defined.getNode!Asn1DefinedValueNode, valueRef, context, errors))
                                return r;

                            return ir.addEnumerationExplicit(
                                defined.getNode!Asn1IdentifierTokenNode.token.text,
                                valueRef
                            );
                        },
                    );
                }
            );
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    ir = context.allocNode!(typeof(ir))(Asn1Location.init); // TODO: Easy way to get a rough location?
    return node.getNode!Asn1EnumerationsNode.match(
        (Asn1RootEnumerationNode enumerations){
            return appendAll(enumerations.getNode!Asn1EnumerationNode);
        },
        (Asn1EnumerationsNode.Case1 case1){
            if(auto r = appendAll(case1.getNode!Asn1RootEnumerationNode.getNode!Asn1EnumerationNode))
                return r;
            
            ir.markAsExtensible();
            return Result.noError;
        },
        (Asn1EnumerationsNode.Case2 case2){
            if(auto r = appendAll(case2.getNode!Asn1RootEnumerationNode.getNode!Asn1EnumerationNode))
                return r;
            
            ir.markAsExtensible();
            return appendAll(case2.getNode!Asn1AdditionalEnumerationNode.getNode!Asn1EnumerationNode);
        },
    );
    return Result.noError;
}
@("asn1AstToIr - Asn1EnumeratedTypeNode > Asn1EnumeratedTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1EnumeratedTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1EnumeratedTypeNode;
    });
    
    with(Harness) run([
        "Plain": T("ENUMERATED { a, b(1), c(d) }", (ir){
            uint length;
            ir.foreachEnumeration((name, number, isExtensible){
                if(name == "a")
                {
                    length++;
                    assert(number.isNull);
                }
                else if(name == "b")
                {
                    length++;
                    assert(number == 1);
                }
                else if(name == "c")
                {
                    length++;
                    assert(number.isNull);
                }
                else
                    assert(false, name);
                assert(!isExtensible);
                return Result.noError;
            }).resultAssert;
            assert(length == 3);
        }),
        "Extensible - no following values": T("ENUMERATED { a, ... }", (ir){
            uint length;
            ir.foreachEnumeration((_, __, isExtensible){
                length++;
                assert(!isExtensible);
                return Result.noError;
            }).resultAssert;
            assert(length == 1);
            assert(ir.isExtensible);
        }),
        "Extensible - with following values": T("ENUMERATED { a, ..., b }", (ir){
            uint length;
            ir.foreachEnumeration((_, __, isExtensible){
                length++;
                if(length == 2)
                    assert(isExtensible);
                else
                    assert(!isExtensible);
                return Result.noError;
            }).resultAssert;
            assert(length == 2);
            assert(ir.isExtensible);
        }),
    ]);
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
            assert(list.items.length, "Asn1NamedNumberListNode is empty? The parser should've caught this!");

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

Result asn1AstToIrForSequence(AstT, IrT)(
    scope AstT node,
    scope out IrT ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Result append(Asn1NamedTypeNode item, bool isOptional)
    {
        Asn1TypeIr typeIr;
        auto convResult = asn1AstToIr(item.getNode!Asn1TypeNode, typeIr, context, errors);
        if(convResult.isError)
            return convResult;

        auto result = ir.addComponent(
            item.getNode!Asn1IdentifierTokenNode.token.text,
            typeIr,
            isOptional,
            errors
        );
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result appendComponent(Asn1ComponentTypeNode item)
    {
        return item.match(
            (Asn1NamedTypeNode namedType){
                return append(namedType, false);
            },
            (Asn1ComponentTypeNode.Optional optional){
                return append(optional.getNode!Asn1NamedTypeNode, true);
            },
            (Asn1ComponentTypeNode.Default default_){
                auto item = default_.getNode!Asn1NamedTypeNode;

                Asn1ValueIr valueIr;
                auto valueResult = asn1AstToIr(default_.getNode!Asn1ValueNode, valueIr, context, errors);
                if(valueResult.isError)
                    return valueResult;

                Asn1TypeIr typeIr;
                auto convResult = asn1AstToIr(item.getNode!Asn1TypeNode, typeIr, context, errors);
                if(convResult.isError)
                    return convResult;

                auto result = ir.addComponentWithDefault(
                    item.getNode!Asn1IdentifierTokenNode.token.text,
                    typeIr,
                    valueIr,
                    errors
                );
                if(result.isError)
                    return result;
                return Result.noError;
            },
            (Asn1TypeNode type){
                Asn1TypeIr typeIr;
                auto convResult = asn1AstToIr(type, typeIr, context, errors);
                if(convResult.isError)
                    return convResult;
                ir.addComponentsOf(typeIr);
                return Result.noError;
            },
        );
    }

    Result appendAll(Asn1ComponentTypeListNode typeList)
    {
        foreach(item; typeList.items)
        {
            if(auto r = appendComponent(item))
                return r;
        }
        return Result.noError;
    }

    Result appendAdditions(Asn1ExtensionAdditionsNode additions)
    {
        if(additions.isNode!Asn1EmptyNode)
            return Result.noError;

        foreach(item; additions.asNode!Asn1ExtensionAdditionListNode.items)
        {
            auto result = item.match(
                (Asn1ComponentTypeNode component) => appendComponent(component),
                (Asn1ExtensionAdditionGroupNode group) 
                    => appendAll(group.getNode!Asn1ComponentTypeListNode)
            );
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    // TODO: Token location?
    ir = context.allocNode!(typeof(ir))(Asn1Location());
    return node.match(
        (AstT.Empty empty) {
            return Result.noError;
        },
        (Asn1ComponentTypeListsNode typeLists) {
            return typeLists.match(
                (Asn1RootComponentTypeListNode node){
                    return appendAll(node.getNode!Asn1ComponentTypeListNode);
                },
                (Asn1ComponentTypeListsNode.Case1 case1){
                    if(auto r = appendAll(case1.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode)) // @suppress(dscanner.style.long_line)
                        return r;
                    
                    ir.markAsExtensible();
                    return appendAdditions(case1.getNode!Asn1ExtensionAdditionsNode);
                },
                (Asn1ComponentTypeListsNode.Case2 case2){
                    if(auto r = appendAll(case2.getNode!Asn1RootComponentTypeListNode.getNode!Asn1ComponentTypeListNode)) // @suppress(dscanner.style.long_line)
                        return r;
                    
                    ir.markAsExtensible();
                    if(auto r = appendAdditions(case2.getNode!Asn1ExtensionAdditionsNode))
                        return r;

                    auto additionalList = case2
                                            .getNode!(typeof(case2).Additional)
                                            .getNode!Asn1RootComponentTypeListNode
                                            .getNode!Asn1ComponentTypeListNode;
                    return appendAll(additionalList);
                },
                (Asn1ComponentTypeListsNode.Case3 case3){
                    ir.markAsExtensible();
                    if(auto r = appendAdditions(case3.getNode!Asn1ExtensionAdditionsNode))
                        return r;
                    return appendAll(
                        case3
                            .getNode!Asn1RootComponentTypeListNode
                            .getNode!Asn1ComponentTypeListNode
                    );
                },
                (Asn1ComponentTypeListsNode.Case4 case4){
                    ir.markAsExtensible();
                    if(auto r = appendAdditions(case4.getNode!Asn1ExtensionAdditionsNode))
                        return r;
                    return Result.noError;
                },
            );
        }
    );
}

@("asn1AstToIrForSequence")
unittest
{
    alias Harness = GenericTestHarness!(Asn1SequenceTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceTypeNode;
    }, asn1AstToIrForSequence);
    
    with(Harness) run([
        "Empty": T("SEQUENCE {}", (ir){ assert(ir !is null); }),
        "ComponentType Cases": T(`
            SEQUENCE { 
                a INTEGER, 
                b INTEGER OPTIONAL, 
                c INTEGER DEFAULT 1, 
                COMPONENTS OF INTEGER
            }
        `, (ir){
            assert(ir.componentsUnittest.length == 4);
            assert(ir.componentsUnittest[0].name == "a");
            assert(ir.componentsUnittest[0].type !is null);
            assert(ir.componentsUnittest[0].defaultValue is null);
            assert(ir.componentsUnittest[0].flags == 0);

            assert(ir.componentsUnittest[1].name == "b");
            assert(ir.componentsUnittest[1].flags != 0);
            
            assert(ir.componentsUnittest[2].name == "c");
            assert(ir.componentsUnittest[2].defaultValue !is null);
            
            assert(ir.componentsUnittest[3].name.length == 0);
            assert(ir.componentsUnittest[3].flags != 0);
        }),
        "Case1": T("SEQUENCE { a INTEGER, ..., b INTEGER, [[c INTEGER]] }", (ir){
            assert(ir.componentsUnittest.length == 3);
        }),
        "Case2": T("SEQUENCE { a INTEGER, ..., b INTEGER, ..., c INTEGER }", (ir){
            assert(ir.componentsUnittest.length == 3);
        }),
        "Case3": T("SEQUENCE { ..., b INTEGER, ..., c INTEGER }", (ir){
            assert(ir.componentsUnittest.length == 2);
        }),
        "Case4": T("SEQUENCE { ..., b INTEGER }", (ir){
            assert(ir.componentsUnittest.length == 1);
        }),
    ]);
}

Result asn1AstToIrForSequenceOf(AstT, IrT)(
    scope AstT node,
    scope out IrT ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1TypeNode type){
            Asn1TypeIr typeIr;
            if(auto r = asn1AstToIr(type, typeIr, context, errors))
                return r;

            ir = context.allocNode!(typeof(ir))(typeIr.getRoughLocation(), typeIr);
            return Result.noError;
        },
        (Asn1NamedTypeNode namedType){
            Asn1TypeIr typeIr;
            if(auto r = asn1AstToIr(namedType.getNode!Asn1TypeNode, typeIr, context, errors))
                return r;

            ir = context.allocNode!(typeof(ir))(
                typeIr.getRoughLocation(),
                typeIr,
                namedType.getNode!Asn1IdentifierTokenNode.token.text
            );
            return Result.noError;
        }
    );
}
@("asn1AstToIrForSequenceOf")
unittest
{
    alias Harness = GenericTestHarness!(Asn1SequenceOfTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1SequenceOfTypeNode;
    }, asn1AstToIrForSequenceOf);
    
    with(Harness) run([
        "Type": T("SEQUENCE OF INTEGER", (ir){ assert(ir.getTypeOfItems() !is null); }),
        "NamedType": T("SEQUENCE OF i INTEGER", (ir){ assert(ir.getItemTypeName() == "i"); }),
    ]);
}

Result asn1AstToIr(
    scope Asn1TaggedTypeNode node,
    scope out Asn1TaggedTypeIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Result set(IrT)(IrT node, Asn1TaggedTypeIr.Encoding encoding)
    {
        auto tagNode = node.getNode!Asn1TagNode;
        auto typeNode = node.getNode!Asn1TypeNode;

        typeof(ir).Class class_;
        tagNode.getNode!Asn1ClassNode.match(
            (Asn1UniversalNode classNode){
                ir = context.allocNode!(typeof(ir))(classNode.token.location);
                class_ = typeof(ir).Class.universal;
                return Result.noError;
            },
            (Asn1ApplicationNode classNode){
                ir = context.allocNode!(typeof(ir))(classNode.token.location);
                class_ = typeof(ir).Class.application;
                return Result.noError;
            },
            (Asn1PrivateNode classNode){
                ir = context.allocNode!(typeof(ir))(classNode.token.location);
                class_ = typeof(ir).Class.private_;
                return Result.noError;
            },
            (Asn1EmptyNode classNode){
                ir = context.allocNode!(typeof(ir))(classNode.token.location);
                class_ = typeof(ir).Class.unspecified;
                return Result.noError;
            },
        ).resultAssert;

        Asn1TypeIr typeIr;
        if(auto r = asn1AstToIr(typeNode, typeIr, context, errors))
            return r;
        ir.setUnderlyingType(typeIr);

        return tagNode.getNode!Asn1ClassNumberNode.match(
            (Asn1NumberTokenNode numberNode) {
                auto value = context.allocNode!Asn1IntegerValueIr(numberNode.token, false);
                ir.setTag(class_, value, encoding);
                return Result.noError;
            },
            (Asn1DefinedValueNode numberNode) {
                Asn1ValueReferenceIr value;
                if(auto r = asn1AstToIr(numberNode, value, context, errors))
                    return r;
                ir.setTag(class_, value, encoding);
                return Result.noError;
            },
        );
    }

    return node.match(
        (Asn1TaggedTypeNode.Default default_) => set(default_, Asn1TaggedTypeIr.Encoding.unspecified),
        (Asn1TaggedTypeNode.Implicit implicit) => set(implicit, Asn1TaggedTypeIr.Encoding.implicit),
        (Asn1TaggedTypeNode.Explicit explicit)  => set(explicit, Asn1TaggedTypeIr.Encoding.explicit)
    );
}
@("asn1AstToIr - Asn1TaggedTypeNode > Asn1TaggedTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1TaggedTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node.asNode!Asn1BuiltinTypeNode.asNode!Asn1TaggedTypeNode;
    });
    
    with(Harness) run([
        "Default": T("[0] INTEGER", (ir){
            assert(ir.getClass() == Asn1TaggedTypeIr.Class.unspecified);
            assert(ir.getEncoding() == Asn1TaggedTypeIr.Encoding.unspecified);
            assert(cast(Asn1IntegerValueIr)ir.getNumberIr() !is null);
            assert(cast(Asn1IntegerTypeIr)ir.getUnderlyingType() !is null);
        }),
        "Implicit": T("[0] IMPLICIT INTEGER", (ir){
            assert(ir.getEncoding() == Asn1TaggedTypeIr.Encoding.implicit);
        }),
        "Explicit": T("[0] EXPLICIT INTEGER", (ir){
            assert(ir.getEncoding() == Asn1TaggedTypeIr.Encoding.explicit);
        }),
        "Universal": T("[UNIVERSAL 0] INTEGER", (ir){
            assert(ir.getClass() == Asn1TaggedTypeIr.Class.universal);
        }),
        "Application": T("[APPLICATION 0] INTEGER", (ir){
            assert(ir.getClass() == Asn1TaggedTypeIr.Class.application);
        }),
        "Private": T("[PRIVATE 0] INTEGER", (ir){
            assert(ir.getClass() == Asn1TaggedTypeIr.Class.private_);
        }),
    ]);
}

/++++ Values ++++/

Result asn1AstToIr(
    scope Asn1ValueNode node,
    scope out Asn1ValueIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1BuiltinValueNode builtin){
            return builtin.match(
                (Asn1BooleanValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1ChoiceValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1IntegerValueNode node){
                    return node.match(
                        (Asn1SignedNumberNode number) {
                            Asn1IntegerValueIr intIr;
                            if(auto r = asn1AstToIr(number, intIr, context, errors))
                                return r;
                            ir = intIr;
                            return Result.noError;
                        },
                        (Asn1IdentifierTokenNode identifier) {
                            ir = context.allocNode!Asn1ValueReferenceIr(
                                identifier.token.location,
                                identifier.token.text,
                            );
                            return Result.noError;
                        },
                    );
                },
                (Asn1NullValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1RealValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1UnresolvedStringValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1UnresolvedSequenceValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1UnresolvedIdentifierValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
            );
        },
        (Asn1ReferencedValueNode referenced){
            return Result.noError;
        },
        (Asn1ObjectClassFieldValueNode _){
            return Result.noError;
        },
    );
}

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

    template GenericTestHarness(IrT, alias ParseFunc, alias Converter = asn1AstToIr)
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
                    auto result = Converter(node, ir, context, Asn1NullSemanticErrorHandler.instance);

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