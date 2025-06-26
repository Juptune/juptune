/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// Provides converter functions to transform AST nodes into IR nodes, while performing light amounts of semantic checks.
module juptune.data.asn1.lang.ast2ir;

import juptune.core.util : Result, resultAssert;
import juptune.data.asn1.lang.ast; // Intentionally everything
import juptune.data.asn1.lang.ir;  // Intentionally everything
import juptune.data.asn1.lang.common : Asn1ParserContext, Asn1Location;
import juptune.data.asn1.lang.parser : Asn1Parser, Asn1ParserError;

/++++ Special ++++/

Result asn1AstToIr(
    scope Asn1ModuleDefinitionNode node,
    scope out Asn1ModuleIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    auto modIdNode = node.getNode!Asn1ModuleIdentifierNode;
    auto modRefToken = modIdNode.getNode!Asn1ModuleReferenceTokenNode.token;
    auto modObjIdIr = context.allocNode!Asn1ObjectIdSequenceValueIr(modRefToken.location);
    auto modObjIdResult = modIdNode.getNode!Asn1DefinitiveIdentifierNode.match(
        (Asn1DefinitiveObjIdComponentListNode listNode){
            foreach(item; listNode.items)
            {
                auto result = item.match(
                    (Asn1NameFormNode nameForm){
                        auto id = nameForm.getNode!Asn1IdentifierTokenNode;
                        modObjIdIr.addObjectId(
                            context.allocNode!Asn1ValueReferenceIr(
                                id.token.location, 
                                id.token.text
                            )
                        );
                        return Result.noError;
                    },
                    (Asn1DefinitiveNumberFormNode numberForm){
                        modObjIdIr.addObjectId(context.allocNode!Asn1IntegerValueIr(
                            numberForm.getNode!Asn1NumberTokenNode.token,
                            false
                        ));
                        return Result.noError;
                    },
                    (Asn1DefinitiveNameAndNumberFormNode nameNumberForm){
                        modObjIdIr.addObjectId(context.allocNode!Asn1IntegerValueIr(
                            nameNumberForm.getNode!Asn1DefinitiveNumberFormNode.getNode!Asn1NumberTokenNode.token,
                            false
                        ));
                        return Result.noError;
                    }
                );
                if(result.isError)
                    return result;
            }
            return Result.noError;
        },
        (Asn1EmptyNode _) => Result.noError
    );
    if(modObjIdResult.isError)
        return modObjIdResult;

    Asn1ModuleIr.TagDefault tagDefault;
    auto tagDefaultResult = node.getNode!Asn1TagDefaultNode.match(
        (Asn1ExplicitTagsNode _){
            tagDefault = Asn1ModuleIr.TagDefault.explicit;
            return Result.noError;
        },
        (Asn1ImplicitTagsNode _){
            tagDefault = Asn1ModuleIr.TagDefault.implicit;
            return Result.noError;
        },
        (Asn1AutomaticTagsNode _){
            tagDefault = Asn1ModuleIr.TagDefault.automatic;
            return Result.noError;
        },
        (Asn1EmptyNode _){
            tagDefault = Asn1ModuleIr.TagDefault.explicit;
            return Result.noError;
        },
    );
    if(tagDefaultResult.isError)
        return tagDefaultResult;

    bool extensibilityImplied;
    auto extensionDefaultResult = node.getNode!Asn1ExtensionDefaultNode.match(
        (Asn1ExtensibilityImpliedNode _){
            extensibilityImplied = true;
            return Result.noError;
        },
        (Asn1EmptyNode _) => Result.noError,
    );
    if(extensionDefaultResult.isError)
        return extensionDefaultResult;

    Asn1ModuleBodyNode.Case1 modBodyNode;
    node.getNode!Asn1ModuleBodyNode.match(
        (Asn1ModuleBodyNode.Case1 case1){
            modBodyNode = case1;
            return Result.noError;
        },
        (Asn1EmptyNode _){
            ir = context.allocNode!(typeof(ir))(
                modRefToken.text,
                modObjIdIr,
                tagDefault,
                extensibilityImplied,
                context.allocNode!Asn1ExportsIr(Asn1Location()),
            );
            return ir.setImports(context.allocNode!Asn1ImportsIr(Asn1Location()), errors);
        },
    ).resultAssert;
    if(modBodyNode is null)
    {
        assert(ir !is null, "bug: ir should've been set?");
        return Result.noError;
    }

    Asn1ExportsIr exportsIr;
    auto exportsResult = asn1AstToIr(modBodyNode.getNode!Asn1ExportsNode, exportsIr, context, errors);
    if(exportsResult.isError)
        return exportsResult;

    Asn1ImportsIr importsIr;
    auto importsResult = asn1AstToIr(modBodyNode.getNode!Asn1ImportsNode, importsIr, context, errors);
    if(importsResult.isError)
        return importsResult;

    ir = context.allocNode!(typeof(ir))(
        modRefToken.text,
        modObjIdIr,
        tagDefault,
        extensibilityImplied,
        exportsIr,
    );
    auto setImportsResult = ir.setImports(importsIr, errors);
    if(setImportsResult.isError)
        return setImportsResult;

    foreach(assNode; modBodyNode.getNode!Asn1AssignmentListNode.items)
    {
        auto assResult = assNode.match(
            (Asn1TypeAssignmentNode typeAss) {
                Asn1TypeIr typeIr;
                if(auto r = asn1AstToIr(typeAss.getNode!Asn1TypeNode, typeIr, context, errors))
                    return r;

                auto assIr = context.allocNode!Asn1TypeAssignmentIr(
                    typeAss.getNode!Asn1TypeReferenceTokenNode.token.location,
                    typeAss.getNode!Asn1TypeReferenceTokenNode.token.text,
                    typeIr
                );
                if(auto r = ir.addAssignment(assIr, errors))
                    return r;
                return Result.noError;
            },
            (Asn1ValueAssignmentNode valueAss) {
                Asn1TypeIr typeIr;
                if(auto r = asn1AstToIr(valueAss.getNode!Asn1TypeNode, typeIr, context, errors))
                    return r;

                Asn1ValueIr valueIr;
                if(auto r = asn1AstToIr(valueAss.getNode!Asn1ValueNode, valueIr, context, errors))
                    return r;

                auto assIr = context.allocNode!Asn1ValueAssignmentIr(
                    valueAss.getNode!Asn1ValueReferenceTokenNode.token.location,
                    valueAss.getNode!Asn1ValueReferenceTokenNode.token.text,
                    typeIr,
                    valueIr
                );
                if(auto r = ir.addAssignment(assIr, errors))
                    return r;
                return Result.noError;
            },
            (Asn1ValueSetTypeAssignmentNode _) {
                assert(false, "Not implemented");
                return Result.noError;
            },
            (Asn1ObjectClassAssignmentNode _) {
                assert(false, "Not implemented");
                return Result.noError;
            },
            (Asn1ObjectAssignmentNode _) {
                assert(false, "Not implemented");
                return Result.noError;
            },
            (Asn1ObjectSetAssignmentNode _) {
                assert(false, "Not implemented");
                return Result.noError;
            },
            (Asn1ParameterizedAssignmentNode _) {
                assert(false, "Not implemented");
                return Result.noError;
            },
        );
        if(assResult.isError)
            return assResult;
    }
    
    return Result.noError;
}
@("asn1AstToIr - Asn1ModuleNode")
unittest
{
    alias Harness = GenericTestHarness!(Asn1ModuleIr, (ref parser){
        Asn1ModuleDefinitionNode node;
        parser.ModuleDefinition(node).resultAssert;
        return node;
    });
    
    with(Harness) run([
        "Plain, empty body": T("MyModule DEFINITIONS ::= BEGIN END", (ir){
            assert(ir.getModuleName() == "MyModule");
            assert(ir.getTagDefault() == Asn1ModuleIr.TagDefault.explicit);
            assert(!ir.isExtensibilityImplied());
        }),
        "EXPLICIT TAGS": T("MyModule DEFINITIONS EXPLICIT TAGS ::= BEGIN END", (ir){
            assert(ir.getTagDefault() == Asn1ModuleIr.TagDefault.explicit);
        }),
        "IMPLICIT TAGS": T("MyModule DEFINITIONS IMPLICIT TAGS ::= BEGIN END", (ir){
            assert(ir.getTagDefault() == Asn1ModuleIr.TagDefault.implicit);
        }),
        "AUTOMATIC TAGS": T("MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN END", (ir){
            assert(ir.getTagDefault() == Asn1ModuleIr.TagDefault.automatic);
        }),
        "EXTENSIBILITY IMPLIED": T("MyModule DEFINITIONS EXTENSIBILITY IMPLIED ::= BEGIN END", (ir){
            assert(ir.isExtensibilityImplied());
        }),
        "Empty Imports": T(`
            MyModule DEFINITIONS ::= BEGIN
                IMPORTS ;
            END
        `, (ir){
        }),
        "Import without module version": T(`
            MyModule DEFINITIONS ::= BEGIN
                IMPORTS
                    FOO, bar FROM SomeMod
                ;
            END
        `, (ir){
            bool hasTypeRef, hasValueRef;
            ir.getImports().foreachImport(
                (modRef, modVersion, typeRef){
                    hasTypeRef = true;
                    assert(modRef == "SomeMod");
                    assert(modVersion is null);
                    assert(typeRef.typeRef == "FOO");
                    return Result.noError;
                },
                (modRef, modVersion, valueRef){
                    hasValueRef = true;
                    assert(modRef == "SomeMod");
                    assert(modVersion is null);
                    assert(valueRef.valueRef == "bar");
                    return Result.noError;
                }
            ).resultAssert;
            assert(hasTypeRef && hasValueRef);
        }),
        "Empty Exports": T(`
            MyModule DEFINITIONS ::= BEGIN
                EXPORTS;
            END
        `, (ir){
        }),
        "EXPORTS ALL": T(`
            MyModule DEFINITIONS ::= BEGIN
                EXPORTS ALL;
            END
        `, (ir){
            assert(ir.getExports().doesExportsAll);
        }),
        "Exports": T(`
            MyModule DEFINITIONS ::= BEGIN
                EXPORTS FOO, bar;
            END
        `, (ir){
            
        }),
        "Assignments": T(`
            MyModule DEFINITIONS ::= BEGIN
                MyType ::= INTEGER
                value INTEGER ::= 0
            END
        `, (ir){
            size_t length;
            ir.foreachAssignment((ass){
                length++;

                switch(length)
                {
                    case 1:
                        auto typeAss = cast(Asn1TypeAssignmentIr)ass;
                        assert(typeAss !is null);
                        assert(typeAss.getSymbolName() == "MyType");
                        assert(cast(Asn1IntegerTypeIr)typeAss.getSymbolType());
                        break;
                    
                    case 2:
                        auto valueAss = cast(Asn1ValueAssignmentIr)ass;
                        assert(valueAss !is null);
                        assert(valueAss.getSymbolName() == "value");
                        assert(cast(Asn1IntegerTypeIr)valueAss.getSymbolType());
                        assert(cast(Asn1IntegerValueIr)valueAss.getSymbolValue());
                        break;

                    default: assert(false, "Missing case for ass");
                }

                return Result.noError;
            }).resultAssert;
            assert(length == 2);
        }),
        "TEMP - Semantics test": T(`
            MyModule DEFINITIONS ::= BEGIN
                a INTEGER ::= 400
                I ::= INTEGER { a(1), b(a) } (I)
                i I ::= b

                C ::= CHOICE { a INTEGER }
                c C ::= a: 20
            END
        `, (ir){
            Asn1ParserContext context; // Don't do this in real code, use the original context, otherwise node lifetimes won't match up (memory corruption fun)
            ir.doSemanticStage(
                Asn1BaseIr.SemanticStageBit.resolveReferences,
                (_) => Asn1BaseIr.LookupItemT.init,
                context,
                Asn1BaseIr.SemanticInfo(),
                Asn1NullSemanticErrorHandler.instance,
            ).resultAssert;

            auto i = cast(Asn1ValueAssignmentIr)ir.lookupSymbolOrNull("i");
            assert(i !is null);

            auto intIr = cast(Asn1IntegerValueIr)(cast(Asn1ValueReferenceIr)i.getSymbolValue()).getResolvedValue();
            assert(intIr !is null);

            long number;
            intIr.asSigned(number, Asn1NullSemanticErrorHandler.instance).resultAssert;
            assert(number == 400);
        })
    ]);
}

Result asn1AstToIr(
    scope Asn1ExportsNode node,
    scope out Asn1ExportsIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1SymbolsExportedNode exportedNode){
            return exportedNode.match(
                (Asn1SymbolListNode symbolList){
                    ir = context.allocNode!(typeof(ir))(Asn1Location()); // TODO: Location
                    foreach(symbolNode; symbolList.items)
                    {
                        Asn1ReferenceNode refNode;
                        symbolNode.match(
                            (Asn1ReferenceNode symbolRefNode){
                                refNode = symbolRefNode;
                                return Result.noError;
                            },
                            (Asn1ParameterizedReferenceNode paramRefNode) {
                                assert(false, "Not implemented");
                                return Result.noError;
                            }
                        ).resultAssert;

                        auto result = refNode.match(
                            (Asn1TypeReferenceTokenNode typeRefNode){
                                return ir.addExport(context.allocNode!Asn1TypeReferenceIr(
                                    typeRefNode.token.location,
                                    typeRefNode.token.text,
                                ), errors);
                            },
                            (Asn1ValueReferenceTokenNode valueRefNode){
                                return ir.addExport(context.allocNode!Asn1ValueReferenceIr(
                                    valueRefNode.token.location,
                                    valueRefNode.token.text
                                ), errors);
                            },
                            (Asn1ObjectClassReferenceTokenNode _){
                                assert(false, "Not implemented");
                                return Result.noError;
                            },
                            (Asn1ObjectReferenceTokenNode _){
                                assert(false, "Not implemented");
                                return Result.noError;
                            },
                            (Asn1ObjectSetReferenceTokenNode _){
                                assert(false, "Not implemented");
                                return Result.noError;
                            },
                        );
                        if(result.isError)
                            return result;
                    }
                    return Result.noError;
                },
                (Asn1EmptyNode emptyNode){
                    ir = context.allocNode!(typeof(ir))(emptyNode.token.location);
                    return Result.noError;
                },
            );
        },
        (Asn1ExportsAllNode allNode){
            ir = context.allocNode!(typeof(ir))(allNode.token.location, true);
            return Result.noError;
        },
        (Asn1EmptyNode emptyNode){
            ir = context.allocNode!(typeof(ir))(emptyNode.token.location);
            return Result.noError;
        },
    );
}
// Tested by the ModuleBody overload as the parser cannot individually generate an ExportsNode

Result asn1AstToIr(
    scope Asn1ImportsNode node,
    scope out Asn1ImportsIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Result handleSymbolMod(Asn1SymbolsFromModuleNode symbolModNode)
    {
        auto modRef = symbolModNode.getNode!Asn1GlobalModuleReferenceNode;

        Asn1ObjectIdSequenceValueIr moduleVersion;
        auto result = modRef.getNode!Asn1AssignedIdentifierNode.match(
            (Asn1ObjectIdentifierValueNode objIdNode){
                return objIdNode.match(
                    (Asn1ObjIdComponentsListNode listNode) {
                        return asn1AstToIr(listNode, moduleVersion, context, errors);
                    },
                    (Asn1ObjectIdentifierValueNode.Case1 case1) {
                        assert(false, "Not implemented");
                        return Result.noError;
                    }
                );
            },
            (Asn1DefinedValueNode definedValue){
                assert(false, "Not implemented");
                return Result.noError;
            },
            (Asn1EmptyNode _) => Result.noError,
        );
        if(result.isError)
            return result;

        auto addResult = ir.setupImportsForModule(
            modRef.getNode!Asn1ModuleReferenceTokenNode.token.text,
            moduleVersion,
            (scope addImport){
                foreach(symbolNode; symbolModNode.getNode!Asn1SymbolListNode.items)
                {
                    auto symbolResult = symbolNode.match(
                        (Asn1ReferenceNode refNode){
                            return refNode.match(
                                (Asn1TypeReferenceTokenNode typeRefNode){
                                    return addImport(context.allocNode!Asn1TypeReferenceIr(
                                        typeRefNode.token.location,
                                        typeRefNode.token.text,
                                    ));
                                },
                                (Asn1ValueReferenceTokenNode valueRefNode){
                                    return addImport(context.allocNode!Asn1ValueReferenceIr(
                                        valueRefNode.token.location,
                                        valueRefNode.token.text
                                    ));
                                },
                                (Asn1ObjectClassReferenceTokenNode _){
                                    assert(false, "Not implemented");
                                    return Result.noError;
                                },
                                (Asn1ObjectReferenceTokenNode _){
                                    assert(false, "Not implemented");
                                    return Result.noError;
                                },
                                (Asn1ObjectSetReferenceTokenNode _){
                                    assert(false, "Not implemented");
                                    return Result.noError;
                                },
                            );
                        },
                        (Asn1ParameterizedReferenceNode paramNode){
                            assert(false, "Not implemented");
                            return Result.noError;
                        }
                    );
                    if(symbolResult.isError)
                        return symbolResult;
                }
                return Result.noError;
            },
            errors
        );
        if(addResult.isError)
            return addResult;
        
        return Result.noError;
    }

    return node.match(
        (Asn1SymbolsImportedNode importedNode){
            ir = context.allocNode!(typeof(ir))(Asn1Location()); // TODO: Location
            return importedNode.match(
                (Asn1SymbolsFromModuleListNode symbolModList){
                    foreach(symbolModNode; symbolModList.items)
                    {
                        if(auto r = handleSymbolMod(symbolModNode))
                            return r;
                    }
                    return Result.noError;
                },
                (Asn1EmptyNode emptyNode){
                    ir = context.allocNode!(typeof(ir))(emptyNode.token.location);
                    return Result.noError;
                }
            );
        },
        (Asn1EmptyNode emptyNode){
            ir = context.allocNode!(typeof(ir))(emptyNode.token.location);
            return Result.noError;
        }
    );
}
// Tested by the ModuleBody overload as the parser cannot individually generate an ImportsNode

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
        (Asn1ReferencedTypeNode type) {
            return type.match(
                (Asn1DefinedTypeNode typeRef){
                    return typeRef.match(
                        (Asn1ExternalTypeReferenceNode refNode){
                            ir = context.allocNode!Asn1TypeReferenceIr(
                                refNode.getNode!Asn1ModuleReferenceTokenNode.token.location,
                                refNode.getNode!Asn1ModuleReferenceTokenNode.token.text,
                                refNode.getNode!Asn1TypeReferenceTokenNode.token.text,
                            );
                            return Result.noError;
                        },
                        (Asn1TypeReferenceTokenNode refNode){
                            ir = context.allocNode!Asn1TypeReferenceIr(
                                refNode.token.location,
                                refNode.token.text,
                            );
                            return Result.noError;
                        },
                        (Asn1ParameterizedTypeNode refNode){
                            assert(false, "Not implemented");
                            return Result.noError;
                        },
                        (Asn1ParameterizedValueSetTypeNode refNode){
                            assert(false, "Not implemented");
                            return Result.noError;
                        },
                    );
                },
                (Asn1UsefulTypeNode typeRef){
                    const token = typeRef.getNode!Asn1TypeReferenceTokenNode.token;
                    switch(token.text)
                    {
                        case "GeneralizedTime":
                            ir = context.allocNode!Asn1GeneralizedTimeTypeIr(token.location);
                            return Result.noError;

                        case "UTCTime":
                            ir = context.allocNode!Asn1UtcTimeTypeIr(token.location);
                            return Result.noError;

                        default: assert(false, "bug: Unknown useful type?");
                    }
                },
                (Asn1SelectionTypeNode typeRef){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1TypeFromObjectNode typeRef){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1ValueSetFromObjectsNode typeRef){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
            );
        },
        (Asn1ConstrainedTypeNode type) {
            return type.match(
                (Asn1ConstrainedTypeNode.Case1 case1) {
                    if(auto r = asn1AstToIr(case1.getNode!Asn1TypeNode, ir, context, errors))
                        return r;

                    Asn1ConstraintIr constraintIr, additionalConstraintIr;
                    bool isExtensible;
                    auto result = asn1AstToIrForConstraint(
                        case1.getNode!Asn1ConstraintNode,
                        constraintIr, // out
                        isExtensible, // out
                        additionalConstraintIr, // out
                        context, 
                        errors
                    );
                    if(result.isError)
                        return result;

                    if(constraintIr !is null)
                    {
                        if(auto r = ir.setMainConstraint(constraintIr, Asn1NullSemanticErrorHandler.instance))
                            return r;

                        if(isExtensible)
                            ir.markAsConstraintExtensible();

                        if(additionalConstraintIr !is null)
                        {
                            if(auto r = ir.setAdditionalConstraint(additionalConstraintIr, Asn1NullSemanticErrorHandler.instance)) // @suppress(dscanner.style.long_line)
                                return r;
                        }
                    }
                    return Result.noError;
                },
                (Asn1TypeWithConstraintNode typeNode) {
                    assert(false, "Not implemented");
                    return Result.noError;
                },
            );
        },
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
            ir.getByName!Asn1IntegerValueIr("a").asUnsigned(value, Asn1NullSemanticErrorHandler.instance).resultAssert;
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
                    return ir.addEnumerationImplicit(
                        identifier.token.text,
                        context.allocNode!Asn1IntegerValueIr(identifier.token.location),
                        errors
                    );
                },
                (Asn1NamedNumberNode number) {
                    return number.match(
                        (Asn1NamedNumberNode.Signed signed){
                            Asn1IntegerValueIr intValue;
                            if(auto r = asn1AstToIr(signed.getNode!Asn1SignedNumberNode, intValue, context, errors))
                                return r;

                            return ir.addEnumerationExplicit(
                                signed.getNode!Asn1IdentifierTokenNode.token.text,
                                intValue,
                                errors
                            );
                        },
                        (Asn1NamedNumberNode.Defined defined){
                            Asn1ValueReferenceIr valueRef;
                            if(auto r = asn1AstToIr(defined.getNode!Asn1DefinedValueNode, valueRef, context, errors))
                                return r;

                            return ir.addEnumerationExplicit(
                                defined.getNode!Asn1IdentifierTokenNode.token.text,
                                valueRef,
                                errors
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
                    assert(number is null);
                }
                else if(name == "b")
                {
                    length++;

                    long value;
                    (cast(Asn1IntegerValueIr)number).asSigned(value, Asn1NullSemanticErrorHandler.instance).resultAssert; // @suppress(dscanner.style.long_line)
                    assert(value == 1);
                }
                else if(name == "c")
                {
                    length++;
                    assert(cast(Asn1ValueReferenceIr)number);
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
            ir.getByName!Asn1IntegerValueIr("a").asSigned(value, Asn1NullSemanticErrorHandler.instance).resultAssert;
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

/++++ Constraints ++++/

Result asn1AstToIrForConstraint(
    scope Asn1ConstraintNode node,
    scope out Asn1ConstraintIr constraintIr,
    scope out bool isExtensible,
    scope out Asn1ConstraintIr additionalConstraintIr, // May be null
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.getNode!Asn1ConstraintSpecNode.match(
        (Asn1SubtypeConstraintNode constraint){
            return constraint.getNode!Asn1ElementSetSpecsNode.match(
                (Asn1RootElementSetSpecNode specNode){
                    return asn1AstToIr(specNode.getNode!Asn1ElementSetSpecNode, constraintIr, context, errors);
                },
                (Asn1ElementSetSpecsNode.Case1 case1){
                    auto root = case1.getNode!Asn1RootElementSetSpecNode;
                    if(auto r = asn1AstToIr(root.getNode!Asn1ElementSetSpecNode, constraintIr, context, errors))
                        return r;
                    isExtensible = true;
                    return Result.noError;
                },
                (Asn1ElementSetSpecsNode.Case2 case2){
                    auto root = case2.getNode!Asn1RootElementSetSpecNode;
                    if(auto r = asn1AstToIr(root.getNode!Asn1ElementSetSpecNode, constraintIr, context, errors))
                        return r;
                    isExtensible = true;

                    auto add = case2.getNode!Asn1AdditionalElementSetSpecNode;
                    return asn1AstToIr(add.getNode!Asn1ElementSetSpecNode, additionalConstraintIr, context, errors);
                },
            );
        },
        (Asn1GeneralConstraintNode constraint){
            assert(false, "Not implemented");
            return Result.noError;
        },
    );
}
@("asn1AstToIrForConstraint")
unittest
{
    import std.conv : to;

    static struct T
    {
        string input;
        void function(Asn1ConstraintIr main, bool isExtensible, Asn1ConstraintIr add) validate;
    }

    auto cases = [
        "SingleValue": T("(1)", (main, isExtensible, add){
            assert(cast(Asn1SingleValueConstraintIr)main !is null);
            assert(!isExtensible);
            assert(add is null);
        }),
        "ContainedSubtype": T("(INCLUDES INTEGER)", (main, isExtensible, add){
            assert(cast(Asn1ContainedSubtypeConstraintIr)main !is null);
        }),
        "Intersection": T("(1 ^ 2)", (main, isExtensible, add){
            auto inter = cast(Asn1IntersectionConstraintIr)main;
            assert(inter !is null);
            
            size_t length;
            inter.foreachIntersectionConstraint((ir){
                assert(cast(Asn1SingleValueConstraintIr)ir);
                length++;
                return Result.noError;
            }, Asn1NullSemanticErrorHandler.instance).resultAssert;
            assert(length == 2);
        }),
        "ValueRange - values": T("(1..2)", (main, isExtensible, add){
            auto range = cast(Asn1ValueRangeConstraintIr)main;
            assert(range !is null);
            assert(range.getLower().valueIr !is null);
            assert(!range.getLower().isOpen);
            assert(!range.getLower().isUnbounded);
            assert(range.getUpper().valueIr !is null);
            assert(!range.getUpper().isOpen);
            assert(!range.getUpper().isUnbounded);
            assert(range.getUpper().valueIr !is range.getLower().valueIr);
        }),
        "ValueRange - unbounded": T("(MIN..MAX)", (main, isExtensible, add){
            auto range = cast(Asn1ValueRangeConstraintIr)main;
            assert(range !is null);
            assert(range.getLower().isUnbounded);
            assert(range.getUpper().isUnbounded);
        }),
        "ValueRange - open": T("(MIN<..<MAX)", (main, isExtensible, add){
            auto range = cast(Asn1ValueRangeConstraintIr)main;
            assert(range !is null);
            assert(range.getLower().isOpen);
            assert(range.getUpper().isOpen);
        }),
        "PermittedAlphabet": T("(FROM (2))", (main, isExtensible, add){
            assert(cast(Asn1PermittedAlphabetConstraintIr)main !is null);
        }),
        "Size": T("(SIZE (2))", (main, isExtensible, add){
            assert(cast(Asn1SizeConstraintIr)main !is null);
        }),
        "Pattern": T("(PATTERN 123)", (main, isExtensible, add){
            assert(cast(Asn1PatternConstraintIr)main !is null);
        }),
        "Union": T("(1 | 2)", (main, isExtensible, add){
            auto onion = cast(Asn1UnionConstraintIr)main;
            assert(onion !is null);
            
            size_t length;
            onion.foreachUnionConstraint((ir){
                assert(cast(Asn1SingleValueConstraintIr)ir);
                length++;
                return Result.noError;
            }).resultAssert;
            assert(length == 2);
        }),
        "Extension - Case1": T("(1, ...)", (main, isExtensible, add){
            assert(isExtensible);
        }),
        "Extension - Case2": T("(1, ..., 2)", (main, isExtensible, add){
            assert(isExtensible);
            assert(cast(Asn1SingleValueConstraintIr)add !is null);
        }),
    ];

    foreach(name, test; cases)
    {
        try
        {
            Asn1ParserContext context;
            auto lexer = Asn1Lexer(test.input);
            auto parser = Asn1Parser(lexer, &context);

            Asn1ConstraintNode node;
            parser.Constraint(node).resultAssert;

            Asn1ConstraintIr main, add;
            bool isExtensible;
            auto result = asn1AstToIrForConstraint(
                node, 
                main,
                isExtensible,
                add,
                context, 
                Asn1NullSemanticErrorHandler.instance
            );

            if(test.validate !is null)
            {
                resultAssert(result);
                Asn1Token token;
                parser.consume(token).resultAssert;
                assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);

                test.validate(main, isExtensible, add);
            }
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}

Result asn1AstToIr(
    scope Asn1ElementSetSpecNode node,
    scope out Asn1ConstraintIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1UnionsNode constraint){
            assert(constraint.items.length > 0, "bug: UnionsNode has 0 items?");
            if(constraint.items.length == 1) // Flatten tree structure
                return asn1AstToIr(constraint.items[0], ir, context, errors);

            // TODO: Location?
            auto unionsIr = context.allocNode!Asn1UnionConstraintIr(Asn1Location());
            foreach(item; constraint.items)
            {
                Asn1ConstraintIr constraintIr;
                if(auto r = asn1AstToIr(item, constraintIr, context, errors))
                    return r;
                unionsIr.addUnionConstraint(constraintIr);
            }
            
            ir = unionsIr;
            return Result.noError;
        },
        (Asn1ExclusionsNode constraint){
            assert(false, "Not implemented");
            return Result.noError;
        },
    );
}
// Tested by asn1AstToIrForConstraint as the parser cannot individually generate an ElementSetSpecsNode

Result asn1AstToIr(
    scope Asn1IntersectionsNode node,
    scope out Asn1ConstraintIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    assert(node.items.length > 0, "bug: IntersectionsNode has 0 items?");

    Result handleItem(
        Asn1IntersectionElementsNode item, 
        scope out Asn1ConstraintIr itemIr,
    )
    {
        return item.match(
            (Asn1ElementsNode elements){
                return asn1AstToIr(elements, itemIr, context, errors);
            },
            (Asn1IntersectionElementsNode.Case1 case1){
                Asn1ConstraintIr constraintIr;
                auto result = asn1AstToIr(
                    case1.getNode!Asn1ElemsNode.getNode!Asn1ElementsNode,
                    constraintIr,
                    context,
                    errors
                );
                if(result.isError)
                    return result;

                Asn1ConstraintIr exlcusionIr;
                result = asn1AstToIr(
                    case1.getNode!Asn1ExclusionsNode.getNode!Asn1ElementsNode,
                    exlcusionIr,
                    context,
                    errors
                );
                if(result.isError)
                    return result;

                itemIr = context.allocNode!Asn1ConstraintWithExclusionsIr(constraintIr, exlcusionIr);
                return Result.noError;
            }
        );
    }

    if(node.items.length == 1) // Flatten tree structure
        return handleItem(node.items[0], ir);

    // TODO: Location?
    auto intersectionsIr = context.allocNode!Asn1IntersectionConstraintIr(Asn1Location());
    foreach(item; node.items)
    {
        Asn1ConstraintIr constraintIr;
        if(auto r = handleItem(item, constraintIr))
            return r;
        intersectionsIr.addIntersectionConstraint(constraintIr);
    }
    
    ir = intersectionsIr;
    return Result.noError;
}
// Tested by asn1AstToIrForConstraint as the parser cannot individually generate an IntersectionsNode

Result asn1AstToIr(
    scope Asn1ElementsNode node,
    scope out Asn1ConstraintIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    return node.match(
        (Asn1SubtypeElementsNode element){
            return element.match(
                (Asn1SingleValueNode constraint){
                    Asn1ValueIr valueIr;
                    if(auto r = asn1AstToIr(constraint.getNode!Asn1ValueNode, valueIr, context, errors))
                        return r;
                    ir = context.allocNode!Asn1SingleValueConstraintIr(valueIr);
                    return Result.noError;
                },
                (Asn1ContainedSubtypeNode constraint){
                    Asn1TypeIr typeIr;
                    if(auto r = asn1AstToIr(constraint.getNode!Asn1TypeNode, typeIr, context, errors))
                        return r;
                    ir = context.allocNode!Asn1ContainedSubtypeConstraintIr(typeIr);
                    return Result.noError;
                },
                (Asn1ValueRangeNode constraint){
                    Asn1ValueRangeConstraintIr constraintIr;
                    if(auto r = asn1AstToIr(constraint, constraintIr, context, errors))
                        return r;
                    ir = constraintIr;
                    return Result.noError;
                },
                (Asn1PermittedAlphabetNode constraint){
                    Asn1ConstraintIr constraintIr, additionalIr;
                    bool isExtensible;
                    if(auto r = asn1AstToIrForConstraint(constraint.getNode!Asn1ConstraintNode, constraintIr, isExtensible, additionalIr, context, errors)) // @suppress(dscanner.style.long_line)
                        return r;
                    ir = context.allocNode!Asn1PermittedAlphabetConstraintIr(constraintIr, isExtensible, additionalIr);
                    return Result.noError;
                },
                (Asn1SizeConstraintNode constraint){
                    Asn1ConstraintIr constraintIr, additionalIr;
                    bool isExtensible;
                    if(auto r = asn1AstToIrForConstraint(constraint.getNode!Asn1ConstraintNode, constraintIr, isExtensible, additionalIr, context, errors)) // @suppress(dscanner.style.long_line)
                        return r;
                    ir = context.allocNode!Asn1SizeConstraintIr(constraintIr, isExtensible, additionalIr);
                    return Result.noError;
                },
                (Asn1TypeConstraintNode constraint){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1InnerTypeConstraintsNode constraint){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1PatternConstraintNode constraint){
                    Asn1ValueIr valueIr;
                    if(auto r = asn1AstToIr(constraint.getNode!Asn1ValueNode, valueIr, context, errors))
                        return r;
                    ir = context.allocNode!Asn1PatternConstraintIr(valueIr);
                    return Result.noError;
                },
            );
        },
        (Asn1ObjectSetElementsNode element){
            assert(false, "Not implemented");
            return Result.noError;
        },
        (Asn1ElementSetSpecNode element){
            return asn1AstToIr(element, ir, context, errors);
        },
    );
}
// Tested by asn1AstToIrForConstraint as the parser cannot individually generate an ElementsNode

Result asn1AstToIr(
    scope Asn1ValueRangeNode node,
    scope out Asn1ValueRangeConstraintIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    Asn1ValueRangeConstraintIr.Endpoint lowerEndpoint, upperEndpoint;

    Result handleEndpoint(
        UnboundedNodeT,
        ValueNodeT,
    )(ValueNodeT valueNode, out Asn1ValueRangeConstraintIr.Endpoint endpoint)
    {
        return valueNode.match(
            (Asn1ValueNode value){
                if(auto r = asn1AstToIr(value, endpoint.valueIr, context, errors))
                    return r;
                return Result.noError;
            },
            (UnboundedNodeT _){
                endpoint.isUnbounded = true;
                return Result.noError;
            }
        );
    }

    auto result = node.getNode!Asn1LowerEndpointNode.match(
        (Asn1LowerEndValueNode lower){
            return handleEndpoint!Asn1MinNode(lower, lowerEndpoint);
        },
        (Asn1LowerEndpointNode.Case1 case1) {
            if(auto r = handleEndpoint!Asn1MinNode(case1.getNode!Asn1LowerEndValueNode, lowerEndpoint))
                return r;
            lowerEndpoint.isOpen = true;
            return Result.noError;
        }
    );
    if(result.isError)
        return result;

    result = node.getNode!Asn1UpperEndpointNode.match(
        (Asn1UpperEndValueNode upper){
            return handleEndpoint!Asn1MaxNode(upper, upperEndpoint);
        },
        (Asn1UpperEndpointNode.Case1 case1) {
            if(auto r = handleEndpoint!Asn1MaxNode(case1.getNode!Asn1UpperEndValueNode, upperEndpoint))
                return r;
            upperEndpoint.isOpen = true;
            return Result.noError;
        }
    );
    if(result.isError)
        return result;
    
    // TODO: Location?
    ir = context.allocNode!Asn1ValueRangeConstraintIr(Asn1Location(), lowerEndpoint, upperEndpoint);
    return Result.noError;
}
// Tested by asn1AstToIrForConstraint as the parser cannot individually generate a Asn1ValueRangeNode

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
                    return node.match(
                        (Asn1BooleanValueNode.True true_) {
                            ir = context.allocNode!Asn1BooleanValueIr(true_.token.location, true);
                            return Result.noError;
                        },
                        (Asn1BooleanValueNode.False false_) {
                            ir = context.allocNode!Asn1BooleanValueIr(false_.token.location, false);
                            return Result.noError;
                        },
                    );
                },
                (Asn1ChoiceValueNode node){
                    Asn1ValueIr valueIr;
                    if(auto r = asn1AstToIr(node.getNode!Asn1ValueNode, valueIr, context, errors))
                        return r;
                    ir = context.allocNode!Asn1ChoiceValueIr(
                        node.getNode!Asn1IdentifierTokenNode.token.location,
                        node.getNode!Asn1IdentifierTokenNode.token.text,
                        valueIr
                    );
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
                    ir = context.allocNode!Asn1NullValueIr(node.token.location);
                    return Result.noError;
                },
                (Asn1RealValueNode node){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
                (Asn1UnresolvedStringValueNode node){
                    return node.match(
                        (Asn1CstringTokenNode cstring){
                            ir = context.allocNode!Asn1CstringValueIr(
                                cstring.token.location, 
                                cstring.token.asSubString().slice
                            );
                            return Result.noError;
                        },
                        (Asn1HstringTokenNode hstring){
                            ir = context.allocNode!Asn1HstringValueIr(
                                hstring.token.location, 
                                hstring.token.asSubString().slice
                            );
                            return Result.noError;
                        },
                        (Asn1BstringTokenNode bstring){
                            ir = context.allocNode!Asn1BstringValueIr(
                                bstring.token.location, 
                                bstring.token.asSubString().slice
                            );
                            return Result.noError;
                        },
                        (Asn1UnresolvedStringValueNode.Containing node){
                            assert(false, "Not implemented");
                            return Result.noError;
                        },
                    );
                },
                (Asn1UnresolvedSequenceValueNode node){
                    return node.match(
                        (Asn1ValueListNode valueList) {
                            auto valueListIr = context.allocNode!Asn1ValueSequenceIr(Asn1Location()); // TODO: Location
                            foreach(item; valueList.items)
                            {
                                Asn1ValueIr valueIr;
                                if(auto r = asn1AstToIr(item, valueIr, context, errors))
                                    return r;
                                valueListIr.addSequenceValue(valueIr);
                            }
                            ir = valueListIr;
                            return Result.noError;
                        },
                        (Asn1NamedValueListNode namedList) {
                            auto namedListIr = context.allocNode!Asn1NamedValueSequenceIr(Asn1Location()); // TODO: Location
                            foreach(item; namedList.items)
                            {
                                Asn1ValueIr namedIr;
                                if(auto r = asn1AstToIr(item.getNode!Asn1ValueNode, namedIr, context, errors))
                                    return r;
                                auto result = namedListIr.addSequenceNamedValue(
                                    item.getNode!Asn1IdentifierTokenNode.token.text, 
                                    namedIr,
                                    errors
                                );
                                if(result.isError)
                                    return result;
                            }
                            ir = namedListIr;
                            return Result.noError;
                        },
                        (Asn1ObjIdComponentsListNode listNode) {
                            Asn1ObjectIdSequenceValueIr valueIr;
                            if(auto r = asn1AstToIr(listNode, valueIr, context, errors))
                                return r;
                            ir = valueIr;
                            return Result.noError;
                        },
                        (Asn1EmptyNode emptyNode) {
                            ir = context.allocNode!Asn1EmptySequenceValueIr(emptyNode.token.location);
                            return Result.noError;
                        },
                    );
                },
            );
        },
        (Asn1ReferencedValueNode referenced){
            return referenced.match(
                (Asn1DefinedValueNode refNode){
                    Asn1ValueReferenceIr refIr;
                    if(auto r = asn1AstToIr(refNode, refIr, context, errors))
                        return r;
                    ir = refIr;
                    return Result.noError;
                },
                (Asn1ValueFromObjectNode refNode){
                    assert(false, "Not implemented");
                    return Result.noError;
                },
            );
        },
        (Asn1ObjectClassFieldValueNode _){
            assert(false, "Not implemented");
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
            ir.asUnsigned(value, Asn1NullSemanticErrorHandler.instance).resultAssert;
            assert(value == 200);
        }),
        "Signed": T("-200", (ir){
            long value;
            ir.asSigned(value, Asn1NullSemanticErrorHandler.instance).resultAssert;
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

Result asn1AstToIr(
    scope Asn1ObjIdComponentsListNode node,
    scope out Asn1ObjectIdSequenceValueIr ir,
    scope ref Asn1ParserContext context,
    scope Asn1SemanticErrorHandler errors,
) @nogc nothrow
{
    auto objIdIr = context.allocNode!Asn1ObjectIdSequenceValueIr(Asn1Location()); // TODO: Location

    Result pushNumber(Asn1NumberFormNode objIdNode)
    {
        return objIdNode.match(
            (Asn1NumberTokenNode numberNode){
                auto numberIr = context.allocNode!Asn1IntegerValueIr(
                    numberNode.token, 
                    false
                );
                objIdIr.addObjectId(numberIr);
                return Result.noError;
            },
            (Asn1DefinedValueNode definedValue) {
                Asn1ValueReferenceIr definedIr;
                if(auto r = asn1AstToIr(definedValue, definedIr, context, errors))
                    return r;
                objIdIr.addObjectId(definedIr);
                return Result.noError;
            }
        );
    }

    foreach(item; node.items)
    {
        auto result = item.match(
            (Asn1NumberFormNode objIdNode){
                return pushNumber(objIdNode);
            },
            (Asn1NameAndNumberFormNode objIdNode){
                return pushNumber(objIdNode.getNode!Asn1NumberFormNode);
            },
            (Asn1DefinedValueNode objIdNode){
                Asn1ValueReferenceIr definedIr;
                if(auto r = asn1AstToIr(objIdNode, definedIr, context, errors))
                    return r;
                objIdIr.addObjectId(definedIr);
                return Result.noError;
            },
        );
        if(result.isError)
            return result;
    }
    ir = objIdIr;
    return Result.noError;
}

version(unittest)
{
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import juptune.data.asn1.lang.lexer; // Intentionally everything

    private template GenericTestHarness(IrT, alias ParseFunc, alias Converter = asn1AstToIr)
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