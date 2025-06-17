/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// Contains a visitor that can transform IR nodes into their ASN.1 notation equivalent.
module juptune.data.asn1.lang.printer;

import juptune.core.util : Result, resultAssert;
import juptune.data.asn1.lang.common : Asn1Location;
import juptune.data.asn1.lang.ir; // Intentionally everything

/++
 + A simple handler for `Asn1PrinterVisitor` that will populate an in-memory array with the
 + printer's result.
 +
 + Usage:
 +  Pass an instance of this class into `Asn1PrinterVisitor`, and then use the result from `.buffer` as needed.
 + ++/
final class Asn1StringPrinterHandler : Asn1SemanticErrorHandler
{
    import juptune.core.ds : Array;

    private
    {
        bool _firstWriteInLine;
        uint _indentLevel;
    }

    Array!char buffer;

    @nogc nothrow:

    this()
    {
        this._firstWriteInLine = true;
    }

    override void startLine(Asn1Location location)
    {
        assert(false, "startLine shouldn't be called by the Asn1PrinterVisitor?");
    }

    override void putInLine(scope const(char)[] slice)
    {
        if(this._firstWriteInLine)
        {
            foreach(i; 0..this._indentLevel)
                this.buffer.put("    ");
            this._firstWriteInLine = false;
        }
        this.buffer.put(slice);
    }

    override void endLine()
    {
        this.buffer.put('\n');
        this._firstWriteInLine = true;
    }

    override void indent() { this._indentLevel++; }
    override void dedent() { this._indentLevel--; }
}

/++
 + A visitor that will convert IR nodes into their (mostly) equivalent ASN.1 notation.
 + ++/
class Asn1PrinterVisitor : Asn1IrVisitor // Intentionally not final
{
    private
    {
        Asn1SemanticErrorHandler _handler;
        Asn1ModuleIr.TagDefault _tagDefault;
    }

    @nogc nothrow:

    // TODO: NOTE that the handler isn't actually for errors... but for constructing the final string.
    //       I'm reusing the interface since it's already exactly what I'd want.
    this(
        Asn1SemanticErrorHandler handler,
        Asn1ModuleIr.TagDefault tagDefault = Asn1ModuleIr.TagDefault.explicit,
    )
    in(handler !is null, "handler is null")
    {
        this._handler = handler;
        this._tagDefault = tagDefault;
    }

    override Result visit(Asn1ModuleIr ir)
    {
        this._tagDefault = ir.getTagDefault();

        with(this._handler)
        {
            putInLine(ir.getModuleName());
            putInLine(" DEFINITIONS ");

            final switch(ir.getTagDefault()) with(Asn1ModuleIr.TagDefault)
            {
                case FAILSAFE: assert(false);
                case implicit: putInLine("IMPLICIT TAGS "); break;
                case explicit: putInLine("EXPLICIT TAGS "); break;
                case automatic: putInLine("AUTOMATIC TAGS "); break;
            }

            if(ir.isExtensibilityImplied)
                putInLine("EXTENSIBILITY IMPLIED ");

            putInLine("::= BEGIN");
            endLine();
            indent();

            auto result = ir.foreachAssignment(ass => ass.visit(this));
            if(result.isError)
                return result;

            endLine();
            dedent();
            putInLine("END");
        }

        return Result.noError;
    }

    /++++ Assignments +++/

    override Result visit(Asn1ValueAssignmentIr ir)
    {
        with(this._handler)
        {
            putInLine(ir.getSymbolName());
            putInLine(" ");
            
            auto result = ir.getSymbolType().visit(this);
            if(result.isError)
                return result;

            putInLine(" ::= ");

            result = ir.getSymbolValue().visit(this);
            if(result.isError)
                return result;

            endLine();
        }

        return Result.noError;
    }

    override Result visit(Asn1TypeAssignmentIr ir)
    {
        with(this._handler)
        {
            putInLine(ir.getSymbolName());
            putInLine(" ::= ");
            
            auto result = ir.getSymbolType().visit(this);
            if(result.isError)
                return result;

            endLine();
        }

        return Result.noError;
    }

    /++++ Types ++++/

    override Result visit(Asn1TypeReferenceIr ir)
    {
        with(this._handler)
        {
            if(ir.moduleRef.length > 0)
            {
                putInLine(ir.moduleRef);
                putInLine(".");
            }
            putInLine(ir.typeRef);
        }

        return Result.noError;
    }

    override Result visit(Asn1BitStringTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("BIT STRING");

        with(this._handler)
        {
            bool hasNamedBits;
            auto result = ir.foreachNamedBit((name, bit){
                if(!hasNamedBits)
                {
                    putInLine(" { ");
                    hasNamedBits = true;
                }
                else
                    putInLine(", ");

                putInLine(name);
                putInLine("(");
                auto result = bit.visit(this);
                if(result.isError)
                    return result;
                putInLine(")");
                return Result.noError;
            });
            if(result.isError)
                return result;
            if(hasNamedBits)
                putInLine(" }");
        }

        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1BooleanTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("BOOLEAN");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1CharacterStringTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("CHARACTER STRING");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1ChoiceTypeIr ir)
    {
        this.visitTypeCommon(ir);
        with(this._handler)
        {
            putInLine("CHOICE {");
            endLine();
            indent();

            bool isFirst = true;
            bool firstExtensible = true;
            auto result = ir.foreachChoice((name, choice, isExtensible){
                if(!isFirst)
                {
                    putInLine(",");
                    endLine();
                }
                isFirst = false;
                
                if(isExtensible && firstExtensible)
                {
                    firstExtensible = false;
                    putInLine("...,");
                    endLine();
                }
                
                putInLine(name);
                putInLine(" ");
                
                auto result = choice.visit(this);
                if(result.isError)
                    return result;

                return Result.noError;
            });
            if(result.isError)
                return result;

            if(ir.isExtensible && firstExtensible)
            {
                putInLine(",");
                endLine();
                putInLine("...");
            }

            endLine();
            dedent();
            putInLine("}");
        }

        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1EnumeratedTypeIr ir)
    {
        this.visitTypeCommon(ir);
        with(this._handler)
        {
            putInLine("ENUMERATED {");
            endLine();
            indent();

            bool isFirst = true;
            bool firstExtensible = true;
            auto result = ir.foreachEnumeration((name, value, isExtensible){
                if(!isFirst)
                {
                    putInLine(",");
                    endLine();
                }
                isFirst = false;
                
                if(isExtensible && firstExtensible)
                {
                    firstExtensible = false;
                    putInLine("...,");
                    endLine();
                }
                
                putInLine(name);

                if(value !is null)
                {
                    putInLine("(");
                    auto result = value.visit(this);
                    if(result.isError)
                        return result;
                    putInLine(")");
                }

                return Result.noError;
            });
            if(result.isError)
                return result;

            if(ir.isExtensible && firstExtensible)
            {
                putInLine(",");
                endLine();
                putInLine("...");
            }

            endLine();
            dedent();
            putInLine("}");
        }

        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1EmbeddedPdvTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("EMBEDDED PDV");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1ExternalTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("EXTERNAL");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1IntegerTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("INTEGER");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1NullTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("NULL");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1OctetStringTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("OCTET STRING");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1RealTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("REAL");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1RelativeOidTypeIr ir)
    {
        this.visitTypeCommon(ir);
        this._handler.putInLine("RELATIVE-OID");
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1SequenceTypeIr ir)
    {
        return this.visitSequenceType("SEQUENCE", ir);
    }

    override Result visit(Asn1SetTypeIr ir)
    {
        return this.visitSequenceType("SET", ir);
    }

    override Result visit(Asn1SequenceOfTypeIr ir)
    {
        this.visitTypeCommon(ir);

        this._handler.putInLine("SEQUENCE OF ");
        if(!ir.getItemTypeName().isNull)
        {
            this._handler.putInLine(ir.getItemTypeName().get);
            this._handler.putInLine(" ");
        }

        auto result = ir.getTypeOfItems().visit(this);
        if(result.isError)
            return result;
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1SetOfTypeIr ir)
    {
        this.visitTypeCommon(ir);

        this._handler.putInLine("SET OF ");
        if(!ir.getItemTypeName().isNull)
        {
            this._handler.putInLine(ir.getItemTypeName().get);
            this._handler.putInLine(" ");
        }

        auto result = ir.getTypeOfItems().visit(this);
        if(result.isError)
            return result;
        return this.visitTypeConstraints(ir);
    }

    override Result visit(Asn1TaggedTypeIr ir)
    {
        // NOTE: Intentionally doesn't call visitTypeCommon
        
        with(this._handler)
        {
            putInLine("[");
            final switch(ir.getClass()) with(Asn1TaggedTypeIr.Class)
            {
                case private_: putInLine("PRIVATE "); break;
                case application: putInLine("APPLICATION "); break;
                case universal: putInLine("UNIVERSAL "); break;
                case unspecified: break;
            }
            auto result = ir.getNumberIr().visit(this);
            if(result.isError)
                return result;
            putInLine("] ");

            Asn1TaggedTypeIr.Encoding defaultEncoding;
            final switch(this._tagDefault) with(Asn1ModuleIr.TagDefault)
            {
                case FAILSAFE: assert(false);
                
                case automatic:
                case implicit:
                    defaultEncoding = Asn1TaggedTypeIr.Encoding.implicit;
                    break;

                case explicit:
                    defaultEncoding = Asn1TaggedTypeIr.Encoding.explicit;
                    break;
            }

            auto encoding = ir.getEncoding();
            if(encoding == Asn1TaggedTypeIr.Encoding.unspecified)
                encoding = defaultEncoding;

            if(encoding != defaultEncoding)
            {
                putInLine(
                    encoding == Asn1TaggedTypeIr.Encoding.explicit
                    ? "EXPLICIT "
                    : "IMPLICIT "
                );
            }
        }

        return ir.getUnderlyingType().visit(this);
    }

    private void visitTypeCommon(Asn1TypeIr ir)
    {
        with(this._handler)
        {
            if(!ir.getUniversalTag().isNull)
            {
                import juptune.core.util : IntToCharBuffer, toBase10;

                IntToCharBuffer buffer;
                putInLine("[UNIVERSAL ");
                putInLine(toBase10(ir.getUniversalTag().get, buffer));
                putInLine("] ");

                final switch(this._tagDefault) with(Asn1ModuleIr.TagDefault)
                {
                    case FAILSAFE: assert(false);

                    case automatic: // AUTOMATIC TAGS also implies IMPLICIT TAGS
                    case implicit:
                        break;

                    case explicit:
                        putInLine("IMPLICIT ");
                        break;
                }
            }
        }
    }

    private Result visitTypeConstraints(Asn1TypeIr ir)
    {
        if(auto constraint = ir.getMainConstraintOrNull())
        {
            auto result = constraint.visit(this);
            if(result.isError)
                return result;
        }
        if(auto constraint = ir.getAdditionalConstraintOrNull())
        {
            auto result = constraint.visit(this);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    private Result visitSequenceType(IrT)(string typeName, IrT ir)
    {
        this.visitTypeCommon(ir);
        with(this._handler)
        {
            putInLine(typeName);
            putInLine(" {");
            indent();
            endLine();

            bool isFirst = true;
            bool firstExtensible = true;
            auto result = ir.foreachComponent((item){
                if(!isFirst)
                {
                    putInLine(",");
                    endLine();
                }
                isFirst = false;
                
                if(item.isExtensible && firstExtensible)
                {
                    firstExtensible = false;
                    putInLine("...,");
                    endLine();
                }
                
                putInLine(item.name);
                putInLine(" ");

                auto result = item.type.visit(this);
                if(result.isError)
                    return result;

                if(item.isOptional)
                    putInLine(" OPTIONAL ");

                if(item.defaultValue !is null)
                {
                    putInLine(" DEFAULT ");
                    result = item.defaultValue.visit(this);
                    if(result.isError)
                        return result;
                }

                return Result.noError;
            });
            if(result.isError)
                return result;

            if(ir.isExtensible && firstExtensible)
            {
                putInLine(",");
                endLine();
                putInLine("...");
            }

            endLine();
            dedent();
            putInLine("}");
        }

        return this.visitTypeConstraints(ir);
    }

    /++++ Values ++++/

    override Result visit(Asn1ValueReferenceIr ir)
    {
        with(this._handler)
        {
            if(ir.moduleRef.length > 0)
            {
                putInLine(ir.moduleRef);
                putInLine(".");
            }
            putInLine(ir.valueRef);

            if(ir.hasDoneSemanticStage(Asn1BaseIr.SemanticStageBit.resolveReferences))
            {
                putInLine(" -- resolves to ");
                if(auto refIr = cast(Asn1ValueReferenceIr)ir.getResolvedValue())
                {
                    // If we're referencing another reference, don't call .visit()
                    // as it'll end up printing out the entire reference chain, which
                    // I don't like - so only print out the first hop in the chain instead.
                    if(refIr.moduleRef.length > 0)
                    {
                        putInLine(refIr.moduleRef);
                        putInLine(".");
                    }
                    putInLine(refIr.valueRef);
                }
                else
                {
                    auto result = ir.getResolvedValue().visit(this);
                    if(result.isError)
                        return result;
                }
                putInLine(" --");
            }
            else
                putInLine(" -- <unresolved - run resolveReferences stage> --");
        }

        return Result.noError;
    }

    override Result visit(Asn1BooleanValueIr ir)
    {
        with(this._handler)
        {
            putInLine(ir.asBool ? "TRUE" : "FALSE");
        }

        return Result.noError;
    }

    override Result visit(Asn1ChoiceValueIr ir)
    {
        with(this._handler)
        {
            putInLine(ir.getChoiceName());
            putInLine(" : ");
            return ir.getChoiceValue().visit(this);
        }
    }

    override Result visit(Asn1IntegerValueIr ir)
    {
        with(this._handler)
        {
            if(ir.isNegative)
                putInLine("-");
            putInLine(ir.getNumberText());
        }

        return Result.noError;
    }

    override Result visit(Asn1NullValueIr ir)
    {
        with(this._handler)
        {
            putInLine("NULL");
        }

        return Result.noError;
    }

    override Result visit(Asn1BstringValueIr ir)
    {
        with(this._handler)
        {
            putInLine("'");
            putInLine(ir.asString);
            putInLine("'B");
        }

        return Result.noError;
    }

    override Result visit(Asn1HstringValueIr ir)
    {
        with(this._handler)
        {
            putInLine("'");
            putInLine(ir.asString);
            putInLine("'H");
        }

        return Result.noError;
    }

    override Result visit(Asn1EmptySequenceValueIr ir)
    {
        with(this._handler)
        {
            putInLine("{}");
        }

        return Result.noError;
    }

    override Result visit(Asn1ObjectIdSequenceValueIr ir)
    {
        with(this._handler)
        {
            putInLine("{ ");
            auto result = ir.foreachObjectId((value){
                auto result = value.visit(this);
                if(result.isError)
                    return result;
                putInLine(" ");
                return Result.noError;
            });
            if(result.isError)
                return result;
            putInLine("}");
        }

        return Result.noError;
    }

    override Result visit(Asn1ValueSequenceIr ir)
    {
        with(this._handler)
        {
            putInLine("{ ");
            bool isFirst = true;
            auto result = ir.foreachSequenceValue((value){
                if(!isFirst)
                    putInLine(", ");
                isFirst = false;
                
                auto result = value.visit(this);
                if(result.isError)
                    return result;
                return Result.noError;
            });
            if(result.isError)
                return result;
            putInLine(" }");
        }

        return Result.noError;
    }
}

@("Asn1PrinterVisitor - everything")
unittest
{
    import std.file : write;
    
    import juptune.data.asn1.lang.common  : Asn1ParserContext;
    import juptune.data.asn1.lang.ir      : Asn1ModuleRegistry;
    import juptune.data.asn1.lang.tooling : Asn1AlwaysCrashErrorHandler, asn1ParseWithSemantics;

    const code = `
        MyMod DEFINITIONS IMPLICIT TAGS ::= BEGIN
            -- BIT STRING
            Bst ::= BIT STRING { a(1), b(2) }
            bstBstring BIT STRING ::= '01010'B
            bstHstring BIT STRING ::= '01010'H
            bstEmpty Bst ::= {}
            -- TODO: bstIdentifier Bst ::= { b }

            -- BOOLEAN
            true BOOLEAN ::= TRUE
            false BOOLEAN ::= FALSE

            -- CHARACTER STRING
            chstr CHARACTER STRING ::= {}

            -- CHOICE
            Choice ::= CHOICE {
                a BIT STRING,
                b INTEGER,
                ...,
                c BOOLEAN,
                d CHOICE {
                    a BOOLEAN
                }
            }
            ChoiceEdgeCase ::= CHOICE { a BOOLEAN, ... }
            choice Choice ::= b: 1

            -- EMBEDDED PDV
            -- TODO: Embed ::= EMBEDDED PDV
            -- embed Embed ::= {}

            -- ENUMERATED
            Enum ::= ENUMERATED { a(0), b(1), ..., c(2) }
            EnumEdgeCase ::= ENUMERATED { a(0), ... }
            e Enum ::= c

            -- EXTERNAL
            -- TODO: Extern ::= EXTERNAL
            -- extern Extern ::= {}

            -- INTEGER
            signed INTEGER ::= -1
            unsigned INTEGER ::= 1

            -- NULL
            null NULL ::= NULL

            -- OCTET STRING
            octbstr OCTET STRING ::= '01010'B
            octhstr OCTET STRING ::= '01010'H

            -- REAL
            -- TODO: real REAL ::= 12.02

            -- RELATIVE-OID
            reloid RELATIVE-OID ::= { 1 }
            -- TODO: reloid2 RELATIVE-OID ::= { a(1) b(2) }

            -- SEQUENCE (and SET by proxy)
            Seq ::= SEQUENCE {
                a INTEGER,
                b BOOLEAN OPTIONAL,
                c INTEGER DEFAULT 1,
                ...,
                d BOOLEAN
            }
            SetEdgeCase ::= SET {
                a INTEGER,
                ...
            }

            -- SEQUENCE OF
            seqOf SEQUENCE OF b BOOLEAN ::= { TRUE, FALSE }

            -- SET OF
            setOf SET OF b BOOLEAN ::= { TRUE, FALSE }

            -- Value reference
            ref1 BOOLEAN ::= TRUE
            ref2 BOOLEAN ::= ref1
            ref3 BOOLEAN ::= ref2

            -- Tagged types
            Tagged ::= [1] [UNIVERSAL 1] [APPLICATION 1] EXPLICIT [PRIVATE 1] IMPLICIT INTEGER
        END
    `;
    
    Asn1ModuleIr modIr;
    Asn1ParserContext context;
    scope registry = new Asn1ModuleRegistry();
    asn1ParseWithSemantics(context, modIr, code, registry, new Asn1AlwaysCrashErrorHandler()).resultAssert;

    scope handler = new Asn1StringPrinterHandler();
    scope visitor = new Asn1PrinterVisitor(handler);
    modIr.visit(visitor).resultAssert;

    // write("debug.asn1", handler.buffer.slice);
}