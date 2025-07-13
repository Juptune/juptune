/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.generator.dlang;

import std.typecons : Nullable;

import juptune.core.util : Result, resultEnforce;
import juptune.data.asn1.decode.bcd.encoding : Asn1Identifier;
import juptune.data.asn1.lang; // Intentionally everything

/++++ Common ++++/

enum DlangGeneratorError
{
    none,
    invalidType,
}

struct DlangGeneratorContext
{
    // Config
    
    string[] baseModuleComponents;
    
    // Dependencies

    Asn1ErrorHandler errors;
}

final class DlangCodeBuilder
{
    import std.array : Appender;

    private
    {
        Appender!(char[]) _buffer;
        uint _indent;
        bool _startOfLine;
    }

    void indent()
    {
        this._indent++;
    }

    void dedent()
    in(this._indent != 0, "bug: attempted to dedent too many times?")
    {
        this._indent--;
    }

    void put(T...)(scope auto ref T values)
    {
        if(this._startOfLine)
        {
            this._startOfLine = false;
            this._buffer.put('\n');
            foreach(_; 0..this._indent)
                this._buffer.put("    ");
        }

        foreach(ref value; values)
            this._buffer.put(value);
    }

    void putLine(T...)(scope auto ref T values)
    {
        this.put(values);
        this.endLine();
    }

    void endLine()
    {
        if(this._startOfLine)
            this._buffer.put('\n');
        this._startOfLine = true;
    }

    override string toString() const @safe pure nothrow
    {
        return this._buffer.data.idup;
    }

    /++++ High level stuff ++++/

    void putStartOfModule(Asn1ModuleIr mod, string packageName, ref DlangGeneratorContext context)
    {
        import std.algorithm : joiner;

        putLine(
            "module ",
            context.baseModuleComponents.joiner("."),
            '.',
            getModuleDlangIdentifier(mod.getModuleName(), mod.getModuleVersion(), context.errors),
            ";"
        );

        mod.getImports().foreachImportByModuleGC((moduleRef, moduleVersion, _){
            putLine(
                "static import ",
                context.baseModuleComponents.joiner("."), // TODO: Alow different modules to have different bases, configurable by the user
                getModuleDlangIdentifier(moduleRef, moduleVersion, context.errors),
                ";"
            );
            return Result.noError;
        }).resultEnforce;
        
        endLine();
    }

    void declareType(string name, scope void delegate() putBody, string type = "struct")
    {
        put(type); put(' ');
        put(name); endLine();
        put('{'); endLine();
        indent();
            putBody();
        dedent();
        put('}'); endLine();
        endLine();
    }

    void declareFunction(
        string returnType, 
        string name, 
        scope void delegate(scope void delegate() next) putParams,
        scope void delegate() putBody,
        string funcAttributes = ""
    )
    {
        put(returnType); put(' ');
        put(name);
        put('('); endLine();
        indent();
            putParams((){ put(','); endLine(); });
        dedent();
        put(") "); put(funcAttributes); endLine();
        put('{'); endLine();
        indent();
            putBody();
        dedent();
        endLine();
        put('}'); endLine();
        endLine();
    }

    void attributeBlock(string attributes, scope void delegate() putBody)
    {
        put(attributes); endLine();
        put('{'); endLine();
        indent();
            putBody();
        dedent();
        put('}'); endLine();
        endLine();
    }

    void putResultCheck()
    {
        putLine("if(result.isError)");
        indent();
            putLine("return result;");
        dedent();
    }

    void putIdentifierClassCheck(
        Asn1Identifier.Class class_,
        
        // For clarity, the following params should be assigned via named parameters
        string tagType,
        string tagValue,
        string parentTypeType,
        string parentTypeName,
        const(char)[] fieldName,
        string classVar = DECODER_VAR_HEADER~".identifier.class_"
    )
    {
        import std.conv : to;

        putLine(
            "if(",
                classVar,
                " != ",
                ASN1_SHORTHAND, ".Asn1Identifier.Class.", class_.to!string,
            ")"
        );
        indent();
            putLine(
                "return ", RESULT_TYPE, ".make(",
                    ASN1_SHORTHAND, ".Asn1DecodeError.identifierHasInvalidClass, ",
                    `"for `, parentTypeType, " ", parentTypeName, 
                    ` when reading `, tagType, " ", tagValue, 
                    ` for field '`, fieldName,
                    `' the tag's class was expected to be `, class_.to!string,
                    `", `, STRING_SHORTHAND, ".String2(",
                        `"class was ", `, classVar,
                    ")",
                ");"
            );
        dedent();
    }

    void putIdentifierTagCheck(
        string tagValue,
        
        // For clarity, the following params should be assigned via named parameters
        string tagType,
        string parentTypeType,
        string parentTypeName,
        const(char)[] fieldName,
        string tagVar = DECODER_VAR_HEADER~".identifier.tag"
    )
    {
        import std.conv : to;

        putLine(
            "if(",
                tagVar,
                " != ",
                tagValue,
            ")"
        );
        indent();
            putLine(
                "return ", RESULT_TYPE, ".make(",
                    ASN1_SHORTHAND, ".Asn1DecodeError.identifierHasInvalidTag, ",
                    `"for `, parentTypeType, " ", parentTypeName, 
                    ` when reading `, tagType, " ", tagValue, 
                    ` for field '`, fieldName,
                    `' the tag's value was expected to be `, tagValue,
                    `", `, STRING_SHORTHAND, ".String2(",
                        `"tag value was ", `, tagVar,
                    ")",
                ");"
            );
        dedent();
    }
}

/++++ Helpers ++++/

private immutable RESULT_SHORTHAND = "jres";
private immutable ASN1_SHORTHAND = "asn1";
private immutable BUFFER_SHORTHAND = "jbuf";
private immutable STRING_SHORTHAND = "jstr";
private immutable TYPE_CON_SHORTHAND = "tcon";

private immutable RESULT_TYPE = RESULT_SHORTHAND~".Result";
private immutable MEMORY_BUFFER_TYPE = BUFFER_SHORTHAND~".MemoryReader";
private immutable NULLABLE_TYPE = TYPE_CON_SHORTHAND~".Nullable";

private immutable DECODER_PARAM_RULESET = "ruleset";
private immutable DECODER_PARAM_MEMORY = "memory";
private immutable DECODER_PARAM_IDENT = "ident";
private immutable DECODER_VAR_HEADER = "componentHeader";

private immutable SETTER_FUNCTION_PREFIX = "set";
private immutable GETTER_FUNCTION_PREFIX = "get";
private immutable CHECKER_FUNCTION_PREFIX = "is";
private immutable VALIDATE_FUNCTION_PREFIX = "validate";

private immutable RETURN_NO_ERROR = "return "~RESULT_TYPE~".noError;";

string getModuleDlangIdentifier(
    scope const(char)[] moduleRef, 
    Asn1ObjectIdSequenceValueIr moduleVersion, 
    Asn1ErrorHandler errors
)
{
    import std.array : Appender;
    import std.exception : assumeUnique;

    Appender!(char[]) buffer;
    buffer.reserve(moduleRef.length * 2);
    buffer.put(moduleRef);

    if(moduleVersion !is null)
    {
        moduleVersion.foreachObjectIdGC((valueIr){
            if(auto intValueIr = cast(Asn1IntegerValueIr)valueIr)
            {
                assert(!intValueIr.isNegative, "bug: module version is negative, why didn't the type checker catch this?"); // @suppress(dscanner.style.long_line)
                buffer.put('_');
                buffer.put(intValueIr.getNumberText());
            }
            else assert(false, "bug: Unhandled value type for module version?");

            return Result.noError;
        }, errors).resultEnforce;
    }

    return buffer.data.assumeUnique;
}

/++++ Raw Model Outputter ++++/

string generateRawDlangModule(Asn1ModuleIr mod, ref DlangGeneratorContext context)
{
    auto code = new DlangCodeBuilder();
    with(code)
    {
        putStartOfModule(mod, "raw", context);
        putLine("static import ", TYPE_CON_SHORTHAND, " = std.typecons;");
        putLine("static import ", ASN1_SHORTHAND, " = juptune.data.asn1.decode.bcd.encoding;");
        putLine("static import ", RESULT_SHORTHAND, " = juptune.core.util.result;");
        putLine("static import ", BUFFER_SHORTHAND, " = juptune.data.buffer;");
        putLine("static import ", STRING_SHORTHAND, " = juptune.core.ds.string2;");
        endLine();

        mod.foreachAssignmentGC((assIr){
            if(auto typeAssIr = cast(Asn1TypeAssignmentIr)assIr)
                putRawType(typeAssIr.getSymbolName().idup, typeAssIr.getSymbolType(), code, context);
            else assert(false, "bug: Unhandled assignment type?");

            return Result.noError;
        }).resultEnforce;
    }

    return code.toString();
}

private void putRawType(
    string name,
    Asn1TypeIr typeIr,
    DlangCodeBuilder code,
    ref DlangGeneratorContext context
)
{
    final class ModelVisitor : Asn1IrVisitorGC
    {
        static immutable BASIC_FIELD_NAME = "_value";

        override void visit(Asn1TaggedTypeIr ir)
        {
            ir.getUnderlyingTypeSkipTags().visitGC(this);
        }

        override void visit(Asn1BooleanTypeIr ir)
        {
            this.wrapAroundBasicType(rawTypeOf(ir));
        }
        
        override void visit(Asn1BitStringTypeIr ir)
        {
            with(code)
            {
                putLine("enum NamedBit");
                putLine('{');
                indent();
                ir.foreachNamedBitGC((name, value){
                    if(auto valueRefIr = cast(Asn1ValueReferenceIr)value)
                        value = valueRefIr.getResolvedValueRecurse();
                    
                    auto intValueIr = cast(Asn1IntegerValueIr)value;
                    assert(intValueIr !is null, "bug: Value's not an integer, why didn't the type checker catch this?");

                    putLine(name, " = ", intValueIr.getNumberText(), ',');
                    return Result.noError;
                }).resultEnforce;
                dedent();
                putLine('}');
            }

            this.wrapAroundBasicType(rawTypeOf(ir));
        }

        override void visit(Asn1ChoiceTypeIr ir)
        {
            immutable CHOICE_ENUM  = "Choice";
            immutable CHOICE_FIELD = "_choice";

            immutable VALUE_UNION = "Value";
            immutable VALUE_FIELD = "_value";

            immutable SETTER_PARAM_VALUE = "value";

            // Model vars + functions
            with(code)
            {
                declareType(CHOICE_ENUM, (){
                    putLine("_FAILSAFE,");
                    ir.foreachChoiceGC((name, typeIr, _){
                        putLine(name, ","); // TODO: I wonder if this should be 1:1 with the underlying tag
                        return Result.noError;
                    }).resultEnforce;
                }, type: "enum");

                declareType(VALUE_UNION, (){
                    ir.foreachChoiceGC((name, typeIr, _){
                        putLine(rawTypeOf(typeIr), ' ', name, ";");
                        return Result.noError;
                    }).resultEnforce;
                }, type: "union");

                putLine("// Sanity check: Ensuring that no types have a proper dtor, as they won't be called.");
                putLine("import std.traits : hasElaborateDestructor;");
                ir.foreachChoiceGC((name, typeIr, __){
                    putLine("static assert(!hasElaborateDestructor!(", rawTypeOf(typeIr), `), "Report a bug if you see this.");`); // @suppress(dscanner.style.long_line)
                    return Result.noError;
                }).resultEnforce;
                endLine();

                attributeBlock("private", (){
                    putLine(CHOICE_ENUM, ' ', CHOICE_FIELD, ";");
                    putLine(VALUE_UNION, ' ', VALUE_FIELD, ";");
                });

                ir.foreachChoiceGC((name, typeIr, _){
                    declareFunction(
                        RESULT_TYPE, 
                        asCamelCase(SETTER_FUNCTION_PREFIX, name), 
                        (next){
                            put("typeof(", VALUE_UNION, '.', name, ") ", SETTER_PARAM_VALUE);
                            next();
                        }, (){
                            if(typeIr.getMainConstraintOrNull() !is null)
                                putLine("// TODO: Warning - type has a constraint but it's not being handled yet!");

                            putLine(VALUE_FIELD, '.', name, " = ", SETTER_PARAM_VALUE, ";");
                            putLine(CHOICE_FIELD, " = ", CHOICE_ENUM, '.', name, ";");
                            put(RETURN_NO_ERROR);
                        }, 
                        funcAttributes: "@nogc nothrow"
                    );

                    declareFunction(
                        ("typeof("~VALUE_UNION~'.'~name~")").idup, 
                        asCamelCase(GETTER_FUNCTION_PREFIX, name), 
                        (next){},
                        (){
                            putLine(
                                "assert(", 
                                    CHOICE_FIELD, " == ", CHOICE_ENUM, '.', name, ", ",
                                    `"This '"~__traits(identifier, typeof(this))~"`, ` does not contain choice '`, name, `'"`, // @suppress(dscanner.style.long_line)
                                ");"
                            );
                            put("return ", VALUE_FIELD, '.', name, ";");
                        },
                        funcAttributes: "@nogc nothrow"
                    );

                    declareFunction(
                        "bool", 
                        asCamelCase(CHECKER_FUNCTION_PREFIX, name), 
                        (next){}, 
                        (){
                            put("return ", CHOICE_FIELD, " == ", CHOICE_ENUM, '.', name, ";");
                        }, 
                        funcAttributes: "@nogc nothrow const"
                    );

                    return Result.noError;
                }).resultEnforce;
            }

            // Decoder function (separated for code readability)
            with(code)
            {
                this.declareFromDecode((){
                    ir.foreachChoiceGC((name, typeIr, _){
                        import std.conv : to;

                        Nullable!ulong topLevelTag;
                        Asn1Identifier.Class topLevelClass;
                        topLevelIrTagAndClass(typeIr, topLevelTag, topLevelClass, context.errors);

                        if(!topLevelTag.isNull)
                        {
                            putLine(
                                "if(",
                                    DECODER_PARAM_IDENT, ".class_",
                                    " == ",
                                    ASN1_SHORTHAND, ".Asn1Identifier.Class.", topLevelClass.to!string,
                                    
                                    " && ",

                                    DECODER_PARAM_IDENT, ".tag",
                                    " == ",
                                    topLevelTag.get().to!string,
                                ")"
                            );
                            putLine("{");
                            indent();
                        }
                        else
                        {
                            assert(false, "TODO: handle types without a tag? Is it even possible here?");
                        }
                            putRawDerDecodingForField(
                                typeIr,
                                name.idup,
                                asCamelCase(SETTER_FUNCTION_PREFIX, name),
                                code,
                                context,
                                parentIsWrapper: false,
                                typeOfOverride: (VALUE_UNION~'.'~name).idup,
                            );
                            putLine(RETURN_NO_ERROR);
                        dedent();
                        putLine("}");
                        endLine();
                        return Result.noError;
                    }).resultEnforce;
                        
                    put(
                        "return ", RESULT_TYPE, ".make(",
                            ASN1_SHORTHAND, ".Asn1DecodeError.choiceHasNoMatch, ",
                            `"when decoding CHOICE of type `, name, 
                            ` the identifier tag & class were unable to match any known option"`,
                        ");",
                    );
                }, emitFinalReturn: false);
            }
        }

        override void visit(Asn1SequenceTypeIr ir)
        {
            immutable MEMORY_VAR_PREFIX = "memory_";
            immutable BACKTRACK_VAR_PREFIX = "backtrack_";

            this.wrapAroundSequenceLikeType(ir);

            with(code) this.declareFromDecode((){
                ir.foreachComponentGC((item){
                    import std.conv : to;

                    putLine("/+++ TAG FOR FIELD: ", item.name, " +++/");
                    
                    Nullable!ulong topLevelTag;
                    Asn1Identifier.Class class_;
                    topLevelIrTagAndClass(item.type, topLevelTag, class_, context.errors);

                    assert(!topLevelTag.isNull, "TODO: Handle special case");
                    assert(!item.isComponentsOf, "TODO: Handle COMPONENTS OF");
                    assert(!item.isExtensible, "TODO: Handle extensible fields");
                    assert(item.defaultValue is null, "TODO: Handle DEFAULT");
                    
                    if(item.isOptional) // Backup the MemoryBuffer and restore it if the field doesn't exist.
                    {
                        putLine(
                            "auto ", BACKTRACK_VAR_PREFIX, item.name, " = ", MEMORY_BUFFER_TYPE, "(",
                                DECODER_PARAM_MEMORY, ".buffer, ",
                                DECODER_PARAM_MEMORY, ".cursor",
                            ");"
                        );
                    }

                    putLine(
                        "result = ", ASN1_SHORTHAND, ".asn1DecodeComponentHeader!", DECODER_PARAM_RULESET, "(",
                            DECODER_PARAM_MEMORY, ", ",
                            DECODER_VAR_HEADER,
                        ");"
                    );
                    putResultCheck();
                    
                    if(item.isOptional)
                    {
                        putLine(
                            "if(",
                                DECODER_VAR_HEADER, ".identifier.class_",
                                " == ",
                                ASN1_SHORTHAND, ".Asn1Identifier.Class.", class_.to!string,

                                " && ",

                                DECODER_VAR_HEADER, ".identifier.tag",
                                " == ",
                                topLevelTag.get.to!string,
                            ")"
                        );
                        putLine("{");
                        indent();
                    }
                    else
                    {
                        putIdentifierClassCheck(
                            class_, 
                            tagType: "top level tag",
                            tagValue: topLevelTag.get.to!string,
                            parentTypeType: "SEQUENCE",
                            parentTypeName: name,
                            fieldName: item.name
                        );

                        putIdentifierTagCheck(
                            topLevelTag.get.to!string, 
                            tagType: "top level tag",
                            parentTypeType: "SEQUENCE",
                            parentTypeName: name,
                            fieldName: item.name
                        );
                    }

                    putLine(MEMORY_BUFFER_TYPE, " ", MEMORY_VAR_PREFIX, item.name, ";");
                    putLine(
                        "result = ", ASN1_SHORTHAND, ".asn1ReadContentBytes(",
                            DECODER_PARAM_MEMORY, ", ",
                            DECODER_VAR_HEADER, ".length, ",
                            MEMORY_VAR_PREFIX, item.name,
                        ");"
                    );
                    putResultCheck();

                    putRawDerDecodingForField(
                        item.type,
                        item.name.idup,
                        asCamelCase(SETTER_FUNCTION_PREFIX, item.name),
                        code,
                        context,
                        parentIsWrapper: false,
                        typeOfOverride: ('_'~item.name).idup,
                        memoryVarOverride: (MEMORY_VAR_PREFIX~item.name).idup
                    );

                    if(item.isOptional)
                    {
                        dedent();
                        putLine("}");
                        putLine("else");
                        indent();
                            putLine(
                                DECODER_PARAM_MEMORY, " = ", MEMORY_BUFFER_TYPE, "(",
                                    BACKTRACK_VAR_PREFIX, item.name, ".buffer, ",
                                    BACKTRACK_VAR_PREFIX, item.name, ".cursor",
                                ");"
                            );
                        dedent();
                    }

                    putLine();
                    return Result.noError;
                }).resultEnforce;

                if(ir.isExtensible)
                {
                    assert(false, "TODO: Skip over any remaining fields (after confirming this is 100% what needs to happen)");
                }
                else
                {
                    putLine("if(memory.bytesLeft != 0)");
                    indent();
                        putLine(
                            "return ", RESULT_TYPE, ".make(", 
                                ASN1_SHORTHAND, ".Asn1DecodeError.sequenceHasExtraData, ",
                                `"when decoding non-extensible SEQUENCE `, name, 
                                ` there were unsused content bytes after attempting to decode all known fields -`,
                                ` this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input"`, 
                            ");"
                        );
                    dedent();
                }

                putLine("return this.", VALIDATE_FUNCTION_PREFIX, "();");
            }, emitFinalReturn: false);
        }

        private void wrapAroundSequenceLikeType(IrT)(IrT ir)
        {
            immutable IS_SET_PREFIX = "_isSet_";

            immutable SETTER_PARAM_VALUE = "value";

            // Model vars + functions
            with(code)
            {
                attributeBlock("private", (){
                    ir.foreachComponentGC((item){
                        assert(!item.isComponentsOf, "TODO: support COMPONENTS OF");
                        assert(item.defaultValue is null, "TODO: support DEFAULT");

                        // I don't want to use Nullable since it makes some of the other code gen logic
                        // kind of clunky, especially where `typeof()` is currently used.
                        putLine("bool ", IS_SET_PREFIX, item.name, ";");
                        putLine(rawTypeOf(item.type), " _", item.name, ";");

                        return Result.noError;
                    }).resultEnforce;
                });

                ir.foreachComponentGC((item){
                    const itemTypeName = (item.isOptional)
                        ? (NULLABLE_TYPE~"!("~rawTypeOf(item.type)~")")
                        : ("typeof(_"~item.name~")").idup;

                    declareFunction(
                        RESULT_TYPE, 
                        asCamelCase(SETTER_FUNCTION_PREFIX, item.name), 
                        (next){
                            put("typeof(_", item.name, ") ", SETTER_PARAM_VALUE);
                            next();
                        }, (){
                            if(item.type.getMainConstraintOrNull() !is null)
                                putLine("// TODO: Warning - type has a constraint but it's not being handled yet!");
                            
                            putLine(IS_SET_PREFIX, item.name, " = true;");
                            putLine('_', item.name, " = ", SETTER_PARAM_VALUE, ";");
                            put(RETURN_NO_ERROR);
                        }, 
                        funcAttributes: "@nogc nothrow"
                    );

                    if(item.isOptional) // Generate a setter overload that supports setting the value to null
                    {
                        declareFunction(
                            RESULT_TYPE, 
                            asCamelCase(SETTER_FUNCTION_PREFIX, item.name), 
                            (next){
                                put(itemTypeName, " ", SETTER_PARAM_VALUE);
                                next();
                            }, (){
                                if(item.type.getMainConstraintOrNull() !is null)
                                    putLine("// TODO: Warning - type has a constraint but it's not being handled yet!");
                                
                                putLine("if(!", SETTER_PARAM_VALUE, ".isNull)");
                                indent();
                                    putLine(
                                        "return ", asCamelCase(SETTER_FUNCTION_PREFIX, item.name), "(",
                                            SETTER_PARAM_VALUE, ".get()",
                                        ");"
                                    );
                                dedent();
                                putLine("else");
                                indent();
                                    putLine(IS_SET_PREFIX, item.name, " = false;");
                                dedent();
                                put(RETURN_NO_ERROR);
                            }, 
                            funcAttributes: "@nogc nothrow"
                        );
                    }

                    declareFunction(
                        itemTypeName, 
                        asCamelCase(GETTER_FUNCTION_PREFIX, item.name), 
                        (next){},
                        (){
                            if(item.isOptional)
                            {
                                putLine("if(", IS_SET_PREFIX, item.name, ")");
                                indent();
                                    putLine("return typeof(return)(_", item.name, ");");
                                dedent();
                                put("return typeof(return).init;");
                            }
                            else
                            {
                                putLine(
                                    "assert(", IS_SET_PREFIX, item.name,
                                        `, "Non-optional field '`, item.name,
                                        `' has not been set yet - please use validate() to check!"`,
                                    ");"
                                );
                                put("return _", item.name, ";");
                            }
                        },
                        funcAttributes: "@nogc nothrow"
                    );

                    return Result.noError;
                }).resultEnforce;

                declareFunction(
                    RESULT_TYPE, 
                    VALIDATE_FUNCTION_PREFIX,
                    (next){},
                    (){
                        ir.foreachComponentGC((item){
                            if(!item.isOptional)
                            {
                                putLine("if(!", IS_SET_PREFIX, item.name, ")");
                                indent();
                                    putLine(
                                        "return ", RESULT_TYPE, ".make(",
                                            ASN1_SHORTHAND, ".Asn1DecodeError.sequenceMissingField",
                                            `, "for SEQUENCE type `, name,
                                            ` non-optional field '`, item.name,
                                            `' has not been given a value - either because its setter wasn't called,`,
                                            ` or the decoded data stream did not provide the field."`,
                                        ");"
                                    );
                                dedent();
                            }

                            return Result.noError;
                        }).resultEnforce;

                        put(RETURN_NO_ERROR);
                    },
                    funcAttributes: "@nogc nothrow"
                );
            }
        }

        private void wrapAroundBasicType(string typeName)
        {
            immutable IS_SET_VAR = "_isSet";
            immutable SETTER_PARAM_NAME = "newValue";

            with(code)
            {
                attributeBlock("private", (){
                    putLine(typeName, " ", BASIC_FIELD_NAME, ";");
                    putLine("bool ", IS_SET_VAR, ";");
                });

                declareFunction(RESULT_TYPE, SETTER_FUNCTION_PREFIX, (next){
                    put(typeName, " ", SETTER_PARAM_NAME);
                    next();
                }, (){
                    putLine(BASIC_FIELD_NAME, " = ", SETTER_PARAM_NAME, ";");
                    putLine(IS_SET_VAR, " = true;");

                    put(RETURN_NO_ERROR);
                }, funcAttributes: "@nogc nothrow");

                declareFunction(typeName, GETTER_FUNCTION_PREFIX, 
                    (next){},
                    (){
                        putLine("assert(", IS_SET_VAR, `, "Cannot call get() when no value has been set!");`);
                        put("return ", BASIC_FIELD_NAME, ";");
                    }, funcAttributes: "@nogc nothrow"
                );
            }

            this.declareFromDecode((){ 
                putRawDerDecodingForField(
                    typeIr, // NOTE: This must always use `typeIr`, as it may be a tagged type which has to be handled properly.
                    BASIC_FIELD_NAME,
                    SETTER_FUNCTION_PREFIX,
                    code, 
                    context, 
                    parentIsWrapper: true
                ); 
            });
        }

        private void declareFromDecode(
            scope void delegate() putBody,
            bool emitFinalReturn = true
        )
        {
            with(code)
            {
                putLine("private alias testInstantiation = fromDecoding!(", ASN1_SHORTHAND, ".Asn1Ruleset.der);");
                declareFunction(RESULT_TYPE, "fromDecoding("~ASN1_SHORTHAND~".Asn1Ruleset "~DECODER_PARAM_RULESET~")", (next){ // @suppress(dscanner.style.long_line)
                    put("scope ref ", MEMORY_BUFFER_TYPE, ' ', DECODER_PARAM_MEMORY);
                    next();

                    put("const ", ASN1_SHORTHAND, ".Asn1Identifier ", DECODER_PARAM_IDENT);
                    next();
                }, (){
                    putLine("auto result = ", RESULT_TYPE, ".noError;");
                    putLine(ASN1_SHORTHAND, ".Asn1ComponentHeader ", DECODER_VAR_HEADER, ";");
                    putLine(DECODER_VAR_HEADER, ".identifier = ", DECODER_PARAM_IDENT, ";");
                    putLine("this = typeof(this).init;");
                    endLine();

                    putBody();
                    if(emitFinalReturn)
                        put(RETURN_NO_ERROR);
                });
            }
        }
    }

    code.declareType(name, (){
        scope visitor = new ModelVisitor();
        typeIr.visitGC(visitor);
    });
}

private void putRawDerDecodingForField(
    Asn1TypeIr fieldType,
    string fieldName,
    string setterName,
    DlangCodeBuilder code,
    ref DlangGeneratorContext context,
    bool parentIsWrapper,
    string typeOfOverride = "",
    string memoryVarOverride = DECODER_PARAM_MEMORY,
)
{
    final class DecoderVisitor : Asn1IrVisitorGC
    {
        override void visit(Asn1TaggedTypeIr ir) => ir.getUnderlyingTypeSkipTags().visitGC(this);

        override void visit(Asn1BooleanTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1BitStringTypeIr ir) => this.decodePrimitive();

        private void decodePrimitive()
        {
            string memoryVar = memoryVarOverride;
            
            with(code)
            {
                this.decodeTags(memoryVar);

                putLine(
                    "typeof(", 
                        typeOfOverride.length > 0 ? typeOfOverride : fieldName, 
                    ") temp_", fieldName, ";"
                );
                putLine(
                    "result = typeof(temp_", fieldName, 
                    ").fromDecoding!", DECODER_PARAM_RULESET, "(",
                        memoryVar, ", ",
                        "temp_", fieldName, ", ",
                        DECODER_VAR_HEADER, ".identifier",
                    ");"
                );
                putResultCheck();
                putLine("result = this.", setterName, "(temp_", fieldName, ");");
                putResultCheck();
                endLine();
            }
        }

        private void decodeTags(scope ref string memoryVar)
        {
            with(code)
            {
                if(auto taggedIr = cast(Asn1TaggedTypeIr)fieldType)
                {
                    string initialMemoryVar = memoryVarOverride;
                    size_t depth;

                    auto result = asn1WalkTags(taggedIr, (ulong tagValue, bool isExplicit, Asn1TaggedTypeIr.Class class_){ // @suppress(dscanner.style.long_line)
                        import std.conv : to;

                        if(!isExplicit) // We don't handle the base default/implicit tag, as that's the caller decoder's job.
                            return Result.noError;

                        memoryVar = "memory_"~depth.to!string~fieldName;
                        putLine(MEMORY_BUFFER_TYPE, ' ', memoryVar, ";");

                        indent();
                        scope(exit) dedent();

                        putLine("// EXPLICIT TAG - ", tagValue.to!string);

                        putLine(
                            "if(", 
                                DECODER_VAR_HEADER, ".identifier.encoding",
                                " != ",
                                ASN1_SHORTHAND, ".Asn1Identifier.Encoding.constructed",
                            ")"
                        );
                        indent();
                            putLine(
                                "return ", RESULT_TYPE, ".make(",
                                    ASN1_SHORTHAND, ".Asn1DecodeError.constructionIsPrimitive, ",
                                    `"when reading EXPLICIT tag `, tagValue.to!string, 
                                    ` for field `, fieldName,
                                    ` a primitive tag was found when a constructed one was expected"`,
                                ");"
                            );
                        dedent();

                        putIdentifierClassCheck(
                            irClassToDecoderClass(class_),
                            tagType: "EXPLICIT tag",
                            tagValue: tagValue.to!string,
                            parentTypeType: "TODO",
                            parentTypeName: "TODO",
                            fieldName: fieldName,
                        );

                        putIdentifierTagCheck(
                            tagValue.to!string,
                            tagType: "EXPLICIT tag",
                            parentTypeType: "TODO",
                            parentTypeName: "TODO",
                            fieldName: fieldName,
                        );

                        putLine(
                            "result = ", ASN1_SHORTHAND, ".asn1DecodeComponentHeader!", DECODER_PARAM_RULESET, "(",
                                initialMemoryVar, ", ",
                                DECODER_VAR_HEADER,
                            ");"
                        );
                        putResultCheck();

                        putLine(
                            "result = ", ASN1_SHORTHAND, ".asn1ReadContentBytes(",
                                initialMemoryVar, ", ",
                                DECODER_VAR_HEADER, ".length, ",
                                memoryVar,
                            ");"
                        );
                        putResultCheck();

                        initialMemoryVar = memoryVar;
                        depth++;
                        return Result.noError;
                    }, context.errors);
                    if(!result.isError(Asn1SemanticError.toolTypeMissingTag))
                        resultEnforce(result); // If the type doesn't have a default tag, then we don't care at this level as it's not an EXPLICIT tag we have to handle.
                }
            }
        }
    }

    code.putLine("/++ FIELD - ", fieldName, " ++/");

    scope visitor = new DecoderVisitor();
    fieldType.visitGC(visitor);
}

private string rawTypeOf(Asn1TypeIr ir)
{
    string result;

    final class Visitor : Asn1IrVisitorGC
    {
        override void visit(Asn1BooleanTypeIr ir) { result = ASN1_SHORTHAND~".Asn1Bool"; }
        override void visit(Asn1BitStringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1BitString"; }

        // TODO: Handle imported symbols - the IR tree needs to add parent information to handle them properly.
        override void visit(Asn1TypeReferenceIr ir) { result = ("."~ir.typeRef).idup; }
        override void visit(Asn1TaggedTypeIr ir) => ir.getUnderlyingTypeSkipTags().visitGC(this);
    }

    scope visitor = new Visitor();
    ir.visitGC(visitor);

    return result;
}

private string asCamelCase(string prefix, const(char)[] irName)
{
    import std.ascii : toUpper;
    return (prefix ~ irName[0].toUpper ~ irName[1..$]).idup;
}

private Asn1Identifier.Class irClassToDecoderClass(Asn1TaggedTypeIr.Class class_)
{
    final switch(class_) with(Asn1TaggedTypeIr.Class)
    {
        case universal: return typeof(return).universal;
        case application: return typeof(return).application;
        case private_: return typeof(return).private_;
        case unspecified: return typeof(return).contextSpecific;
    }
}

private void topLevelIrTagAndClass(
    Asn1TypeIr typeIr, 
    scope out Nullable!ulong tag, 
    scope out Asn1Identifier.Class class_, 
    scope Asn1ErrorHandler errors,
)
{
    if(auto taggedIr = cast(Asn1TaggedTypeIr)typeIr)
    {
        auto _  = asn1WalkTags(taggedIr, (ulong tagValue, bool _, Asn1TaggedTypeIr.Class tagClass){
            tag = tagValue;
            class_ = irClassToDecoderClass(tagClass);

            enum Dummy { n }
            return Result.make(Dummy.n); // Just to short circuit the logic, not an actual error.            
        }, errors);
        return;
    }
    else if(auto typeRefIr = cast(Asn1TypeReferenceIr)typeIr) // If there's been no other tags added to the reference, let's dig deeper to find one.
    {
        topLevelIrTagAndClass(typeRefIr.getResolvedTypeRecurse(), tag, class_, errors);
        return;
    }

    tag = typeIr.getUniversalTag();
    class_ = Asn1Identifier.Class.universal;
}