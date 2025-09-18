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
        Asn1ModuleIr _currentModule;
        Appender!(char[]) _buffer;
        uint _indent;
        bool _startOfLine;
    }

    private this(Asn1ModuleIr currentModule)
    in(currentModule !is null)
    {
        this._currentModule = currentModule;
    }

    Asn1ModuleIr currentModule() => this._currentModule;

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
            import std.algorithm : canFind;
            const dlangId = getModuleDlangIdentifier(moduleRef, moduleVersion, context.errors);
            if(dlangId.canFind("Dasn1-Intrinsics")) // Don't import intrinsics
                return Result.noError;
            
            putLine(
                "static import ",
                dlangId, // TODO: Make this a bit better since this prevents modules with the same name but different versions from being used together.
                " = ",
                context.baseModuleComponents.joiner("."), // TODO: Alow different modules to have different bases, configurable by the user
                ".",
                dlangId,
                ";"
            );
            return Result.noError;
        }).resultEnforce;
        
        endLine();
    }

    void declareType(string name, scope void delegate() putBody, string type = "struct")
    {
        put(type); put(' ');
        put(fixName(name)); endLine();
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

    void putResultCheck(scope const(char)[] debugContext)
    {
        putLine("if(result.isError)");
        indent();
            putLine(
                `return result.wrapError("when `, 
                debugContext, 
                ` in type "~__traits(identifier, typeof(this))~":");`
            );
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
private immutable UTF8_SHORTHAND = "utf8";

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
private immutable DEFAULT_VALUE_PREFIX = "defaultOf";

private immutable INTRINSIC_ANY_NAME = "Dasn1-Any";

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
    auto code = new DlangCodeBuilder(mod);
    with(code)
    {
        putStartOfModule(mod, "raw", context);
        putLine("static import ", TYPE_CON_SHORTHAND, " = std.typecons;");
        putLine("static import ", ASN1_SHORTHAND, " = juptune.data.asn1.decode.bcd.encoding;");
        putLine("static import ", RESULT_SHORTHAND, " = juptune.core.util.result;");
        putLine("static import ", BUFFER_SHORTHAND, " = juptune.data.buffer;");
        putLine("static import ", STRING_SHORTHAND, " = juptune.core.ds.string2;");
        putLine("static import ", UTF8_SHORTHAND, " = juptune.data.utf8;");
        endLine();

        mod.foreachAssignmentGC((assIr){
            if(auto typeAssIr = cast(Asn1TypeAssignmentIr)assIr)
                putRawType(typeAssIr.getSymbolName().idup, typeAssIr.getSymbolType(), code, context);
            else if(auto valueAssIr = cast(Asn1ValueAssignmentIr)assIr)
            {
                declareFunction(
                    rawTypeOf(valueAssIr.getSymbolType(), mod, context.errors),
                    fixName(valueAssIr.getSymbolName()),
                    (scope next){},
                    (){
                        putValueLiteral("mainValue", valueAssIr.getSymbolType(), valueAssIr.getSymbolValue(), code, context); // @suppress(dscanner.style.long_line)
                        putLine("return mainValue;");
                    },
                    "@nogc nothrow"
                );
            }
            else assert(false, "bug: Unhandled assignment type?");

            return Result.noError;
        }).resultEnforce;
    }

    return code.toString();
}

private void putValueLiteral(
    string varName,
    Asn1TypeIr typeIr,
    Asn1ValueIr valueIr,
    DlangCodeBuilder code,
    ref DlangGeneratorContext context,
)
{
    varName = fixName(varName);

    final class TypeVisitor : Asn1IrVisitorGC
    {
        override void visit(Asn1TaggedTypeIr ir)
        {
            ir.getUnderlyingTypeSkipTags().visitGC(this);
        }

        override void visit(Asn1ObjectIdentifierTypeIr ir)
        {
            import std.conv : to;

            ulong[] ids;
            void getIds(Asn1ValueIr idIr)
            {
                if(auto objIdIr = cast(Asn1ObjectIdSequenceValueIr)idIr)
                {
                    objIdIr.foreachObjectIdGC((subValueIr){
                        getIds(subValueIr);
                        return Result.noError;
                    }, context.errors).resultEnforce;
                }
                else if(auto valueSeqIr = cast(Asn1ValueSequenceIr)idIr)
                {
                    valueSeqIr.foreachSequenceValueGC((subValueIr){
                        getIds(subValueIr);
                        return Result.noError;
                    }, context.errors).resultEnforce;
                }
                else if(auto namedSeqIr = cast(Asn1NamedValueSequenceIr)idIr)
                {
                    // TODO: juptune.data.asn1 should probably find a more elegant way to handle transforming this
                    //       into an Asn1ObjectIdSequenceValueIr during semantics.
                    namedSeqIr.foreachSequenceNamedValueGC((subValueName, subValueIr){
                        // TEMP: Again, something like this really needs to be handled inside of Juptune itself...
                        //       I just have 0 idea on what the best way to handle this is.
                        auto item = code.currentModule.lookup(new Asn1ValueReferenceIr(
                            subValueIr.getRoughLocation(), subValueName
                        ));
                        assert(!item.isNull, "todo: this needs to be handled in Juptune for a better error message "~subValueName);
                        
                        if(auto castedIr = cast(Asn1ValueAssignmentIr)item.get)
                        {
                            getIds(castedIr.getSymbolValue());                        
                            getIds(subValueIr);
                        }
                        else // Last ditch attempt - needs to be made better by putting something into Juptune natively.
                        {
                            getIds(cast(Asn1ValueIr)item.get.ir);
                            getIds(subValueIr);
                        }
                        return Result.noError;
                    }, context.errors).resultEnforce;
                }
                else if(auto intValueIr = cast(Asn1IntegerValueIr)idIr)
                {
                    // Type checker should've made sure it's unsigned.
                    ulong id;
                    intValueIr.asUnsigned(id, context.errors).resultEnforce;
                    ids ~= id;
                }
                else assert(false, "Unhandled OBJECT IDENTIFIER value type: "~typeid(idIr).name);
            }
            getIds(valueIr);

            // TODO: Validate first and second ids are in bounds.

            with(code)
            {
                const valueName = varName~"__value";
                putLine("static immutable ubyte[] ", valueName, " = [");
                indent();
                foreach(i, id; ids[2..$])
                {
                    if(id <= 127)
                    {
                        put(id.to!string, ", ");
                        continue;
                    }

                    put("/* ", id.to!string, " */ ");

                    ubyte[] bits7InReverse;
                    bool isFirst = true;
                    while(id > 0)
                    {
                        bits7InReverse ~= isFirst ? (id & 0b0111_1111) : (id & 0b0111_1111) | 0b1000_0000;
                        id >>= 7;
                        isFirst = false;
                    }

                    for(ptrdiff_t j = cast(ptrdiff_t)bits7InReverse.length-1; j >= 0; j--)
                        put("0x", bits7InReverse[j].to!string(16), ", ");
                }
                dedent();
                putLine();
                putLine("];");
                put(varName, " = ", rawTypeOf(typeIr, code.currentModule, context.errors), ".fromUnownedBytes(");
                    put(ids.length == 0 ? "0" : ids[0].to!string, ", ");
                    put(ids.length == 1 ? "0" : ids[1].to!string, ", ");
                putLine(valueName, ");");
            }
        }

        override void visit(Asn1TypeReferenceIr ir)
        {
            if(isIntrinsicAnyType(ir))
                assert(false, "TODO: Figure out what to do with this case");

            with(code)
            {
                const underlyingVarName = varName~"__underlying";
                indent();
                    putValueLiteral(
                        underlyingVarName, 
                        ir.getResolvedTypeRecurse(Asn1TypeReferenceIr.StopForConstraints.no),
                        valueIr,
                        code,
                        context
                    );
                dedent();

                // TODO: Need to distinguish between types that have a .set, and ones that have more complex stuff (e.g. SEQUENCES)?
                putLine(
                    RESULT_SHORTHAND, ".resultAssert(",
                        varName, ".set(", underlyingVarName, ")",
                    ");"
                );
            }
        }

        override void visit(Asn1IntegerTypeIr ir)
        {
            import std.conv : to;
            import juptune.data.asn1.decode.bcd.encoding : Asn1Integer;

            auto intValueIr = cast(Asn1IntegerValueIr)valueIr;
            assert(intValueIr !is null, "bug: Type checker didn't catch that this isn't an integer?");

            ulong value;
            intValueIr.asUnsigned(value, context.errors).resultEnforce;

            with(code)
            {
                const underlyingVarName = varName~"__underlying";
                auto number = Asn1Integer.fromNumberGC(value);

                putLine("static immutable ubyte[] ", underlyingVarName, " = [");
                indent();
                put("/* ", value.to!string, " */ ");
                foreach(byte_; number.rawBytes)
                    put("0x", byte_.to!string(16), ", ");
                dedent();
                putLine();
                putLine("];");

                putLine(varName, " = ", ASN1_SHORTHAND, ".Asn1Integer.fromUnownedBytes(", underlyingVarName, ");");
            }
        }

        override void visit(Asn1BooleanTypeIr ir)
        {
            auto boolValueIr = cast(Asn1BooleanValueIr)valueIr;
            assert(boolValueIr !is null, "bug: Type checker didn't catch that this isn't a boolean?");

            with(code)
            {
                if(boolValueIr.asBool)
                    putLine(varName, " = ", ASN1_SHORTHAND, ".Asn1Bool(0xFF);");
                else
                    putLine(varName, " = ", ASN1_SHORTHAND, ".Asn1Bool(0);");
            }
        }
    }

    if(auto valueRefIr = cast(Asn1ValueReferenceIr)valueIr)
        valueIr = valueRefIr.getResolvedValueRecurse();

    code.putLine(rawTypeOf(typeIr, code.currentModule, context.errors), " ", varName, ";");

    scope visitor = new TypeVisitor();
    typeIr.visitGC(visitor);
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

        override void visit(Asn1TaggedTypeIr ir) => ir.getUnderlyingTypeSkipTags().visitGC(this);
        override void visit(Asn1BooleanTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1ObjectIdentifierTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1OctetStringTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1SetOfTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1SequenceOfTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1UTF8StringTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1PrintableStringTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1NumericStringTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1IA5StringTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1TypeReferenceIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        override void visit(Asn1UtcTimeTypeIr ir) => this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));

        override void visit(Asn1BitStringTypeIr ir)
        {
            with(code) if(ir.hasNamedBits())
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

            this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
        }
        
        override void visit(Asn1IntegerTypeIr ir)
        {
            with(code) if(ir.hasNamedNumbers())
            {
                putLine("enum NamedNumber");
                putLine('{');
                indent();
                ir.foreachNamedNumberGC((name, value){
                    if(auto valueRefIr = cast(Asn1ValueReferenceIr)value)
                        value = valueRefIr.getResolvedValueRecurse();
                    
                    auto intValueIr = cast(Asn1IntegerValueIr)value;
                    assert(intValueIr !is null, "bug: Value's not an integer, why didn't the type checker catch this?");

                    putLine(fixName(name), " = ", intValueIr.getNumberText(), ',');
                    return Result.noError;
                }).resultEnforce;
                dedent();
                putLine('}');
            }

            this.wrapAroundBasicType(rawTypeOf(ir, code.currentModule, context.errors));
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
                        putLine(fixName(name), ","); // TODO: I wonder if this should be 1:1 with the underlying tag
                        return Result.noError;
                    }).resultEnforce;
                }, type: "enum");

                declareType(VALUE_UNION, (){
                    ir.foreachChoiceGC((name, typeIr, _){
                        putLine(rawTypeOf(typeIr, code.currentModule, context.errors), ' ', fixName(name), ";");
                        return Result.noError;
                    }).resultEnforce;
                }, type: "union");

                putLine("// Sanity check: Ensuring that no types have a proper dtor, as they won't be called.");
                putLine("import std.traits : hasElaborateDestructor;");
                ir.foreachChoiceGC((name, typeIr, __){
                    putLine("static assert(!hasElaborateDestructor!(", rawTypeOf(typeIr, code.currentModule, context.errors), `), "Report a bug if you see this.");`); // @suppress(dscanner.style.long_line)
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
                            put("typeof(", VALUE_UNION, '.', fixName(name), ") ", SETTER_PARAM_VALUE);
                            next();
                        }, (){
                            putLine(RESULT_TYPE, " result = ", RESULT_TYPE, ".noError;");
                            putSetterConstraintChecksForField(typeIr, name.idup, SETTER_PARAM_VALUE, code, context); // @suppress(dscanner.style.long_line)

                            putLine(VALUE_FIELD, '.', fixName(name), " = ", SETTER_PARAM_VALUE, ";");
                            putLine(CHOICE_FIELD, " = ", CHOICE_ENUM, '.', fixName(name), ";");
                            put(RETURN_NO_ERROR);
                        }, 
                        funcAttributes: "@nogc nothrow"
                    );

                    declareFunction(
                        ("typeof("~VALUE_UNION~'.'~fixName(name)~")").idup, 
                        asCamelCase(GETTER_FUNCTION_PREFIX, name), 
                        (next){},
                        (){
                            putLine(
                                "assert(", 
                                    CHOICE_FIELD, " == ", CHOICE_ENUM, '.', fixName(name), ", ",
                                    `"This '"~__traits(identifier, typeof(this))~"`, ` does not contain choice '`, fixName(name), `'"`, // @suppress(dscanner.style.long_line)
                                ");"
                            );
                            put("return ", VALUE_FIELD, '.', fixName(name), ";");
                        },
                        funcAttributes: "@nogc nothrow"
                    );

                    declareFunction(
                        "bool", 
                        asCamelCase(CHECKER_FUNCTION_PREFIX, name), 
                        (next){}, 
                        (){
                            put("return ", CHOICE_FIELD, " == ", CHOICE_ENUM, '.', fixName(name), ";");
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

            with(code) this.declareToString((){
                ir.foreachChoiceGC((name, _, __){
                    putLine("if(", asCamelCase(CHECKER_FUNCTION_PREFIX, name), ")");
                    putLine("{");
                    indent();
                        putLine("depth++;");
                        putLine("putIndent();");
                        putLine(`sink("`, name, `: ");`);
                        putLine(`sink("\n");`);
                        putLine("static if(__traits(hasMember, typeof(", asCamelCase(GETTER_FUNCTION_PREFIX, name), "())", `, "toString"))`); // @suppress(dscanner.style.long_line)
                        indent();
                            putLine(VALUE_FIELD, ".", fixName(name), ".toString(sink, depth+1);");
                        dedent();
                        putLine("else");
                        indent();
                        putLine("{");
                            putLine("putIndent();");
                            putLine(`sink("<no toString impl>\n");`);
                        dedent();
                        putLine("}");
                        putLine("depth--;");
                    dedent();
                    putLine("}");
                    return Result.noError;
                }).resultEnforce;
            });
        }

        override void visit(Asn1SequenceTypeIr ir)
        {
            this.wrapAroundSequenceLikeType(ir);

            with(code) this.declareFromDecode((){
                ir.foreachComponentGC((item){                    
                    Nullable!ulong topLevelTag;
                    Asn1Identifier.Class class_;
                    topLevelIrTagAndClass(item.type, topLevelTag, class_, context.errors);

                    return this.decodeFieldOfSequenceLikeType(topLevelTag, class_, item);
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

                put("return this.", VALIDATE_FUNCTION_PREFIX, "();");
            }, emitFinalReturn: false);
        }

        override void visit(Asn1SetTypeIr ir)
        {
            import std.algorithm : sort;

            this.wrapAroundSequenceLikeType(ir);

            static struct TagAndItem
            {
                ulong tag;
                Asn1Identifier.Class class_;
                Asn1SetTypeIr.Item item;
            }

            TagAndItem[] tagAndItems;
            ir.foreachComponentGC((item){
                Nullable!ulong topLevelTag;
                Asn1Identifier.Class class_;
                topLevelIrTagAndClass(item.type, topLevelTag, class_, context.errors);

                if(!topLevelTag.isNull)
                {
                    tagAndItems ~= TagAndItem(topLevelTag.get, class_, item);
                    return Result.noError;
                }

                assert(false, "TODO: Support CHOICE within a SET... good luck");
                return Result.noError;
            }).resultEnforce;

            tagAndItems.sort!"a.tag < b.tag"();

            with(code) this.declareFromDecode((){
                // DER and BER encodings of SET are too different to create a singular solution for.
                // DER is closer to how SEQUENCE works, whereas BER is much more of a PITA.
                putLine("static assert(ruleset == ", ASN1_SHORTHAND, `.Asn1Ruleset.der, "TODO: Support non-DER SET encodings");`); // @suppress(dscanner.style.long_line)

                foreach(item; tagAndItems)
                {
                    this.decodeFieldOfSequenceLikeType(
                        Nullable!ulong(item.tag),
                        item.class_,
                        item.item
                    ).resultEnforce;
                }

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
                                ASN1_SHORTHAND, ".Asn1DecodeError.setHasExtraData, ",
                                `"when decoding non-extensible SET `, name, 
                                ` there were unsused content bytes after attempting to decode all known fields -`,
                                ` this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input"`, 
                            ");"
                        );
                    dedent();
                }

                put("return this.", VALIDATE_FUNCTION_PREFIX, "();");
            }, emitFinalReturn: false);
        }

        private Result decodeFieldOfSequenceLikeType(ItemT)(
            Nullable!ulong topLevelTag,
            Asn1Identifier.Class class_,
            ItemT item,
        )
        {
            import std.conv : to;

            immutable MEMORY_VAR_PREFIX = "memory_";
            immutable BACKTRACK_VAR_PREFIX = "backtrack_";

            auto typeRefIr = cast(Asn1TypeReferenceIr)item.type;
            const isAnyIntrinsic = (typeRefIr !is null && isIntrinsicAnyType(typeRefIr));

            // Here be dragons... this needs a refactor because fml this is combinatronics hell.

            with(code)
            {
                putLine("/+++ TAG FOR FIELD: ", item.name, " +++/");

                assert(!item.isComponentsOf, "TODO: Handle COMPONENTS OF");
                assert(!item.isExtensible, "TODO: Handle extensible fields");

                if(item.isOptional || item.defaultValue !is null) // Backup the MemoryBuffer and restore it if the field doesn't exist.
                {
                    putLine(
                        "auto ", BACKTRACK_VAR_PREFIX, fixName(item.name), " = ", MEMORY_BUFFER_TYPE, "(",
                            DECODER_PARAM_MEMORY, ".buffer, ",
                            DECODER_PARAM_MEMORY, ".cursor",
                        ");"
                    );
                }

                if(item.isOptional || item.defaultValue !is null)
                {
                    putLine("if(", DECODER_PARAM_MEMORY, ".bytesLeft != 0)");
                    putLine("{");
                    indent();
                }
                putLine(
                    "result = ", ASN1_SHORTHAND, ".asn1DecodeComponentHeader!", DECODER_PARAM_RULESET, "(",
                        DECODER_PARAM_MEMORY, ", ",
                        DECODER_VAR_HEADER,
                    ");"
                );
                putResultCheck("decoding header of field '"~item.name~"'");
                
                if(!topLevelTag.isNull && !isAnyIntrinsic)
                {
                    if(item.isOptional || item.defaultValue !is null)
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
                }
                else if(isAnyIntrinsic)
                    putLine("// Field is the intrinsic ANY type - any tag is allowed.");

                putLine(MEMORY_BUFFER_TYPE, " ", MEMORY_VAR_PREFIX, fixName(item.name), ";");
                putLine(
                    "result = ", ASN1_SHORTHAND, ".asn1ReadContentBytes(",
                        DECODER_PARAM_MEMORY, ", ",
                        DECODER_VAR_HEADER, ".length, ",
                        MEMORY_VAR_PREFIX, fixName(item.name),
                    ");"
                );
                putResultCheck("reading content bytes of field '"~item.name~"'");

                if(topLevelTag.isNull && item.isOptional)
                {
                    putLine("result = (){ // Field is OPTIONAL and has a variable starting tag");
                    indent();
                }

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

                if(!topLevelTag.isNull)
                {
                    if((item.isOptional || item.defaultValue !is null) && !isAnyIntrinsic)
                    {
                        dedent();
                        putLine("}");
                        putLine("else");
                        putLine("{");
                        indent();
                            putLine(
                                DECODER_PARAM_MEMORY, " = ", MEMORY_BUFFER_TYPE, "(",
                                    BACKTRACK_VAR_PREFIX, fixName(item.name), ".buffer, ",
                                    BACKTRACK_VAR_PREFIX, fixName(item.name), ".cursor",
                                ");"
                            );
                            if(item.defaultValue !is null)
                            {
                                putLine("result = this.", asCamelCase(SETTER_FUNCTION_PREFIX, item.name), "(",
                                    asCamelCase(DEFAULT_VALUE_PREFIX, item.name), "()",
                                ");");
                                putResultCheck("setting field '"~item.name~"' to default value");
                            }
                        dedent();
                        putLine("}");
                    }
                }
                else
                {
                    if(item.isOptional && !isAnyIntrinsic)
                    {
                        putLine("return ", RESULT_TYPE, ".noError;");
                        dedent();
                        putLine("}();");
                        putLine("if(result.isError(", ASN1_SHORTHAND, ".Asn1DecodeError.choiceHasNoMatch))");
                        indent();
                            putLine(
                                DECODER_PARAM_MEMORY, " = ", MEMORY_BUFFER_TYPE, "(",
                                    BACKTRACK_VAR_PREFIX, fixName(item.name), ".buffer, ",
                                    BACKTRACK_VAR_PREFIX, fixName(item.name), ".cursor",
                                ");"
                            );
                        dedent();
                        putLine("else if(result.isError)");
                        indent();
                            putLine(`return result.wrapError("For "~__traits(identifier, typeof(this))~":");`);
                        dedent();
                    }
                }

                if(item.isOptional || item.defaultValue !is null)
                {
                    dedent();
                    putLine("}");

                    if(item.defaultValue !is null)
                    {
                        putLine("else");
                        putLine("{");
                        indent();
                            putLine("result = this.", asCamelCase(SETTER_FUNCTION_PREFIX, item.name), "(",
                                asCamelCase(DEFAULT_VALUE_PREFIX, item.name), "()",
                            ");");
                            putResultCheck("setting field '"~item.name~"' to default value");
                        dedent();
                        putLine("}");
                    }
                }

                putLine();
            }

            return Result.noError;
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

                        // I don't want to use Nullable since it makes some of the other code gen logic
                        // kind of clunky, especially where `typeof()` is currently used.
                        putLine("bool ", IS_SET_PREFIX, fixName(item.name), ";");
                        putLine(rawTypeOf(item.type, code.currentModule, context.errors), " _", fixName(item.name), ";");

                        return Result.noError;
                    }).resultEnforce;
                });

                ir.foreachComponentGC((item){
                    const itemTypeName = (item.isOptional)
                        ? (NULLABLE_TYPE~"!("~rawTypeOf(item.type, code.currentModule, context.errors)~")")
                        : ("typeof(_"~fixName(item.name)~")").idup;

                    declareFunction(
                        RESULT_TYPE, 
                        asCamelCase(SETTER_FUNCTION_PREFIX, item.name), 
                        (next){
                            put("typeof(_", fixName(item.name), ") ", SETTER_PARAM_VALUE);
                            next();
                        }, (){
                            putLine(RESULT_TYPE, " result = ", RESULT_TYPE, ".noError;");
                            putSetterConstraintChecksForField(item.type, item.name.idup, SETTER_PARAM_VALUE, code, context); // @suppress(dscanner.style.long_line)
                            
                            putLine(IS_SET_PREFIX, fixName(item.name), " = true;");
                            putLine('_', fixName(item.name), " = ", SETTER_PARAM_VALUE, ";");
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
                                putLine(RESULT_TYPE, " result = ", RESULT_TYPE, ".noError;");
                                
                                putLine("if(!", SETTER_PARAM_VALUE, ".isNull)");
                                putLine("{");
                                indent();
                                    putSetterConstraintChecksForField(item.type, item.name.idup, SETTER_PARAM_VALUE~".get", code, context); // @suppress(dscanner.style.long_line)
                                    putLine(
                                        "return ", asCamelCase(SETTER_FUNCTION_PREFIX, item.name), "(",
                                            SETTER_PARAM_VALUE, ".get()",
                                        ");"
                                    );
                                dedent();
                                putLine("}");
                                putLine("else");
                                indent();
                                    putLine(IS_SET_PREFIX, fixName(item.name), " = false;");
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
                                putLine("if(", IS_SET_PREFIX, fixName(item.name), ")");
                                indent();
                                    putLine("return typeof(return)(_", fixName(item.name), ");");
                                dedent();
                                put("return typeof(return).init;");
                            }
                            else
                            {
                                putLine(
                                    "assert(", IS_SET_PREFIX, fixName(item.name),
                                        `, "Non-optional field '`, item.name,
                                        `' has not been set yet - please use validate() to check!"`,
                                    ");"
                                );
                                put("return _", fixName(item.name), ";");
                            }
                        },
                        funcAttributes: "@nogc nothrow"
                    );

                    if(item.defaultValue !is null)
                    {
                        declareFunction(
                            "static " ~ itemTypeName,
                            asCamelCase(DEFAULT_VALUE_PREFIX, item.name),
                            (next){},
                            (){
                                putValueLiteral(
                                    "mainValue", 
                                    item.type, 
                                    item.defaultValue, 
                                    code, 
                                    context
                                );
                                putLine("return mainValue;");
                            },
                            funcAttributes: "@nogc nothrow"
                        );
                    }

                    return Result.noError;
                }).resultEnforce;

                declareFunction(
                    RESULT_TYPE, 
                    VALIDATE_FUNCTION_PREFIX,
                    (next){},
                    (){
                        ir.foreachComponentGC((item){
                            if(item.defaultValue !is null)
                            {
                                putLine("if(!", IS_SET_PREFIX, fixName(item.name), ")");
                                putLine("{");
                                indent();
                                    putLine("auto result = this.", asCamelCase(SETTER_FUNCTION_PREFIX, item.name), "(",
                                        asCamelCase(DEFAULT_VALUE_PREFIX, item.name), "()",
                                    ");");
                                    putResultCheck("setting field '"~item.name~"'");
                                dedent();
                                putLine("}");
                            }
                            
                            if(!item.isOptional && item.defaultValue is null)
                            {
                                putLine("if(!", IS_SET_PREFIX, fixName(item.name), ")");
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

                this.declareToString((){
                    ir.foreachComponentGC((item){
                        putLine("putIndent();");
                        putLine("depth++;");
                        putLine(`sink("`, item.name, `: ");`);
                        putLine(`sink("\n");`);
                        putLine("static if(__traits(hasMember, typeof(_", fixName(item.name), ")", `, "toString"))`);
                        indent();
                            putLine("_", fixName(item.name), ".toString(sink, depth+1);");
                        dedent();
                        putLine("else");
                        indent();
                        putLine("{");
                            putLine("putIndent();");
                            putLine(`sink("<no toString impl>\n");`);
                        dedent();
                        putLine("}");
                        putLine("depth--;");
                        return Result.noError;
                    }).resultEnforce;
                });
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
                    putLine(RESULT_TYPE, " result = ", RESULT_TYPE, ".noError;");
                    putSetterConstraintChecksForField(typeIr, "value", SETTER_PARAM_NAME, code, context);

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

                this.declareToString((){
                    putLine("static if(__traits(hasMember, ", typeName, `, "toString"))`);
                    indent();
                        putLine(BASIC_FIELD_NAME, ".toString(sink, depth+1);");
                    dedent();
                    putLine("else");
                    putLine("{");
                    indent();
                        putLine("putIndent();");
                        putLine(`sink("<no toString impl>");`);
                    dedent();
                    putLine("}");
                    putLine(`sink("\n");`);
                });
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

        private void declareToString(scope void delegate() putBody)
        {
            with(code)
            {
                putLine("private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);");
                declareFunction("void", "toString(SinkT)", (next){
                    put("scope SinkT sink");
                    next();

                    put("int depth = 0");
                    next();
                }, (){
                    putLine(`void putIndent(){ foreach(i; 0..depth) sink("  "); }`);
                    putLine();
                    putLine("putIndent();");
                    putLine(`sink("["~__traits(identifier, typeof(this))~"]\n");`);
                    putLine("depth++;");
                    putBody();
                    putLine("depth--;");
                });
            }
        }
    }

    code.declareType(name, (){
        scope visitor = new ModelVisitor();
        typeIr.visitGC(visitor);
    });
}

private void putSetterConstraintChecksForField(
    Asn1TypeIr fieldTypeIr,
    string fieldName,
    string fieldVarName,
    DlangCodeBuilder code,
    ref DlangGeneratorContext context
)
{
    final class ConstraintVisitor : Asn1IrVisitorGC
    {
        override void visit(Asn1BooleanTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                );
            });
        }

        override void visit(Asn1IntegerTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    valueRange: (valueRangeConstraintIr, subSuccessFlag) {
                        import std.conv : to;

                        void handleEndpoint(
                            Asn1ValueRangeConstraintIr.Endpoint endpoint, 
                            out ulong value, 
                            ulong maxOrMin
                        )
                        {
                            if(endpoint.valueIr is null)
                            {
                                value = maxOrMin;
                                return;
                            }

                            auto valueIr = endpoint.valueIr;
                            if(auto valueRefIr = cast(Asn1ValueReferenceIr)valueIr)
                                valueIr = valueRefIr.getResolvedValueRecurse();

                            auto intValueIr = cast(Asn1IntegerValueIr)valueIr;
                            assert(intValueIr !is null, "bug: Why didn't the type checker catch this?");

                            intValueIr.asUnsigned(value, context.errors).resultEnforce;
                        }

                        ulong lower, upper;
                        handleEndpoint(valueRangeConstraintIr.getLower(), lower, ulong.min);
                        handleEndpoint(valueRangeConstraintIr.getUpper(), upper, ulong.max);

                        putLine("{");
                        indent();
                            const VALUE_VAR = "_integer__value";
                            putLine("long ", VALUE_VAR, ";");
                            putLine("result = ", fieldVarName, ".asInt!long(", VALUE_VAR, ");");
                            putResultCheck("converting ASN.1 integer into native integer");
                            putLine(subSuccessFlag, " = ", 
                                VALUE_VAR, " >= ", lower.to!string,
                                " && ",
                                VALUE_VAR, " <= ", upper.to!string,
                            ";");
                        dedent();
                        putLine("}");
                    },
                );
            });
        }

        override void visit(Asn1ObjectIdentifierTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                );
            });
        }

        override void visit(Asn1OctetStringTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                );
            });
        }

        override void visit(Asn1SetOfTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        this.putSizeConstraint(
                            sizeConstraintIr, 
                            subSuccessFlag,
                            fieldVarName~".elementCount",
                        );
                    }
                );
            });
        }

        override void visit(Asn1SequenceOfTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        this.putSizeConstraint(
                            sizeConstraintIr, 
                            subSuccessFlag,
                            fieldVarName~".elementCount",
                        );
                    }
                );
            });
        }

        override void visit(Asn1UTF8StringTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        const lengthVar = "_utf8string__length";
                        putLine("{");
                        indent();
                            putLine("size_t ", lengthVar, ";");
                            putLine("result = ", UTF8_SHORTHAND, ".utf8Length(",
                                fieldVarName, ".asSlice",
                                ", ", lengthVar,
                            ");");
                            putResultCheck("counting length of utf8 string");

                            this.putSizeConstraint(
                                sizeConstraintIr, 
                                subSuccessFlag,
                                lengthVar,
                            );
                        dedent();
                        putLine("}");
                    }
                );
            });
        }

        override void visit(Asn1PrintableStringTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        this.putSizeConstraint(
                            sizeConstraintIr, 
                            subSuccessFlag,
                            fieldVarName~".asSlice.length",
                        );
                    }
                );
            });
        }

        override void visit(Asn1NumericStringTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        this.putSizeConstraint(
                            sizeConstraintIr, 
                            subSuccessFlag,
                            fieldVarName~".asSlice.length",
                        );
                    }
                );
            });
        }

        override void visit(Asn1IA5StringTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                    size: (sizeConstraintIr, subSuccessFlag) {
                        this.putSizeConstraint(
                            sizeConstraintIr, 
                            subSuccessFlag,
                            fieldVarName~".asSlice.length",
                        );
                    }
                );
            });
        }

        override void visit(Asn1TypeReferenceIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                );
            });
        }

        override void visit(Asn1UtcTimeTypeIr ir)
        {
            with(code) this.putStandardSetup((mainSuccessFlag, counter){
                this.foreachConstraintSmart(ir.getMainConstraintOrNull(), counter, mainSuccessFlag,
                );
            });
        }

        private void putStandardSetup(
            scope void delegate(string successFlagVar, ref size_t counter) putConstraints
        )
        {
            const SUCCESS_FLAG_VAR = "_successFlag";

            size_t counter;
            with(code)
            {
                putLine("bool ", SUCCESS_FLAG_VAR, ";");
                putConstraints(SUCCESS_FLAG_VAR, counter);
                putLine("if(!", SUCCESS_FLAG_VAR, ")");
                indent();
                    putLine("return ", RESULT_TYPE, ".make(", 
                        ASN1_SHORTHAND, ".Asn1DecodeError.constraintFailed, ",
                        `"Value failed to match against type's constraint (TODO: A much more specific error message)"`,
                    ");");
                dedent();
            }
        }

        private void putSizeConstraint(
            Asn1SizeConstraintIr sizeConstraintIr, 
            string subSuccessFlag, 
            string lengthField
        )
        {
            import std.conv : to;

            with(code)
            {
                if(auto singleValueIr = cast(Asn1SingleValueConstraintIr)sizeConstraintIr.getMainConstraint())
                {
                    auto valueIr = singleValueIr.getValue();
                    if(auto valueRefIr = cast(Asn1ValueReferenceIr)valueIr)
                        valueIr = valueRefIr.getResolvedValueRecurse();

                    auto intValueIr = cast(Asn1IntegerValueIr)valueIr;
                    assert(intValueIr !is null, "bug: Why didn't the type checker catch this?");

                    ulong value;
                    intValueIr.asUnsigned(value, context.errors).resultEnforce;
                    putLine(subSuccessFlag, " = ", lengthField, " == ", value.to!string, ";");
                }
                else if(auto valueRangeIr = cast(Asn1ValueRangeConstraintIr)sizeConstraintIr.getMainConstraint())
                {
                    void handleEndpoint(Asn1ValueRangeConstraintIr.Endpoint endpoint, out ulong value, ulong maxOrMin)
                    {
                        if(endpoint.valueIr is null)
                        {
                            value = maxOrMin;
                            return;
                        }

                        auto valueIr = endpoint.valueIr;
                        if(auto valueRefIr = cast(Asn1ValueReferenceIr)valueIr)
                            valueIr = valueRefIr.getResolvedValueRecurse();

                        auto intValueIr = cast(Asn1IntegerValueIr)valueIr;
                        assert(intValueIr !is null, "bug: Why didn't the type checker catch this?");

                        intValueIr.asUnsigned(value, context.errors).resultEnforce;
                    }

                    ulong lower, upper;
                    handleEndpoint(valueRangeIr.getLower(), lower, ulong.min);
                    handleEndpoint(valueRangeIr.getUpper(), upper, ulong.max);

                    putLine(subSuccessFlag, " = ", 
                        lengthField, " >= ", lower.to!string,
                        " && ",
                        lengthField, " <= ", upper.to!string,
                        ";"
                    );
                }
                else
                    assert(false, "bug: unhandled constraint case for SizeConstraint");
            }
        }

        private void foreachConstraintSmart(
            Asn1ConstraintIr ir,
            scope ref size_t counter,
            string successFlagVar,
            scope void delegate(Asn1SingleValueConstraintIr constraintIr, string successFlagVar) singleValue = null,
            scope void delegate(Asn1SizeConstraintIr constraintIr, string successFlagVar) size = null,
            scope void delegate(Asn1ValueRangeConstraintIr constraintIr, string successFlagVar) valueRange = null,
        )
        {
            this.foreachConstraint(ir, (constraintIr, subSuccessFlag){
                import std.meta : AliasSeq;

                // I could technically use Parameters!() instead of manually specifying the IR type, but for some reason
                // I just don't want to. #thuglifechoseme
                alias TypeAndHandler = AliasSeq!(
                    Asn1SingleValueConstraintIr,    singleValue,
                    Asn1SizeConstraintIr,           size,
                    Asn1ValueRangeConstraintIr,     valueRange,
                );

                static foreach(i; 0..TypeAndHandler.length / 2)
                if(auto castedIr = cast(TypeAndHandler[i*2])constraintIr)
                {
                    // if(TypeAndHandler[(i*2)+1] !is null) {
                    assert(
                        TypeAndHandler[(i*2)+1] !is null, 
                        "bug: Field "~fieldName~" of type "~typeid(fieldTypeIr).name~" has a constraint"
                        ~" of type "~typeid(constraintIr).name~" attached to it, but has a null handler."
                    );
                    TypeAndHandler[(i*2)+1](castedIr, subSuccessFlag);
                    // }
                    return;
                }

                import juptune.data.asn1.lang.tooling : asn1ToStringGC;
                assert(false, 
                    "bug: Unhandled constraint IR type: "
                    ~typeid(constraintIr).name
                    ~" -> "
                    ~asn1ToStringGC(constraintIr)
                );
            }, counter, successFlagVar);
        }

        private void foreachConstraint(
            Asn1ConstraintIr constraintIr,
            scope void delegate(Asn1ConstraintIr constraintIr, string successFlagVar) onConstraint,
            scope ref size_t counter,
            string successFlagVar,
        )
        {
            import std.format : format;

            if(constraintIr is null)
                return;

            if(auto unionIr = cast(Asn1UnionConstraintIr)constraintIr)
            {
                with(code)
                {
                    string[] subSuccessFlags;
                    unionIr.foreachUnionConstraintGC((childIr){
                        indent();
                        scope(exit) dedent();

                        putLine("// subconstraint of type ", typeid(childIr).name);

                        const subSuccessFlag = format!"_successFlag%s"(counter++);
                        subSuccessFlags ~= subSuccessFlag;
                        putLine("bool ", subSuccessFlag, ";");
                        
                        this.foreachConstraint(childIr, onConstraint, counter, subSuccessFlag);
                        return Result.noError;
                    }).resultEnforce;

                    putLine(successFlagVar, " = ");
                    indent();
                    foreach(i, flagName; subSuccessFlags)
                    {
                        if(i != 0)
                            put("|| ");
                        putLine(flagName);
                    }
                    dedent();
                    putLine(";");
                }
            }
            else if(auto intersectionIr = cast(Asn1IntersectionConstraintIr)constraintIr)
            {
                assert(false, "TODO: Intersection constraint");
            }

            onConstraint(constraintIr, successFlagVar);
        }
    }

    if(fieldTypeIr.getMainConstraintOrNull() is null)
        return;

    scope visitor = new ConstraintVisitor();
    fieldTypeIr.visitGC(visitor);
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
        override void visit(Asn1OctetStringTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1ObjectIdentifierTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1IntegerTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1UTF8StringTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1PrintableStringTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1NumericStringTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1IA5StringTypeIr ir) => this.decodePrimitive();
        override void visit(Asn1UtcTimeTypeIr ir) => this.decodePrimitive();

        override void visit(Asn1TypeReferenceIr ir)
        {
            if(isIntrinsicAnyType(ir)) // Since this is masquerading as a primitive, we need to call decodePrimitive.
            {
                this.decodePrimitive();
                return;
            }

            with(code)
            {
                this.decodeTags(memoryVarOverride);

                putLine(
                    "typeof(", 
                        fixName(typeOfOverride.length > 0 ? typeOfOverride : fieldName), 
                    ") temp_", fixName(fieldName), ";"
                );
                putLine(
                    "result = temp_", fixName(fieldName), ".fromDecoding!", DECODER_PARAM_RULESET, "(",
                        memoryVarOverride, ", ",
                        DECODER_VAR_HEADER, ".identifier",
                    ");"
                );
                putResultCheck("decoding field '"~fieldName~"'");
                putLine("result = this.", setterName, "(temp_", fixName(fieldName), ");");
                putResultCheck("setting field '"~fieldName~"'");
                endLine();
            }
        }

        override void visit(Asn1SetOfTypeIr ir)
        {
            this.decodePrimitive();

            // This doesn't decode into anything - it's just for validation.
            with(code)
            {
                putLine(
                    "result = this.", typeOfOverride.length > 0 ? typeOfOverride : fieldName, 
                    ".foreachElementAuto((element) => ", RESULT_TYPE, ".noError", ");"
                );
                putResultCheck("decoding subelements of SET OF field '"~fieldName~"'");
                endLine();
            }
        }

        override void visit(Asn1SequenceOfTypeIr ir)
        {
            this.decodePrimitive();

            // This doesn't decode into anything - it's just for validation.
            with(code)
            {
                putLine(
                    "result = this.", typeOfOverride.length > 0 ? typeOfOverride : fieldName, 
                    ".foreachElementAuto((element) => ", RESULT_TYPE, ".noError", ");"
                );
                putResultCheck("decoding subelements of SEQEUENCE OF field '"~fieldName~"'");
                endLine();
            }
        }

        private void decodePrimitive()
        {
            string memoryVar = memoryVarOverride;
            
            with(code)
            {
                this.decodeTags(memoryVar);

                putLine(
                    "typeof(", 
                        fixName(typeOfOverride.length > 0 ? typeOfOverride : fieldName), 
                    ") temp_", fixName(fieldName), ";"
                );
                putLine(
                    "result = typeof(temp_", fixName(fieldName), 
                    ").fromDecoding!", DECODER_PARAM_RULESET, "(",
                        memoryVar, ", ",
                        "temp_", fixName(fieldName), ", ",
                        DECODER_VAR_HEADER, ".identifier",
                    ");"
                );
                putResultCheck("decoding field '"~fieldName~"'");
                putLine("result = this.", setterName, "(temp_", fixName(fieldName), ");");
                putResultCheck("setting field '"~fieldName~"'");
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
                        putResultCheck("decoding header of field '"~fieldName~"'");

                        putLine(
                            "result = ", ASN1_SHORTHAND, ".asn1ReadContentBytes(",
                                initialMemoryVar, ", ",
                                DECODER_VAR_HEADER, ".length, ",
                                memoryVar,
                            ");"
                        );
                        putResultCheck("reading content bytes of field '"~fieldName~"'");

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
    fieldName = fixName(fieldName);
    memoryVarOverride = fixName(memoryVarOverride);

    scope visitor = new DecoderVisitor();
    fieldType.visitGC(visitor);
}

private string rawTypeOf(Asn1TypeIr ir, Asn1ModuleIr currentModule, Asn1ErrorHandler errors)
{
    string result;

    final class Visitor : Asn1IrVisitorGC
    {
        override void visit(Asn1BooleanTypeIr ir) { result = ASN1_SHORTHAND~".Asn1Bool"; }
        override void visit(Asn1BitStringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1BitString"; }
        override void visit(Asn1ObjectIdentifierTypeIr ir) { result = ASN1_SHORTHAND~".Asn1ObjectIdentifier"; }
        override void visit(Asn1OctetStringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1OctetString"; }
        override void visit(Asn1SetOfTypeIr ir) { result = ASN1_SHORTHAND~".Asn1SetOf!("~rawTypeOf(ir.getTypeOfItems(), currentModule, errors)~")"; } // @suppress(dscanner.style.long_line)
        override void visit(Asn1SequenceOfTypeIr ir) { result = ASN1_SHORTHAND~".Asn1SequenceOf!("~rawTypeOf(ir.getTypeOfItems(), currentModule, errors)~")"; } // @suppress(dscanner.style.long_line)
        override void visit(Asn1IntegerTypeIr ir) { result = ASN1_SHORTHAND~".Asn1Integer"; }
        override void visit(Asn1UTF8StringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1Utf8String"; }
        override void visit(Asn1PrintableStringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1PrintableString"; }
        override void visit(Asn1NumericStringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1NumericString"; }
        override void visit(Asn1IA5StringTypeIr ir) { result = ASN1_SHORTHAND~".Asn1Ia5String"; }
        override void visit(Asn1UtcTimeTypeIr ir) { result = ASN1_SHORTHAND~".Asn1UtcTime"; }

        override void visit(Asn1TypeReferenceIr ir)
        {
            import juptune.data.asn1.lang.operations : asn1GetParentModule;

            auto parentModIr = asn1GetParentModule(ir.getResolvedType());

            if(isIntrinsicAnyType(ir))
                result = ASN1_SHORTHAND~".Asn1OctetString";
            else if (parentModIr is currentModule)
                result = fixName("."~ir.typeRef);
            else
            {
                result = fixName(
                    getModuleDlangIdentifier(parentModIr.getModuleName(), parentModIr.getModuleVersion(), errors)
                    ~ "."
                    ~ ir.typeRef
                );
            }
        }
        override void visit(Asn1TaggedTypeIr ir) => ir.getUnderlyingTypeSkipTags().visitGC(this);
    }

    scope visitor = new Visitor();
    ir.visitGC(visitor);

    return result;
}

private string asCamelCase(string prefix, const(char)[] irName)
{
    import std.ascii : toUpper;
    return fixName(prefix ~ irName[0].toUpper ~ irName[1..$]);
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

private string fixName(scope const char[] name)
{
    import std.exception : assumeUnique;

    char[] result;
    result.reserve(name.length);

    for(size_t i = 0; i < name.length; i++)
    {
        if(name[i] != '-')
        {
            result ~= name[i];
            continue;
        }

        i++;
        result ~= '_';
        result ~= name[i];
    }

    return result.assumeUnique;
}

private bool isIntrinsicAnyType(Asn1TypeReferenceIr ir)
{
    // TODO: Add an extra check to ensure the type is from the intrinsics module - IR tree needs parent info first though (or at least module info).
    return ir.typeRef == INTRINSIC_ANY_NAME;
}