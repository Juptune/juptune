module dasn1.generator;

import dasn1.builder : StringBuilder;

import juptune.core.util : Result, resultEnforce;
import juptune.data.asn1.lang.ir; // Intentionally everything

struct GeneratorInput
{
    string[] moduleComponents; // e.g. ["foo", "bar"] -> module foo.bar.model;
}

final class GeneratorContext // I want reference semantics, so may as well make it a class
{
    // File builders
    StringBuilder modelFile;
    StringBuilder bcdDecoderFile;
    StringBuilder packageFile;

    // Sub builders
    StringBuilder modelTypeBuilder;

    this()
    {
        this.modelFile = new StringBuilder();
        this.bcdDecoderFile = new StringBuilder();
        this.packageFile = new StringBuilder();
        this.modelTypeBuilder = new StringBuilder();
    }
}

GeneratorContext generateD(Asn1ModuleIr ir, GeneratorInput input)
{
    auto context = new GeneratorContext();

    // Add module statements
    void addModuleStatement(StringBuilder builder)
    {
        builder.put("module ");
        foreach(i, component; input.moduleComponents)
        {
            if(i != 0)
                builder.put(".");
            builder.put(component);
        }
    }

    addModuleStatement(context.packageFile);
    context.packageFile.put(";\n");

    addModuleStatement(context.bcdDecoderFile);
    context.bcdDecoderFile.put(".decoder;\n");

    addModuleStatement(context.modelFile);
    context.modelFile.put(".model;\n");

    // Add imports
    context.modelFile.put("import std.typecons : Nullable;\n");

    // Handle assignments
    ir.foreachAssignmentGC((assIr){
        if(auto typeAss = cast(Asn1TypeAssignmentIr)assIr)
        {
            generateD(typeAss, 0, input, context);
            return Result.noError;
        }
        
        assert(false, "bug: Unhandled assignment type?");
    }).resultEnforce;

    return context;
}

/++++ Types & TypeAssignment ++++/

private final class TypeVisitor : Asn1IrVisitorGC
{
    import std.meta : AliasSeq;
    
    const(char)[] symbolName;
    uint nestingDepth;
    GeneratorInput input;
    GeneratorContext context;

    this(
        const(char)[] symbolName,
        uint nestingDepth, 
        GeneratorInput input, 
        GeneratorContext context
    )
    {
        this.symbolName = symbolName;
        this.nestingDepth = nestingDepth;
        this.input = input;
        this.context = context;
    }

    static foreach(IrT; AliasSeq!(
        Asn1BooleanTypeIr,
        Asn1SequenceTypeIr
    ))
    override void visit(IrT typeIr)
    {
        generateD(this.symbolName, typeIr, this.nestingDepth, this.input, this.context);
    }
}

void generateD(
    Asn1TypeAssignmentIr ir, 
    uint nestingDepth,
    GeneratorInput input, 
    GeneratorContext context,
)
{
    scope visitor = new TypeVisitor(ir.getSymbolName(), nestingDepth, input, context);
    ir.getSymbolType().visitGC(visitor);
}

void generateD(
    const(char)[] typeName,
    Asn1BooleanTypeIr typeIr,
    uint nestingDepth,
    GeneratorInput input, 
    GeneratorContext context,
)
{
    with(context.modelTypeBuilder)
    {
        put("struct ");
        put(typeName);
        put("\n{\n");
        indent();

        put("bool value;\n");
        put("alias value this;\n");

        dedent();
        put("}\n");
    }

    if(nestingDepth == 0)
    {
        context.modelFile.put(context.modelTypeBuilder.data);
        context.modelTypeBuilder.clear();
    }
}

void generateD(IrT)(
    const(char)[] typeName,
    IrT typeIr,
    uint nestingDepth,
    GeneratorInput input, 
    GeneratorContext context,
)
if(is(IrT == Asn1SequenceTypeIr) || is(IrT == Asn1SetTypeIr))
{
    with(context.modelTypeBuilder)
    {
        final class Visitor : Asn1IrVisitorGC
        {
            override void visit(Asn1TypeReferenceIr ir)
            {
                assert(ir.moduleRef.length == 0, "TODO: add moduleref support");
                put(ir.typeRef);
            }

            override void visit(Asn1BooleanTypeIr ir) => put("bool");
        }

        put(nestingDepth > 0 ? "static struct " : "struct ");
        put(typeName);
        put("\n{\n");
        indent();

        typeIr.foreachComponentGC((comp){
            assert(comp.defaultValue is null, "TODO: support default values");
            assert(!comp.isComponentsOf, "TODO: support COMPONENTS OF");

            if(auto ir = cast(Asn1SequenceTypeIr)comp.type)
            {
                generateD(comp.name~"_t", ir, nestingDepth+1, input, context);
                if(comp.isOptional)
                    put("Nullable!");
                put(comp.name);
                put("_t ");
                put(comp.name);
                put(";\n");
                return Result.noError;
            }
            else if(auto ir = cast(Asn1SetTypeIr)comp.type)
            {
                generateD(comp.name~"_t", ir, nestingDepth+1, input, context);
                if(comp.isOptional)
                    put("Nullable!");
                put(comp.name);
                put("_t ");
                put(comp.name);
                put(";\n");
                return Result.noError;
            }
            // End of special cases

            if(comp.isOptional)
                put("Nullable!");
            
            scope typeNameVisitor = new Visitor();
            comp.type.visitGC(typeNameVisitor);
            put(" ");
            put(comp.name);
            put(";\n");
            return Result.noError;
        }).resultEnforce;

        dedent();
        put("}\n");
    }

    if(nestingDepth == 0)
    {
        context.modelFile.put(context.modelTypeBuilder.data);
        context.modelTypeBuilder.clear();
    }
}

unittest
{
    import juptune.data.asn1.lang.ast, 
           juptune.data.asn1.lang.ast2ir,
           juptune.data.asn1.lang.common,
           juptune.data.asn1.lang.lexer,
           juptune.data.asn1.lang.parser,
           juptune.data.asn1.lang.typecheck;

    const code = `
MyModule DEFINITIONS ::= BEGIN
    MyB ::= BOOLEAN
    MyS ::= SEQUENCE {
        b MyB OPTIONAL,
        otherB BOOLEAN,
        s SET {
            a MyB,
            b BOOLEAN
        }
    }
END
`;

    Asn1ParserContext context;
    auto lexer = Asn1Lexer(code);
    auto parser = Asn1Parser(lexer, &context);
    
    Asn1ModuleDefinitionNode modDef;
    parser.ModuleDefinition(modDef).resultEnforce;

    Asn1ModuleIr modIr;
    asn1AstToIr(modDef, modIr, context, Asn1NullSemanticErrorHandler.instance).resultEnforce;
    modIr.doSemanticStage(
        Asn1BaseIr.SemanticStageBit.resolveReferences,
        (_) => Asn1ModuleIr.LookupItemT.init,
        context,
        Asn1BaseIr.SemanticInfo()
    ).resultEnforce;
    modIr.doSemanticStage(
        Asn1BaseIr.SemanticStageBit.implicitMutations,
        (_) => Asn1ModuleIr.LookupItemT.init,
        context,
        Asn1BaseIr.SemanticInfo()
    ).resultEnforce;

    import std.file : write;
    auto test = generateD(modIr, GeneratorInput(["foo", "bar"]));

    write("test_model.d", test.modelFile.data);
    write("test_package.d", test.packageFile.data);
    write("test_bcd.d", test.bcdDecoderFile.data);
}