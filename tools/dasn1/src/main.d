int main(string[] args)
{
    // This is just insanely rough, prototype-level code to get
    // something very very basic working.
    import juptune.core.util.result,
           juptune.data.asn1.lang.ast, 
           juptune.data.asn1.lang.ast2ir,
           juptune.data.asn1.lang.common,
           juptune.data.asn1.lang.lexer,
           juptune.data.asn1.lang.parser,
           juptune.data.asn1.lang.ir,
           juptune.data.asn1.lang.typecheck,
           dasn1.generator;

    final static class Asn1PrototypeErrorHandler : Asn1SemanticErrorHandler
    {
        import core.stdc.stdio : printf;

        @nogc nothrow:

        uint indentLevel;

        override void startLine(Asn1Location location)
        {
            printf("[%lld..%lld]: ", location.start, location.end);
            foreach(i; 0..this.indentLevel)
                printf("  ");
        }

        override void putInLine(scope const(char)[] slice)
        {
            printf("%.*s", cast(uint)slice.length, slice.ptr);
        }

        override void endLine()
        {
            printf("\n");
        }

        override void indent() { this.indentLevel++; }
        override void dedent() { this.indentLevel--; }
    }

    import std.stdio : writeln;

    if(args.length != 2)
    {
        writeln("Expected 1 argument, which is the path to the ASN.1 notation file");
        return 1;
    }

    import std.file : readText;
    const code = readText(args[1]);

    Asn1ParserContext context;
    auto lexer = Asn1Lexer(code);
    auto parser = Asn1Parser(lexer, &context);
    
    Asn1ModuleDefinitionNode modDef;
    parser.ModuleDefinition(modDef).resultEnforce;

    Asn1ModuleIr modIr;
    asn1AstToIr(modDef, modIr, context, new Asn1PrototypeErrorHandler()).resultEnforce;
    foreach(semanticStage; [
        Asn1BaseIr.SemanticStageBit.resolveReferences,
        Asn1BaseIr.SemanticStageBit.implicitMutations,
    ])
    {
        modIr.doSemanticStage(
            semanticStage,
            (_) => Asn1ModuleIr.LookupItemT.init,
            context,
            Asn1BaseIr.SemanticInfo()
        ).resultEnforce;
    }

    auto visitor = new Asn1TypeCheckVisitor(new Asn1PrototypeErrorHandler());
    modIr.visit(visitor).resultEnforce;
    // TODO: I need to make an actual error handler, since errors right now will just be gobbled.

    import std.file : write;
    auto test = generateD(modIr, GeneratorInput(["foo", "bar"]));

    write("test_model.d", test.modelFile.data);
    write("test_package.d", test.packageFile.data);
    write("test_bcd.d", test.bcdDecoderFile.data);

    return 0;
}