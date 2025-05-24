int main(string[] args)
{
    import juptune.core.util.result,
           juptune.data.asn1.lang.ast, 
           juptune.data.asn1.lang.ast2ir,
           juptune.data.asn1.lang.common,
           juptune.data.asn1.lang.lexer,
           juptune.data.asn1.lang.parser,
           juptune.data.asn1.lang.ir,
           juptune.data.asn1.lang.typecheck,
           dasn1.generator;

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
    asn1AstToIr(modDef, modIr, context, Asn1NullSemanticErrorHandler.instance).resultEnforce;

    import std.file : write;
    auto test = generateD(modIr, GeneratorInput(["foo", "bar"]));

    write("test_model.d", test.modelFile.data);
    write("test_package.d", test.packageFile.data);
    write("test_bcd.d", test.bcdDecoderFile.data);

    return 0;
}