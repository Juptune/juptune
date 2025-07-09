/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.compile;

import std.algorithm : splitter;
import std.array : array;
import std.file : FileException, mkdirRecurse, writeFile = write;
import std.stdio : writeln;
import std.path : buildNormalizedPath, setExtension;
import std.getopt;

import juptune.core.util : resultEnforce, JuptuneResultException;
import juptune.data.asn1.lang : Asn1SemanticError, Asn1ParserError, Asn1LexerError, Asn1AlwaysCrashErrorHandler;

import dasn1.context : CompilerContext;
import dasn1.generator.dlang;
import std.regex; // Intentionally everything

int compileDlangRawCommand(string[] args)
{
    DlangGeneratorContext generatorContext;
    string outDir;
    string baseModule;
    bool makeDirs;

    auto helpInfo = args.getopt(
        "out-dir",
            "The root directory to generate files into.", 
            &outDir,
        "base-module",
            "The base D module name. This will affect the subdirectories created, as well as the generated `module` statements.", // @suppress(dscanner.style.long_line)
            &baseModule,
        "make-dirs",
            "If specified, then dasn1 will generate subdirectories corresponding to the D full module name.",
            &makeDirs,
    );

    if(helpInfo.helpWanted)
    {
        defaultGetoptPrinter(
            "Usage: compile dlang-raw [flags] <file/dir>...\n",
            helpInfo.options
        );
        return 1;
    }
    
    generatorContext.baseModuleComponents = baseModule.splitter('.').array ~ "raw";

    try
    {
        if(makeDirs)
        {
            mkdirRecurse(buildNormalizedPath(
                outDir
                ~ generatorContext.baseModuleComponents
            ));
        }

        auto context = new CompilerContext();
        context.addFromInputArgs(args[1..$]);
        context.doSyntaxAnalysis();
        context.doSemanticAnalysis();

        if(context.wereErrors)
        {
            writeln("error: at least one error was produced, aborting");
            return 1;
        }

        foreach(source; context.sources)
        {
            auto code = generateRawDlangModule(source.moduleIr, generatorContext);
            writeFile(
                buildNormalizedPath(
                    outDir
                    ~ (makeDirs ? generatorContext.baseModuleComponents : [])
                    ~ getModuleDlangIdentifier(
                        source.moduleIr.getModuleName(),
                        source.moduleIr.getModuleVersion(),
                        Asn1AlwaysCrashErrorHandler.instance,
                    ).setExtension(".d")
                ),
                code
            );
        }

        return 0;
    }
    catch(FileException exec)
    {
        writeln("file error: ", exec.msg);
        return 1;
    }
    catch(JuptuneResultException exec)
    {
        if(
            exec.result.isErrorType!Asn1SemanticError
            || exec.result.isErrorType!Asn1ParserError
            || exec.result.isErrorType!Asn1LexerError
        )
        {
            // do nothing - the error handler should've been called.
        }
        else
            writeln("error: ", exec.msg);

        return 1;
    }
}