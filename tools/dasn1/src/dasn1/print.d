/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.print;

import std.file : FileException;
import std.stdio : writeln;
import std.getopt;

import juptune.core.util : resultEnforce, JuptuneResultException;
import juptune.data.asn1.lang : Asn1PrinterVisitor, Asn1StringPrinterHandler;

import dasn1.context : CompilerContext;

int printCommand(string[] args)
{
    bool noSemantics;

    auto helpInfo = args.getopt(
        "no-semantics", "Disable (most) semantics analysis. Only performs syntax parsing.", &noSemantics,
    );

    if(helpInfo.helpWanted)
    {
        defaultGetoptPrinter(
            "Usage: print [file/dir]...\n",
            helpInfo.options
        );
        return 0;
    }

    bool wereErrors;
    try
    {
        auto context = new CompilerContext();
        context.addFromInputArgs(args[1..$]);
        context.doSyntaxAnalysis();
        if(!noSemantics)
            context.doSemanticAnalysis();

        scope handler = new Asn1StringPrinterHandler();
        scope visitor = new Asn1PrinterVisitor(handler);
        foreach(source; context.sources)
        {
            handler.putInLine("-- FOR: ");
            handler.putInLine(source.debugName);
            handler.endLine();
            source.moduleIr.visit(visitor).resultEnforce;
            handler.endLine();
            wereErrors = wereErrors || source.errors.wasCalled;
        }

        writeln(handler.buffer.slice);
    }
    catch(FileException exec)
    {
        writeln("failed to read file: ", exec.msg);
        return 1;
    }
    catch(JuptuneResultException exec)
    {
        // TODO: Handle results directly instead of using resultEnforce, otherwise it's really hard
        //       to create consistent looking error messages.
        writeln(exec.msg);
        return 1;
    }

    return wereErrors ? 1 : 0;
}