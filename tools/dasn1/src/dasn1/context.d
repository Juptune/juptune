/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.context;

import std.sumtype : SumType, match;

import juptune.core.util : resultEnforce;

import dasn1.errors : DefaultErrorHandler;

struct Source
{
    import juptune.data.asn1.lang : Asn1ModuleIr;

    string debugName;
    string code;
    DefaultErrorHandler errors;
    Asn1ModuleIr moduleIr; // May be null if parsing hasn't ran yet.
}

final class CompilerContext
{
    import juptune.data.asn1.lang : Asn1ParserContext, Asn1ModuleRegistry;

    private
    {
        Asn1ModuleRegistry _registry;
        Asn1ParserContext  _context;
        Source[]           _sources;
    }

    this()
    {
        this._registry = new Asn1ModuleRegistry();
    }

    void addFromInputArgs(string[] args)
    {
        import std.file : isFile, dirEntries, SpanMode;

        foreach(arg; args)
        {
            if(isFile(arg))
            {
                this.addFile(arg);
                continue;
            }

            foreach(entry; dirEntries(arg, "*.asn1", SpanMode.breadth))
                this.addFile(entry.name);
        }
    }

    void addRawCode(string debugName, string code)
    {
        this._sources ~= Source(debugName, code, new DefaultErrorHandler(debugName, code));
    }

    void addFile(string path)
    {
        import std.file : readText;
        auto code = readText(path);
        this._sources ~= Source(path, code, new DefaultErrorHandler(path, code));
    }

    void doSyntaxAnalysis()
    {
        import std.algorithm : filter;
        import juptune.data.asn1.lang : asn1Parse;

        foreach(ref source; this._sources.filter!(s => s.moduleIr is null))
        {
            asn1Parse(this._context, source.moduleIr, source.code, source.errors).resultEnforce;
            this._registry.register(source.moduleIr, source.errors).resultEnforce;
        }
    }

    void doSemanticAnalysis()
    {
        import std.algorithm : filter;
        import juptune.data.asn1.lang : asn1Semantics;

        foreach(ref source; this._sources.filter!(s => s.moduleIr !is null))
            asn1Semantics(this._context, source.moduleIr, source.errors).resultEnforce;
    }

    Source[] sources()
    {
        return this._sources;
    }
}