/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.context;

import std.sumtype : SumType, match;

import juptune.core.util        : resultEnforce;
import juptune.asn1.lang   : Asn1PrintfErrorHandler;

struct Source
{
    import juptune.asn1.lang : Asn1ModuleIr;

    string debugName;
    string code;
    Asn1ModuleIr moduleIr; // May be null if parsing hasn't ran yet.
    
    private bool _needsCodeGen = true;
}

final class CompilerContext
{
    import juptune.asn1.lang : Asn1ParserContext, Asn1ModuleRegistry;

    private
    {
        Asn1ModuleRegistry      _registry;
        Asn1ParserContext       _context;
        Source[]                _sources;
        Asn1PrintfErrorHandler  _errors;
    }

    this()
    {
        this._registry = new Asn1ModuleRegistry();
        this._errors = new Asn1PrintfErrorHandler();

        this.addIntrinsicCode("Dasn1-Intrinsics(dasn1/generator/context.d)", DASN1_INTRINSIC_MODULE);
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
        this._sources ~= Source(debugName, code);
    }

    private void addIntrinsicCode(string debugName, string code)
    {
        this._sources ~= Source(debugName, code);
        this._sources[$-1]._needsCodeGen = false;
    }

    void addFile(string path)
    {
        import std.file : readText;
        auto code = readText(path);
        this._sources ~= Source(path, code);
    }

    void doSyntaxAnalysis()
    {
        import std.algorithm : filter;
        import juptune.asn1.lang : asn1Parse;

        foreach(ref source; this._sources.filter!(s => s.moduleIr is null))
        {
            asn1Parse(this._context, source.moduleIr, source.code, this._errors, source.debugName).resultEnforce;
            this._registry.register(source.moduleIr, this._errors).resultEnforce;
        }
    }

    void doSemanticAnalysis()
    {
        import std.algorithm : filter;
        import juptune.asn1.lang : asn1Semantics;

        foreach(ref source; this._sources.filter!(s => s.moduleIr !is null))
            asn1Semantics(this._context, source.moduleIr, this._errors).resultEnforce;
    }

    bool wereErrors() => this._errors.wasCalled;
    size_t parserBytesAllocated() => this._context.bytesAllocated;

    // TODO: Maybe make this better.
    import std.algorithm : filter;
    import std.array : array;
    Source[] sources() => this._sources.filter!(s => s._needsCodeGen).array;
}

private immutable DASN1_INTRINSIC_MODULE = `
-- I can't find a single piece of information on what's allowed for custom OBJECT IDENTIFIERS, so I'll
-- just start everything with 0 0
--
-- NOTE: Most of these intrinsics are super hacky, so please don't expect a good debugging experience using them (for now at least).
Dasn1-Intrinsics { iso(0) custom(0) dasn1(1) intrinsics(0) } DEFINITIONS IMPLICIT TAGS ::=
BEGIN
    EXPORTS ALL;

    -- Use of this instrinsic value will cause dasn1 to allow any tag for the field.
    --
    -- Currently you should always use this type directly, and never define an alias to it (implementation limitations):
    --
    -- '
    --      /* BAD */
    --      MyType ::= Dasn1-Any
    --      MySeq ::= SEQUENCE { yada MyType }
    --
    --      /* GOOD */
    --      MySeq ::= SEQUENCE { yada Dasn1-Any }
    -- '
    Dasn1-Any ::= OCTET STRING

    -- Use of this instrinsic value will cause dasn1 to stuff the entire raw byte slice for a SEQUENCE/SET type into
    -- a special field.
    --
    -- This is useful if the raw encoding bytes are meaningful, e.g. x.509 uses part of the DER encoding to calculate
    -- the certificate's signature, so these bytes also need to be easily available to the code.
    --
    -- This should only ever be used inside of SEQUENCE and SET types; should always be the first field, and MUST always be defined as:
    -- '
    --      dasn1-RawBytes Dasn1-RawBytes OPTIONAL
    -- '
    --
    -- This is to simplify the extremely hacky implementation of this feature.
    Dasn1-RawBytes ::= OCTET STRING
END
`;