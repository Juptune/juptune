/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.util.result;

import core.attribute : mustuse;
import juptune.core.ds.string;

@nogc nothrow:

import std.traits : getUDAs;
alias InheritResults(alias Symbol) = getUDAs!(Symbol, Result);

@mustuse
struct Result
{
    int    errorCode;
    string errorType;
    string error;
    String context;
    string file;
    string module_;
    string function_;
    size_t line;

    void toString(OutputRange)(auto ref OutputRange range) const
    {
        import juptune.core.util.conv;

        range.put("=========================\n");
        range.put("| RESULT INFORMATION    |\n");
        range.put("=========================\n");
        range.put("File:     "); range.put(this.file); range.put("\n");
        range.put("Module:   "); range.put(this.module_); range.put("\n");
        range.put("Function: "); range.put(this.function_); range.put("\n");
        range.put("Line:     "); toStringSink(this.line, range); range.put("\n");
        range.put("-------------------------\n");
        range.put("Code:     "); toStringSink(this.errorCode, range); range.put("\n");
        range.put("Type:     "); range.put(this.errorType); range.put("\n");
        range.put("Error:    "); range.put(this.error);

        if(this.context.length)
        {
            range.put("\n");
            range.put(this.context.slice);
        }
    }

    @nogc nothrow @safe:

    /// For UDAs only please.
    this(T)(T errorCode)if(!is(T == typeof(this))){ this.errorCode = errorCode; this.errorType = __traits(identifier, T); } // @suppress(dscanner.style.long_line)
    @disable this();

    this(ref return Result other) 
    {
        this.errorCode = other.errorCode;
        this.errorType = other.errorType;
        this.error     = other.error;
        this.context   = other.context;
        this.file      = other.file;
        this.module_   = other.module_;
        this.function_ = other.function_;
        this.line      = other.line;
    }

    void opAssign(T)(auto ref T other)
    {
        this.errorCode = other.errorCode;
        this.errorType = other.errorType;
        this.error     = other.error;
        this.context   = other.context;
        this.file      = other.file;
        this.module_   = other.module_;
        this.function_ = other.function_;
        this.line      = other.line;
    }

    static Result noError()
    {
        return Result.init;
    }

    static Result make
    (
        T,
        string FILE     = __FILE__, 
        string MODULE   = __MODULE__, 
        string FUNCTION = __PRETTY_FUNCTION__,
        size_t LINE     = __LINE__
    )
    (
        T      errorCode, 
        string error   = null, 
        String context = String.init
    ) 
    {
        enum R { none }
        auto r = Result(R.none);

        r.errorCode = errorCode;
        r.errorType = __traits(identifier, T); 
        r.error     = error;
        r.context   = context;

        r.file      = FILE;
        r.module_   = MODULE;
        r.function_ = FUNCTION;
        r.line      = LINE;

        return r;
    }

    bool isError()
    {
        return this.errorType.length != 0;
    }

    bool isError(T)(T value)
    {
        return this.isErrorType!T && this.errorCode == cast(int)value;
    }

    bool isErrorType(T)()
    {
        return this.errorType == __traits(identifier, T);
    }

    void changeErrorType(T)(T errorCode)
    {
        this.errorCode = errorCode;
        this.errorType = __traits(identifier, T); 
    }
}

template then(Funcs...)
{
    @nogc nothrow
    Result then()(scope auto ref Result _this)
    {
        if(_this.isError)
            return _this;

        Result result = Result.noError;
        static foreach(next; Funcs)
        {
            result = next();
            if(result.isError)
                return result;
        }

        return result;
    }
}

@("Result - copyable")
unittest
{
    enum E
    {
        e
    }

    auto r = Result.make(E.e, "abc", String("123"));
    auto r2 = r;
    assert(r == r2);
}

void resultAssert(Result result)
{
    if(!result.isError)
        return;

    String s;
    result.toString(s);
    assert(false, s.slice);
}