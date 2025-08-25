/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.util.result;

import core.attribute : mustuse;
import juptune.core.ds : String, String2;

import std.traits : getUDAs;
alias InheritResults(alias Symbol) = getUDAs!(Symbol, Result);

@mustuse
struct Result // @suppress(dscanner.suspicious.incomplete_operator_overloading)
{
    import std.traits : Unqual;

    int             errorCode;
    TypeInfo_Enum   errorType;
    string          error;
    String2         context;
    string          file;
    string          module_;
    string          function_;
    size_t          line;

    void toString(OutputRange)(auto ref OutputRange range) const @trusted
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
        range.put("Type:     "); range.put(this.errorType.name); range.put("\n");
        range.put("Error:    "); range.put(this.error);

        if(this.context.length)
        {
            range.put("\n");
            range.put(this.context.sliceMaybeFromStack);
        }
    }

    @nogc nothrow @safe:

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

    bool opEquals()(scope auto ref Result other) const @nogc nothrow
    {
        return 
            this.errorType is other.errorType
            && this.errorCode == other.errorCode
        ;
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
        string error    = null, 
        String2 context = String2.init
    ) 
    {
        auto r = Result.noError;

        r.errorCode = errorCode;
        r.errorType = typeid(Unqual!T); 
        r.error     = error;
        r.context   = context;

        r.file      = FILE;
        r.module_   = MODULE;
        r.function_ = FUNCTION;
        r.line      = LINE;

        return r;
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
        string error, 
        String context
    ) @trusted
    {
        auto r = Result.noError;

        r.errorCode = errorCode;
        r.errorType = typeid(Unqual!T); 
        r.error     = error;
        r.context   = String2(context.slice);

        r.file      = FILE;
        r.module_   = MODULE;
        r.function_ = FUNCTION;
        r.line      = LINE;

        return r;
    }

    bool isError()
    {
        return this.errorType !is null;
    }

    bool isError(T)(T value)
    {
        return this.isErrorType!T && this.errorCode == cast(int)value;
    }

    bool isErrorType(T)()
    {
        return this.errorType is typeid(Unqual!T);
    }

    void changeErrorType(T)(T errorCode)
    {
        this.errorCode = errorCode;
        this.errorType = typeid(Unqual!T); 
    }

    Result wrapError(string newError) @trusted
    {
        Result r = this;
        r.context = String2(r.error, " ", r.context.sliceMaybeFromStack);
        r.error = newError;
        return r;
    }

    // Allows if(auto result = ...) { onError }
    bool opCast(T)() // @suppress(dscanner.suspicious.object_const)
    if (is(T == bool)) => this.isError;
}

template then(Funcs...)
{
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

void resultAssert(Result result) @nogc nothrow
{
    if(!result.isError)
        return;

    // Quirk: Assert seems to hold onto the string slice longer than it should do,
    //        so we have to destroy the string without actually calling the destructor.
    import std.algorithm : moveEmplace;

    String s;
    result.toString(s);

    String s2;
    auto slice = s[];
    moveEmplace(s2, s);
    
    assert(false, slice);
}

version(unittest) void resultAssertSameCode(ExpectedErrorT)(Result got, Result expected) @nogc nothrow
in(got.isError && expected.isError, "Both results must be errors")
{
    import juptune.core.ds   : Array, String;
    import juptune.core.util : toStringSink;

    if(got.errorCode != expected.errorCode || got.errorType !is expected.errorType)
    {
        Array!char msg;
        msg.put("Result mismatch!\n");
        
        msg.put("  Got: ");
        if(got.isErrorType!ExpectedErrorT)
            (cast(ExpectedErrorT)got.errorCode).toStringSink(msg);
        else
            got.errorCode.toStringSink(msg);
        msg.put(" of type ");
        msg.put(got.errorType.name);
        
        msg.put("\n  Wanted: ");
        if(expected.isErrorType!ExpectedErrorT)
            (cast(ExpectedErrorT)expected.errorCode).toStringSink(msg);
        else
            expected.errorCode.toStringSink(msg);
        msg.put(" of type ");
        msg.put(expected.errorType.name);

        // Since this function is only ever used in unittests, we can bypass the global @nogc of this module.
        debug assert(false, "" ~ msg.slice);
    }
}

/++++ @gc helpers ++++/

final class JuptuneResultException : Exception
{
    import std.exception : basicExceptionCtors;

    Result result = Result.noError;

    mixin basicExceptionCtors;
}

void resultEnforce(Result result)
{
    import std.array        : Appender;
    import std.exception    : assumeUnique;

    if(!result.isError)
        return;

    Appender!(char[]) buffer;
    result.toString(buffer);
    
    auto exception = new JuptuneResultException(buffer.data.assumeUnique);
    exception.result = result;
    throw exception;
}