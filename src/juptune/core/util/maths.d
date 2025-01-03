module juptune.core.util.maths;

import std.traits : isUnsigned;
import juptune.core.util.result : Result;

/// A `Result` error enum.
enum CheckedError
{
    none,
    overflow
}

Result checkedAdd(T)(T a, T b, out T result)
if(isUnsigned!T)
{
    if(a > (T.max - b))
        return Result.make(CheckedError.overflow, "overflow");
    result = a + b;
    return Result.noError;
}

Result checkedMul(T)(T a, T b, out T result)
if(isUnsigned!T)
{
    if(b > (T.max / a) + (T.max % a > 0 ? 1 : 0))
        return Result.make(CheckedError.overflow, "overflow");
    result = a * b;
    return Result.noError;
}