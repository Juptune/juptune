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
        return Result.error(CheckedError.overflow);
    result = a + b;
    return Result.ok;
}