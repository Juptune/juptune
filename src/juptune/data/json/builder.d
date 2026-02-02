/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.json.builder;

import std.range : isOutputRange;

import juptune.core.util : Result;

/// A `Result` error enum.
enum JsonBuilderError
{
    none,

    tooDeep,    /// Attempted to start an object or array, but the depth buffer has been completely used up.
    noDepth,    /// Attempted to use an object or array function, but the depth buffer was empty.
    wrongDepth, /// Attempted to call an object-specific function when the current depth is an array, or vice-versa.
    incomplete, /// Attempted to call `JsonBuild.finish` when the depth buffer isn't empty.
}

/++
 + A lowish-level builder for writing JSON output to a sink.
 +
 + Depth:
 +  This struct does not allocate memory, so in order to keep track of whether the builder is inside
 +  an object or array, the caller must provide a depth buffer.
 +
 +  Each byte in the buffer allows for 8 levels of depth, so an 8 byte buffer would allow for a max of 64 levels of nesting.
 +
 + Values:
 +  The following types can be passed as values to the `putObjectValue` and `putArrayValue` functions:
 +
 +  `const(char)[]` for strings - strings will be ran through `juptune.data.utf8.utf8Validate`, and outputted as UTF-8.
 +
 +  `bool` - handled as you'd expect.
 +
 +  Any integer type - signed and unsigned are handled correctly.
 +
 +  Currently there's no support for floating point types due to the lack of a string converter for these types.
 +
 + Sink:
 +  The `SinkT` should be a type that matches the following: `Result delegate(scope const(char)[] text)`.
 +
 +  This type is templated in order to easily support the sink having whatever sleuth of attributes you desire.
 +  Most functions in this struct are templated so that the compiler can infer attributes.
 +
 +  You'll usually need to store the delegate inside a separate scope variable in order to use this
 +  struct under `@nogc` - e.g. `scope sink = delegate(scope const(char)[] text) { return Result.noError; }`.
 +
 + Limitations:
 +  This builder does not support outputting UTF-16 surrogate pairs, so some parsers may choke on the generated output
 +  if they follow the JSON RFC strictly.
 +
 +  This builder currently does not support pretty printing, largely due to lack of effort :D
 +
 +  This builder does not prevent certain common errors, such as ensuring object keys are unique. This is because 
 +  it's assumed stuff like this has been handled at a higher level before calling into the builder.
 + ++/
struct JsonBuilder(SinkT)
{
    import std.traits : isIntegral;

    private
    {
        enum BITS_PER_BYTE = 8;

        SinkT   _sink;
        ubyte[] _depthMarkers; // Each bit represents whether the depth was created by an object (0) or array (1)
        size_t  _depth;
        bool    _isFirstItem;
    }

    @disable this(this){} // To keep the internal arrays consistent

    /++
     + Constructs a new JSON builder using the given sink.
     +
     + Assertions:
     +  `sink` must not be null.
     +
     +  `depthMarkers` must have at least 1 byte.
     +
     + Params:
     +  sink            = The sink to write into.
     +  depthMarkers    = The depth buffer (see main comment for JsonBuilder).
     + ++/
    this(SinkT sink, ubyte[] depthMarkers) @safe @nogc nothrow
    in(sink !is null, "sink is null")
    in(depthMarkers.length > 0, "depthMarkers is empty - please provide at least 1 marker byte")
    {
        this._sink = sink;
        this._depthMarkers = depthMarkers;
    }

    /++
     + Starts a new object, using the given key if this object is nested inside another object.
     +
     + Params:
     +  keyIfInObject = The key to give the object, if it's being started within another object.
     +
     + Throws:
     +  `JsonBuilderError.tooDeep` if the depth buffer is full.
     +
     +  Anything that the provided sink can throw.
     +
     +  Anything that `juptune.data.utf8.utf8DecodeNext` can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result startObject()(scope const(char)[] keyIfInObject = "")
    {
        if(this._depth >= this._depthMarkers.length * BITS_PER_BYTE)
            return Result.make(JsonBuilderError.tooDeep, "Attempted to start an object, with a full depth buffer.");

        if(this._depth != 0)
        {
            if(!this._isFirstItem)
            {
                auto result = this._sink(", ");
                if(result.isError)
                    return result;
            }

            if(this.inObject)
            {
                auto result = this.put(keyIfInObject);
                if(result.isError)
                    return result;
                
                result = this._sink(": ");
                if(result.isError)
                    return result;
            }
        }

        const byteIndex = this._depth / 8;
        const bitIndex = this._depth % 8;
        this._depthMarkers[byteIndex] &= ~(1 << bitIndex);
        this._depth++;
        this._isFirstItem = true;

        return this._sink("{");
    }

    /++
     + Starts a new array, using the given key if this array is nested inside an object.
     +
     + Params:
     +  keyIfInObject = The key to give the array, if it's being started within an object.
     +
     + Throws:
     +  `JsonBuilderError.tooDeep` if the depth buffer is full.
     +
     +  Anything that the provided sink can throw.
     +
     +  Anything that `juptune.data.utf8.utf8DecodeNext` can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result startArray()(scope const(char)[] keyIfInObject = "")
    {
        if(this._depth >= this._depthMarkers.length * BITS_PER_BYTE)
            return Result.make(JsonBuilderError.tooDeep, "Attempted to start an array, with a full depth buffer.");

        if(this._depth != 0)
        {
            if(!this._isFirstItem)
            {
                auto result = this._sink(", ");
                if(result.isError)
                    return result;
            }
            
            if(this.inObject)
            {
                auto result = this.put(keyIfInObject);
                if(result.isError)
                    return result;
                
                result = this._sink(": ");
                if(result.isError)
                    return result;
            }
        }

        const byteIndex = this._depth / 8;
        const bitIndex = this._depth % 8;
        this._depthMarkers[byteIndex] |= (1 << bitIndex);
        this._depth++;
        this._isFirstItem = true;

        return this._sink("[");
    }

    /++
     + Ends the current object.
     +
     + Throws:
     +  `JsonBuilderError.noDepth` if the depth buffer is empty.
     +
     +  `JsonBuilderError.wrongDepth` if the latest depth was created by an object instead of an array.
     +
     +  Anything that the provided sink can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result endObject()()
    {
        if(this._depth == 0)
            return Result.make(JsonBuilderError.noDepth, "Attempted to end an object, with an empty depth buffer.");
        
        this._isFirstItem = false;
        this._depth--;
        const byteIndex = this._depth / 8;
        const bitIndex = this._depth % 8;

        if((this._depthMarkers[byteIndex] & (1 << bitIndex)) != 0)
            return Result.make(JsonBuilderError.wrongDepth, "Attempted to end an object, while the current depth is an array."); // @suppress(dscanner.style.long_line)

        return this._sink("}");
    }

    /++
     + Ends the current array.
     +
     + Throws:
     +  `JsonBuilderError.noDepth` if the depth buffer is empty.
     +
     +  `JsonBuilderError.wrongDepth` if the latest depth was created by an array instead of an object.
     +
     +  Anything that the provided sink can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result endArray()()
    {
        if(this._depth == 0)
            return Result.make(JsonBuilderError.noDepth, "Attempted to end an array, with an empty depth buffer.");
        
        this._isFirstItem = false;
        this._depth--;
        const byteIndex = this._depth / 8;
        const bitIndex = this._depth % 8;

        if((this._depthMarkers[byteIndex] & (1 << bitIndex)) == 0)
            return Result.make(JsonBuilderError.wrongDepth, "Attempted to end an array, while the current depth is an object."); // @suppress(dscanner.style.long_line)

        return this._sink("]");
    }

    /++
     + Selectively calls `endObject` or `endArray` depending on the latest value in the depth buffer.
     +
     + Notes:
     +  Prefer to use `endArray` and `endObject` directly. Only use this function if it's impractical
     +  for your code to know whether it's currently inside an array or object. This is to keep your
     +  code very explicit on what it's supposed to be doing.
     +
     + Throws:
     +  Anything `endObject` and `endArray` can throw.
     +
     + Returns:
     +  A `Result` indicating whether an error occurred or not.
     + ++/
    Result end()()
    {
        if(this._depth == 0)
            return Result.make(JsonBuilderError.noDepth, "Attempted to end an array or object, with an empty depth buffer."); // @suppress(dscanner.style.long_line)
        return this.inObject() ? this.endObject() : this.endArray();
    }

    /++
     + Checks whether the depth buffer is empty (i.e. the value can be considered "finished").
     +
     + Throws:
     +  `JsonBuilderError.incomplete` if the depth buffer isn't empty, indicating that there's missing
     +  calls to `end`, `endArray`, and `endObject`.
     +
     + Returns:
     +  A `Result` indicating whether the value can be considered "finished" or not.
     + ++/
    Result finish() @safe @nogc nothrow
    {
        if(this._depth != 0)
            return Result.make(JsonBuilderError.incomplete, "Depth buffer is not empty - JSON value is incomplete.");
        return Result.noError;
    }

    /++
     + Puts a value within the current array.
     +
     + Notes:
     +  Please see the main `JsonBuilder` comment for information on how `value` is handled.
     +
     + Params:
     +  value = The value to output.
     +
     + Throws:
     +  `JsonBuilderError.noDepth` if the depth buffer is empty.
     +
     +  `JsonBuilderError.wrongDepth` if the latest depth was created by an object instead of an array.
     +
     +  Anything that the provided sink can throw.
     +
     +  If `ItemT` is a string, then anything that `juptune.data.utf8.utf8DecodeNext` can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result putArrayValue(ItemT)(scope ItemT value)
    if(
        is(ItemT : const(char)[])
        || is(ItemT == bool)
        || isIntegral!ItemT
    )
    {
        if(this._depth == 0)
            return Result.make(JsonBuilderError.noDepth, "Attempted to put an array value while the depth buffer is empty."); // @suppress(dscanner.style.long_line)
        if(!this.inArray)
            return Result.make(JsonBuilderError.wrongDepth, "Attempted to put an array value while the current depth is an object."); // @suppress(dscanner.style.long_line)

        if(!this._isFirstItem)
        {
            auto result = this._sink(", ");
            if(result.isError)
                return result;
        }
        this._isFirstItem = false;

        return this.put(value);
    }

    /++
     + Puts a value with the specified key within the current object.
     +
     + Notes:
     +  Please see the main `JsonBuilder` comment for information on how `value` is handled.
     +
     + Params:
     +  key   = The key for the value.
     +  value = The value to output.
     +
     + Throws:
     +  `JsonBuilderError.noDepth` if the depth buffer is empty.
     +
     +  `JsonBuilderError.wrongDepth` if the latest depth was created by an array instead of an object.
     +
     +  Anything that the provided sink can throw.
     +
     +  Anything that `juptune.data.utf8.utf8DecodeNext` can throw.
     +
     + Returns:
     +  A `Result` indicating whether any errors occurred.
     + ++/
    Result putObjectValue(ItemT)(scope const(char)[] key, scope ItemT value)
    if(
        is(ItemT : const(char)[])
        || is(ItemT == bool)
        || isIntegral!ItemT
    )
    {
        if(this._depth == 0)
            return Result.make(JsonBuilderError.noDepth, "Attempted to put an object value while the depth buffer is empty."); // @suppress(dscanner.style.long_line)
        if(!this.inObject)
            return Result.make(JsonBuilderError.wrongDepth, "Attempted to put an object value while the current depth is an array."); // @suppress(dscanner.style.long_line)

        if(!this._isFirstItem)
        {
            auto result = this._sink(", ");
            if(result.isError)
                return result;
        }
        this._isFirstItem = false;

        auto result = this.put(key);
        if(result.isError)
            return result;

        result = this._sink(": ");
        if(result.isError)
            return result;

        return this.put(value);
    }

    bool inArray() @safe @nogc nothrow
    in(this._depth > 0, "depth buffer is empty")
    {
        const byteIndex = (this._depth - 1) / 8;
        const bitIndex  = (this._depth - 1) % 8;
        return (this._depthMarkers[byteIndex] & (1 << bitIndex)) != 0;
    }

    bool inObject() @safe @nogc nothrow
    in(this._depth > 0, "depth buffer is empty")
    {
        const byteIndex = (this._depth - 1) / 8;
        const bitIndex  = (this._depth - 1) % 8;
        return (this._depthMarkers[byteIndex] & (1 << bitIndex)) == 0;
    }

    private Result put()(scope const(char)[] str)
    {
        auto result = this._sink(`"`);
        if(result.isError)
            return result;

        size_t cursor;
        size_t start;

        Result flush()
        {
            import juptune.data.utf8 : utf8Validate;

            if(start >= cursor)
                return Result.noError;

            const slice = str[start..cursor];

            auto result = utf8Validate(slice);
            if(result.isError)
                return result;

            result = this._sink(slice);
            start = cursor + 1;
            return result;
        }

        while(cursor < str.length)
        {
            const ch = str[cursor];

            switch(ch)
            {
                // Using shorthand error handling syntax since conciseness matters more here.
                case '"': if(auto r = flush()) return r; else if(auto r = this._sink(`\"`)) return r; else { cursor++; break; }
                case '\\': if(auto r = flush()) return r; else if(auto r = this._sink(`\\`)) return r; else { cursor++; break; }
                case '/': if(auto r = flush()) return r; else if(auto r = this._sink(`\/`)) return r; else { cursor++; break; } // Reason #1000230 on why not to model anything after Javascript
                case '\b': if(auto r = flush()) return r; else if(auto r = this._sink(`\b`)) return r; else { cursor++; break; }
                case '\f': if(auto r = flush()) return r; else if(auto r = this._sink(`\f`)) return r; else { cursor++; break; }
                case '\n': if(auto r = flush()) return r; else if(auto r = this._sink(`\n`)) return r; else { cursor++; break; }
                case '\r': if(auto r = flush()) return r; else if(auto r = this._sink(`\r`)) return r; else { cursor++; break; }
                case '\t': if(auto r = flush()) return r; else if(auto r = this._sink(`\t`)) return r; else { cursor++; break; }

                default:
                    cursor++;
                    break; // No special handling needed - wait until we can flush an entire slice to the sink.
            }
        }

        result = flush();
        if(result.isError)
            return result;
        return this._sink(`"`);
    }

    private Result put(IntT)(IntT number)
    if(isIntegral!IntT)
    {
        import juptune.core.util : toBase10, IntToCharBuffer;

        IntToCharBuffer buffer;
        const slice = toBase10(number, buffer);
        return this._sink(slice);
    }

    private Result put()(bool bool_)
    {
        return bool_ ? this._sink("true") : this._sink("false");
    }

    private Result put()(typeof(null) _)
    {
        return this._sink("null");
    }
}

@("JsonBuilder - Example")
unittest
{
    import std.json          : parseJSON;
    import juptune.core.ds   : Array;
    import juptune.core.util : resultAssert;

    Array!char buffer;
    scope append = (scope const char[] ch){
        buffer.put(ch);
        return Result.noError;
    };
    ubyte[8] depth;
    auto json = JsonBuilder!(typeof(append))(append, depth[]);

    with(json)
    {
        startObject().resultAssert;
        
        putObjectValue("level", "ERROR").resultAssert;
        putObjectValue("isError", true).resultAssert;

        startObject("🎂 ⋆ 🍰  🎀  𝒹𝑒𝒷𝓊𝑔  🎀  🍰 ⋆ 🎂").resultAssert;
            putObjectValue("line", 20).resultAssert;
            putObjectValue("column", 50).resultAssert;
            startArray("module").resultAssert;
                putArrayValue("juptune").resultAssert;
                putArrayValue("json").resultAssert;
                putArrayValue("example").resultAssert;
            endArray().resultAssert;
        endObject().resultAssert;
        
        endObject().resultAssert;
    }

    parseJSON(buffer.slice);
}

// TODO: This really needs more exhaustive tests lol