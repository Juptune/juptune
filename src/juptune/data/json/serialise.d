/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.json.serialise;

import std.traits : isInstanceOf;
import std.typecons : Nullable;

import juptune.core.util : Result;

import juptune.data.json.builder : JsonBuilder;
import juptune.data.json.parser : JsonParser;

/++
 + A UDA to be attached onto any fields of a type that is meant to be the target of JSON serialisation/deserialisation.
 +
 + ONLY fields with this UDA attached will be considered targets by (de)serialisation functions - even if only the type itself is attached 
 + attached as `@Json`
 +
 + This UDA only affects fields within a struct (e.g. attaching it onto a struct directly does nothing).
 + ++/
struct Json
{
    /// If non-empty, the value of this field is used as the name when serialising/deserialising.
    string name;

    /++
     + If true, then if the attached field is empty, it won't be written when serialising, and it will be set to
     + its `.init` value when deserialising a JSON value where the field is null/absent.
     +
     + (If setting the field to `.init` isn't able to compile for some reason, then the value of the field is undefined during deserilisation
     +  cases where this flag is relevant).
     +
     + A field is empty if it has a `.length` and it returns the value `0`.
     + ++/
    bool omitWhenEmpty;

    /++
     + Similar to `omitWhenEmpty`, except the omission only occurs if the field is null when serialising.
     +
     + A field is null if:
     +
     +  * It supports the `is null` syntax, and `is null` returns true.
     +  * It is a type with a `.isNull` field, and it returns true.
     + ++/
    bool omitWhenNull;
    
    /// If true, then `null` is written as a field's value if it would otherwise be omitted (see `omitWhenEmpty` and `omitWhenNull`)
    bool useNullForOmit;
}

/++ 
 + Resolves to the `@Json` UDA attached onto `Symbol`, or `typeof(null)` if `Symbol` doesn't have the `@Json` UDA attached to it.
 +
 + If the attached `Json` UDA has an empty `Json.name` field, then this field is set to the identifier of `Symbol`.
 +
 + If the attached `Json` UDA is just the _type_ `Json` (rather than an instantiation like `@Json()`), then `Json.init` will be used
 + as the UDA's value.
 + ++/
template JsonUdaOf(alias Symbol)
{
    static foreach(Uda; __traits(getAttributes, Symbol))
    {
        static if(__traits(compiles, typeof(Uda)) && is(typeof(Uda) == Json))
            enum FoundUda = Uda;
        else static if(is(Uda == Json))
            enum FoundUda = Json();
    }

    static if(__traits(compiles, FoundUda))
    {
        enum JsonUdaOf = (){
            Json uda = FoundUda;
            
            if(uda.name.length == 0)
                uda.name = __traits(identifier, Symbol);

            return uda;
        }();
    }
    else
        enum JsonUdaOf = null;
}

private bool isNullForOmit(ToSerialiseT)(scope auto ref ToSerialiseT toSerialise)
{
    static if(__traits(compiles, { bool b = toSerialise is null; }))
        return toSerialise is null;
    else static if(__traits(hasMember, ToSerialiseT, "isNull"))
        return toSerialise.isNull;

    return false;
}

private bool isEmptyForOmit(ToSerialiseT)(scope auto ref ToSerialiseT toSerialise)
{
    static if(__traits(compiles, { long length = toSerialise.length; }))
        return toSerialise.length == 0;

    return false;
}

/++ Serialisation ++/

/++
 + Serialises the given value into the provided json builder.
 +
 + Support:
 +  All primitive types supported by `JsonBuilder`.
 +
 +  Slices of any other supported type.
 +
 +  Structs, where fields are marked with `@Json` are subject to serialisation.
 +
 + Params:
 +  json        = An instance of some sort of `JsonBuilder`.
 +  toSerialise = The value to serialise into `json`.
 +
 + Throws:
 +  Anything that `JsonBuilder` can throw.
 +
 + Returns:
 +  An errorful `Result` if something went wrong.
 + ++/
Result jsonSerialise(ToSerialiseT, JsonBuilderT)(scope ref JsonBuilderT json, scope auto ref ToSerialiseT toSerialise)
if(isInstanceOf!(JsonBuilder, JsonBuilderT))
{
    return jsonSerialiseImpl!(ToSerialiseT, JsonBuilderT, Json())(json, toSerialise);
}

/// This overload allows you to manually provide a `Json` Uda to serialise the value with - useful for custom `toJson` functions.
Result jsonSerialise(Json Uda, ToSerialiseT, JsonBuilderT)(
    scope ref JsonBuilderT json, 
    scope auto ref ToSerialiseT toSerialise
)
if(isInstanceOf!(JsonBuilder, JsonBuilderT))
{
    return jsonSerialiseImpl!(ToSerialiseT, JsonBuilderT, Uda)(json, toSerialise);
}

// Overload for value types that are natively supported by JsonBuilder (and that we have no specific interest in processing differently).
private Result jsonSerialiseImpl(ToSerialiseT, JsonBuilderT, Json Uda)(
    scope ref JsonBuilderT json, 
    scope auto ref ToSerialiseT toSerialise
)
if(__traits(compiles, { auto _ = JsonBuilderT.init.putArrayValue(ToSerialiseT.init); }))
{
    return json.inObject
        ? json.putObjectValue(Uda.name, toSerialise)
        : json.putArrayValue(toSerialise);
}

// Overload for Nullable.
private Result jsonSerialiseImpl(ToSerialiseT, JsonBuilderT, Json Uda)(
    scope ref JsonBuilderT json, 
    scope auto ref ToSerialiseT toSerialise
)
if(is(ToSerialiseT == struct) && isInstanceOf!(Nullable, ToSerialiseT))
{
    if(toSerialise.isNull)
    {
        return json.inObject
            ? json.putObjectValue(Uda.name, null)
            : json.putArrayValue(null);
    }

    return jsonSerialiseImpl!(typeof(ToSerialiseT.get), JsonBuilderT, Uda)(json, toSerialise.get);
}

// Overload for structs.
private Result jsonSerialiseImpl(ToSerialiseT, JsonBuilderT, Json Uda)(
    scope ref JsonBuilderT json, 
    scope auto ref ToSerialiseT toSerialise
)
if(is(ToSerialiseT == struct) && !isInstanceOf!(Nullable, ToSerialiseT))
{
    auto result = json.startObject(Uda.name);
    if(result.isError)
        return result;

    static foreach(i, MemberField; toSerialise.tupleof)
    {{
        enum MemberUda = JsonUdaOf!MemberField;
        alias MemberT = typeof(MemberField);

        scope field = &toSerialise.tupleof[i];

        // MemberUda can be `null` if the field isn't marked with the @Json UDA, so ignore any that lack the marking.
        static if(!is(typeof(MemberUda) == typeof(null)))
        {
            bool omit = false;

            static if(MemberUda.omitWhenEmpty)
            if(isEmptyForOmit(*field))
                omit = true;

            static if(MemberUda.omitWhenNull)
            if(isNullForOmit(*field))
                omit = true;

            if(omit) // This _should_ get optimised out properly for fields that can't be omitted.
            {
                static if(MemberUda.useNullForOmit)
                {
                    result = json.putObjectValue(MemberUda.name, null);
                    if(result.isError)
                        return result;
                }
                else
                {
                    // Otherwise, we don't generate any output at all.
                }
            }
            else
            {
                result = jsonSerialiseImpl!(MemberT, JsonBuilderT, MemberUda)(json, *field);
                if(result.isError)
                    return result;
            }
        }
    }}

    return json.endObject();
}

// Overload for arrays (that don't look like strings).
private Result jsonSerialiseImpl(ToSerialiseT, JsonBuilderT, Json Uda)(
    scope ref JsonBuilderT json, 
    scope auto ref ToSerialiseT toSerialise
)
if(is(ToSerialiseT == ElementT[], ElementT) && !is(ToSerialiseT : const(char)[]))
{
    auto result = json.startArray(Uda.name);
    if(result.isError)
        return result;

    foreach(scope ref value; toSerialise)
    {
        result = jsonSerialise(json, value);
        if(result.isError)
            return result;
    }

    return json.endArray();
}

/++ Deserialisation ++/

/++ Unittests ++/

@("jsonSerialise - General success cases")
unittest
{
    import std.meta : AliasSeq;
    import std.typecons : Nullable;

    import juptune.core.util : resultAssert;

    static struct Case(string name_, TestT)
    {
        TestT input;
        string expected;
        string name = name_;
    }

    static struct SimpleWrapper(TestT)
    {
        @Json
        TestT v;
    }

    static struct OmitWhenEmptyWrapper(TestT)
    {
        @Json(omitWhenEmpty: true)
        TestT v;
    }

    static struct OmitWhenNullWrapper(TestT)
    {
        @Json(omitWhenNull: true)
        TestT v;
    }

    auto case_(string name, TestT)(TestT input, string expected) => Case!(name, TestT)(input, expected);
    auto simple(string name, TestT)(TestT input, string expected) => case_!name(SimpleWrapper!TestT(input), expected);
    auto omitWhenEmpty(string name, TestT)(TestT input, string expected) => case_!name(OmitWhenEmptyWrapper!TestT(input), expected); // @suppress(dscanner.style.long_line)
    auto omitWhenNull(string name, TestT)(TestT input, string expected) => case_!name(OmitWhenNullWrapper!TestT(input), expected); // @suppress(dscanner.style.long_line)

    alias Cases = AliasSeq!(
        simple!("boolean - true"        )(true,                 `{"v": true}`),
        simple!("boolean - false"       )(false,                `{"v": false}`),
        simple!("int - zero"            )(0,                    `{"v": 0}`),
        simple!("int - positive"        )(1,                    `{"v": 1}`),
        simple!("int - negative"        )(-1,                   `{"v": -1}`),
        simple!("string - null"         )(cast(string)null,     `{"v": ""}`),
        simple!("string - empty"        )("",                   `{"v": ""}`),
        simple!("string - non-empty"    )("foo",                `{"v": "foo"}`),
        simple!("nested struct"         )(SimpleWrapper!int(0), `{"v": {"v": 0}}`),
        simple!("array - empty"         )(cast(int[])[],        `{"v": []}`),
        simple!("array - null"          )(cast(int[])null,      `{"v": []}`),
        simple!("array - non-empty"     )([1, 2, 3],            `{"v": [1, 2, 3]}`),
        simple!("Nullable - null"       )(Nullable!int.init,    `{"v": null}`),

        simple!"array - nested struct"([
            SimpleWrapper!int(0),
            SimpleWrapper!int(1)
        ], `{"v": [{"v": 0}, {"v": 1}]}`),

        simple!"array - nested array"([
            [1, 2, 3],
            [],
            [3, 2, 1]
        ], `{"v": [[1, 2, 3], [], [3, 2, 1]]}`),

        omitWhenEmpty!"array - null"(cast(int[])null, `{}`),
        omitWhenEmpty!"string - empty"("", `{}`),
        omitWhenNull!"array - null"(cast(int[])null, `{}`),
        omitWhenNull!"Nullable - null"(Nullable!int.init, `{}`),
        omitWhenNull!"Nullable - not-null"(Nullable!int(0), `{"v": 0}`),
    );

    static foreach(TestCase; Cases)
    {
        try
        {
            import juptune.core.ds : Array;

            Array!char buffer;
            scope put = (scope const(char)[] slice) { buffer.put(slice); return Result.noError; };
            
            auto builder = JsonBuilder!(typeof(put))(put, new ubyte[8]);
            builder.jsonSerialise(TestCase.input).resultAssert;

            assert(buffer.slice == TestCase.expected, "Expected:\n---\n"~TestCase.expected~"\n---\nGot:\n---\n"~buffer.slice.idup); // @suppress(dscanner.style.long_line)
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~TestCase.name~"]: "~err.msg);
    }
}