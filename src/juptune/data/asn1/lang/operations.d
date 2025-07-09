/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// Contains useful functions that are needed by parts of this package, but
/// don't really have any other place to exist. User code may find these functions useful as well,
/// but the functions aren't tailored towards user code usage, so may be awkward to use.
module juptune.data.asn1.lang.operations;

import juptune.core.util                : Result;
import juptune.data.asn1.lang.common    : Asn1ErrorHandler;
import juptune.data.asn1.lang.ir        : Asn1TypeIr, Asn1ValueIr;

/++
 + Determines if the two IR nodes are valid OBJECT IDENTIFIER values, and are
 + functionally equal to eachother.
 +
 + Because there's a variety of nodes that can be used as a valid OBJECT IDENTIFIER value,
 + there's no singular location that feels best to place this logic, hence why it exists in this specific module.
 +
 + Notes:
 +  While this function does attempt to perform compile time checks to ensure IdIrA and IdIrB are valid types for this
 +  function; there are some checks that can only occur at runtime for otherwise valid IR types, hence why things like
 +  `typeMismatch` can be thrown.
 +
 + Valid forms:
 +  `Asn1ValueSequenceIr` - when there is only 1 value of type INTEGER: `{ 1 }`, `{ myInt }`
 +
 +  `Asn1ObjectIdentifierSequenceIr` - any form is supported.
 +
 +  `ulong[]` is also accepted to massively simplify programatic comparisons.
 +
 +  ast2ir _should_ also cover most cases where it's ambiguous whether a named value list or object id sequence is used,
 +  so `Asn1NamedValueSequenceIr` is unsupported in this function.
 +
 + Params:
 +  objIdA   = One of the object identifier values.
 +  objIdB   = The other object identifier value.
 +  areEqual = Set to true if the values are equal, false otherwise.
 +  errors   = Errors handler.
 +
 + Throws:
 +  `Asn1SemanticError.typeMismatch` if either `objIdA` or `objIdB` cannot represent a valid OBJECT IDENTIFIER value.
 +
 +  `Asn1SemanticError.typeMismatch` if either `objIdA` or `objIdB` contain a subvalue that 
 +   is not of type INTEGER.
 +
 + Returns:
 +  A `Result` indicating if some type of error occurred, unrelated to whether the values area equal or not.
 + ++/
Result asn1AreObjectIdentifiersEqual(IdIrA, IdIrB)(
    scope IdIrA objIdA,
    scope IdIrB objIdB,
    out scope bool areEqual,
    Asn1ErrorHandler errors,
) @nogc nothrow
in(objIdA !is null, "objIdA is null")
in(objIdB !is null, "objIdB is null")
in(errors !is null, "errors is null")
{
    import juptune.core.ds : Array;
    import juptune.data.asn1.lang.ir : Asn1ObjectIdSequenceValueIr, Asn1ValueSequenceIr, Asn1ValueReferenceIr,
                                       Asn1IntegerValueIr, Asn1SemanticError;

    // Try to use the stack for storage, but fallback to the heap if there's too many values.
    ulong[16] stackA, stackB;
    Array!ulong heapA, heapB;
    size_t cursorA, cursorB;

    Result toArray(IrT)(IrT objId, out ulong[] slice, ref ulong[16] stack, ref Array!ulong heap, ref size_t cursor)
    {
        size_t length;
        void put(ulong i)
        {
            if(length > stack.length)
                heap.put(i);
            else
                stack[cursor] = i;
            cursor++;
        }

        // TODO: If the logic ever needs to grow, just DRY things up a bit - not too worth the effort right now.
        static if(is(IrT == Asn1ObjectIdSequenceValueIr))
        {
            length = objId.getObjectCount();
            auto result = objId.foreachObjectId((value){
                if(auto casted = cast(Asn1ValueReferenceIr)value)
                    value = casted.getResolvedValueRecurse();

                if(auto intIr = cast(Asn1IntegerValueIr)value)
                {
                    if(intIr.isNegative)
                    {
                        return Result.make(
                            Asn1SemanticError.typeMismatch,
                            "value type mismatch",
                            errors.errorAndString(
                                value.getRoughLocation(),
                                "when comparing OBJECT IDENTIFIER values, expected value #", cursor,
                                " within an ObjectIdSequence to a positive number, instead of -", intIr.getNumberText()
                            )
                        );
                    }

                    ulong number;
                    auto result = intIr.asUnsigned(number, errors);
                    if(result.isError)
                        return result;
                    put(number);
                }
                else
                {
                    return Result.make(
                        Asn1SemanticError.typeMismatch,
                        "value type mismatch",
                        errors.errorAndString(
                            value.getRoughLocation(),
                            "when comparing OBJECT IDENTIFIER values, expected value #", cursor,
                            " within an ObjectIdSequence to be of type INTEGER, not type ", typeid(value).name
                        )
                    );
                }
                return Result.noError;
            }, errors);
            if(result.isError)
                return result;
        }
        else static if(is(IrT == Asn1ValueSequenceIr))
        {
            length = objId.getValueCount();
            auto result = objId.foreachSequenceValue((value){
                if(auto casted = cast(Asn1ValueReferenceIr)value)
                    value = casted.getResolvedValueRecurse();

                if(auto intIr = cast(Asn1IntegerValueIr)value)
                {
                    if(intIr.isNegative)
                    {
                        return Result.make(
                            Asn1SemanticError.typeMismatch,
                            "value type mismatch",
                            errors.errorAndString(
                                value.getRoughLocation(),
                                "when comparing OBJECT IDENTIFIER values, expected value #", cursor,
                                " within a ValueSequence to a positive number, instead of -", intIr.getNumberText()
                            )
                        );
                    }

                    ulong number;
                    auto result = intIr.asUnsigned(number, errors);
                    if(result.isError)
                        return result;
                    put(number);
                }
                else
                {
                    return Result.make(
                        Asn1SemanticError.typeMismatch,
                        "value type mismatch",
                        errors.errorAndString(
                            value.getRoughLocation(),
                            "when comparing OBJECT IDENTIFIER values, expected value #", cursor,
                            " within a ValueSequence to be of type INTEGER, not type ", typeid(value).name
                        )
                    );
                }
                return Result.noError;
            }, errors);
            if(result.isError)
                return result;
        }
        else static if(is(IrT : const(ulong)[]))
        {
            slice = objId;
            return Result.noError;
        }
        else static assert(false, "IR node of type "~IrT.stringof~" can never contain a valid OBJECT IDENTIFIER value");

        slice = (length > stack.length) ? heap.slice : stack[0..cursor];
        return Result.noError;
    }

    ulong[] sliceA, sliceB;
    
    auto result = toArray(objIdA, sliceA, stackA, heapA, cursorA);
    if(result.isError)
        return result;
    result = toArray(objIdB, sliceB, stackB, heapB, cursorB);
    if(result.isError)
        return result;

    areEqual = sliceA == sliceB;
    return Result.noError;
}
///
@("asn1AreObjectIdentifiersEqual")
unittest
{
    import juptune.core.util              : resultAssert;
    import juptune.data.asn1.lang.common  : Asn1ParserContext;
    import juptune.data.asn1.lang.ir      : Asn1ModuleIr, Asn1ObjectIdentifierTypeIr, Asn1ModuleRegistry,
                                            Asn1ValueSequenceIr, Asn1ValueAssignmentIr, Asn1ObjectIdSequenceValueIr;
    import juptune.data.asn1.lang.tooling : asn1ParseWithSemantics, Asn1AlwaysCrashErrorHandler;

    Asn1ParserContext context;
    Asn1ModuleIr modIr;
    scope registry = new Asn1ModuleRegistry();
    asn1ParseWithSemantics(context, modIr, `
        MyMod DEFINITIONS ::= BEGIN
            b INTEGER ::= 3
            idA OBJECT IDENTIFIER ::= { foo(1) bar(2) baz(b) }
            idB OBJECT IDENTIFIER ::= { baz(b) }
            idC OBJECT IDENTIFIER ::= { b }
        END
    `, registry, new Asn1AlwaysCrashErrorHandler()).resultAssert;

    Asn1ValueAssignmentIr idA, idB, idC;
    modIr.getAssignmentByName("idA", idA).resultAssert;
    modIr.getAssignmentByName("idB", idB).resultAssert;
    modIr.getAssignmentByName("idC", idC).resultAssert;

    bool areEqual;

    // idA != idB
    asn1AreObjectIdentifiersEqual(
        cast(Asn1ObjectIdSequenceValueIr)idA.getSymbolValue(),
        cast(Asn1ObjectIdSequenceValueIr)idB.getSymbolValue(),
        areEqual,
        new Asn1AlwaysCrashErrorHandler()
    ).resultAssert;
    assert(!areEqual);

    // idA != idC
    asn1AreObjectIdentifiersEqual(
        cast(Asn1ObjectIdSequenceValueIr)idA.getSymbolValue(),
        cast(Asn1ValueSequenceIr)idC.getSymbolValue(),
        areEqual,
        new Asn1AlwaysCrashErrorHandler()
    ).resultAssert;
    assert(!areEqual);

    // idB == idC
    asn1AreObjectIdentifiersEqual(
        cast(Asn1ObjectIdSequenceValueIr)idB.getSymbolValue(),
        cast(Asn1ValueSequenceIr)idC.getSymbolValue(),
        areEqual,
        new Asn1AlwaysCrashErrorHandler()
    ).resultAssert;
    assert(areEqual);

    // programatic == idA
    asn1AreObjectIdentifiersEqual(
        cast(Asn1ObjectIdSequenceValueIr)idA.getSymbolValue(),
        [1UL, 2, 3],
        areEqual,
        new Asn1AlwaysCrashErrorHandler()
    ).resultAssert;
    assert(areEqual);
}

/++
 + Helper function that skips over any wrapper/indirect types, and returns the
 + actual underlying type.
 +
 + Useful for type-aware contexts, such as type checking, which don't really care too much about
 + the tag wrappers or indirect type references.
 +
 + Params:
 +  type = The type to get the exact underlying type of.
 +
 + Returns:
 +  The exact underlying type of `type`.
 + ++/
Asn1TypeIr asn1GetExactUnderlyingType(Asn1TypeIr type) @nogc nothrow
in(type !is null, "type is null")
{
    import juptune.data.asn1.lang.ir : Asn1TypeReferenceIr, Asn1TaggedTypeIr;

    if(auto ir = cast(Asn1TypeReferenceIr)type)
    {
        return asn1GetExactUnderlyingType(ir.getResolvedTypeRecurse(
            Asn1TypeReferenceIr.StopForConstraints.no
        ));
    }
    else if(auto ir = cast(Asn1TaggedTypeIr)type)
        return asn1GetExactUnderlyingType(ir.getUnderlyingTypeSkipTags());
    return type;
}

/++
 + Walks over all meaningful tags for the given type, calling `onTag` for each meaningful tag.
 +
 + This function is useful for code that needs to handle EXPLICIT tags, as well as easily coalesce IMPLICIT tags,
 + e.g. because you're writing a encoder/decoder.
 +
 + Notes:
 +  Any side-by-side IMPLICIT tags will be collapsed into the left-most tag, so `[2] [0] [1]` would condense into just `[2]`.
 +
 +  If an EXPLICIT tag has an IMPLICIT tag to the left of it, the IMPLICIT tag's value is used but the EXPLICIT flag is kept,
 +  so `[1] IMPLICIT [2] EXPLICIT` would result in `[1] EXPLICIT`.
 +
 +  A "meaningful tag" is either: any EXPLICIT tag (after IMPLICIT tags are merged into it), 
 +  the type's default tag (after IMPLICIT tags are merged into it).
 +
 +  Some types (such as `CHOICE`) are not assigned a default tag by the x.680 specification, and so AFTER all other
 +  meaningful tags have been sent to `onTag`, an `Asn1SemanticError.toolTypeMissingTag` error will be returned. This isn't
 +  a fatal error, but more a way to detect types that have this annoying edge case your code likely needs to handle.
 +
 +  Type references are NOT followed, so tags of the referenced type are NOT returned but instead the above error
 +  is thrown.
 +
 + Cases:
 +  Please note that `BOOLEAN` has a default tag of `1`
 +
 +  `BOOLEAN`                           -> onTag(1, false)
 +
 +  `[0] IMPLICIT BOOLEAN`              -> onTag(0, false)
 +
 +  `[2] IMPLICIT [0] IMPLICIT BOOLEAN` -> onTag(2, false)
 +
 +  `[2] EXPLICIT BOOLEAN`              -> onTag(2, true), onTag(1, false)
 +
 +  `[1] IMPLICIT [2] EXPLICIT BOOLEAN` -> onTag(1, true), onTag(1, false)
 +
 +  `[3] EXPLICIT [2] EXPLICIT BOOLEAN` -> onTag(3, true), onTag(2, true), onTag(1, false)
 +
 +  `[2] EXPLICIT CHOICE { a BOOLEAN }` -> onTag(2, true), Asn1SemanticError.toolTypeMissingTag
 +
 + Params:
 +  DelegateT = A function type that must match `Result (ulong tag, bool isExplicit, Asn1TaggedType.Class class_)`.
 +  type      = The type to walk the tags of.
 +  onTag     = The callback to use whenever a meaningful tag is encountered.
 +
 + Throws:
 +  Anything `onTag` throws.
 +
 +  `Asn1SemanticError.toolTypeMissingTag` if the default tag of the exact underlying type of `type` is required,
 +  but said type has no default tag assigned by x.680. As this is a "signal error" no error will be sent to `errors`.
 +
 + Returns:
 +  A `Result` indicating if something went wrong.
 + ++/
Result asn1WalkTags(DelegateT)(Asn1TypeIr type, scope DelegateT onTag, scope Asn1ErrorHandler errors)
{
    import juptune.data.asn1.lang.ir : Asn1TaggedTypeIr, Asn1ValueReferenceIr, Asn1IntegerValueIr, Asn1SemanticError;

    Asn1TaggedTypeIr latestImplicit; // May be null

    Result asNumber(Asn1ValueIr valueIr, out ulong value)
    {
        if(auto valueRefIr = cast(Asn1ValueReferenceIr)valueIr)
            valueIr = valueRefIr.getResolvedValueRecurse();
        
        auto intValueIr = cast(Asn1IntegerValueIr)valueIr;
        assert(intValueIr !is null, "bug: Tag isn't an INTEGER? Why didn't the type checker catch this?");

        return intValueIr.asUnsigned(value, errors);
    }

    while(true)
    {
        if(auto taggedIr = cast(Asn1TaggedTypeIr)type)
        {
            type = taggedIr.getUnderlyingType();

            assert(taggedIr.getEncoding() != Asn1TaggedTypeIr.Encoding.unspecified, "bug: TaggedType has an unspecified encoding - were semantics ran?"); // @suppress(dscanner.style.long_line)
            if(taggedIr.getEncoding() == Asn1TaggedTypeIr.Encoding.implicit)
            {
                if(latestImplicit is null)
                    latestImplicit = taggedIr;
                continue;
            }

            ulong tag;
            auto result = asNumber(latestImplicit !is null ? latestImplicit.getNumberIr() : taggedIr.getNumberIr(), tag); // @suppress(dscanner.style.long_line)
            if(result.isError)
                return result;
            latestImplicit = null;

            result = onTag(tag, true, taggedIr.getClass());
            if(result.isError)
                return result;

            continue;
        }

        ulong tag;
        Asn1TaggedTypeIr.Class class_;
        if(latestImplicit !is null)
        {
            auto result = asNumber(latestImplicit.getNumberIr(), tag);
            if(result.isError)
                return result;
            class_ = latestImplicit.getClass();
        }
        else
        {
            if(type.getUniversalTag.isNull)
            {
                return Result.make(
                    Asn1SemanticError.toolTypeMissingTag, 
                    "the given type does not have a default tag, please detect this error code as an edge case"
                );
            }

            tag = type.getUniversalTag.get();
            class_ = Asn1TaggedTypeIr.Class.universal;
        }

        return onTag(tag, false, class_);
    }
}
@("asn1WalkTags")
unittest
{
    import std.conv                       : to;
    import juptune.core.util              : resultAssert, resultAssertSameCode;
    import juptune.data.asn1.lang.common  : Asn1ParserContext;
    import juptune.data.asn1.lang.ir      : Asn1ModuleIr, Asn1ModuleRegistry, Asn1TaggedTypeIr,
                                            Asn1IntegerValueIr, Asn1TypeAssignmentIr, Asn1SemanticError;
    import juptune.data.asn1.lang.tooling : asn1ParseWithSemantics, Asn1AlwaysCrashErrorHandler;

    Asn1ParserContext context;
    Asn1ModuleIr modIr;
    scope registry = new Asn1ModuleRegistry();
    asn1ParseWithSemantics(context, modIr, `
        MyMod DEFINITIONS ::= BEGIN
            Case1 ::=                           BOOLEAN
            Case2 ::=              [0] IMPLICIT BOOLEAN
            Case3 ::= [2] IMPLICIT [0] IMPLICIT BOOLEAN
            Case4 ::=              [2] EXPLICIT BOOLEAN
            Case5 ::= [1] IMPLICIT [2] EXPLICIT BOOLEAN
            Case6 ::= [3] EXPLICIT [2] EXPLICIT BOOLEAN
            Case7 ::=              [2] EXPLICIT CHOICE { a BOOLEAN }
        END
    `, registry, new Asn1AlwaysCrashErrorHandler()).resultAssert;

    static struct Got
    {
        ulong tag;
        bool isExplicit;
        Asn1TaggedTypeIr.Class class_;
    }

    Got[] tags;

    scope collectTags = (ulong tagIr, bool isExplicit, Asn1TaggedTypeIr.Class class_){
        tags ~= Got(tagIr, isExplicit, class_);
        return Result.noError;
    };

    // Table testing? Never heard of it!
    Asn1TypeAssignmentIr case1, case2, case3, case4, case5, case6, case7;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case1", case1).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case2", case2).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case3", case3).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case4", case4).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case5", case5).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case6", case6).resultAssert;
    modIr.getAssignmentByName!Asn1TypeAssignmentIr("Case7", case7).resultAssert;

    alias cl = Asn1TaggedTypeIr.Class;

    tags = [];
    asn1WalkTags(case1.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(1, false, cl.universal)], tags.to!string);

    tags = [];
    asn1WalkTags(case2.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(0, false)], tags.to!string);

    tags = [];
    asn1WalkTags(case3.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(2, false)], tags.to!string);

    tags = [];
    asn1WalkTags(case4.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(2, true), Got(1, false, cl.universal)], tags.to!string);

    tags = [];
    asn1WalkTags(case5.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(1, true), Got(1, false, cl.universal)], tags.to!string);

    tags = [];
    asn1WalkTags(case6.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance).resultAssert;
    assert(tags == [Got(3, true), Got(2, true), Got(1, false, cl.universal)], tags.to!string);

    tags = [];
    asn1WalkTags(case7.getSymbolType(), collectTags, Asn1AlwaysCrashErrorHandler.instance)
        .resultAssertSameCode!Asn1SemanticError(Result.make(Asn1SemanticError.toolTypeMissingTag));
    assert(tags == [Got(2, true)], tags.to!string);
}