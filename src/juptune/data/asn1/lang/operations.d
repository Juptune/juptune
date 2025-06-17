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

import juptune.core.util         : Result;
import juptune.data.asn1.lang.ir : Asn1TypeIr, Asn1ValueIr, Asn1SemanticErrorHandler;

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
    Asn1SemanticErrorHandler errors,
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
                    auto result = intIr.asUnsigned(number);
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
            });
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
                    auto result = intIr.asUnsigned(number);
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
            });
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