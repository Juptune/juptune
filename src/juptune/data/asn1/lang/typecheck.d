/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.typecheck;

import juptune.core.util : Result;
import juptune.data.asn1.lang.common : Asn1Location;
import juptune.data.asn1.lang.ir; // Intentionally everything

class Asn1TypeCheckVisitor : Asn1IrVisitor // Intentionally not final - allows users to build on top of the built-in checks.
{
    // NOTE: This visitor only returns results for genuine errors - type check failures are not returned
    //       via a Result but should be checked using the TODO functions.

    private
    {
        Asn1SemanticErrorHandler _errors;
    }

    @nogc nothrow:

    this(Asn1SemanticErrorHandler errors)
    in(errors !is null, "errors is null")
    {
        this._errors = errors;
    }

    /++++ Error funcs ++++/

    void reportError(Args...)(
        Asn1Location location,
        Asn1SemanticError error,
        scope auto ref Args args,
    )
    {
        if(error == Asn1SemanticError.none)
        {
            auto _ = this._errors.errorAndString(location, args);
        }
        else
        {
            auto _ = this._errors.errorAndString(
                location,
                "[", error, "] ",
                args,
            );
        }
    }

    /++++ General visit funcs ++++/

    override Result visit(Asn1ModuleIr ir)
    {
        auto result = ir.foreachAssignment((ass) => ass.visit(this));
        if(result.isError)
            return result;

        return Result.noError;
    }

    override Result visit(Asn1TypeAssignmentIr ir)
    {
        return Result.noError;
    }

    override Result visit(Asn1ValueAssignmentIr ir)
    {
        auto result = ir.getSymbolType().visit(this);
        if(result.isError)
            return result;

        result = ir.getSymbolValue().visit(this);
        if(result.isError)
            return result;

        auto typeIr = ir.getSymbolType();
        auto exactTypeIr = this.getExactUnderlyingType(ir.getSymbolType());
        if(auto type = cast(Asn1TaggedTypeIr)typeIr)
            typeIr = type.getUnderlyingTypeSkipTags();

        if(auto _ = cast(Asn1IntegerTypeIr)exactTypeIr)
            return checkIntegerAss(ir.getSymbolName(), typeIr, ir.getSymbolValue());
        else if(auto _ = cast(Asn1BooleanTypeIr)exactTypeIr)
        {
            // TODO:
            return Result.noError;
        }

        assert(false, "bug: Missing type check case");
    }

    override Result visit(Asn1IntegerValueIr ir) => Result.noError;
    override Result visit(Asn1BooleanValueIr ir) => Result.noError;

    /++++ Type checkers ++++/

    override Result visit(Asn1TypeReferenceIr ir) => ir.getResolvedType().visit(this);
    override Result visit(Asn1BooleanTypeIr ir) => Result.noError;

    override Result visit(Asn1IntegerTypeIr ir)
    {
        // Not efficient, but it's simple
        foreach(kvp; ir.byNamedNumberKvp())
        {
            auto kvpNumber = cast(Asn1IntegerValueIr)kvp.value;
            if(kvpNumber is null)
            {
                this.reportError(
                    ir.getRoughLocation(),
                    Asn1SemanticError.bug,
                    "integer value isn't an Asn1IntegerValueIr? Has the caller run semantic passes yet?"
                );
                continue;
            }

            foreach(toCompare; ir.byNamedNumberKvp())
            {
                if(toCompare.key == kvp.key)
                    continue;
                
                auto compareNumber = cast(Asn1IntegerValueIr)toCompare.value;
                if(compareNumber is null)
                    continue; // Don't need to bother reporting an error, it'll get caught in its own iteration.

                if(compareNumber.getNumber() == kvpNumber.getNumber())
                {
                    this.reportError(
                        ir.getRoughLocation(),
                        Asn1SemanticError.duplicateNamedNumber,
                        "named number '", kvp.key, "' has a value of ", kvpNumber.getNumberText,
                        " which conflicts with named number '", toCompare.key, "'"
                    );
                }
            }
        }

        // Check all the constraint values are INTEGERS
        bool _;
        return this.checkConstraints("TODO", ir, (constraint, shouldReport, out wasSuccess){
            if(auto constraintIr = cast(Asn1SingleValueConstraintIr)constraint)
            {
                this.checkType!Asn1IntegerTypeIr(
                    constraintIr.getValue(), 
                    "single value constraint's value", 
                    shouldReport, 
                    wasSuccess
                );
                return Result.noError;
            }
            else if(auto constraintIr = cast(Asn1ValueRangeConstraintIr)constraint)
            {
                if(constraintIr.getLower().valueIr !is null)
                {
                    this.checkType!Asn1IntegerTypeIr(
                        constraintIr.getLower().valueIr,
                        "value range constraint's lower bound",
                        shouldReport,
                        wasSuccess
                    );
                }
                if(constraintIr.getUpper().valueIr !is null)
                {
                    bool success;
                    this.checkType!Asn1IntegerTypeIr(
                        constraintIr.getUpper().valueIr,
                        "value range constraint's upper bound",
                        shouldReport,
                        success
                    );
                    wasSuccess = wasSuccess && success;
                }
                return Result.noError;
            }

            assert(false, "bug: Missing constraint case for INTEGER (type check variant)?");
        }, false, _);
    }

    /++++ Ass(ignment) checkers ++++/

    private:

    Result checkIntegerAss(const(char)[] symbolName, Asn1TypeIr type, Asn1ValueIr value)
    {
        auto intValue = cast(Asn1IntegerValueIr)value;
        if(intValue is null)
        {
            this.reportError(
                value.getRoughLocation(), 
                Asn1SemanticError.typeMismatch,
                "symbol '", symbolName, "' of type ", type.getKindName(),
                " cannot be assigned value of type ", value.getValueKind(),
            );
            return Result.noError;
        }

        bool _;
        return this.checkConstraints(symbolName, type, (constraint, shouldReport, out wasSuccess){
            if(auto ir = cast(Asn1SingleValueConstraintIr)constraint)
            {
                auto valueIr = cast(Asn1IntegerValueIr)ir.getValue();
                if(valueIr is null)
                {
                    wasSuccess = false;
                    // Don't need an error message here - it'll be caught in Asn1IntegerTypeIr's checks.
                }
                else
                {
                    wasSuccess = valueIr.getNumber() == intValue.getNumber();
                    if(!wasSuccess && shouldReport)
                    {
                        this.reportError(
                            value.getRoughLocation(),
                            Asn1SemanticError.none,
                            "expected ", valueIr.getNumberText(), " but got ", intValue.getNumberText()
                        );
                    }
                }
                return Result.noError;
            }
            else if(auto ir = cast(Asn1ValueRangeConstraintIr)constraint)
            {
                bool getEndpoint(Asn1ValueRangeConstraintIr.Endpoint endpoint, long default_, out long result)
                {
                    result = default_;

                    if(!endpoint.isUnbounded)
                    {
                        assert(endpoint.valueIr !is null, "bug: endpoint is bounded but valueIr is null?");
                        auto intIr = cast(Asn1IntegerValueIr)endpoint.valueIr;
                        if(intIr is null)
                        {
                            // Don't need an error message here - it'll be caught in Asn1IntegerTypeIr's checks.
                            return false;
                        }

                        auto intResult = intIr.asSigned(result);
                        if(intResult.isError)
                        {
                            if(shouldReport)
                            {
                                this.reportError(
                                    endpoint.valueIr.getRoughLocation(),
                                    Asn1SemanticError.none,
                                    "failed to convert value range endpoint into a native integer: ",
                                    intResult.error,
                                    intResult.context
                                );
                            }
                            return false;
                        }
                    }

                    if(endpoint.isOpen && default_ < 0)
                        result++;
                    else if(endpoint.isOpen && default_ >= 0)
                        result--;

                    return true;
                }

                wasSuccess = true;

                long lower, upper;
                if(!getEndpoint(ir.getUpper(), long.max, upper))
                {
                    wasSuccess = false;
                    return Result.noError;
                }
                if(!getEndpoint(ir.getLower(), long.min, lower))
                {
                    wasSuccess = false;
                    return Result.noError;
                }

                long assValue;
                auto result = intValue.asSigned(assValue);
                if(result.isError)
                {
                    if(shouldReport)
                    {
                        this.reportError(
                            intValue.getRoughLocation(),
                            Asn1SemanticError.none,
                            "failed to convert integer value into a native integer: ",
                            result.error,
                            result.context
                        );
                    }
                    return Result.noError;
                }

                if(assValue < lower)
                {
                    wasSuccess = false;
                    if(shouldReport)
                    {
                        this.reportError(
                            intValue.getRoughLocation(),
                            Asn1SemanticError.none,
                            "value ", intValue.getNumberText(), " is less than lower bound of ", lower
                        );
                    }
                }
                if(assValue > upper)
                {
                    wasSuccess = false;
                    if(shouldReport)
                    {
                        this.reportError(
                            intValue.getRoughLocation(),
                            Asn1SemanticError.none,
                            "value ", intValue.getNumberText(), " is greater than upper bound of ", upper
                        );
                    }
                }

                return Result.noError;
            }
            assert(false, "bug: Unhandled constraint case for INTEGER?");
        }, false, _);
    }
    
    /++++ Helpers ++++/

    void checkType(ExpectedT)(Asn1TypeIr got, string context, bool shouldReport, out bool wasSuccess)
    {
        got = this.getExactUnderlyingType(got);
        wasSuccess = (cast(ExpectedT)got) !is null;
        if(!wasSuccess && shouldReport)
        {
            this.reportError(
                got.getRoughLocation(),
                Asn1SemanticError.none,
                "expected ", context, 
                " to be of type ", ExpectedT.stringof,
                " instead of type ", got.getKindName()
            );
        }
    }

    void checkType(ExpectedT)(Asn1ValueIr got, string context, bool shouldReport, out bool wasSuccess)
    {
        static if(is(ExpectedT == Asn1IntegerTypeIr))
        {
            wasSuccess = (cast(Asn1IntegerValueIr)got) !is null;
        }
        else static assert(false, "bug: Missing case for "~ExpectedT.stringof);

        if(!wasSuccess && shouldReport)
        {
            this.reportError(
                got.getRoughLocation(),
                Asn1SemanticError.none,
                "expected ", context, 
                " to be of type ", ExpectedT.stringof,
                " instead of type ", got.getValueKind(),
            );
        }
    }

    Result checkConstraints(
        const(char)[] symbolName,
        Asn1TypeIr type,
        scope Result delegate(Asn1ConstraintIr, bool, out bool) @nogc nothrow handleConstraint,
        bool isSubType,
        out bool wasSuccessOverall,
        bool shouldReport = false,
    )
    {
        Result check(Asn1ConstraintIr constraint, out bool wasSuccess)
        {
            if(!isSubType)
            {
                auto result = this.checkConstraints(symbolName, type, constraint, handleConstraint, false, wasSuccess);
                if(result.isError)
                    return result;

                if(wasSuccess)
                    return Result.noError;
                
                this.reportError(
                    constraint.getRoughLocation(), 
                    Asn1SemanticError.constraint,
                    "top-level constraint failed, specifically:"
                );
                this._errors.indent();
                scope(exit) this._errors.dedent();
                return this.checkConstraints(symbolName, type, constraint, handleConstraint, true, wasSuccess);
            }

            return this.checkConstraints(symbolName, type, constraint, handleConstraint, shouldReport, wasSuccess);
        }

        wasSuccessOverall = true;
        while(true)
        {
            if(auto constraint = type.getMainConstraintOrNull())
            {
                bool wasSuccess;
                auto result = check(constraint, wasSuccess);
                if(!wasSuccess)
                    wasSuccessOverall = false;
                if(result.isError)
                    return result;
            }
            if(auto constraint = type.getAdditionalConstraintOrNull())
            {
                bool wasSuccess;
                auto result = check(constraint, wasSuccess);
                if(!wasSuccess)
                    wasSuccessOverall = false;
                if(result.isError)
                    return result;
            }

            // Handle nested chain of constraints
            if(auto taggedIr = cast(Asn1TaggedTypeIr)type)
            {
                type = taggedIr.getUnderlyingTypeSkipTags();
                continue;
            }
            else if(auto refIr = cast(Asn1TypeReferenceIr)type)
            {
                type = refIr.getResolvedType();
                continue;
            }

            break;
        }
        return Result.noError;
    }

    Result checkConstraints(
        const(char)[] symbolName,
        Asn1TypeIr type,
        Asn1ConstraintIr constraint,
        scope Result delegate(Asn1ConstraintIr, bool, out bool) @nogc nothrow handleConstraint,
        bool shouldReport,
        out bool wasSuccess,
    )
    {
        if(shouldReport)
        {
            this.reportError(
                constraint.getRoughLocation(),
                Asn1SemanticError.none,
                constraint.getConstraintKind(),
            );
            this._errors.indent();
        }
        scope(exit) if(shouldReport)
        {
            this.reportError(
                constraint.getRoughLocation(),
                Asn1SemanticError.none,
                wasSuccess ? "SUCCESS" : "FAILED"
            );
            this._errors.dedent();
        }

        if(auto ir = cast(Asn1UnionConstraintIr)constraint)
        {
            return ir.foreachUnionConstraint((childConstraint){
                bool success;
                auto result = this.checkConstraints(
                    symbolName,
                    type,
                    childConstraint, 
                    handleConstraint, 
                    shouldReport, 
                    success
                );
                wasSuccess = wasSuccess || success;
                return result;
            });
        }
        else if(auto ir = cast(Asn1IntersectionConstraintIr)constraint)
        {
            wasSuccess = true;
            return ir.foreachIntersectionConstraint((childConstraint){
                bool success;
                auto result = this.checkConstraints(
                    symbolName,
                    type,
                    childConstraint,
                    handleConstraint,
                    shouldReport,
                    success
                );
                if(!success)
                    wasSuccess = false;
                return result;
            });
        }
        else if(auto ir = cast(Asn1ContainedSubtypeConstraintIr)constraint)
        {
            auto subtypeExact = this.getExactUnderlyingType(ir.getSubtype());
            auto typeExact = this.getExactUnderlyingType(type);

            if(typeid(subtypeExact) is typeid(typeExact))
                return this.checkConstraints(symbolName, ir.getSubtype(), handleConstraint, true, wasSuccess, shouldReport); // @suppress(dscanner.style.long_line)

            wasSuccess = false;
            if(shouldReport)
            {
                this.reportError(
                    constraint.getRoughLocation(),
                    Asn1SemanticError.none,
                    "expected subtype to be of kind '", typeExact.getKindName(),
                    "' instead of kind '", subtypeExact.getKindName(), "'"
                );
            }

            return Result.noError;
        }
        else
            return handleConstraint(constraint, shouldReport, wasSuccess);
    }

    Asn1TypeIr getExactUnderlyingType(Asn1TypeIr type)
    {
        if(auto ir = cast(Asn1TypeReferenceIr)type)
        {
            return this.getExactUnderlyingType(ir.getResolvedTypeRecurse(
                Asn1TypeReferenceIr.StopForConstraints.no
            ));
        }
        else if(auto ir = cast(Asn1TaggedTypeIr)type)
            return this.getExactUnderlyingType(ir.getUnderlyingTypeSkipTags());
        return type;
    }
}

/++++ Unittests ++++/

version(unittest):

import juptune.core.util : resultAssert, resultAssertSameCode;
import juptune.data.asn1.lang.common; // Intentionally everything
import juptune.data.asn1.lang.parser; // Intentionally everything
import juptune.data.asn1.lang.lexer; // Intentionally everything
import juptune.data.asn1.lang.ast2ir; // Intentionally everything
import juptune.data.asn1.lang.ast; // Intentionally everything

@("Asn1IntegerTypeIr")
unittest
{
    alias Harness = GenericTestHarness!(Asn1TypeIr, Asn1IntegerTypeIr, (ref parser){
        Asn1TypeNode node;
        parser.Type(node).resultAssert;
        return node;
    });

    with(Harness) run([
        "No duplicate named numbers": T(
            "INTEGER { a(0), b(0) }",
            Asn1SemanticError.duplicateNamedNumber
        ),
        "Success": T(
            "INTEGER { a(0), b(1) }",
            Asn1SemanticError.none
        ),

        "SingleValue - wrong value type": T(
            "INTEGER (TRUE)",
            Asn1SemanticError.constraint
        ),

        "ValueRange - wrong lower bound type": T(
            "INTEGER (TRUE..1)",
            Asn1SemanticError.constraint
        ),
        "ValueRange - wrong upper bound type": T(
            "INTEGER (0..TRUE)",
            Asn1SemanticError.constraint
        ),
    ]);
}

@("ValueAssignment - INTEGER")
unittest
{
    alias Harness = GenericTestHarness!(Asn1ModuleIr, Asn1ModuleIr, (ref parser){
        Asn1ModuleDefinitionNode node;
        parser.ModuleDefinition(node).resultAssert;
        return node;
    });

    with(Harness) run([
        "No constraint - success": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER
                i I ::= 0
            END
        `, Asn1SemanticError.none),

        "SingleValue - failure": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0)
                i I ::= 1
            END
        `, Asn1SemanticError.constraint),
        "SingleValue - success": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0)
                i I ::= 0
            END
        `, Asn1SemanticError.none),

        "SubType - failure": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (1)
                I2 ::= INTEGER (I)
                i I2 ::= 0
            END
        `, Asn1SemanticError.constraint),
        "SubType - combined failure": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..2)
                I2 ::= INTEGER (I ^ 1)
                i I2 ::= 2
            END
        `, Asn1SemanticError.constraint),
        "SubType - success": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0)
                I2 ::= INTEGER (I)
                i I2 ::= 0
            END
        `, Asn1SemanticError.none),

        "SubType 2 - failure": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (1)
                I2 ::= I
                i I2 ::= 0
            END
        `, Asn1SemanticError.constraint),
        "SubType 2 - combined failure": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..2)
                I2 ::= I (1)
                i I2 ::= 2
            END
        `, Asn1SemanticError.constraint),

        "ValueRange - closed lower out of bounds": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..1)
                i I ::= -1
            END
        `, Asn1SemanticError.constraint),
        "ValueRange - closed upper out of bounds": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..1)
                i I ::= 2
            END
        `, Asn1SemanticError.constraint),
        "ValueRange - open upper out of bounds": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..<1)
                i I ::= 1
            END
        `, Asn1SemanticError.constraint),
        "ValueRange - open lower out of bounds": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0<..1)
                i I ::= 0
            END
        `, Asn1SemanticError.constraint),
        "ValueRange - in bounds closed upper": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..1)
                i I ::= 1
            END
        `, Asn1SemanticError.none),
        "ValueRange - in bounds closed lower": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..1)
                i I ::= 0
            END
        `, Asn1SemanticError.none),
        "ValueRange - in bounds open upper": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0..<1)
                i I ::= 0
            END
        `, Asn1SemanticError.none),
        "ValueRange - in bounds open lower": T(`
            Unittest DEFINITIONS ::= BEGIN
                I ::= INTEGER (0<..1)
                i I ::= 1
            END
        `, Asn1SemanticError.none),
    ]);
}

private final class ErrorCollector : Asn1SemanticErrorHandler
{
    import juptune.core.util.conv : toStringSink;
    import juptune.core.ds : String2, Array;

    @nogc nothrow:

    Array!String2 errors;
    Array!char buffer;
    uint _indent;

    override void startLine(Asn1Location location)
    {
        this.buffer.put('(');
        toStringSink(location.start, this.buffer);
        this.buffer.put("..");
        toStringSink(location.end, this.buffer);
        this.buffer.put("): ");
        foreach(i; 0..this._indent)
            this.buffer.put("  ");

    }
    override void putInLine(scope const(char)[] slice)
    {
        this.buffer.put(slice);
    }
    override void endLine()
    {
        this.errors.put(String2(this.buffer[0..$]));
        this.buffer.length = 0; // Not using .fromDestroyingArray since we want to keep the underlying capacity.
    }
    override void indent() { this._indent++; }
    override void dedent() { this._indent--; }
}

private template GenericTestHarness(NodeToIrT, ActualIrT, alias ParseFunc, alias Converter = asn1AstToIr)
{
    static struct T
    {
        string input;
        Asn1SemanticError expectedError;
    }

    void run(T[string] cases)
    {
        import std.conv : to;
        foreach(name, test; cases)
        {
            try
            {
                Asn1ParserContext context;
                auto lexer = Asn1Lexer(test.input);
                auto parser = Asn1Parser(lexer, &context);

                auto node = ParseFunc(parser);
                NodeToIrT irFromNode;
                auto result = Converter(node, irFromNode, context, Asn1NullSemanticErrorHandler.instance);

                auto ir = cast(ActualIrT)irFromNode;
                assert(ir !is null, "Could not cast result to "~ActualIrT.stringof);

                resultAssert(result);
                Asn1Token token;
                parser.consume(token).resultAssert;
                assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);

                foreach(stage; [
                    Asn1ModuleIr.SemanticStageBit.resolveReferences,
                    Asn1ModuleIr.SemanticStageBit.implicitMutations,
                ])
                {
                    ir.doSemanticStage(stage, (_) => Asn1ModuleIr.LookupItemT.init, context, Asn1ModuleIr.SemanticInfo()).resultAssert; // @suppress(dscanner.style.long_line)
                }

                scope errors = new ErrorCollector();
                scope typeChecker = new Asn1TypeCheckVisitor(errors);
                typeChecker.visit(ir).resultAssert;

                import std.algorithm : map, joiner;
                if(test.expectedError == Asn1SemanticError.none)
                {
                    assert(errors.errors.length == 0, 
                        "Unfortunately, there were errors.\n"
                        ~errors.errors[].map!(str => cast(string)str.slice).joiner("\n").to!string
                    );
                    continue;
                }

                auto errorString = test.expectedError.to!string;
                bool found = false;
                foreach(error; errors.errors)
                {
                    import std.algorithm : canFind;
                    if(error.sliceMaybeFromStack.canFind(errorString))
                    {
                        found = true;
                        break;
                    }
                }

                assert(found, 
                    "Did not find error message for error: "~errorString~"\n"
                    ~errors.errors[].map!(str => cast(string)str.slice).joiner("\n").to!string
                );
            }
            catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
                assert(false, "\n["~name~"]:\n"~err.msg);
        }
    }
}