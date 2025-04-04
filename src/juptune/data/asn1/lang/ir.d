/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.ir;

import std.sumtype  : SumType;
import std.typecons : Nullable;

import juptune.core.ds : Array, String2, HashMap;
import juptune.core.util : Result;
import juptune.data.asn1.lang.ast; // Intentionally everything
import juptune.data.asn1.lang.common : Asn1Location;
import juptune.data.asn1.lang.lexer : Asn1Token;

enum Asn1SemanticError
{
    none,

    constraintIsNotAllowed,
    duplicateKey,
    numberMustBeUnsigned,
    numberIsTooLarge,
    numberCannotBeNegativeZero,
    typeCannotBeImplicit,
}

private enum ConstraintBit
{
    none,
    union_ = 1 << 0,
    intersection = 1 << 1,
    singleValue = 1 << 2,
    containedSubtype = 1 << 3,
    valueRange = 1 << 4,
    permittedAlphabet = 1 << 5,
    size = 1 << 6,
    type = 1 << 7,
    innerType = 1 << 8,
    pattern = 1 << 9,
}
private immutable ALL_CONSTRAINT_BITS = (){
    static struct KVP
    {
        string name;
        ConstraintBit value;
    }

    KVP[] bits;

    static foreach(Name; __traits(allMembers, ConstraintBit))
    {
        static if(Name != "none")
            bits ~= KVP(Name, mixin("ConstraintBit."~Name));
    }

    return bits;
}();

/++++ Error Handling ++++/

abstract class Asn1SemanticErrorHandler
{
    @nogc nothrow:

    abstract void startLine(Asn1Location location);
    abstract void putInLine(scope const(char)[] slice);
    abstract void endLine();
    abstract void indent();
    abstract void dedent();

    final String2 errorAndString(Args...)(Asn1Location location, scope auto ref Args args)
    {
        import juptune.core.util : toStringSink;

        Array!char buffer;

        static struct Putter
        {
            Asn1SemanticErrorHandler handler;
            Array!char* buffer;
            void put(scope const(char)[] slice) @nogc nothrow
            {
                this.handler.putInLine(slice);
                buffer.put(slice);
            }
        }
        scope putter = Putter(this);

        this.startLine(location);
        scope(exit) this.endLine();

        foreach(ref arg; args)
        {
            static if(!__traits(compiles, putInLine(arg)))
                toStringSink(arg, putter);
            else
            {
                this.putInLine(arg);
                buffer.put(arg);
            }
        }

        return String2.fromDestroyingArray(buffer);
    }
}

final class Asn1NullSemanticErrorHandler : Asn1SemanticErrorHandler
{
    __gshared instance = new Asn1NullSemanticErrorHandler();
    
    @nogc nothrow:

    override void startLine(Asn1Location location) {}
    override void putInLine(scope const(char)[] slice) {}
    override void endLine() {}
    override void indent() {}
    override void dedent() {}
}

/++++ Special ++++/

private mixin template IrBoilerplate()
{
    override Result visit(Asn1IrVisitor visitor) @nogc nothrow
    {
        return visitor.visit(this);
    }

    override void visitGc(Asn1IrVisitorGc visitor)
    {
        visitor.visit(this);
    }
}

abstract class Asn1BaseIr
{
    private
    {
        Asn1Location _roughLocation;
    }

    this(Asn1Location roughLocation) @nogc nothrow
    {
        this._roughLocation = roughLocation;
    }

    final Asn1Location getRoughLocation() @nogc nothrow
    {
        return this._roughLocation;
    }

    void dispose() @nogc nothrow {}

    abstract Result visit(Asn1IrVisitor visitor) @nogc nothrow;
    abstract void visitGc(Asn1IrVisitorGc visitor);
}

private struct OneOf(BaseIrT : Asn1BaseIr, IrTypes...)
{
    import std.meta : anySatisfy;

    BaseIrT ir;
    alias ir this;

    this(IrT : BaseIrT)(IrT ir)
    {
        enum ErrorMsg = "Invalid IR node was passed in. Is not one of: "~IrTypes.stringof;
        static if(is(IrT == BaseIrT))
        {
            static foreach(TargetIrT; IrTypes)
            {
                if(auto casted = cast(TargetIrT) ir)
                {
                    this.ir = ir;
                    return;
                }
            }
            assert(false, ErrorMsg);
        }
        else
        {
            enum isInputT(T) = is(T == IrT);
            static assert(anySatisfy!(isInputT, IrTypes), ErrorMsg);
            this.ir = ir;
        }
    }
}

/++++ Types ++++/

abstract class Asn1TypeIr : Asn1BaseIr
{
    @nogc nothrow:

    struct CustomTag
    {
        enum Class
        {
            unspecified,
            application,
            universal,
            private_,
        }

        alias NumberT = OneOf!(Asn1ValueIr, Asn1IntegerValueIr, Asn1ValueReferenceIr);

        Class class_;
        NumberT number;
    }

    enum TagEncoding
    {
        unspecified, // Use whatever the module default is
        implicit, // Replace the encoded tag number
        explicit, // Wrap encoded value in a structure with the specified tag number
    }

    enum Flags
    {
        none,
    }

    private
    {
        Array!Asn1ConstraintIr  _constraints;
        ConstraintBit           _allowedConstraints;
        Nullable!CustomTag      _customTag;
        TagEncoding             _tagEncoding;
        Flags                   _flags;
    }

    this(Asn1Location roughLocation, ConstraintBit allowedConstraints, Flags flags = Flags.none)
    {
        super(roughLocation);
        this._allowedConstraints = allowedConstraints;
        this._flags = flags;
    }

    ~this()
    {
        this.dispose(); // For edge cases where a node isn't allocated from a ParserContext
    }

    void setCustomTag(CustomTag tag)
    {
        this._customTag = tag;
    }
    Nullable!CustomTag getCustomTag() => this._customTag;

    void setTagEncoding(TagEncoding encoding)
    {
        this._tagEncoding = encoding;
    }
    TagEncoding getTagEncoding() => this._tagEncoding;

    Result addConstraint(
        Asn1ConstraintIr constraint, 
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(constraint !is null, "constraint is null")
    {
        const bits = constraint.getConstraintBits();
        String2 firstFailure;
        foreach(bit; ALL_CONSTRAINT_BITS)
        {
            if((bits & bit.value) == 0)
                continue; // Bit not in constraint, safe to ignore.
            if((this._allowedConstraints & bit.value) != 0)
                continue; // Bit is allowed.
            
            auto failMessage = errors.errorAndString(this.getRoughLocation(),
                "constraint of kind ", bit.name,
                " is not allowed on type of kind ", this.getKindName()
            );
            if(firstFailure == String2.init)
                firstFailure = failMessage;
        }
        if(firstFailure != String2.init)
        {
            return Result.make(
                Asn1SemanticError.constraintIsNotAllowed,
                "constraint is not allowed by type",
                firstFailure
            );
        }

        this._constraints.put(constraint);
        return Result.noError;
    }

    override void dispose()
    {
        this._constraints.__xdtor();
    }

    abstract string getKindName();
}

final class Asn1IntegerTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        alias ValueT = OneOf!(Asn1ValueIr, Asn1IntegerValueIr, Asn1ValueReferenceIr);
        HashMap!(const(char)[], ValueT) _namedNumbers;
    }

    this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue 
                | containedSubtype
                | valueRange
            );
        }
    }

    Result addNamedNumber(NodeT)(
        const(char)[] name,
        NodeT node, 
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    if(is(NodeT == Asn1IntegerValueIr) || is(NodeT == Asn1ValueReferenceIr))
    in(node !is null, "named number value is null")
    {
        if(this._namedNumbers.getPtr(name) !is null)
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for named number within INTEGER named number list",
                errors.errorAndString(this.getRoughLocation(), "named number called '", name, "' already exists")
            );
        }
        this._namedNumbers.put(name, ValueT(node));
        return Result.noError;
    }

    Result foreachNamedNumber(scope Result delegate(const(char)[] name, Asn1ValueIr number) @nogc nothrow handler)
    {
        foreach(kvp; this._namedNumbers.byKeyValue)
        {
            auto result = handler(kvp.key, kvp.value);
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    version(unittest) IrT getByName(IrT : Asn1ValueIr)(const(char)[] name)
    {
        return cast(IrT)this._namedNumbers[name];
    }

    override string getKindName() => "INTEGER";

    override void dispose()
    {
        super.dispose();
        this._namedNumbers.__xdtor();
    }
}

/++++ Values ++++/

abstract class Asn1ValueIr : Asn1BaseIr
{
    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }
}

final class Asn1IntegerValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        bool _isNegative;
        Asn1Token _token;
    }

    this(Asn1Token token, bool isNegative)
    in(token.type == Asn1Token.Type.number, "token is not of type number")
    {
        super(token.location);
        this._token = token;
        this._isNegative = isNegative;
    }

    Asn1Token.Number getNumber() => this._token.asNumber;
    
    Result asUnsigned(out ulong value, scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance)
    {
        if(this._isNegative)
        {
            return Result.make(
                Asn1SemanticError.numberMustBeUnsigned,
                "expected number to be positive/unsigned",
                errors.errorAndString(
                    this.getRoughLocation(), 
                    "number -", this._token.text, 
                    " is not positive"
                )
            );
        }

        if(!this._token.asNumber.canFitNatively)
        {
            return Result.make(
                Asn1SemanticError.numberIsTooLarge,
                "number is too large to fit into a native 64-bit unsigned integer",
                errors.errorAndString(
                    this.getRoughLocation(), 
                    "number ", this._token.text, 
                    " is not able to be represented as a native 64-bit unsigned integer"
                )
            );
        }

        value = this._token.asNumber.value;
        return Result.noError;
    }
    
    Result asSigned(out long value, scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance)
    {
        if(
            !this._token.asNumber.canFitNatively 
            || this._token.asNumber.value > long.max
            || this._token.asNumber.value > (cast(ulong)-(long.min+1))+2
        )
        {
            return Result.make(
                Asn1SemanticError.numberIsTooLarge,
                "number is too large to fit into a native 64-bit signed integer",
                errors.errorAndString(
                    this.getRoughLocation(), 
                    "number ", this._isNegative ? "-" : "", this._token.text, 
                    " is not able to be represented as a native 64-bit signed integer"
                )
            );
        }

        value = -this._token.asNumber.value;
        return Result.noError;
    }
}

final class Asn1ValueReferenceIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    version(unittest) string getFullString() 
        => (this._moduleRef.length == 0) ? this._valueRef.idup : (this._moduleRef ~ "." ~ this._valueRef).idup;

    @nogc nothrow:

    private
    {
        const(char)[] _moduleRef;
        const(char)[] _valueRef;
    }

    this(Asn1Location roughLocation, const(char)[] module_, const(char)[] valueRef)
    in(module_.length > 0, "module_ must have a length greater than 0")
    in(valueRef.length > 0, "valueRef must have a length greater than 0")
    {
        super(roughLocation);
        this._moduleRef = module_;
        this._valueRef = valueRef;
    }

    this(Asn1Location roughLocation, const(char)[] valueRef)
    in(valueRef.length > 0, "valueRef must have a length greater than 0")
    {
        super(roughLocation);
        this._valueRef = valueRef;
    }
}

/++++ Constraints ++++/

abstract class Asn1ConstraintIr : Asn1BaseIr
{
    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    abstract ConstraintBit getConstraintBits();
}

/++++ Visitor ++++/

private mixin template IrVisitor(ReturnT)
{
    import std.meta : AliasSeq;

    static foreach(Type; AliasSeq!(
        Asn1IntegerTypeIr,

        Asn1IntegerValueIr,
        Asn1ValueReferenceIr,
    ))
    {
        ReturnT visit(Type ir)
        {
            assert(false, "No visit() implementation for IR of type "~Type.stringof);

            static if(is(ReturnT == Result))
                return Result.noError;
        }
    }
}

abstract class Asn1IrVisitor
{
    @nogc nothrow:

    mixin IrVisitor!Result;
}

abstract class Asn1IrVisitorGc
{
    mixin IrVisitor!void;
}