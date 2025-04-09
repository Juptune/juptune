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

    String2 errorAndString(Args...)(Asn1Location location, scope auto ref Args args)
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

// A type that doesn't really have any special extras beyond being builtin.
private final class Asn1BasicTypeIr(string Kind, ConstraintBit AllowedConstraints) : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation, AllowedConstraints);
    }

    override string getKindName() => Kind;
}

final class Asn1BitStringTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        alias ValueT = OneOf!(Asn1ValueIr, Asn1IntegerValueIr, Asn1ValueReferenceIr);
        HashMap!(const(char)[], ValueT) _namedBits;
    }

    this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue 
                | containedSubtype
                | size
            );
        }
    }

    Result addNamedBit(NodeT)(
        const(char)[] name,
        NodeT node, 
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    if(is(NodeT == Asn1IntegerValueIr) || is(NodeT == Asn1ValueReferenceIr))
    in(node !is null, "named bit value is null")
    {
        if(this._namedBits.getPtr(name) !is null)
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for named bit within BIT STRING named number list",
                errors.errorAndString(this.getRoughLocation(), "named bit called '", name, "' already exists")
            );
        }
        this._namedBits.put(name, ValueT(node));
        return Result.noError;
    }

    Result foreachNamedBit(scope Result delegate(const(char)[] name, Asn1ValueIr bit) @nogc nothrow handler)
    {
        foreach(kvp; this._namedBits.byKeyValue)
        {
            auto result = handler(kvp.key, kvp.value);
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    version(unittest) IrT getByName(IrT : Asn1ValueIr)(const(char)[] name)
    {
        return cast(IrT)this._namedBits[name];
    }

    override string getKindName() => "BIT STRING";

    override void dispose()
    {
        super.dispose();
        this._namedBits.__xdtor();
    }
}

alias Asn1BooleanTypeIr = Asn1BasicTypeIr!("BOOLEAN", ConstraintBit.singleValue | ConstraintBit.containedSubtype);
alias Asn1CharacterStringTypeIr = Asn1BasicTypeIr!("CHARACTER STRING", ConstraintBit.singleValue | ConstraintBit.size | ConstraintBit.innerType); // @suppress(dscanner.style.long_line)
alias Asn1BMPStringTypeIr = Asn1BasicTypeIr!("BMPString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1GeneralStringTypeIr = Asn1BasicTypeIr!("GeneralString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1GraphicStringTypeIr = Asn1BasicTypeIr!("GraphicString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1IA5StringTypeIr = Asn1BasicTypeIr!("IA5String", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1ISO646StringTypeIr = Asn1BasicTypeIr!("ISO646String", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1NumericStringTypeIr = Asn1BasicTypeIr!("NumericString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1PrintableStringTypeIr = Asn1BasicTypeIr!("PrintableString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1TeletexStringTypeIr = Asn1BasicTypeIr!("TeletexString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1T61StringTypeIr = Asn1BasicTypeIr!("T61String", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1UniversalStringTypeIr = Asn1BasicTypeIr!("UniversalString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1UTF8StringTypeIr = Asn1BasicTypeIr!("UTF8String", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1VideotexStringTypeIr = Asn1BasicTypeIr!("VideotexString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)
alias Asn1VisibleStringTypeIr = Asn1BasicTypeIr!("VisibleString", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.size | ConstraintBit.permittedAlphabet | ConstraintBit.pattern); // @suppress(dscanner.style.long_line)

final class Asn1ChoiceTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        static struct Item
        {
            const(char)[] name;
            Asn1TypeIr type;
        }

        Array!Item      _choices; // Not using a hashmap as lexical order is important to know. Can always have both side-by-side if key lookups are needed/too slow with a linear search.
        Nullable!size_t _extensibleIndex; // Points to the first element that appears after the extensible marker (if one was provided). When == to _choices, it means no further types follow the marker.
    }

    this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue
                | containedSubtype
                | innerType
            );
        }
    }

    Result addChoice(
        const(char)[] name,
        Asn1TypeIr type,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        import std.algorithm : any;

        if(this._choices.slice.any!(item => item.name == name))
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "found duplicate key within `CHOICE` selection list",
                errors.errorAndString(this.getRoughLocation(), "key `", name, "` appears multiple times in `CHOICE` selection list") // @suppress(dscanner.style.long_line)
            );
        }

        this._choices.put(Item(name, type));
        return Result.noError;
    }

    void markAsExtensible()
    in(this._extensibleIndex.isNull, "this CHOICE type was already marked as extensible?")
    {
        this._extensibleIndex = this._choices.length;
    }

    bool isExtensible() => !this._extensibleIndex.isNull;

    Result foreachChoice(
        scope Result delegate(const(char)[] name, Asn1TypeIr choice, bool isExtensible) @nogc nothrow handler
    )
    {
        foreach(i, nameAndType; this._choices.slice)
        {
            auto result = handler(
                nameAndType.name, 
                nameAndType.type, 
                this._extensibleIndex.isNull ? false : this._extensibleIndex.get <= i
            );
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    override string getKindName() => "CHOICE";

    override void dispose()
    {
        super.dispose();
        this._choices.__xdtor();
    }
}

alias Asn1EmbeddedPdvTypeIr = Asn1BasicTypeIr!("EMBEDDED PDV", ConstraintBit.singleValue | ConstraintBit.innerType);

final class Asn1EnumeratedTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        static struct Item
        {
            const(char)[] name;
            Nullable!long number;
            Asn1ValueReferenceIr numberRef;
        }

        Array!Item      _enumerations; // Not using a hashmap as lexical order is important to know. Can always have both side-by-side if key lookups are needed/too slow with a linear search.
        Nullable!size_t _extensibleIndex; // Points to the first element that appears after the extensible marker (if one was provided). When == to _choices, it means no further types follow the marker.
    }

    this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue
                | containedSubtype
            );
        }
    }

    Result addEnumerationImplicit(
        const(char)[] name,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        import std.algorithm : any;

        if(this._enumerations.slice.any!(item => item.name == name))
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "found duplicate key within `ENUMERATED` enumerations list",
                errors.errorAndString(this.getRoughLocation(), "key `", name, "` appears multiple times in `ENUMERATED` enumerations list") // @suppress(dscanner.style.long_line)
            );
        }

        this._enumerations.put(Item(name)); // Both value fields are null to signal that it needs resolving.
        return Result.noError;
    }

    Result addEnumerationExplicit(IrT)(
        const(char)[] name,
        IrT enumeration,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    if(is(IrT == Asn1ValueIr) || is(IrT == Asn1ValueReferenceIr) || is(IrT == Asn1IntegerValueIr))
    {
        import std.algorithm : any;

        if(this._enumerations.slice.any!(item => item.name == name))
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "found duplicate key within `ENUMERATED` enumerations list",
                errors.errorAndString(this.getRoughLocation(), "key `", name, "` appears multiple times in `ENUMERATED` enumerations list") // @suppress(dscanner.style.long_line)
            );
        }

        auto item = Item(name);
        if(auto intValue = cast(Asn1IntegerValueIr)enumeration)
        {
            long value;
            auto result = intValue.asSigned(value);
            if(result.isError)
                return result;
            item.number = value;
        }
        else if(auto valueRef = cast(Asn1ValueReferenceIr)enumeration)
            item.numberRef = valueRef;
        else
            assert(false, "invalid value passed as `enumeration` - unhandled type");

        this._enumerations.put(item);
        return Result.noError;
    }

    void markAsExtensible()
    in(this._extensibleIndex.isNull, "this ENUMERATED type was already marked as extensible?")
    {
        this._extensibleIndex = this._enumerations.length;
    }

    bool isExtensible() => !this._extensibleIndex.isNull;

    // TODO: note that `number` is null for items where a value needs to be auto-assigned/is a reference,
    //       but the semantic pass for this node hasn't been ran yet, so it cannot be determined.
    Result foreachEnumeration(
        scope Result delegate(const(char)[] name, Nullable!long number, bool isExtensible) @nogc nothrow handler,
    )
    {
        foreach(i, nameAndValue; this._enumerations.slice)
        {
            const isExtensible = this._extensibleIndex.isNull 
                ? false 
                : this._extensibleIndex.get <= i;

            auto result = handler(nameAndValue.name, nameAndValue.number, isExtensible);
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    override string getKindName() => "ENUMERATED";

    override void dispose()
    {
        super.dispose();
        this._enumerations.__xdtor();
    }
}

alias Asn1ExternalTypeIr = Asn1BasicTypeIr!("EXTERNAL", ConstraintBit.singleValue | ConstraintBit.innerType);

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

alias Asn1NullTypeIr = Asn1BasicTypeIr!("NULL", ConstraintBit.singleValue | ConstraintBit.containedSubtype);
alias Asn1ObjectIdentifierTypeIr = Asn1BasicTypeIr!("OBJECT IDENTIFIER", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)
alias Asn1OctetStringTypeIr = Asn1BasicTypeIr!("OCTET STRING", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.size); // @suppress(dscanner.style.long_line)
alias Asn1RealTypeIr = Asn1BasicTypeIr!("REAL", ConstraintBit.singleValue | ConstraintBit.containedSubtype | ConstraintBit.valueRange | ConstraintBit.innerType); // @suppress(dscanner.style.long_line)
alias Asn1RelativeOidTypeIr = Asn1BasicTypeIr!("RELATIVE-OID", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)

private final class Asn1SequenceTypeBase(string Kind) : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        static struct Item
        {
            enum Flags : ubyte
            {
                none,

                // Not compatible with any other flag.
                isComponentsOf = 1 << 0,
                isOptional = 1 << 1,
            }

            Flags flags;
            const(char)[] name;
            Asn1TypeIr type;
            Asn1ValueIr defaultValue;

            @nogc nothrow:

            bool isOptional() => (this.flags & Flags.isOptional) > 0;
            bool isComponentsOf() => (this.flags & Flags.isComponentsOf) > 0;
            bool hasDefault() => this.defaultValue !is null;
        }

        Array!Item _components;
        Nullable!size_t _extensibleIndex; // Points to the first element that appears after the extensible marker (if one was provided). When == to _choices, it means no further types follow the marker.
    }

    this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue 
                | containedSubtype
                | innerType
            );
        }
    }

    Result addComponent(
        const(char)[] name,
        Asn1TypeIr node,
        bool isOptional,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(node !is null, "component is null")
    {
        import std.algorithm : any;

        if(this._components.slice.any!(c => c.name == name))
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for component within SEQUENCE named type list",
                errors.errorAndString(this.getRoughLocation(), "component called '", name, "' already exists")
            );
        }

        Item item;
        item.name = name;
        item.type = node;
        if(isOptional)
            item.flags |= Item.Flags.isOptional;
        this._components.put(item);

        return Result.noError;
    }

    Result addComponentWithDefault(
        const(char)[] name,
        Asn1TypeIr node,
        Asn1ValueIr value,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(node !is null, "component is null")
    {
        import std.algorithm : any;

        if(this._components.slice.any!(c => c.name == name))
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for component within SEQUENCE named type list",
                errors.errorAndString(this.getRoughLocation(), "component called '", name, "' already exists")
            );
        }

        Item item;
        item.name = name;
        item.type = node;
        item.defaultValue = value;
        this._components.put(item);

        return Result.noError;
    }

    void addComponentsOf(Asn1TypeIr node)
    in(node !is null, "component is null")
    {
        Item item;
        item.type = node;
        item.flags |= Item.Flags.isComponentsOf;
        this._components.put(item);
    }

    void markAsExtensible()
    in(this._extensibleIndex.isNull, "this "~Kind~" type was already marked as extensible?")
    {
        this._extensibleIndex = this._components.length;
    }

    bool isExtensible() => !this._extensibleIndex.isNull;

    version(unittest) auto componentsUnittest()
    {
        return this._components.slice;
    }

    override string getKindName() => Kind;

    override void dispose()
    {
        super.dispose();
        this._components.__xdtor();
    }
}
alias Asn1SequenceTypeIr = Asn1SequenceTypeBase!("SEQUENCE");
alias Asn1SetTypeIr = Asn1SequenceTypeBase!("SET");

private final class Asn1SequenceOfTypeBase(string Kind) : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Nullable!(const(char)[]) _name;
        Asn1TypeIr _type;
    }

    private this(Asn1Location roughLocation)
    {
        with(ConstraintBit)
        {
            super(roughLocation,
                singleValue 
                | containedSubtype
                | innerType
            );
        }
    }

    this(Asn1Location roughLocation, Asn1TypeIr type)
    {
        this(roughLocation);
        this._type = type;
    }

    this(Asn1Location roughLocation, Asn1TypeIr type, const(char)[] name)
    {
        this(roughLocation);
        this._type = type;
        this._name = name;
    }

    Nullable!(const(char)[]) getItemTypeName() => this._name;
    Asn1TypeIr getTypeOfItems() => this._type;

    override string getKindName() => Kind;
}
alias Asn1SequenceOfTypeIr = Asn1SequenceOfTypeBase!("SEQUENCE");
alias Asn1SetOfTypeIr = Asn1SequenceOfTypeBase!("SET");

final class Asn1TaggedTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;
    
    @nogc nothrow:

    enum Encoding
    {
        unspecified, // Use whatever the module default is
        implicit, // Replace the encoded tag number
        explicit, // Wrap encoded value in a structure with the specified tag number
    }
    
    enum Class
    {
        unspecified,
        application,
        universal,
        private_,
    }

    private
    {
        alias NumberT = OneOf!(Asn1ValueIr, Asn1IntegerValueIr, Asn1ValueReferenceIr);

        Class       _class;
        NumberT     _number;
        Encoding    _encoding;
        Asn1TypeIr  _type;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation, ConstraintBit.none);
    }

    void setTag(NodeT)(Class class_, NodeT number, Encoding encoding)
    if(is(NodeT == Asn1IntegerValueIr) || is(NodeT == Asn1ValueReferenceIr))
    in(number !is null, "number is null")
    {
        this._class = class_;
        this._number = number;
        this._encoding = encoding;
    }
    Class getClass() => this._class;
    Asn1ValueIr getNumberIr() => this._number; // TODO: Helper function to resolve it to a number
    Encoding getEncoding() => this._encoding;

    void setUnderlyingType(Asn1TypeIr type)
    in(type !is null, "type is null")
    {
        this._type = type;
    }
    Asn1TypeIr getUnderlyingType()
    out(result; result !is null, "Underlying type hasn't been set yet")
        => this._type;

    override string getKindName() => this._type.getKindName();
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

        value = this._isNegative ? -this._token.asNumber.value : this._token.asNumber.value;
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
        Asn1BitStringTypeIr,
        Asn1BooleanTypeIr,
        Asn1CharacterStringTypeIr,
        Asn1BMPStringTypeIr,
        Asn1GeneralStringTypeIr,
        Asn1GraphicStringTypeIr,
        Asn1IA5StringTypeIr,
        Asn1ISO646StringTypeIr,
        Asn1NumericStringTypeIr,
        Asn1PrintableStringTypeIr,
        Asn1TeletexStringTypeIr,
        Asn1T61StringTypeIr,
        Asn1UniversalStringTypeIr,
        Asn1UTF8StringTypeIr,
        Asn1VideotexStringTypeIr,
        Asn1VisibleStringTypeIr,
        Asn1IntegerTypeIr,
        Asn1ChoiceTypeIr,
        Asn1EmbeddedPdvTypeIr,
        Asn1EnumeratedTypeIr,
        Asn1ExternalTypeIr,
        Asn1NullTypeIr,
        Asn1ObjectIdentifierTypeIr,
        Asn1OctetStringTypeIr,
        Asn1RealTypeIr,
        Asn1RelativeOidTypeIr,
        Asn1SequenceTypeIr,
        Asn1SetTypeIr,
        Asn1SequenceOfTypeIr,
        Asn1SetOfTypeIr,
        Asn1TaggedTypeIr,

        Asn1IntegerValueIr,
        Asn1ValueReferenceIr,
    ))
    {
        ReturnT visit(Type ir) // @suppress(dscanner.suspicious.unused_parameter)
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