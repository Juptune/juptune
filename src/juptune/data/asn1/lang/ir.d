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
    singleValue = 1 << 2,
    containedSubtype = 1 << 3,
    valueRange = 1 << 4,
    permittedAlphabet = 1 << 5,
    size = 1 << 6,
    type = 1 << 7,
    innerType = 1 << 8,
    pattern = 1 << 9,

    all = singleValue | containedSubtype | valueRange | permittedAlphabet | size | type | innerType | pattern
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

/++++ Special ++++/

final class Asn1ModuleIr : Asn1BaseIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    enum TagDefault
    {
        FAILSAFE,
        explicit,
        implicit,
        automatic,
    }

    private
    {
        const(char)[] _name;
        Asn1ObjectIdSequenceValueIr _moduleVersion;
        TagDefault _tagDefault;
        bool _extensibilityImplied;
        Asn1ExportsIr _exports;
        Asn1ImportsIr _imports;
        Array!Asn1AssignmentIr _assignments;
    }

    this(
        const(char)[] name,
        Asn1ObjectIdSequenceValueIr moduleVersion, 
        TagDefault tagDefault,
        bool extensibilityImplied,
        Asn1ExportsIr exports,
        Asn1ImportsIr imports,
    )
    in(name.length > 0)
    in(moduleVersion !is null)
    in(exports !is null)
    in(imports !is null)
    {
        super(Asn1Location.init);
        this._name = name;
        this._moduleVersion = moduleVersion;
        this._tagDefault = tagDefault;
        this._extensibilityImplied = extensibilityImplied;
        this._exports = exports;
        this._imports = imports;
    }

    Result addAssignment(
        Asn1AssignmentIr ass,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        // TODO: Ensure name is unique.
        this._assignments.put(ass);
        return Result.noError;
    }

    Result foreachAssignment(
        scope Result delegate(Asn1AssignmentIr ass) @nogc nothrow assHandler, // Believe it or not I'm 26
    )
    {
        foreach(ass; this._assignments)
        {
            auto result = assHandler(ass);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    const(char)[] getModuleName() => this._name;
    Asn1ObjectIdSequenceValueIr getModuleVersion() => this._moduleVersion;
    TagDefault getTagDefault() => this._tagDefault;
    bool isExtensibilityImplied() => this._extensibilityImplied;
    Asn1ExportsIr getExports() => this._exports;
    Asn1ImportsIr getImports() => this._imports;
}

final class Asn1ExportsIr : Asn1BaseIr
{
    mixin IrBoilerplate;
    
    @nogc nothrow:

    private
    {
        alias ItemT = OneOf!(Asn1BaseIr, Asn1ValueReferenceIr, Asn1TypeReferenceIr);

        bool _exportsAll;
        Array!ItemT _items;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    this(Asn1Location roughLocation, bool exportsAll)
    in(exportsAll, "when using this overload, exportsAll must be true")
    {
        super(roughLocation);
        this._exportsAll = exportsAll;
    }

    Result addExport(
        Asn1ValueReferenceIr valueRefIr,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(!this._exportsAll, "addExport cannot be used when EXPORTS ALL is in use")
    in(valueRefIr !is null, "valueRefIr is null")
    {
        import std.algorithm : any, map, filter;
        if(this._items
                .slice
                .map!(i => cast(Asn1ValueReferenceIr)i)
                .filter!(i => i !is null)
                .any!(i => i.referToSameModuleLocalSymbol(valueRefIr))
        )
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for exported symbol EXPORTS symbol list",
                errors.errorAndString(
                    this.getRoughLocation(), 
                    "symbol called '", valueRefIr.valueRef, "' has already been exported"
                )
            );
        }

        this._items.put(ItemT(valueRefIr));
        return Result.noError;
    }

    Result addExport(
        Asn1TypeReferenceIr typeRefIr,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(!this._exportsAll, "addExport cannot be used when EXPORTS ALL is in use")
    in(typeRefIr !is null, "typeRefIr is null")
    {
        import std.algorithm : any, map, filter;
        if(this._items
                .slice
                .map!(i => cast(Asn1TypeReferenceIr)i)
                .filter!(i => i !is null)
                .any!(i => i.referToSameModuleLocalSymbol(typeRefIr))
        )
        {
            return Result.make(
                Asn1SemanticError.duplicateKey,
                "duplicate key for exported symbol EXPORTS symbol list",
                errors.errorAndString(
                    this.getRoughLocation(), 
                    "symbol called '", typeRefIr.typeRef, "' has already been exported"
                )
            );
        }

        this._items.put(ItemT(typeRefIr));
        return Result.noError;
    }

    bool doesExportsAll() => this._exportsAll;

    override void dispose()
    {
        this._items.__xdtor();
    }
}

final class Asn1ImportsIr : Asn1BaseIr
{
    mixin IrBoilerplate;
    
    @nogc nothrow:

    private
    {
        alias ItemT = OneOf!(Asn1BaseIr, Asn1ValueReferenceIr, Asn1TypeReferenceIr);

        static struct ImportsFromModule
        {
            const(char)[] moduleRef;
            Asn1ObjectIdSequenceValueIr moduleVersion; // May be null
            Array!ItemT imports;

            this(scope ref typeof(this) other) @nogc nothrow
            {
                this.moduleRef = other.moduleRef;
                this.moduleVersion = other.moduleVersion;
                this.imports = other.imports;
            }
        }

        Array!ImportsFromModule _imports;
        bool _importsLock;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    Result setupImportsForModule(
        const(char)[] moduleRef,
        Asn1ObjectIdSequenceValueIr optionalModuleVersion, // May be null
        scope Result delegate(
            scope Result delegate(Asn1BaseIr ir) @nogc nothrow addImport,
        ) @nogc nothrow populateImports,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(!this._importsLock, "cannot have multiple active calls of this function at once, due to a small risk of memory corruption") // @suppress(dscanner.style.long_line)
    {
        this._importsLock = true;
        scope(exit) this._importsLock = false;

        this._imports.put(ImportsFromModule(moduleRef, optionalModuleVersion));
        scope importsPtr = &this._imports[$-1]; // Done this way around so the import array doesn't perform a needless copy

        Result addImport(Asn1BaseIr ir)
        {
            importsPtr.imports.put(ItemT(ir));
            return Result.noError;
        }

        return populateImports(&addImport);
    }

    Result foreachImport(
        scope Result delegate(
            const(char)[] moduleRef, 
            Asn1ObjectIdSequenceValueIr optionalModuleVersion, // May be null
            Asn1TypeReferenceIr typeRef,
        ) @nogc nothrow handleTypeReference,
        scope Result delegate(
            const(char)[] moduleRef, 
            Asn1ObjectIdSequenceValueIr optionalModuleVersion, // May be null
            Asn1ValueReferenceIr valueRef,
        ) @nogc nothrow handleValueReference,
    )
    {
        foreach(ref importsFromMod; this._imports)
        {
            foreach(import_; importsFromMod.imports)
            {
                if(auto typeRef = cast(Asn1TypeReferenceIr)import_)
                {
                    auto result = handleTypeReference(importsFromMod.moduleRef, importsFromMod.moduleVersion, typeRef);
                    if(result.isError)
                        return result;
                }
                else if(auto valueRef = cast(Asn1ValueReferenceIr)import_)
                {
                    auto result = handleValueReference(importsFromMod.moduleRef, importsFromMod.moduleVersion, valueRef); // @suppress(dscanner.style.long_line)
                    if(result.isError)
                        return result;
                }
                else
                    assert(false, "TODO: Missing case for import_");
            }
        }

        return Result.noError;
    }

    override void dispose()
    {
        this._imports.__xdtor();
    }
}

/++++ Assignments ++++/

abstract class Asn1AssignmentIr : Asn1BaseIr
{
    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }
}

final class Asn1ValueAssignmentIr : Asn1AssignmentIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _name;
        Asn1TypeIr _type;
        Asn1ValueIr _value;
    }

    this(Asn1Location roughLocation, const(char)[] name, Asn1TypeIr type, Asn1ValueIr value)
    in(name.length > 0, "name is empty")
    in(type !is null, "type is null")
    in(value !is null, "value is null")
    {
        super(roughLocation);
        this._name = name;
        this._type = type;
        this._value = value;
    }

    const(char)[] getSymbolName() => this._name;
    Asn1TypeIr getSymbolType() => this._type;
    Asn1ValueIr getSymbolValue() => this._value;
}

final class Asn1TypeAssignmentIr : Asn1AssignmentIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _name;
        Asn1TypeIr _type;
    }

    this(Asn1Location roughLocation, const(char)[] name, Asn1TypeIr type)
    in(name.length > 0, "name is empty")
    in(type !is null, "type is null")
    {
        super(roughLocation);
        this._name = name;
        this._type = type;
    }

    const(char)[] getSymbolName() => this._name;
    Asn1TypeIr getSymbolType() => this._type;
}

/++++ Types ++++/

abstract class Asn1TypeIr : Asn1BaseIr
{
    @nogc nothrow:

    enum Flags
    {
        none,
    }

    private
    {
        Asn1ConstraintIr  _mainConstraint; // May be null
        Asn1ConstraintIr  _additionalConstraint; // May be null
        bool              _isConstraintExtensible;
        ConstraintBit     _allowedConstraints;
        Flags             _flags;
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

    private Result setConstraint(
        Asn1ConstraintIr constraint, 
        scope out Asn1ConstraintIr target,
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

        target = constraint;
        return Result.noError;
    }

    Result setMainConstraint(
        Asn1ConstraintIr constraint,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    ) 
    in(this._mainConstraint is null, "Main constraint has already been set")
        => setConstraint(
            constraint,
            this._mainConstraint,
            errors
        );

    Result setAdditionalConstraint(
        Asn1ConstraintIr constraint,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    in(this._mainConstraint !is null, "Attempted to set additional constraint befor setting main constraint")
    in(this._additionalConstraint is null, "Additional constraint has already been set")
        => setConstraint(
            constraint,
            this._additionalConstraint,
            errors
        );

    void markAsConstraintExtensible()
    in(this._mainConstraint !is null, "Cannot mark type as constraint extensible without first setting a main constraint")
    {
        this._isConstraintExtensible = true;
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

final class Asn1TypeReferenceIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    version(unittest) string getFullString() 
        => (this._moduleRef.length == 0) ? this._typeRef.idup : (this._moduleRef ~ "." ~ this._typeRef).idup;

    @nogc nothrow:

    private
    {
        const(char)[] _moduleRef;
        const(char)[] _typeRef;
    }

    this(Asn1Location roughLocation, const(char)[] module_, const(char)[] typeRef)
    in(module_.length > 0, "module_ must have a length greater than 0")
    in(typeRef.length > 0, "typeRef must have a length greater than 0")
    {
        super(roughLocation, ConstraintBit.none);
        this._moduleRef = module_;
        this._typeRef = typeRef;
    }

    this(Asn1Location roughLocation, const(char)[] typeRef)
    in(typeRef.length > 0, "typeRef must have a length greater than 0")
    {
        super(roughLocation, ConstraintBit.none);
        this._typeRef = typeRef;
    }

    bool referToSameModuleLocalSymbol(Asn1TypeReferenceIr other)
    in(this._moduleRef.length == 0, "this TypeReference does not refer to a module-local symbol")
    in(other._moduleRef.length == 0, "other TypeReference does not refer to a module-local symbol")
    {
        return this._typeRef == other._typeRef;
    }

    override string getKindName() => "<unresolved type reference>";
    const(char)[] moduleRef() => this._moduleRef;
    const(char)[] typeRef() => this._typeRef;
}

alias Asn1GeneralizedTimeTypeIr = Asn1BasicTypeIr!("GeneralizedTime", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)
alias Asn1UtcTimeTypeIr = Asn1BasicTypeIr!("UTCTime", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)

/++++ Values ++++/

abstract class Asn1ValueIr : Asn1BaseIr
{
    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }
}

final class Asn1BooleanValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        bool _value;
    }

    this(Asn1Location roughLocation, bool value)
    {
        super(roughLocation);
        this._value = value;
    }

    bool asBool() => this._value;
}

final class Asn1ChoiceValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _name;
        Asn1ValueIr _value;
    }

    this(Asn1Location roughLocation, const(char)[] name, Asn1ValueIr value)
    in(name.length > 0, "name must not be empty")
    in(value !is null, "value is null")
    {
        super(roughLocation);
        this._name = name;
        this._value = value;
    }

    const(char)[] getChoiceName() => this._name;
    Asn1ValueIr getChoiceValue() => this._value;
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

final class Asn1NullValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }
}

final class Asn1CstringValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _value;
    }

    this(Asn1Location roughLocation, const(char)[] value)
    {
        super(roughLocation);
        this._value = value;
    }

    const(char)[] asString() => this._value;
}

final class Asn1HstringValueIr : Asn1ValueIr
{
    import juptune.data.asn1.lang.lexer : Asn1HstringRange;

    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _value;
    }

    this(Asn1Location roughLocation, const(char)[] value)
    {
        super(roughLocation);
        this._value = value;
    }

    const(char)[] asString() => this._value;
    Asn1HstringRange asHstringRange() => Asn1HstringRange(this._value);
}

final class Asn1BstringValueIr : Asn1ValueIr
{
    import juptune.data.asn1.lang.lexer : Asn1BstringRange;
    
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        const(char)[] _value;
    }

    this(Asn1Location roughLocation, const(char)[] value)
    {
        super(roughLocation);
        this._value = value;
    }

    const(char)[] asString() => this._value;
    Asn1BstringRange asBstringRange() => Asn1BstringRange(this._value);
}

final class Asn1ValueSequenceIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Array!Asn1ValueIr _values;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    void addSequenceValue(Asn1ValueIr value)
    in(value !is null, "value is null")
    {
        this._values.put(value);
    }

    Result foreachSequenceValue(
        scope Result delegate(Asn1ValueIr) @nogc nothrow handler,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        foreach(value; this._values)
        {
            auto result = handler(value);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    override void dispose()
    {
        super.dispose();
        this._values.__xdtor();
    }
}

final class Asn1NamedValueSequenceIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        static struct Item
        {
            const(char)[] name;
            Asn1ValueIr value;
        }

        Array!Item _values;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    void addSequenceNamedValue(const(char)[] name, Asn1ValueIr value)
    in(name.length > 0, "name is empty?")
    in(value !is null, "value is null")
    {
        this._values.put(Item(name, value));
    }

    Result foreachSequenceNamedValue(
        scope Result delegate(const(char)[], Asn1ValueIr) @nogc nothrow handler,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        foreach(value; this._values)
        {
            auto result = handler(value.name, value.value);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    override void dispose()
    {
        super.dispose();
        this._values.__xdtor();
    }
}

final class Asn1ObjectIdSequenceValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Array!Asn1ValueIr _values;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    void addObjectId(Asn1ValueIr value)
    in(value !is null, "value is null")
    {
        this._values.put(value);
    }

    Result foreachObjectId(
        scope Result delegate(Asn1ValueIr) @nogc nothrow handler,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        foreach(value; this._values)
        {
            auto result = handler(value);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    override void dispose()
    {
        super.dispose();
        this._values.__xdtor();
    }
}

// Since any sequence-like value can be empty, and it has different meanings, it's better to have a
// unique IR for this use-case and distinguish its meaning later.
final class Asn1EmptySequenceValueIr : Asn1ValueIr
{
    import juptune.data.asn1.lang.lexer : Asn1BstringRange;
    
    mixin IrBoilerplate;

    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
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

    bool referToSameModuleLocalSymbol(Asn1ValueReferenceIr other)
    in(this._moduleRef.length == 0, "this ValueReference does not refer to a module-local symbol")
    in(other._moduleRef.length == 0, "other ValueReference does not refer to a module-local symbol")
    {
        return this._valueRef == other.valueRef;
    }

    const(char)[] moduleRef() => this._moduleRef;
    const(char)[] valueRef() => this._valueRef;
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

final class Asn1UnionConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Array!Asn1ConstraintIr _constraints;
        ConstraintBit _constraintBit;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    void addUnionConstraint(Asn1ConstraintIr constraint)
    in(constraint !is null, "constraint is null")
    {
        this._constraintBit |= constraint.getConstraintBits();
        this._constraints.put(constraint);
    }

    Result foreachUnionConstraint(
        scope Result delegate(Asn1ConstraintIr) @nogc nothrow handler,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        foreach(item; this._constraints)
        {
            auto result = handler(item);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    override void dispose()
    {
        this._constraints.__xdtor();
    }

    override ConstraintBit getConstraintBits() => this._constraintBit;
}

final class Asn1IntersectionConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Array!Asn1ConstraintIr _constraints;
        ConstraintBit _constraintBit;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    void addIntersectionConstraint(Asn1ConstraintIr constraint)
    in(constraint !is null, "constraint is null")
    {
        this._constraintBit |= constraint.getConstraintBits();
        this._constraints.put(constraint);
    }

    Result foreachIntersectionConstraint(
        scope Result delegate(Asn1ConstraintIr) @nogc nothrow handler,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance
    )
    {
        foreach(item; this._constraints)
        {
            auto result = handler(item);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    override void dispose()
    {
        this._constraints.__xdtor();
    }

    override ConstraintBit getConstraintBits() => this._constraintBit;
}

final class Asn1ConstraintWithExclusionsIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1ConstraintIr _constraint;
        Asn1ConstraintIr _exclusion;
    }

    this(Asn1ConstraintIr constraint, Asn1ConstraintIr exclusion)
    in(constraint !is null, "constraint is null")
    in(exclusion !is null, "exclusion is null")
    {
        super(constraint.getRoughLocation());
        this._constraint = constraint;
        this._exclusion = exclusion;
    }

    override ConstraintBit getConstraintBits() 
        => this._constraint.getConstraintBits() | this._exclusion.getConstraintBits();
}

final class Asn1SingleValueConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1ValueIr _value;
    }

    this(Asn1ValueIr value)
    in(value !is null, "value is null")
    {
        super(value.getRoughLocation());
        this._value = value;
    }

    Asn1ValueIr getValue() => this._value;

    override ConstraintBit getConstraintBits() => ConstraintBit.singleValue;
}

final class Asn1ContainedSubtypeConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1TypeIr _type;
    }

    this(Asn1TypeIr type)
    in(type !is null, "type is null")
    {
        super(type.getRoughLocation());
        this._type = type;
    }

    Asn1TypeIr getSubtype() => this._type;

    override ConstraintBit getConstraintBits() => ConstraintBit.containedSubtype;
}

final class Asn1ValueRangeConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    static struct Endpoint
    {
        Asn1ValueIr valueIr;    // Specified value for the endpoint - will be null if isUnbounded is `true`.
        bool isOpen;            // Whether "<" was attached or not.
        bool isUnbounded;       // Not specified or specified as MIN/MAX.
    }

    private
    {
        Endpoint _lower;
        Endpoint _upper;
    }

    this(Asn1Location location, Endpoint lower, Endpoint upper)
    {
        super(location);
        this._lower = lower;
        this._upper = upper;
    }

    Endpoint getLower() => this._lower;
    Endpoint getUpper() => this._upper;

    override ConstraintBit getConstraintBits() => ConstraintBit.valueRange;
}

final class Asn1PermittedAlphabetConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1ConstraintIr _constraint;
        Asn1ConstraintIr _additionalConstraint; // May be null
        bool             _isExtensible;
    }

    this(Asn1ConstraintIr constraint, bool isExtensible, Asn1ConstraintIr additional)
    in(constraint !is null, "constraint is null")
    in(additional is null || isExtensible, "additional cannot be non-null if isExtensible is true")
    {
        super(constraint.getRoughLocation());
        this._constraint = constraint;
        this._additionalConstraint = additional;
        this._isExtensible = isExtensible;
    }

    Asn1ConstraintIr getMainConstraint() => this._constraint;
    Asn1ConstraintIr getAdditionalConstraint() => this._additionalConstraint;
    bool isExtensible() => this._isExtensible;

    override ConstraintBit getConstraintBits() => ConstraintBit.permittedAlphabet;
}

final class Asn1SizeConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1ConstraintIr _constraint;
        Asn1ConstraintIr _additionalConstraint; // May be null
        bool             _isExtensible;
    }

    this(Asn1ConstraintIr constraint, bool isExtensible, Asn1ConstraintIr additional)
    in(constraint !is null, "constraint is null")
    in(additional is null || isExtensible, "additional cannot be non-null if isExtensible is true")
    {
        super(constraint.getRoughLocation());
        this._constraint = constraint;
        this._additionalConstraint = additional;
        this._isExtensible = isExtensible;
    }

    Asn1ConstraintIr getMainConstraint() => this._constraint;
    Asn1ConstraintIr getAdditionalConstraint() => this._additionalConstraint;
    bool isExtensible() => this._isExtensible;

    override ConstraintBit getConstraintBits() => ConstraintBit.size;
}

final class Asn1PatternConstraintIr : Asn1ConstraintIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        Asn1ValueIr _value;
    }

    this(Asn1ValueIr value)
    in(value !is null, "value is null")
    {
        super(value.getRoughLocation());
        this._value = value;
    }

    Asn1ValueIr getValue() => this._value;

    override ConstraintBit getConstraintBits() => ConstraintBit.pattern;
}

/++++ Visitor ++++/

private mixin template IrVisitor(ReturnT)
{
    import std.meta : AliasSeq;

    static foreach(Type; AliasSeq!(
        Asn1ModuleIr,
        Asn1ExportsIr,
        Asn1ImportsIr,

        Asn1ValueAssignmentIr,
        Asn1TypeAssignmentIr,

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
        Asn1TypeReferenceIr,
        Asn1GeneralizedTimeTypeIr,
        Asn1UtcTimeTypeIr,

        Asn1UnionConstraintIr,
        Asn1IntersectionConstraintIr,
        Asn1ConstraintWithExclusionsIr,
        Asn1SingleValueConstraintIr,
        Asn1ContainedSubtypeConstraintIr,
        Asn1ValueRangeConstraintIr,
        Asn1PermittedAlphabetConstraintIr,
        Asn1SizeConstraintIr,
        Asn1PatternConstraintIr,

        Asn1BooleanValueIr,
        Asn1ChoiceValueIr,
        Asn1IntegerValueIr,
        Asn1NullValueIr,
        Asn1CstringValueIr,
        Asn1HstringValueIr,
        Asn1BstringValueIr,
        Asn1ValueSequenceIr,
        Asn1NamedValueSequenceIr,
        Asn1ObjectIdSequenceValueIr,
        Asn1EmptySequenceValueIr,
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