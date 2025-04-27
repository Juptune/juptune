/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.ir;

import std.sumtype  : SumType;
import std.typecons : Nullable, Flag;

import juptune.core.ds : Array, String2, HashMap;
import juptune.core.util : Result;
import juptune.data.asn1.lang.ast; // Intentionally everything
import juptune.data.asn1.lang.common : Asn1Location, Asn1ParserContext;
import juptune.data.asn1.lang.lexer : Asn1Token;

enum Asn1SemanticError
{
    none,

    // Generated during parsing.
    constraintIsNotAllowed,
    duplicateKey,
    numberMustBeUnsigned,
    numberIsTooLarge,
    numberCannotBeNegativeZero,
    typeCannotBeImplicit,

    // Actual semantic errors.
    typeMismatch,
    duplicateNamedNumber,
    constraint,

    bug,
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
        scope putter = Putter(this, &buffer);

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
    // These stages only cover destructive steps; non-destructive steps are done externally (e.g. typechecker.d)
    //
    // This is because I believe in keeping as little semantic logic as required in the actual IR classes, so it's
    // solely isolated to steps that need to modify internal state in a way that the public API doesn't allow for.
    enum SemanticStageBit
    {
        none = 0,
        
        // NOTE: Annex C.3.2.3 is performed first since it simplifies a lot of the other stuff.
        resolveReferences = 1 << 0, // Covers ISO/IEC 8824-1:2021 Annex C.3.2.3 and Annex C.3.2.5
        implicitMutations = 1 << 1, // Covers automatic tagging; setting the tag default, EXTENSIBILITY IMPLIED, etc...
    }

    static struct SemanticInfo // NOTE: This is setup internally when using Asn1ModuleIr, no need to set it up externally in such cases.
    {
        Asn1ModuleIr.TagDefault tagDefault;
    }

    private
    {
        Asn1Location _roughLocation;
        SemanticStageBit _stageBits;
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

    /++++ Semantic Stages (I don't care it's a slow design, I can change it if it ever becomes an actual) ++++/

    alias LookupOneOf = OneOf!(Asn1BaseIr, 
        // Returned by:
        //  Asn1ModuleIr
        //  The user code will likely implement a cross-module lookup which returns these
        Asn1ValueAssignmentIr,
        Asn1TypeAssignmentIr,

        // Returned by:
        //  Asn1BitStringTypeIr
        //  Asn1ChoiceTypeIr
        //  Asn1SequenceTypeBase
        //  Asn1IntegerTypeIr
        Asn1ValueIr, 
        Asn1TypeIr
    );
    alias LookupItemT = Nullable!LookupOneOf;
    alias LookupFunc = LookupItemT delegate(Asn1BaseIr refNode) @nogc nothrow;

    bool hasDoneSemanticStage(SemanticStageBit stageBit) @nogc nothrow
        => (this._stageBits & stageBit) > 0;
    
    Result doSemanticStage(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        if(this._stageBits & stageBit)
            return Result.noError;
        this._stageBits |= stageBit;

        return this.doSemanticStageImpl(stageBit, lookup, context, info, errors);
    }

    protected abstract Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow;

    /++++ Some general helpers ++++/

    // Purpose: To help flatten the tree to make it easier to work with.
    protected static void replaceIfReference(scope ref Asn1ValueIr value) @nogc nothrow
    {
        if(auto valueRef = cast(Asn1ValueReferenceIr)value)
            value = valueRef.getResolvedValueRecurse();
    }

    // Purpose: To help flatten the tree to make it easier to work with.
    protected static void replaceIfReference(scope ref Asn1TypeIr type) @nogc nothrow
    {
        if(auto typeRef = cast(Asn1TypeReferenceIr)type)
            type = typeRef.getResolvedTypeRecurse();
    }
}

private struct OneOf(BaseIrT : Asn1BaseIr, IrTypes...) // @suppress(dscanner.suspicious.incomplete_operator_overloading)
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

    size_t toHash() const @nogc @safe pure nothrow
    {
        // To produce the warning, just comment out this entire function.
        assert(false, "toHash is not implemented due to a compiler warning I don't know how to solve");
        return 0;
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

    // NOTE: This one is more for user code than semantic stuff.
    // NOTE: Only looks up local, top-level symbols.
    Asn1BaseIr lookupSymbolOrNull(const(char)[] symbolName)
    {
        foreach(ass; this._assignments)
        {
            if(ass.getSymbolName() == symbolName)
                return ass;
        }

        return null;
    }

    version(unittest) IrT mustLookupAs(IrT)(const(char)[] symbolName)
    {
        auto symbol = cast(IrT)this.lookupSymbolOrNull(symbolName);
        assert(symbol !is null, symbolName);
        return symbol;
    }

    LookupItemT lookup(Asn1BaseIr refNode) @nogc nothrow
    {
        if(auto typeRef = cast(Asn1TypeReferenceIr)refNode)
        {
            if(typeRef.moduleRef.length > 0 && typeRef.moduleRef != this._name)
                return LookupItemT.init;

            foreach(ass; this._assignments)
            {
                auto typeAss = cast(Asn1TypeAssignmentIr)ass;
                if(typeAss is null || typeAss.getSymbolName() != typeRef.typeRef)
                    continue;
                return LookupItemT(LookupOneOf(typeAss));
            }

            return LookupItemT.init;
        }
        else if(auto valueRef = cast(Asn1ValueReferenceIr)refNode)
        {
            if(valueRef.moduleRef.length > 0 && valueRef.moduleRef != this._name)
                return LookupItemT.init;

            foreach(ass; this._assignments)
            {
                auto valueAss = cast(Asn1ValueAssignmentIr)ass;
                if(valueAss is null || valueAss.getSymbolName() != valueRef.valueRef)
                    continue;
                return LookupItemT(LookupOneOf(valueAss));
            }

            return LookupItemT.init;
        }
        else
            assert(false, "bug: Missing case for reference node? Wrong node passed into lookup?");

        return LookupItemT.init;
    }

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        info.tagDefault = this._tagDefault;

        auto fallbackLookup = lookup;
        lookup = (refNode) {
            auto resultIr = this.lookup(refNode);
            return resultIr.isNull ? fallbackLookup(refNode) : resultIr;
        };

        auto result = this._moduleVersion.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;
        
        result = this._exports.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;
        
        result = this._imports.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ass; this._assignments)
        {
            result = ass.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }
        
        return Result.noError;
    }
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
                .any!(i => i.refersToSameModuleLocalSymbol(valueRefIr))
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
                .any!(i => i.refersToSameModuleLocalSymbol(typeRefIr))
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

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        // NOTE: We intentionally don't destructively replace references in this type,
        //       as we need to still access the symbol names.

        foreach(item; this._items)
        {
            auto result = item.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
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

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        // NOTE: We intentionally don't destructively replace references in this type,
        //       as we need to still access the symbol names.

        foreach(ref item; this._imports)
        {
            if(item.moduleVersion !is null)
            {
                auto result = item.moduleVersion.doSemanticStage(stageBit, lookup, context, info, errors);
                if(result.isError)
                    return result;
            }

            foreach(import_; item.imports)
            {
                auto result = import_.doSemanticStage(stageBit, lookup, context, info, errors);
                if(result.isError)
                    return result;
            }
        }

        return Result.noError;
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

    abstract const(char)[] getSymbolName();
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

    override const(char)[] getSymbolName() => this._name;
    Asn1TypeIr getSymbolType() => this._type;
    Asn1ValueIr getSymbolValue() => this._value;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._type.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._type);

        scope fallbackLookup = lookup;
        lookup = (ir) {
            auto resolved = this._type.lookup(ir);
            return resolved.isNull ? fallbackLookup(ir) : resolved;
        };

        result = this._value.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._value);

        return Result.noError;
    }
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

    override const(char)[] getSymbolName() => this._name;
    Asn1TypeIr getSymbolType() => this._type;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._type.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._type);

        return Result.noError;
    }
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
    in(this._mainConstraint !is null, "Cannot mark type as constraint extensible without first setting a main constraint") // @suppress(dscanner.style.long_line)
    {
        this._isConstraintExtensible = true;
    }

    Asn1ConstraintIr getMainConstraintOrNull() => this._mainConstraint;
    Asn1ConstraintIr getAdditionalConstraintOrNull() => this._additionalConstraint;

    LookupItemT lookup(Asn1BaseIr refNode) => LookupItemT.init; // Some types, like BIT STRING, have additional scoped values

    abstract string getKindName();

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        if(this._mainConstraint !is null)
        {
            auto result = this._mainConstraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        if(this._additionalConstraint !is null)
        {
            auto result = this._additionalConstraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
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

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        return Result.noError;
    }
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

    override LookupItemT lookup(Asn1BaseIr refIr)
    {
        if(auto valueRef = cast(Asn1ValueReferenceIr)refIr)
        {
            if(valueRef.moduleRef.length > 0)
                return LookupItemT.init;

            bool wasFound;
            auto number = this._namedBits.tryGet(valueRef.valueRef, wasFound);
            
            return wasFound ? LookupItemT(LookupOneOf(number.ir)) : LookupItemT.init;
        }

        return LookupItemT.init;
    }

    override void dispose()
    {
        super.dispose();
        this._namedBits.__xdtor();
    }

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ref kvp; this._namedBits.byKeyValue)
        {
            result = kvp.value.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(kvp.value);
        }

        return Result.noError;
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

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ref nameAndType; this._choices.slice)
        {
            result = nameAndType.type.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(nameAndType.type);
        }

        return Result.noError;
    }
}

alias Asn1EmbeddedPdvTypeIr = Asn1BasicTypeIr!("EMBEDDED PDV", ConstraintBit.singleValue | ConstraintBit.innerType);

final class Asn1EnumeratedTypeIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    private
    {
        alias NumberT = OneOf!(Asn1ValueIr, Asn1ValueReferenceIr, Asn1IntegerValueIr);

        static struct Item
        {
            const(char)[] name;
            NumberT number;
            bool isImplicit;
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
        Asn1IntegerValueIr emptyValue, // Value doesn't matter, we just need an allocated object to overwrite the data of later.
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

        this._enumerations.put(Item(name, NumberT(emptyValue), true));
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
            item.number = NumberT(intValue);
        else if(auto valueRef = cast(Asn1ValueReferenceIr)enumeration)
            item.number = NumberT(valueRef);
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

    // TODO: note that `number` is null for items where a value needs to be auto-assigned,
    //       but the semantic pass for this node hasn't been ran yet, so it cannot be determined.
    Result foreachEnumeration(
        scope Result delegate(const(char)[] name, Asn1ValueIr, bool isExtensible) @nogc nothrow handler,
    )
    {
        foreach(i, nameAndValue; this._enumerations.slice)
        {
            const isExtensible = this._extensibleIndex.isNull 
                ? false 
                : this._extensibleIndex.get <= i;

            auto number = nameAndValue.isImplicit ? null : nameAndValue.number;

            auto result = handler(nameAndValue.name, number, isExtensible);
            if(result.isError)
                return result;
        }
        return Result.noError;
    }

    override string getKindName() => "ENUMERATED";

    override LookupItemT lookup(Asn1BaseIr refIr)
    {
        if(auto valueRef = cast(Asn1ValueReferenceIr)refIr)
        {
            if(valueRef.moduleRef.length > 0)
                return LookupItemT.init;

            foreach(nameAndValue; this._enumerations)
            {
                if(nameAndValue.name == valueRef.valueRef)
                    return LookupItemT(LookupOneOf(nameAndValue.number.ir));
            }
        }

        return LookupItemT.init;
    }

    override void dispose()
    {
        super.dispose();
        this._enumerations.__xdtor();
    }

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ref nameAndValue; this._enumerations.slice)
        {
            result = nameAndValue.number.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
            if(auto numberRef = cast(Asn1ValueReferenceIr)nameAndValue.number)
            {
                auto numberValueIr = cast(Asn1IntegerValueIr)numberRef.getResolvedValueRecurse();
                if(numberValueIr is null)
                {
                    return Result.make(
                        Asn1SemanticError.typeMismatch,
                        "expected value reference for named enumerated value to resolve to an integer value",
                        errors.errorAndString(this.getRoughLocation(),
                            "expected value reference `",
                            numberRef.moduleRef, ".", numberRef.valueRef,
                            "` for named enumerated value `",
                            nameAndValue.name,
                            "` to resolve to an INTEGER value"
                        )
                    );
                }
                nameAndValue.number = numberValueIr;
            }
        }

        return Result.noError;
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

    // I'm intentionally preventing access to the underlying data store for user code in order to
    // avoid some potentially dodgy memory access patterns; but it makes some semantic checks awkward as hell,
    // so the lang package gets an escape hatch.
    package auto byNamedNumberKvp()
    {
        return this._namedNumbers.byKeyValue;
    } 

    version(unittest) IrT getByName(IrT : Asn1ValueIr)(const(char)[] name)
    {
        return cast(IrT)this._namedNumbers[name];
    }

    override string getKindName() => "INTEGER";

    override LookupItemT lookup(Asn1BaseIr refIr)
    {
        if(auto valueRef = cast(Asn1ValueReferenceIr)refIr)
        {
            if(valueRef.moduleRef.length > 0)
                return LookupItemT.init;

            bool wasFound;
            auto number = this._namedNumbers.tryGet(valueRef.valueRef, wasFound);
            
            return wasFound ? LookupItemT(LookupOneOf(number.ir)) : LookupItemT.init;
        }

        return LookupItemT.init;
    }

    override void dispose()
    {
        super.dispose();
        this._namedNumbers.__xdtor();
    }

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ref kvp; this._namedNumbers.byKeyValue)
        {
            result = kvp.value.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
            if(auto valueRefIr = cast(Asn1ValueReferenceIr)kvp.value)
            {
                auto numberValueIr = cast(Asn1IntegerValueIr)valueRefIr.getResolvedValueRecurse();
                if(numberValueIr is null)
                {
                    return Result.make(
                        Asn1SemanticError.typeMismatch,
                        "expected value reference for named integer value to resolve to an integer value",
                        errors.errorAndString(this.getRoughLocation(),
                            "expected value reference `",
                            valueRefIr.moduleRef, ".", valueRefIr.valueRef,
                            "` for named integer value `",
                            kvp.key,
                            "` to resolve to an INTEGER value"
                        )
                    );
                }
                kvp.value = ValueT(numberValueIr);
            }
        }

        return Result.noError;
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
            Asn1ValueIr defaultValue; // May be null

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

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        foreach(ref item; this._components)
        {
            result = item.type.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
            
            if(item.defaultValue !is null)
            {
                result = item.defaultValue.doSemanticStage(stageBit, lookup, context, info, errors);
                if(result.isError)
                    return result;

                if(stageBit == SemanticStageBit.resolveReferences)
                    super.replaceIfReference(item.defaultValue);
            }

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(item.type);
        }

        return Result.noError;
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
    in(type !is null, "type is null")
    {
        this(roughLocation);
        this._type = type;
    }

    this(Asn1Location roughLocation, Asn1TypeIr type, const(char)[] name)
    in(type !is null, "type is null")
    in(name.length > 0, "name is empty")
    {
        this(roughLocation);
        this._type = type;
        this._name = name;
    }

    Nullable!(const(char)[]) getItemTypeName() => this._name;
    Asn1TypeIr getTypeOfItems() => this._type;

    override string getKindName() => Kind;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        result = this._type.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._type);

        return Result.noError;
    }
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

    Asn1TypeIr getUnderlyingTypeSkipTags() // Useful in type checking contexts, since tags don't really matter much there.
    in(this._type !is null, "Underlying type hasn't been set yet")
    {
        auto type = this._type;
        while(true)
        {
            if(auto tagged = cast(Asn1TaggedTypeIr)type)
            {
                type = tagged.getUnderlyingType();
                continue;
            }
            break;
        }
        return type;
    }

    override string getKindName() => this._type.getKindName();
    override LookupItemT lookup(Asn1BaseIr refIr) => this._type.lookup(refIr);

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        result = this._type.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        result = this._number.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
        {
            super.replaceIfReference(this._type);

            if(auto valueRefIr = cast(Asn1ValueReferenceIr)this._number)
            {
                auto numberValueIr = cast(Asn1IntegerValueIr)valueRefIr.getResolvedValueRecurse();
                if(numberValueIr is null)
                {
                    return Result.make(
                        Asn1SemanticError.typeMismatch,
                        "expected value reference for tag number to resolve to an integer value",
                        errors.errorAndString(this.getRoughLocation(),
                            "expected value reference `",
                            valueRefIr.moduleRef, ".", valueRefIr.valueRef,
                            "` for tag number to resolve to an INTEGER value"
                        )
                    );
                }
                else if(numberValueIr._isNegative)
                {
                    return Result.make(
                        Asn1SemanticError.numberMustBeUnsigned,
                        "expected value reference for tag number to be a positive value",
                        errors.errorAndString(this.getRoughLocation(),
                            "expected value reference `",
                            valueRefIr.moduleRef, ".", valueRefIr.valueRef,
                            "` which resolved to value `", 
                            numberValueIr._token.text,
                            "` for tag number to be positive"
                        )
                    );
                }
                this._number = NumberT(numberValueIr);
            }
        }
        else if(stageBit == SemanticStageBit.implicitMutations)
        {
            // ITU-T X.680 (02/2021) 31.2.7
            if(this._encoding == Encoding.unspecified && cast(Asn1ChoiceTypeIr)this.getUnderlyingType() is null)
            {
                if(info.tagDefault == Asn1ModuleIr.TagDefault.implicit)
                    this._encoding = Encoding.implicit;
                else if(info.tagDefault == Asn1ModuleIr.TagDefault.explicit)
                    this._encoding = Encoding.explicit;
            }
        }

        return Result.noError;
    }
}

final class Asn1TypeReferenceIr : Asn1TypeIr
{
    mixin IrBoilerplate;

    alias StopForConstraints = Flag!"stopForConstraints";

    version(unittest) string getFullString() 
        => (this._moduleRef.length == 0) ? this._typeRef.idup : (this._moduleRef ~ "." ~ this._typeRef).idup;

    @nogc nothrow:

    private
    {
        const(char)[] _moduleRef;
        const(char)[] _typeRef;
        Asn1TypeIr _resolvedType;
    }

    this(Asn1Location roughLocation, const(char)[] module_, const(char)[] typeRef)
    in(module_.length > 0, "module_ must have a length greater than 0")
    in(typeRef.length > 0, "typeRef must have a length greater than 0")
    {
        super(roughLocation, ConstraintBit.all);
        this._moduleRef = module_;
        this._typeRef = typeRef;
    }

    this(Asn1Location roughLocation, const(char)[] typeRef)
    in(typeRef.length > 0, "typeRef must have a length greater than 0")
    {
        super(roughLocation, ConstraintBit.all);
        this._typeRef = typeRef;
    }

    bool refersToSameModuleLocalSymbol(Asn1TypeReferenceIr other)
    in(this._moduleRef.length == 0, "this TypeReference does not refer to a module-local symbol")
    in(other._moduleRef.length == 0, "other TypeReference does not refer to a module-local symbol")
    {
        return this._typeRef == other._typeRef;
    }

    Asn1TypeIr getResolvedType()
    in(super.hasDoneSemanticStage(SemanticStageBit.resolveReferences), "getResolvedType can only be called after the resolveReferences pass has completed") // @suppress(dscanner.style.long_line)
    out(type; type !is null, "bug: return value is null")
        => this._resolvedType;

    Asn1TypeIr getResolvedTypeRecurse(StopForConstraints stopForConstraints = StopForConstraints.yes)
    {
        if(stopForConstraints && super.getMainConstraintOrNull() !is null)
            return this;

        auto type = this.getResolvedType();
        while(true)
        {
            if(auto typeRefIr = cast(Asn1TypeReferenceIr)type)
            {
                if(stopForConstraints && typeRefIr.getMainConstraintOrNull() !is null)
                    return typeRefIr;

                type = typeRefIr.getResolvedType();
                continue;
            }
            break;
        }

        return type;
    }

    override string getKindName() => 
        this._resolvedType is null 
        ? "<unresolved type reference>" 
        : this._resolvedType.getKindName();

    const(char)[] moduleRef() => this._moduleRef;
    const(char)[] typeRef() => this._typeRef;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = super.doSemanticStageImpl(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
        {
            auto resolved = lookup(this);
            if(auto typeAss = cast(Asn1TypeAssignmentIr)resolved.get(null))
            {
                this._resolvedType = typeAss.getSymbolType();
            }
            else if(auto typeIr = cast(Asn1TypeIr)resolved.get(null))
            {
                this._resolvedType = typeIr;
            }
            else
            {
                return Result.make(
                    Asn1SemanticError.bug,
                    "bug: lookup() didn't return a type for a type reference lookup?",
                    errors.errorAndString(this.getRoughLocation(),
                        "bug: when performing lookup for type reference ", this._moduleRef, ".", this._typeRef,
                        "a non-type was returned"
                    )
                );
            }
        }

        if(this._resolvedType !is null)
        {
            result = this._resolvedType.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
}

alias Asn1GeneralizedTimeTypeIr = Asn1BasicTypeIr!("GeneralizedTime", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)
alias Asn1UtcTimeTypeIr = Asn1BasicTypeIr!("UTCTime", ConstraintBit.singleValue | ConstraintBit.containedSubtype); // @suppress(dscanner.style.long_line)

/++++ Values ++++/

abstract class Asn1ValueIr : Asn1BaseIr
{
    @nogc nothrow:

    private
    {
        Asn1TypeIr _type;
    }

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    abstract string getValueKind();
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
    override string getValueKind() => "BOOLEAN";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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
    override string getValueKind() => "CHOICE";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._value.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._value);

        return Result.noError;
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

    // Should only be used for values that are passed into `addImplicitEnumeration()`
    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    Asn1Token.Number getNumber() => this._token.asNumber;
    override string getValueKind() => "INTEGER";
    
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

    bool isNegative() => this._isNegative;
    const(char)[] getNumberText() => this._token.text;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
}

final class Asn1NullValueIr : Asn1ValueIr
{
    mixin IrBoilerplate;

    @nogc nothrow:

    this(Asn1Location roughLocation)
    {
        super(roughLocation);
    }

    override string getValueKind() => "NULL";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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
    override string getValueKind() => "CSTRING";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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
    override string getValueKind() => "HSTRING";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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
    override string getValueKind() => "BSTRING";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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

    override string getValueKind() => "SEQUENCE(value variant)";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        foreach(ref value; this._values)
        {
            auto result = value.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(value);
        }

        return Result.noError;
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

    override string getValueKind() => "SEQUENCE(named value variant)";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        foreach(ref value; this._values)
        {
            auto result = value.value.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(value.value);
        }

        return Result.noError;
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

    override string getValueKind() => "OBJECT IDENTIFIER";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        foreach(ref value; this._values)
        {
            auto result = value.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(value);
        }

        return Result.noError;
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

    override string getValueKind() => "SEQUENCE(empty variant)";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
        => Result.noError;
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
        Asn1ValueIr _resolvedValue;
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

    bool refersToSameModuleLocalSymbol(Asn1ValueReferenceIr other)
    in(this._moduleRef.length == 0, "this ValueReference does not refer to a module-local symbol")
    in(other._moduleRef.length == 0, "other ValueReference does not refer to a module-local symbol")
    {
        return this._valueRef == other.valueRef;
    }

    Asn1ValueIr getResolvedValue()
    in(super.hasDoneSemanticStage(SemanticStageBit.resolveReferences), "getResolvedValue can only be called after the resolveReferences pass has completed") // @suppress(dscanner.style.long_line)
    out(value; value !is null, "bug: return value is null")
        => this._resolvedValue;

    Asn1ValueIr getResolvedValueRecurse()
    {
        auto value = this.getResolvedValue();
        while(true)
        {
            if(auto valueRefIr = cast(Asn1ValueReferenceIr)value)
            {
                value = valueRefIr;
                continue;
            }
            break;
        }

        return value;
    }

    const(char)[] moduleRef() => this._moduleRef;
    const(char)[] valueRef() => this._valueRef;
    override string getValueKind() => 
        this._resolvedValue is null 
        ? "<unresolved value reference>" 
        : this._resolvedValue.getValueKind();

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        if(stageBit == SemanticStageBit.resolveReferences)
        {
            auto resolved = lookup(this);
            if(auto valueAss = cast(Asn1ValueAssignmentIr)resolved.get(null))
            {
                this._resolvedValue = valueAss.getSymbolValue();
            }
            else if(auto valueIr = cast(Asn1ValueIr)resolved.get(null))
            {
                this._resolvedValue = valueIr;
            }
            else
            {
                return Result.make(
                    Asn1SemanticError.bug,
                    "bug: lookup() didn't return a value for a value reference lookup?",
                    errors.errorAndString(this.getRoughLocation(),
                        "bug: when performing lookup for value reference ", this._moduleRef, ".", this._valueRef,
                        "a non-value was returned"
                    )
                );
            }
        }

        if(this._resolvedValue !is null)
        {
            auto result = this._resolvedValue.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
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

    abstract string getConstraintKind();
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
    override string getConstraintKind() => "UNION";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        foreach(constraint; this._constraints)
        {
            auto result = constraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
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
    override string getConstraintKind() => "INTERSECTION";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        foreach(constraint; this._constraints)
        {
            auto result = constraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
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
    override string getConstraintKind() => "EXCEPT";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._constraint.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        result = this._exclusion.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        return Result.noError;
    }
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
    override string getConstraintKind() => "SINGLE VALUE";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._value.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._value);

        return Result.noError;
    }
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
    override string getConstraintKind() => "SUBTYPE";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._type.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._type);

        return Result.noError;
    }
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
    override string getConstraintKind() => "VALUE RANGE";

    override ConstraintBit getConstraintBits() => ConstraintBit.valueRange;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        if(this._lower.valueIr !is null)
        {
            auto result = this._lower.valueIr.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(this._lower.valueIr);
        }

        if(this._upper.valueIr !is null)
        {
            auto result = this._upper.valueIr.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;

            if(stageBit == SemanticStageBit.resolveReferences)
                super.replaceIfReference(this._upper.valueIr);
        }

        return Result.noError;
    }
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
    override string getConstraintKind() => "FROM";

    override ConstraintBit getConstraintBits() => ConstraintBit.permittedAlphabet;

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._constraint.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(this._additionalConstraint !is null)
        {
            result = this._additionalConstraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
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
    override string getConstraintKind() => "SIZE";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._constraint.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(this._additionalConstraint !is null)
        {
            result = this._additionalConstraint.doSemanticStage(stageBit, lookup, context, info, errors);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }
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
    override string getConstraintKind() => "PATTERN";

    protected override Result doSemanticStageImpl(
        SemanticStageBit stageBit, 
        scope LookupFunc lookup,
        scope ref Asn1ParserContext context,
        SemanticInfo info,
        scope Asn1SemanticErrorHandler errors = Asn1NullSemanticErrorHandler.instance,
    ) @nogc nothrow
    {
        auto result = this._value.doSemanticStage(stageBit, lookup, context, info, errors);
        if(result.isError)
            return result;

        if(stageBit == SemanticStageBit.resolveReferences)
            super.replaceIfReference(this._value);

        return Result.noError;
    }
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

/++++ Unittests ++++/

@("Asn1Ir - Semantics")
unittest
{
    import std.conv : to;
    import juptune.core.util : resultAssert, resultAssertSameCode;
    import juptune.data.asn1.lang.ast2ir;
    import juptune.data.asn1.lang.lexer;
    import juptune.data.asn1.lang.common;
    import juptune.data.asn1.lang.parser;

    static struct T
    {
        string input;
        void function(Asn1ModuleIr) validate;
        Asn1SemanticError expectedError;
    }

    auto cases = [
        "ISO/IEC 8824-1:2021 - 19.4 Example": T(`
            Unittest DEFINITIONS ::= BEGIN
                a INTEGER ::= 1
                T1 ::= INTEGER { a(2) }
                T2 ::= INTEGER { a(3), b(a) }
                c T2 ::= b
                d T2 ::= a -- Also tests clause 19.12
            END
        `, (Asn1ModuleIr ir){
            auto cValue = cast(Asn1IntegerValueIr)ir.mustLookupAs!Asn1ValueAssignmentIr("c").getSymbolValue();
            auto dValue = cast(Asn1IntegerValueIr)ir.mustLookupAs!Asn1ValueAssignmentIr("d").getSymbolValue();

            ulong number;
            assert(cValue !is null);
            cValue.asUnsigned(number).resultAssert;
            assert(number == 1);

            assert(dValue !is null);
            dValue.asUnsigned(number).resultAssert;
            assert(number == 3);
            // https://www.youtube.com/watch?v=SlSylJRwtCk&pp=ygUMaXQncyB3b3JraW5n
        })
    ];

    foreach(name, test; cases)
    {
        try
        {
            Asn1ParserContext context;
            auto lexer = Asn1Lexer(test.input);
            auto parser = Asn1Parser(lexer, &context);

            Asn1ModuleDefinitionNode modDefNode;
            parser.ModuleDefinition(modDefNode).resultAssert;

            Asn1ModuleIr modIr;
            auto result = asn1AstToIr(modDefNode, modIr, context, Asn1NullSemanticErrorHandler.instance);

            if(test.validate !is null)
            {
                resultAssert(result);
                Asn1Token token;
                parser.consume(token).resultAssert;
                assert(token.type == Asn1Token.Type.eof, "Expected no more tokens, but got: "~token.to!string);

                foreach(stage; [
                    Asn1ModuleIr.SemanticStageBit.resolveReferences,
                    Asn1ModuleIr.SemanticStageBit.implicitMutations,
                ])
                {
                    result = modIr.doSemanticStage(
                        stage,
                        (_) => Asn1ModuleIr.LookupItemT.init,
                        context,
                        Asn1ModuleIr.SemanticInfo()
                    );
                    if(result.isError)
                        resultAssertSameCode!Asn1SemanticError(result, Result.make(test.expectedError));
                }

                test.validate(modIr);
            }
            else
            {
                resultAssertSameCode!Asn1SemanticError(result, Result.make(test.expectedError));
            }
        }
        catch(Throwable err) // @suppress(dscanner.suspicious.catch_em_all)
            assert(false, "\n["~name~"]:\n"~err.msg);
    }
}