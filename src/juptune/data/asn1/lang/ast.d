/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.ast;

import juptune.data.asn1.lang.common : Asn1ParserContext;
import juptune.data.asn1.lang.lexer  : Asn1Token;

// NOTE: This aims to stay 1:1 with the spec for my own sanity, even if a lot of it is a waste of memory.
// NOTE: Not all nodes are actually used, since the parser either lacks information, or prefers to represent things in a different way.

enum Asn1NodeType // For faster/easier to write type checks, instead of using casting.
{
    FAILSAFE,

    // Names are directly from the spec

    empty, // I know, the casing stuff is annoying.

    ModuleDefinition,
    ModuleIdentifier,
    DefinitiveIdentifier,
    DefinitiveObjIdComponentList,
    DefinitiveObjIdComponent,
    DefinitiveNumberForm,
    DefinitiveNameAndNumberForm,
    TagDefault,
    ExtensionDefault,
    ModuleBody,
    Exports,
    SymbolsExported,
    Imports,
    SymbolsImported,
    SymbolsFromModuleList,
    SymbolsFromModule,
    GlobalModuleReference,
    AssignedIdentifier,
    SymbolList,
    Symbol,
    Reference,
    AssignmentList,
    Assignment,
    DefinedType,
    DefinedValue,
    NonParameterizedTypeName,
    ExternalTypeReference,
    ExternalValueReference,
    AbsoluteReference,
    ItemSpec,
    ItemId,
    ComponentId,
    TypeAssignment,
    ValueAssignment,
    ValueSetTypeAssignment,
    ValueSet,
    Type,
    BuiltinType,
    ReferencedType,
    NamedType,
    Value,
    BuiltinValue,
    ReferencedValue,
    NamedValue,
    BooleanType,
    IntegerType,
    NamedNumberList,
    NamedNumber,
    SignedNumber,
    IntegerValue,
    EnumeratedType,
    Enumerations,
    RootEnumeration,
    AdditionalEnumeration,
    Enumeration,
    EnumerationItem,
    EnumeratedValue,
    RealType,
    RealValue,
    NumericRealValue,
    SpecialRealValue,
    BitStringType,
    NamedBitList,
    NamedBit,
    BitStringValue,
    IdentifierList,
    OctetStringType,
    OctetStringValue,
    NullType,
    NullValue,
    SequenceType,
    ExtensionAndException,
    OptionalExtensionMarker,
    ComponentTypeLists,
    RootComponentTypeList,
    ExtensionEndMarker,
    ExtensionAdditions,
    ExtensionAdditionList,
    ExtensionAddition,
    ExtensionAdditionGroup,
    VersionNumber,
    ComponentTypeList,
    ComponentType,
    SequenceValue,
    ComponentValueList,
    SequenceOfType,
    SequenceOfValue,
    ValueList,
    NamedValueList,
    SetType,
    SetValue,
    SetOfType,
    SetOfValue,
    ChoiceType,
    AlternativeTypeLists,
    RootAlternativeTypeList,
    ExtensionAdditionAlternatives,
    ExtensionAdditionAlternativesList,
    ExtensionAdditionAlternative,
    ExtensionAdditionAlternativesGroup,
    AlternativeTypeList,
    ChoiceValue,
    SelectionType,
    TaggedType,
    Tag,
    ClassNumber,
    Class,
    TaggedValue,
    ObjectIdentifierValue,
    ObjIdComponentsList,
    ObjIdComponents,
    NameForm,
    NumberForm,
    NameAndNumberForm,
    RelativeOIDValue,
    RelativeOIDComponentsList,
    RelativeOIDComponents,
    EmbeddedPdvValue,
    ExternalValue,
    CharacterStringType,
    CharacterStringValue,
    RestrictedCharacterStringType,
    RestrictedCharacterStringValue,
    CharacterStringList,
    CharSyms,
    CharsDefn,
    Quadruple,
    Group,
    Plane,
    Row,
    Cell,
    Tuple,
    TableColumn,
    TableRow,
    UnrestrictedCharacterStringValue,
    UsefulType,
    ConstrainedType,
    TypeWithConstraint,
    Constraint,
    ConstraintSpec,
    SubtypeConstraint,
    ElementSetSpecs,
    RootElementSetSpec,
    AdditionalElementSetSpec,
    ElementSetSpec,
    Unions,
    Intersections,
    IntersectionElements,
    Elems,
    Exclusions,
    Elements,
    SubtypeElements,
    SingleValue,
    ContainedSubtype,
    Includes,
    ValueRange,
    LowerEndpoint,
    UpperEndpoint,
    LowerEndValue,
    UpperEndValue,
    SizeConstraint,
    TypeConstraint,
    PermittedAlphabet,
    InnerTypeConstraints,
    SingleTypeConstraint,
    MultipleTypeConstraints,
    FullSpecification,
    PartialSpecification,
    TypeConstraints,
    NamedConstraint,
    ComponentConstraint,
    ValueConstraint,
    PresenceConstraint,
    PatternConstraint,
    ExceptionSpec,
    ExceptionIdentification,

    DefinedObjectClass,
    DefinedObject,
    DefinedObjectSet,
    ExternalObjectClassReference,
    ExternalObjectReference,
    ExternalObjectSetReference,
    UsefulObjectClassReference,
    ObjectClassAssignment,
    ObjectClass,
    ObjectClassDefn,
    FieldSpecList, // Not part of spec - unrolled short hand syntax
    WithSyntaxSpec,
    FieldSpec,
    TypeFieldSpec,
    TypeOptionalitySpec,
    FixedTypeValueFieldSpec,
    OptionalUniqueMark, // Not part of spec
    ValueOptionalitySpec,
    VariableTypeValueFieldSpec,
    FixedTypeValueSetFieldSpec,
    ValueSetOptionalitySpec,
    VariableTypeValueSetFieldSpec,
    ObjectFieldSpec,
    ObjectOptionalitySpec,
    ObjectSetFieldSpec,
    ObjectSetOptionalitySpec,
    PrimitiveFieldName,
    FieldName,
    SyntaxList,
    TokenOrGroupSpec,
    OptionalGroup,
    RequiredToken,
    Literal,
    ObjectAssignment,
    Object,
    ObjectDefn,
    DefaultSyntax,
    FieldSetting,
    DefinedSyntax,
    DefinedSyntaxToken,
    Setting,
    ObjectSetAssignment,
    ObjectSet,
    ObjectSetSpec,
    ObjectSetElements,
    ObjectClassFieldType,
    ObjectClassFieldValue,
    OpenTypeFieldVal,
    FixedTypeFieldVal,
    InformationFromObjects,
    ValueFromObject,
    ValueSetFromObjects,
    TypeFromObject,
    ObjectFromObject,
    ObjectSetFromObjects,
    ReferencedObjects,
    InstanceOfType,
    InstanceOfValue,

    ParameterizedAssignment,
    ParameterizedTypeAssignment,
    ParameterizedValueAssignment,
    ParameterizedValueSetTypeAssignment,
    ParameterizedObjectClassAssignment,
    ParameterizedObjectAssignment,
    ParameterizedObjectSetAssignment,
    ParameterList,
    ParameterListValues, // Not part of spec
    Parameter,
    ParamGovernor,
    Governor,
    DummyGovernor,
    DummyReference,
    ParameterizedReference,
    ParameterizedType,
    SimpleDefinedType,
    ParameterizedValue,
    SimpleDefinedValue,
    ParameterizedValueSetType,
    ParameterizedObjectClass,
    ParameterizedObjectSet,
    ParameterizedObject,
    ActualParameterList,
    ActualParameterListValues,
    ActualParameter,

    GeneralConstraint,
    UserDefinedConstraint,
    UserDefinedConstraintParameter,
    TableConstraint,
    SimpleTableConstraint,
    ComponentRelationConstraint,
    AtNotationList, // Not part of spec
    AtNotation,
    Level,
    ComponentIdList,
    ContentsConstraint,

    EXPLICIT_TAGS,
    IMPLICIT_TAGS,
    AUTOMATIC_TAGS,
    EXTENSIBILITY_IMPLIED,
    EXPORTS_ALL,
    ASTERISK, // "*"
    ELIPSIS, // "..."
    TRUE,
    FALSE,
    INTEGER,
    PLUS_INFINITY,
    MINUS_INFINITY,
    BIT_STRING,
    UNIVERSAL,
    APPLICATION,
    PRIVATE,
    OBJECT_IDENTIFIER,
    RELATIVE_OID,
    EMBEDDED_PDV,
    EXTERNAL,
    CHARACTER_STRING,
    UNION, // Both `UNION` and `|`
    INTERSECTION, // Both `INTERSECTION` and `^`
    INCLUDES,
    MIN,
    MAX,
    PRESENT,
    ABSENT,
    OPTIONAL,
    TYPE_IDENTIFIER,
    ABSTRACT_SYNTAX,
    UNIQUE,
    COMMA, // ","

    // "t" stands for token
    tIdentifier,
    tNumber,
    tRealNumber,
    tBstring,
    tHstring,
    tCstring,
    tBMPString,
    tGeneralString,
    tGraphicString,
    tIA5String,
    tISO646String,
    tNumericString,
    tPrintableString,
    tTeletexString,
    tT61String,
    tUniversalString,
    tUTF8String,
    tVideotexString,
    tVisibleString,

    tModuleReference,
    tTypeReference,
    tValueReference,
    
    tObjectClassReference,
    tObjectReference,
    tObjectSetReference,
    tTypeFieldReference,
    tValueFieldReference,
    tValueSetFieldReference,
    tObjectFieldReference,
    tObjectSetFieldReference,
    tWord,
}

/**** Mixins ****/

private mixin template OneOf(Asn1NodeType MyType, NodeTypes...)
{
    private
    {
        int _oneOfIndex = -1;
        NodeTypes _oneOfValue;
    }

    @nogc nothrow:

    protected template oneOfIndexOf(NodeT)
    {
        import std.meta : staticIndexOf;
        enum oneOfIndexOf = staticIndexOf!(NodeT, NodeTypes);
        enum Error = "Invalid node type: "~NodeT.stringof;
        static assert(oneOfIndexOf != -1, Error);
    }

    static foreach(NodeT; NodeTypes)
    this(NodeT node)
    {
        this.oneOfSet(node);
        super(MyType);
    }

    protected void oneOfSet(NodeT)(NodeT node) @safe
    in(node, "node is null")
    {
        enum Index = oneOfIndexOf!NodeT;
        this._oneOfIndex = Index;
        this._oneOfValue[Index] = node;
    }

    bool isNode(NodeT)() @safe const pure
    {
        enum Index = oneOfIndexOf!NodeT;
        return this._oneOfIndex == Index;
    }

    NodeT asNode(NodeT)() @safe
    out(n; n !is null, "bug: Node is null?")
    {
        static immutable ErrorMsg = "This node is not of type "~NodeT.stringof;
        assert(this.isNode!NodeT, ErrorMsg);

        enum Index = oneOfIndexOf!NodeT;
        return this._oneOfValue[Index];
    }

    NodeT maybeNode(NodeT)() @safe
    {
        enum Index = oneOfIndexOf!NodeT;
        return this.isNode!NodeT ? this._oneOfValue[Index] : null;
    }
}

private mixin template Token(Asn1Token.Type MustBeType, Asn1NodeType AstType)
{
    import std.conv : to;

    private
    {
        Asn1Token _token;
    }

    enum TokenT = MustBeType;

    @nogc nothrow:

    private enum CtorError = "expected token of type: "~MustBeType.to!string;
    this(Asn1Token token) @safe pure
    in(token.type == MustBeType, CtorError)
    {
        super(AstType);
        this._token = token;
    }

    Asn1Token token() @safe pure
    {
        return this._token;
    }
}

private mixin template Container(Asn1NodeType MyType, NodeTypes...)
{
    private
    {
        NodeTypes _containerValues;
    }

    alias ContainerNodeTypes = NodeTypes;

    @nogc nothrow:

    protected template containerIndexOf(NodeT)
    {
        import std.meta : staticIndexOf;
        enum containerIndexOf = staticIndexOf!(NodeT, NodeTypes);
        enum Error = "Invalid node type: "~NodeT.stringof;
        static assert(containerIndexOf != -1, Error);
    }

    this(NodeTypes nodes) @safe pure
    {
        super(MyType);

        static foreach(i, NodeT; NodeTypes)
        {{
            import std.conv : to;
            enum Error = "Parameter "~i.to!string~" of type "~NodeT.stringof~" is null";
            assert(nodes[i] !is null, Error);
        }}

        this._containerValues = nodes;
    }

    NodeT getNode(NodeT)() @safe
    {
        return this._containerValues[containerIndexOf!NodeT];
    }
}

private mixin template List(Asn1NodeType MyType, ItemT)
{
    import juptune.core.ds : Array;

    enum _MustBeDtored = true;

    private
    {
        Array!ItemT _items;
    }

    @nogc nothrow:

    this()
    {
        super(MyType);
    }

    ref typeof(_items) items() => this._items;

    override void dispose()
    {
        this._items.__xdtor();
    }
}

/**** Nodes ****/

abstract class Asn1BaseNode
{
    private
    {
        Asn1NodeType _nodeType;
    }

    protected this(Asn1NodeType type) @safe @nogc nothrow pure
    {
        this._nodeType = type;
    }

    final Asn1NodeType nodeType() @safe @nogc nothrow pure const
    {
        return this._nodeType;
    }

    void dispose() @nogc nothrow {}
}

final class Asn1StaticNode(Asn1NodeType MyType) : Asn1BaseNode
{
    Asn1Token token;

    this(Asn1Token token) @safe @nogc nothrow pure
    {
        super(MyType);
        this.token = token;
    }
}

/*** Special nodes ***/

alias Asn1EmptyNode = Asn1StaticNode!(Asn1NodeType.empty);
alias Asn1ExplicitTagsNode = Asn1StaticNode!(Asn1NodeType.EXPLICIT_TAGS);
alias Asn1ImplicitTagsNode = Asn1StaticNode!(Asn1NodeType.IMPLICIT_TAGS);
alias Asn1AutomaticTagsNode = Asn1StaticNode!(Asn1NodeType.AUTOMATIC_TAGS);
alias Asn1ExtensibilityImpliedNode = Asn1StaticNode!(Asn1NodeType.EXTENSIBILITY_IMPLIED);
alias Asn1ExportsAllNode = Asn1StaticNode!(Asn1NodeType.EXPORTS_ALL);
alias Asn1AsteriskNode = Asn1StaticNode!(Asn1NodeType.ASTERISK);
alias Asn1PlusInfinityNode = Asn1StaticNode!(Asn1NodeType.PLUS_INFINITY);
alias Asn1MinusInfinityNode = Asn1StaticNode!(Asn1NodeType.MINUS_INFINITY);
alias Asn1ElipsisNode = Asn1StaticNode!(Asn1NodeType.ELIPSIS);
alias Asn1UniversalNode = Asn1StaticNode!(Asn1NodeType.UNIVERSAL);
alias Asn1ApplicationNode = Asn1StaticNode!(Asn1NodeType.APPLICATION);
alias Asn1PrivateNode = Asn1StaticNode!(Asn1NodeType.PRIVATE);

alias Asn1BMPStringNode = Asn1StaticNode!(Asn1NodeType.tBMPString);
alias Asn1GeneralStringNode = Asn1StaticNode!(Asn1NodeType.tGeneralString);
alias Asn1GraphicStringNode = Asn1StaticNode!(Asn1NodeType.tGraphicString);
alias Asn1IA5StringNode = Asn1StaticNode!(Asn1NodeType.tIA5String);
alias Asn1ISO646StringNode = Asn1StaticNode!(Asn1NodeType.tISO646String);
alias Asn1NumericStringNode = Asn1StaticNode!(Asn1NodeType.tNumericString);
alias Asn1PrintableStringNode = Asn1StaticNode!(Asn1NodeType.tPrintableString);
alias Asn1TeletexStringNode = Asn1StaticNode!(Asn1NodeType.tTeletexString);
alias Asn1T61StringNode = Asn1StaticNode!(Asn1NodeType.tT61String);
alias Asn1UniversalStringNode = Asn1StaticNode!(Asn1NodeType.tUniversalString);
alias Asn1UTF8StringNode = Asn1StaticNode!(Asn1NodeType.tUTF8String);
alias Asn1VideotexStringNode = Asn1StaticNode!(Asn1NodeType.tVideotexString);
alias Asn1VisibleStringNode = Asn1StaticNode!(Asn1NodeType.tVisibleString);
alias Asn1UnionMarkNode = Asn1StaticNode!(Asn1NodeType.UNION);
alias Asn1IntersectionMarkNode = Asn1StaticNode!(Asn1NodeType.INTERSECTION);
alias Asn1IncludesMarkNode = Asn1StaticNode!(Asn1NodeType.INCLUDES);
alias Asn1MinNode = Asn1StaticNode!(Asn1NodeType.MIN);
alias Asn1MaxNode = Asn1StaticNode!(Asn1NodeType.MAX);
alias Asn1PresentNode = Asn1StaticNode!(Asn1NodeType.PRESENT);
alias Asn1AbsentNode = Asn1StaticNode!(Asn1NodeType.ABSENT);
alias Asn1OptionalNode = Asn1StaticNode!(Asn1NodeType.OPTIONAL);
alias Asn1TypeIdentifierNode = Asn1StaticNode!(Asn1NodeType.TYPE_IDENTIFIER);
alias Asn1AbstractSyntaxNode = Asn1StaticNode!(Asn1NodeType.ABSTRACT_SYNTAX);
alias Asn1UniqueNode = Asn1StaticNode!(Asn1NodeType.UNIQUE);
alias Asn1CommaNode = Asn1StaticNode!(Asn1NodeType.COMMA);

/*** Raw token nodes ***/

final class Asn1ModuleReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.moduleReference, Asn1NodeType.tModuleReference);
}

final class Asn1TypeReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tTypeReference);
}

final class Asn1ValueReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.valueReference, Asn1NodeType.tValueReference);
}

final class Asn1ObjectClassReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tObjectClassReference);
}

final class Asn1ObjectReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.objectReference, Asn1NodeType.tObjectReference);
}

final class Asn1ObjectSetReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tObjectSetReference);
}

final class Asn1TypeFieldReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tTypeFieldReference);
}

final class Asn1ValueFieldReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.valueReference, Asn1NodeType.tValueFieldReference);
}

final class Asn1ValueSetFieldReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tValueSetFieldReference);
}

final class Asn1ObjectFieldReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.objectReference, Asn1NodeType.tObjectFieldReference);
}

final class Asn1ObjectSetFieldReferenceTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.objectSetReference, Asn1NodeType.tObjectSetFieldReference);
}

final class Asn1WordTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.typeReference, Asn1NodeType.tWord);
}

final class Asn1IdentifierTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.identifier, Asn1NodeType.tIdentifier);
}

final class Asn1NumberTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.number, Asn1NodeType.tNumber);
}

final class Asn1RealNumberTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.realNumber, Asn1NodeType.tRealNumber);
}

final class Asn1BstringTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.bstring, Asn1NodeType.tBstring);
}

final class Asn1HstringTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.hstring, Asn1NodeType.tHstring);
}

final class Asn1CstringTokenNode : Asn1BaseNode
{
    mixin Token!(Asn1Token.Type.cstring, Asn1NodeType.tCstring);
}

/*** 12.1 ISO/IEC 8824-1:2003 ***/

/++
    ModuleDefinition ::=
        ModuleIdentifier
        DEFINITIONS
        TagDefault
        ExtensionDefault
        "::="
        BEGIN
        ModuleBody
        END
 ++/
final class Asn1ModuleDefinitionNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ModuleDefinition,
        Asn1ModuleIdentifierNode,
        Asn1TagDefaultNode,
        Asn1ExtensionDefaultNode,
        Asn1ModuleBodyNode,
    );
}

/++
    ModuleIdentifier ::=
        modulereference
        DefinitiveIdentifier
 ++/
final class Asn1ModuleIdentifierNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ModuleIdentifier,
        Asn1ModuleReferenceTokenNode,
        Asn1DefinitiveIdentifierNode,
    );
}

/++
    DefinitiveIdentifier ::=
        "{" DefinitiveObjIdComponentList "}"
        | empty
 ++/
final class Asn1DefinitiveIdentifierNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinitiveIdentifier,
        Asn1DefinitiveObjIdComponentListNode,
        Asn1EmptyNode,
    );
}

/++
    DefinitiveObjIdComponentList ::=
        DefinitiveObjIdComponent
        | DefinitiveObjIdComponent DefinitiveObjIdComponentList
 ++/
final class Asn1DefinitiveObjIdComponentListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.DefinitiveObjIdComponentList, Asn1DefinitiveObjIdComponentNode);
}

/++
    DefinitiveObjIdComponent ::=
        NameForm
        | DefinitiveNumberForm
        | DefinitiveNameAndNumberForm
 + ++/
final class Asn1DefinitiveObjIdComponentNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinitiveObjIdComponent, 
        Asn1NameFormNode, 
        Asn1DefinitiveNumberFormNode,
        Asn1DefinitiveNameAndNumberFormNode,
    );
}

// DefinitiveNumberForm ::= number
final class Asn1DefinitiveNumberFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DefinitiveNumberForm, Asn1NumberTokenNode);
}

// DefinitiveNameAndNumberForm ::= identifier "(" DefinitiveNumberForm ")"
final class Asn1DefinitiveNameAndNumberFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DefinitiveNameAndNumberForm,
        Asn1IdentifierTokenNode,
        Asn1DefinitiveNumberFormNode,
    );
}

/++
    TagDefault ::=
        EXPLICIT TAGS
        | IMPLICIT TAGS
        | AUTOMATIC TAGS
        | empty
 ++/
final class Asn1TagDefaultNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.TagDefault,
        Asn1ExplicitTagsNode,
        Asn1ImplicitTagsNode,
        Asn1AutomaticTagsNode,
        Asn1EmptyNode,
    );
}

/++
    ExtensionDefault ::=
        EXTENSIBILITY IMPLIED
        | empty
 ++/
final class Asn1ExtensionDefaultNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionDefault,
        Asn1ExtensibilityImpliedNode,
        Asn1EmptyNode,
    );
}

/++
    ModuleBody ::=
        [Case1] Exports Imports AssignmentList
        | empty
 ++/
final class Asn1ModuleBodyNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ExportsNode,
            Asn1ImportsNode,
            Asn1AssignmentListNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ModuleBody,
        Case1,
        Asn1EmptyNode,
    );
}

/++
    Exports ::=
        EXPORTS SymbolsExported ";"
        | EXPORTS ALL ";"
        | empty
 ++/
final class Asn1ExportsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Exports,
        Asn1SymbolsExportedNode,
        Asn1ExportsAllNode,
        Asn1EmptyNode,
    );
}

/++
    SymbolsExported ::=
        SymbolList
        | empty
 ++/
final class Asn1SymbolsExportedNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SymbolsExported,
        Asn1SymbolListNode,
        Asn1EmptyNode,
    );
}

/++
    Imports ::=
        IMPORTS SymbolsImported ";"
        | empty
 ++/
final class Asn1ImportsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Imports,
        Asn1SymbolsImportedNode,
        Asn1EmptyNode,
    );
}

/++
    SymbolsImported ::=
        SymbolsFromModuleList
        | empty
 ++/
final class Asn1SymbolsImportedNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SymbolsImported,
        Asn1SymbolsFromModuleListNode,
        Asn1EmptyNode,
    );
}

/++
    SymbolsFromModuleList ::=
        SymbolsFromModule
        | SymbolsFromModuleList SymbolsFromModule
 ++/
final class Asn1SymbolsFromModuleListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.SymbolsFromModuleList, Asn1SymbolsFromModuleNode);
}

/++
    SymbolsFromModule ::=
        SymbolList FROM GlobalModuleReference
 ++/
final class Asn1SymbolsFromModuleNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SymbolsFromModule,
        Asn1SymbolListNode,
        Asn1GlobalModuleReferenceNode,
    );
}

/++
    GlobalModuleReference ::=
        modulereference AssignedIdentifier
 ++/
final class Asn1GlobalModuleReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.GlobalModuleReference,
        Asn1ModuleReferenceTokenNode,
        Asn1AssignedIdentifierNode,
    );
}

/++
    AssignedIdentifier ::=
        ObjectIdentifierValue
        | DefinedValue
        | empty
 ++/
final class Asn1AssignedIdentifierNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.AssignedIdentifier,
        Asn1ObjectIdentifierValueNode,
        Asn1DefinedValueNode,
        Asn1EmptyNode,
    );
}

/++
    SymbolList ::=
        Symbol
        | SymbolList "," Symbol
 ++/
final class Asn1SymbolListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.SymbolList, Asn1SymbolNode);
}

/++
    Symbol ::=
        Reference
        | ParameterizedReference
 ++/
final class Asn1SymbolNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Symbol,
        Asn1ReferenceNode,
        Asn1ParameterizedReferenceNode,
    );
}

/++
    Reference ::=
        typereference
        | valuereference
        | objectclassreference
        | objectreference
        | objectsetreference
 ++/
final class Asn1ReferenceNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Reference,
        Asn1TypeReferenceTokenNode,
        Asn1ValueReferenceTokenNode,
        Asn1ObjectClassReferenceTokenNode,
        Asn1ObjectReferenceTokenNode,
        Asn1ObjectSetReferenceTokenNode,
    );
}

/++
    AssignmentList ::=
        Assignment
        | AssignmentList Assignment
 ++/
final class Asn1AssignmentListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.AssignmentList, Asn1AssignmentNode);
}

/++
    Assignment ::=
        TypeAssignment
        | ValueAssignment
        | XMLValueAssignment
        | ValueSetTypeAssignment
        | ObjectClassAssignment
        | ObjectAssignment
        | ObjectSetAssignment
        | ParameterizedAssignment
 ++/

final class Asn1AssignmentNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Assignment, 
        Asn1AssignmentNode,
        Asn1TypeAssignmentNode,
        Asn1ValueAssignmentNode,
        Asn1ValueSetTypeAssignmentNode,
        Asn1ObjectClassAssignmentNode,
        Asn1ObjectAssignmentNode,
        Asn1ObjectSetAssignmentNode,
        Asn1ParameterizedAssignmentNode,
    );
}

/++
    DefinedType ::=
        ExternalTypeReference
        | Typereference
        | ParameterizedType
        | ParameterizedValueSetType
 ++/
final class Asn1DefinedTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedType,
        Asn1ExternalTypeReferenceNode,
        Asn1TypeReferenceTokenNode,
        Asn1ParameterizedTypeNode,
        Asn1ParameterizedValueSetTypeNode,
    );
}

/++
    DefinedValue ::=
        ExternalValueReference
        | Valuereference
        | ParameterizedValue
 ++/
final class Asn1DefinedValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedValue,
        Asn1ExternalValueReferenceNode,
        Asn1ValueReferenceTokenNode,
        Asn1ParameterizedValueNode,
    );
}

/++
    NonParameterizedTypeName ::=
        ExternalTypeReference
        | typereference
        | xmlasn1typename
 ++/
final class Asn1NonParameterizedTypeNameNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.NonParameterizedTypeName,
        Asn1ExternalTypeReferenceNode,
        Asn1TypeReferenceTokenNode,
    );
}

/++
    ExternalTypeReference ::=
        modulereference
        "."
        typereference
 ++/
final class Asn1ExternalTypeReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalTypeReference,
        Asn1ModuleReferenceTokenNode,
        Asn1TypeReferenceTokenNode,
    );
}

/++
    ExternalValueReference ::=
        modulereference
        "."
        valuereference
 ++/
final class Asn1ExternalValueReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalValueReference,
        Asn1ModuleReferenceTokenNode,
        Asn1ValueReferenceTokenNode,
    );
}

/++
    AbsoluteReference ::= "@" ModuleIdentifier
        "."
        ItemSpec
 ++/
final class Asn1AbsoluteReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.AbsoluteReference,
        Asn1ModuleIdentifierNode,
        Asn1ItemSpecNode,
    );
}

/++
    ItemSpec ::=
        typereference
        [Case2] | ItemId "." ComponentId
 ++/
final class Asn1ItemSpecNode : Asn1BaseNode
{
    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ItemIdNode,
            Asn1ComponentIdNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ItemSpec,
        Asn1TypeReferenceTokenNode,
        Case2,
    );
}

/++
    ItemId ::= ItemSpec
 ++/
final class Asn1ItemIdNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ItemId,
        Asn1ItemSpecNode,
    );
}

/++
    ComponentId ::=
        identifier
        | number
        | "*"
 ++/
final class Asn1ComponentIdNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ComponentId,
        Asn1IdentifierTokenNode,
        Asn1NumberTokenNode,
        Asn1AsteriskNode,
    );
}

/++
    TypeAssignment ::=
        typereference
        "::="
        Type
 ++/
final class Asn1TypeAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TypeAssignment,
        Asn1TypeReferenceTokenNode,
        Asn1TypeNode
    );
}

/++
    ValueAssignment ::=
        valuereference
        Type
        "::="
        Value
 ++/
final class Asn1ValueAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueAssignment,
        Asn1ValueReferenceTokenNode,
        Asn1TypeNode,
        Asn1ValueNode
    );
}

/++
    ValueSetTypeAssignment ::=
        typereference
        Type
        "::="
        ValueSet
 ++/
final class Asn1ValueSetTypeAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueSetTypeAssignment,
        Asn1TypeReferenceTokenNode,
        Asn1TypeNode,
        Asn1ValueSetNode,
    );
}

/++
    ValueSet ::= "{" ElementSetSpecs "}"
 ++/
final class Asn1ValueSetNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueSet,
        Asn1ElementSetSpecsNode,
    );
}

/++
    Type ::= BuiltinType | ReferencedType | ConstrainedType
 ++/
final class Asn1TypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Type,
        Asn1BuiltinTypeNode,
        Asn1ReferencedTypeNode,
        Asn1ConstrainedTypeNode,
    );
}

/++
    BuiltinType ::=
        BitStringType
        | BooleanType
        | CharacterStringType
        | ChoiceType
        | EmbeddedPDVType
        | EnumeratedType
        | ExternalType
        | InstanceOfType
        | IntegerType
        | NullType
        | ObjectClassFieldType
        | ObjectIdentifierType
        | OctetStringType
        | RealType
        | RelativeOIDType
        | SequenceType
        | SequenceOfType
        | SetType
        | SetOfType
        | TaggedType
 ++/
final class Asn1BuiltinTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.BuiltinType,
        Asn1BitStringTypeNode,
        Asn1BooleanTypeNode,
        Asn1CharacterStringTypeNode,
        Asn1ChoiceTypeNode,
        Asn1EmbeddedPDVTypeNode,
        Asn1EnumeratedTypeNode,
        Asn1ExternalTypeNode,
        Asn1InstanceOfTypeNode,
        Asn1IntegerTypeNode,
        Asn1NullTypeNode,
        Asn1ObjectClassFieldTypeNode,
        Asn1ObjectIdentifierTypeNode,
        Asn1OctetStringTypeNode,
        Asn1RealTypeNode,
        Asn1RelativeOIDTypeNode,
        Asn1SequenceTypeNode,
        Asn1SequenceOfTypeNode,
        Asn1SetTypeNode,
        Asn1SetOfTypeNode,
        Asn1TaggedTypeNode,
    );
}

/++
    ReferencedType ::=
        DefinedType
        | UsefulType
        | SelectionType
        | TypeFromObject
        | ValueSetFromObjects
 ++/
final class Asn1ReferencedTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ReferencedType,
        Asn1DefinedTypeNode,
        Asn1UsefulTypeNode,
        Asn1SelectionTypeNode,
        Asn1TypeFromObjectNode,
        Asn1ValueSetFromObjectsNode,
    );
}

/++
    NamedType ::= identifier Type
 ++/
final class Asn1NamedTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.NamedType,
        Asn1IdentifierTokenNode,
        Asn1TypeNode,
    );
}

/++
    Value ::=
        BuiltinValue
        | ReferencedValue
        | ObjectClassFieldValue
 ++/
final class Asn1ValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Value,
        Asn1BuiltinValueNode,
        Asn1ReferencedValueNode,
        Asn1ObjectClassFieldValueNode,
    );
}

/++
    BuiltinValue ::=
        BitStringValue
        | BooleanValue
        | CharacterStringValue
        | ChoiceValue
        | EmbeddedPDVValue
        | EnumeratedValue
        | ExternalValue
        | InstanceOfValue
        | IntegerValue
        | NullValue
        | ObjectIdentifierValue
        | OctetStringValue
        | RealValue
        | RelativeOIDValue
        | SequenceValue
        | SequenceOfValue
        | SetValue
        | SetOfValue
        | TaggedValue
 ++/
final class Asn1BuiltinValueNode : Asn1BaseNode
{
    // NOTE: Due to ambiguity
    //      - Any type that requires a sequence value is instead replaced by
    //        Asn1UnresolvedSequenceValueNode, as type information is needed.
    //      - Any raw string case is unused, instead replaced by Asn1UnresolvedStringValueNode.

    mixin OneOf!(Asn1NodeType.BuiltinValue,
        // Asn1BitStringValueNode,
        Asn1BooleanValueNode,
        // Asn1CharacterStringValueNode,
        Asn1ChoiceValueNode,
        // Asn1EmbeddedPdvValueNode,
        Asn1EnumeratedValueNode,
        // Asn1ExternalValueNode,
        // Asn1InstanceOfValueNode,
        Asn1IntegerValueNode,
        Asn1NullValueNode,
        // Asn1ObjectIdentifierValueNode,
        // Asn1OctetStringValueNode,
        Asn1RealValueNode,
        // Asn1RelativeOIDValueNode,
        // Asn1SequenceValueNode,
        // Asn1SequenceOfValueNode,
        // Asn1SetValueNode,
        // Asn1SetOfValueNode,
        Asn1TaggedValueNode,

        // Non-standard, helps with parsing logic
        Asn1UnresolvedStringValueNode,
        Asn1UnresolvedSequenceValueNode,
        Asn1UnresolvedIdentifierValueNode,
    );
}

final class Asn1UnresolvedStringValueNode : Asn1BaseNode // Requires semantic analysis to determine exact type.
{
    // The string value nodes support this syntax:
    //  CONTAINING Value
    final static class Containing : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.FAILSAFE,
        Asn1CstringTokenNode,
        Asn1HstringTokenNode,
        Asn1BstringTokenNode,
        Containing
    );
}

final class Asn1UnresolvedSequenceValueNode : Asn1BaseNode // Requires semantic analysis to determine exact type.
{
    mixin OneOf!(Asn1NodeType.FAILSAFE,
        Asn1ValueListNode,
        Asn1NamedValueListNode,
        Asn1ObjIdComponentsListNode,
        Asn1EmptyNode
    );
}

final class Asn1UnresolvedIdentifierValueNode : Asn1BaseNode // Requires semantic analysis to determine exact meaning.
{
    mixin OneOf!(Asn1NodeType.FAILSAFE,
        Asn1IdentifierTokenNode,
    );
}

/++
    ReferencedValue ::=
        DefinedValue
        | ValueFromObject
 ++/
final class Asn1ReferencedValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ReferencedValue,
        Asn1DefinedValueNode,
        Asn1ValueFromObjectNode,
    );
}

/++
    NamedValue ::= identifier Value
 ++/
final class Asn1NamedValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.NamedValue,
        Asn1IdentifierTokenNode,
        Asn1ValueNode,
    );
}

// BooleanType ::= BOOLEAN
alias Asn1BooleanTypeNode = Asn1StaticNode!(Asn1NodeType.BooleanType);

// BooleanValue ::= TRUE | FALSE
final class Asn1BooleanValueNode : Asn1BaseNode
{
    alias True = Asn1StaticNode!(Asn1NodeType.TRUE);
    alias False = Asn1StaticNode!(Asn1NodeType.FALSE);

    mixin OneOf!(Asn1NodeType.BooleanType,
        True,
        False
    );
}

/++
    IntegerType ::=
        INTEGER
        | INTEGER "{" NamedNumberList "}"
 ++/
final class Asn1IntegerTypeNode : Asn1BaseNode
{
    alias Plain = Asn1StaticNode!(Asn1NodeType.INTEGER);

    mixin OneOf!(Asn1NodeType.IntegerType,
        Plain,
        Asn1NamedNumberListNode,
    );
}

/++
    NamedNumberList ::=
        NamedNumber
        | NamedNumberList "," NamedNumber
 ++/
final class Asn1NamedNumberListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.NamedNumberList, Asn1NamedNumberNode);
}

/++
    NamedNumber ::=
        identifier "(" SignedNumber ")"
        | identifier "(" DefinedValue ")"
 ++/
final class Asn1NamedNumberNode : Asn1BaseNode
{
    final static class Signed : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1IdentifierTokenNode,
            Asn1SignedNumberNode,
        );
    }

    final static class Defined : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1IdentifierTokenNode,
            Asn1DefinedValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.NamedNumber,
        Signed,
        Defined
    );
}

/++
    SignedNumber ::=
        number
        | "-" number
 ++/
final class Asn1SignedNumberNode : Asn1BaseNode
{
    final static class Negative : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1NumberTokenNode,
        );
    }

    mixin OneOf!(Asn1NodeType.SignedNumber,
        Asn1NumberTokenNode,
        Negative,
    );
}

/++
    IntegerValue ::=
        SignedNumber
        | identifier
 ++/
final class Asn1IntegerValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.IntegerValue,
        Asn1SignedNumberNode,
        Asn1IdentifierTokenNode,
    );
}

/++
    EnumeratedType ::=
        ENUMERATED "{" Enumerations "}"
 ++/
final class Asn1EnumeratedTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.EnumeratedType,
        Asn1EnumerationsNode,
    );
}

/++
    Enumerations ::=
        RootEnumeration
        [Case1] | RootEnumeration "," "..." ExceptionSpec
        [Case2] | RootEnumeration "," "..." ExceptionSpec "," AdditionalEnumeration
 ++/
final class Asn1EnumerationsNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootEnumerationNode,
            Asn1ExceptionSpecNode,
        );
    }

    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootEnumerationNode,
            Asn1ExceptionSpecNode,
            Asn1AdditionalEnumerationNode,
        );
    }

    mixin OneOf!(Asn1NodeType.Enumerations,
        Asn1RootEnumerationNode,
        Case1,
        Case2
    );
}

// RootEnumeration ::= Enumeration
final class Asn1RootEnumerationNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.RootEnumeration,
        Asn1EnumerationNode
    );
}

// AdditionalEnumeration ::= Enumeration
final class Asn1AdditionalEnumerationNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.AdditionalEnumeration,
        Asn1EnumerationNode
    );
}

// Enumeration ::= EnumerationItem | EnumerationItem "," Enumeration
final class Asn1EnumerationNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.Enumeration, Asn1EnumerationItemNode);
}

// EnumerationItem ::= identifier | NamedNumber
final class Asn1EnumerationItemNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.EnumerationItem,
        Asn1IdentifierTokenNode,
        Asn1NamedNumberNode,
    );
}

// EnumeratedValue ::= identifier
final class Asn1EnumeratedValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.EnumeratedValue,
        Asn1IdentifierTokenNode
    );
}

// RealType ::= REAL
alias Asn1RealTypeNode = Asn1StaticNode!(Asn1NodeType.RealType);

/++
    RealValue ::=
        NumericRealValue
        | SpecialRealValue
 + ++/
final class Asn1RealValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.RealValue,
        Asn1NumericRealValueNode,
        Asn1SpecialRealValueNode,
    );
}

/++
    NumericRealValue ::=
        realnumber
        | "-" realnumber
        | SequenceValue
 + ++/
final class Asn1NumericRealValueNode : Asn1BaseNode
{
    final static class Negative : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RealNumberTokenNode
        );
    }

    mixin OneOf!(Asn1NodeType.NumericRealValue,
        Asn1RealNumberTokenNode,
        Negative,
        Asn1SequenceValueNode,
    );
}

/++
    SpecialRealValue ::=
        PLUS-INFINITY
        | MINUS-INFINITY
 + ++/
final class Asn1SpecialRealValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SpecialRealValue,
        Asn1PlusInfinityNode,
        Asn1MinusInfinityNode,
    );
}

/++
    BitStringType ::=
        BIT STRING
        | BIT STRING "{" NamedBitList "}"
 ++/
final class Asn1BitStringTypeNode : Asn1BaseNode
{
    alias Plain = Asn1StaticNode!(Asn1NodeType.BIT_STRING);

    mixin OneOf!(Asn1NodeType.BitStringType,
        Plain,
        Asn1NamedBitListNode,
    );
}

/++
    NamedBitList ::=
        NamedBit
        | NamedBitList "," NamedBit
 ++/
final class Asn1NamedBitListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.NamedBitList, Asn1NamedBitNode);
}

/++
    NamedBit ::=
        identifier "(" number ")"
        | identifier "(" DefinedValue ")"
 ++/
final class Asn1NamedBitNode : Asn1BaseNode
{
    final static class Number : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1IdentifierTokenNode,
            Asn1NumberTokenNode,
        );
    }

    final static class DefinedValue : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1IdentifierTokenNode,
            Asn1DefinedValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.NamedBit, 
        Number,
        DefinedValue,
    );
}

/++
    BitStringValue ::=
        bstring
        | hstring
        | "{" IdentifierList "}"
        | "{" "}"
        | CONTAINING Value
 ++/
final class Asn1BitStringValueNode : Asn1BaseNode
{
    final static class Empty : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE, Asn1EmptyNode);
    }

    mixin OneOf!(Asn1NodeType.BitStringValue, 
        Asn1BstringTokenNode,
        Asn1HstringTokenNode,
        Asn1IdentifierListNode,
        Empty,
        Asn1ValueNode,
    );
}

/++
    IdentifierList ::=
        identifier
        | IdentifierList "," identifier
 ++/
final class Asn1IdentifierListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.IdentifierList, Asn1IdentifierTokenNode);
}

/++
    OctetStringType ::= OCTET STRING
 ++/
alias Asn1OctetStringTypeNode = Asn1StaticNode!(Asn1NodeType.OctetStringType);

/++
    OctetStringValue ::=
        bstring
        | hstring
        | CONTAINING Value
 ++/
final class Asn1OctetStringValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.OctetStringValue,
        Asn1BstringTokenNode,
        Asn1HstringTokenNode,
        Asn1ValueNode,
    );
}

/++
    NullType ::= NULL
 ++/
alias Asn1NullTypeNode = Asn1StaticNode!(Asn1NodeType.NullType);

/++
    NullValue ::= NULL
 ++/
alias Asn1NullValueNode = Asn1StaticNode!(Asn1NodeType.NullValue);

/++
    SequenceType ::=
        SEQUENCE "{" "}"
        | SEQUENCE "{" ExtensionAndException OptionalExtensionMarker "}"
            (I don't know why this one exists, since ComponentTypeLists covers this case?)
        | SEQUENCE "{" ComponentTypeLists "}"
 ++/
final class Asn1SequenceTypeNode : Asn1BaseNode
{
    alias Empty = Asn1StaticNode!(Asn1NodeType.FAILSAFE);

    mixin OneOf!(Asn1NodeType.SequenceType,
        Empty,
        Asn1ComponentTypeListsNode,
    );
}

/++
    ExtensionAndException ::= "..." | "..." ExceptionSpec
 ++/
final class Asn1ExtensionAndExceptionNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionAndException,
        Asn1ElipsisNode,
        Asn1ExceptionSpecNode,
    );
}

/++
    OptionalExtensionMarker ::= "," "..." | empty
 ++/
final class Asn1OptionalExtensionMarkerNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.OptionalExtensionMarker,
        Asn1ElipsisNode,
        Asn1EmptyNode,
    );
}

/++
    ComponentTypeLists ::=
        RootComponentTypeList
        [case1] | RootComponentTypeList "," ExtensionAndException ExtensionAdditions OptionalExtensionMarker
        [case2] | RootComponentTypeList "," ExtensionAndException ExtensionAdditions ExtensionEndMarker "," RootComponentTypeList
        [case3] | ExtensionAndException ExtensionAdditions ExtensionEndMarker "," RootComponentTypeList
        [case4] | ExtensionAndException ExtensionAdditions OptionalExtensionMarker
 ++/
final class Asn1ComponentTypeListsNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootComponentTypeListNode,
            Asn1ExtensionAndExceptionNode,
            Asn1ExtensionAdditionsNode,
            Asn1OptionalExtensionMarkerNode,
        );
    }

    final static class Case2 : Asn1BaseNode
    {
        final static class Additional : Asn1BaseNode
        {
            mixin Container!(Asn1NodeType.FAILSAFE,
                Asn1RootComponentTypeListNode
            );
        }

        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootComponentTypeListNode,
            Asn1ExtensionAndExceptionNode,
            Asn1ExtensionAdditionsNode,
            Asn1ExtensionEndMarkerNode,
            Additional,
        );
    }

    final static class Case3 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ExtensionAndExceptionNode,
            Asn1ExtensionAdditionsNode,
            Asn1ExtensionEndMarkerNode,
            Asn1RootComponentTypeListNode,
        );
    }

    final static class Case4 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ExtensionAndExceptionNode,
            Asn1ExtensionAdditionsNode,
            Asn1OptionalExtensionMarkerNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ComponentTypeLists,
        Asn1RootComponentTypeListNode,
        Case1,
        Case2,
        Case3,
        Case4,
    );
}

/++
    RootComponentTypeList ::= ComponentTypeList
 ++/
final class Asn1RootComponentTypeListNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.RootComponentTypeList,
        Asn1ComponentTypeListNode
    );
}

/++
    ExtensionEndMarker ::= "," "..."
 ++/
alias Asn1ExtensionEndMarkerNode = Asn1StaticNode!(Asn1NodeType.ExtensionEndMarker);

/++
    ExtensionAdditions ::=
        "," ExtensionAdditionList
        | empty
 ++/
final class Asn1ExtensionAdditionsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionAdditions,
        Asn1ExtensionAdditionListNode,
        Asn1EmptyNode,
    );
}

/++
    ExtensionAdditionList ::=
        ExtensionAddition
        | ExtensionAdditionList "," ExtensionAddition
 ++/
final class Asn1ExtensionAdditionListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ExtensionAdditionList, Asn1ExtensionAdditionNode);
}

/++
    ExtensionAddition ::=
        ComponentType
        | ExtensionAdditionGroup
 ++/
final class Asn1ExtensionAdditionNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionAddition,
        Asn1ComponentTypeNode,
        Asn1ExtensionAdditionGroupNode,
    );
}

/++
    ExtensionAdditionGroup ::= "[[" VersionNumber ComponentTypeList "]]"
 ++/
final class Asn1ExtensionAdditionGroupNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExtensionAdditionGroup,
        Asn1VersionNumberNode,
        Asn1ComponentTypeListNode,
    );
}

/++
    VersionNumber ::= empty | number ":"
 ++/
final class Asn1VersionNumberNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.VersionNumber,
        Asn1EmptyNode,
        Asn1NumberTokenNode,
    );
}

/++
    ComponentTypeList ::=
        ComponentType
        | ComponentTypeList "," ComponentType
 ++/
final class Asn1ComponentTypeListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ComponentTypeList, Asn1ComponentTypeNode);
}

/++
    ComponentType ::=
        NamedType
        | NamedType OPTIONAL
        | NamedType DEFAULT Value
        | COMPONENTS OF Type
 ++/
final class Asn1ComponentTypeNode : Asn1BaseNode
{
    final static class Optional : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1NamedTypeNode,
        );
    }

    final static class Default : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1NamedTypeNode,
            Asn1ValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ComponentType, 
        Asn1NamedTypeNode,
        Optional,
        Default,
        Asn1TypeNode,
    );
}

/++
    SequenceValue ::=
        "{" ComponentValueList "}"
        | "{" "}"
 ++/
final class Asn1SequenceValueNode : Asn1BaseNode
{
    final static class Empty : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE, Asn1EmptyNode);
    }

    mixin OneOf!(Asn1NodeType.SequenceValue, 
        Asn1ComponentValueListNode,
        Empty,
    );
}

/++
    ComponentValueList ::=
        NamedValue
        | ComponentValueList "," NamedValue
 ++/
final class Asn1ComponentValueListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ComponentValueList, Asn1NamedValueNode);
}

/++
    SequenceOfType ::= SEQUENCE OF Type | SEQUENCE OF NamedType
 ++/
final class Asn1SequenceOfTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SequenceOfType, 
        Asn1TypeNode,
        Asn1NamedTypeNode,
    );
}

/++
    SequenceOfValue ::=
        "{" ValueList "}"
        | "{" NamedValueList "}"
        | "{" "}"
 ++/
final class Asn1SequenceOfValueNode : Asn1BaseNode
{
    final static class Empty : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE, Asn1EmptyNode);
    }

    mixin OneOf!(Asn1NodeType.SequenceOfValue, 
        Asn1ValueListNode,
        Asn1NamedValueListNode,
        Empty,
    );
}

/++
    ValueList ::=
        Value
        | ValueList "," Value
 ++/
final class Asn1ValueListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ValueList, Asn1ValueNode);
}

/++
    NamedValueList ::=
        NamedValue
        | NamedValueList "," NamedValue
 ++/
final class Asn1NamedValueListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.NamedValueList, Asn1NamedValueNode);
}

/++
    SetType ::=
        SET "{" "}"
        | SET "{" ExtensionAndException OptionalExtensionMarker "}"
        | SET "{" ComponentTypeLists "}"
 ++/
final class Asn1SetTypeNode : Asn1BaseNode
{
    alias Empty = Asn1StaticNode!(Asn1NodeType.empty);

    mixin OneOf!(Asn1NodeType.SetType, 
        Empty,
        Asn1ComponentTypeListsNode,
    );
}

/++
    SetValue ::=
        "{" ComponentValueList "}"
        | "{" "}"
 ++/
final class Asn1SetValueNode : Asn1BaseNode
{
    final static class Empty : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE, Asn1EmptyNode);
    }

    mixin OneOf!(Asn1NodeType.SetValue, 
        Asn1ComponentValueListNode,
        Empty,
    );
}

/++
    SetOfType ::=
        SET OF Type
        | SET OF NamedType
 ++/
final class Asn1SetOfTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SetOfType, 
        Asn1TypeNode,
        Asn1NamedTypeNode,
    );
}

/++
    SetOfValue ::=
        "{" ValueList "}"
        | "{" NamedValueList "}"
        | "{" "}"
 ++/
final class Asn1SetOfValueNode : Asn1BaseNode
{
    final static class Empty : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE, Asn1EmptyNode);
    }

    mixin OneOf!(Asn1NodeType.SetOfValue, 
        Asn1ValueListNode,
        Asn1NamedValueListNode,
        Empty,
    );
}

/++
    ChoiceType ::= CHOICE "{" AlternativeTypeLists "}"
 ++/
final class Asn1ChoiceTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ChoiceType, 
        Asn1AlternativeTypeListsNode,
    );
}

/++
    AlternativeTypeLists ::=
                RootAlternativeTypeList
        [Case1] | RootAlternativeTypeList "," ExtensionAndException ExtensionAdditionAlternatives OptionalExtensionMarker
 ++/
final class Asn1AlternativeTypeListsNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootAlternativeTypeListNode,
            Asn1ExtensionAndExceptionNode,
            Asn1ExtensionAdditionAlternativesNode,
            Asn1OptionalExtensionMarkerNode,
        );
    }

    mixin OneOf!(Asn1NodeType.AlternativeTypeLists,
        Asn1RootAlternativeTypeListNode,
        Case1,
    );
}

/++
    RootAlternativeTypeList ::= AlternativeTypeList
 ++/
final class Asn1RootAlternativeTypeListNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.RootAlternativeTypeList,
        Asn1AlternativeTypeListNode,
    );
}

/++
    ExtensionAdditionAlternatives ::=
        "," ExtensionAdditionAlternativesList
        | empty
 ++/
final class Asn1ExtensionAdditionAlternativesNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionAdditionAlternatives,
        Asn1ExtensionAdditionAlternativesListNode,
        Asn1EmptyNode,
    );
}

/++
    ExtensionAdditionAlternativesList ::=
        ExtensionAdditionAlternative
        | ExtensionAdditionAlternativesList "," ExtensionAdditionAlternative
 ++/
final class Asn1ExtensionAdditionAlternativesListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ExtensionAdditionAlternativesList,
        Asn1ExtensionAdditionAlternativeNode,
    );
}

/++
    ExtensionAdditionAlternative ::=
        ExtensionAdditionAlternativesGroup
        | NamedType
 ++/
final class Asn1ExtensionAdditionAlternativeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExtensionAdditionAlternative,
        Asn1ExtensionAdditionAlternativesGroupNode,
        Asn1NamedTypeNode,
    );
}

/++
    ExtensionAdditionAlternativesGroup ::=
        "[[" VersionNumber AlternativeTypeList "]]"
 ++/
final class Asn1ExtensionAdditionAlternativesGroupNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExtensionAdditionAlternativesGroup,
        Asn1VersionNumberNode,
        Asn1AlternativeTypeListNode,
    );
}

/++
    AlternativeTypeList ::=
        NamedType
        | AlternativeTypeList "," NamedType
 ++/
final class Asn1AlternativeTypeListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.AlternativeTypeList, Asn1NamedTypeNode);
}

/++
    ChoiceValue ::= identifier ":" Value
 ++/
final class Asn1ChoiceValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ChoiceValue, 
        Asn1IdentifierTokenNode,
        Asn1ValueNode,
    );
}

/++
    SelectionType ::= identifier "<" Type
 ++/
final class Asn1SelectionTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SelectionType, 
        Asn1IdentifierTokenNode,
        Asn1TypeNode,
    );
}

/++
    TaggedType ::=
        Tag Type
        | Tag IMPLICIT Type
        | Tag EXPLICIT Type
 ++/
final class Asn1TaggedTypeNode : Asn1BaseNode
{
    final static class Default : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TagNode,
            Asn1TypeNode,
        );
    }

    final static class Implicit : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TagNode,
            Asn1TypeNode,
        );
    }

    final static class Explicit : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TagNode,
            Asn1TypeNode,
        );
    }

    mixin OneOf!(Asn1NodeType.TaggedType, 
        Default,
        Implicit,
        Explicit,
    );
}

/++
    Tag ::= "[" Class ClassNumber "]"
 ++/
final class Asn1TagNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Tag, 
        Asn1ClassNode,
        Asn1ClassNumberNode,
    );
}

/++
    ClassNumber ::=
        number
        | DefinedValue
 ++/
final class Asn1ClassNumberNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ClassNumber, 
        Asn1NumberTokenNode,
        Asn1DefinedValueNode,
    );
}

/++
    Class ::= UNIVERSAL
        | APPLICATION
        | PRIVATE
        | empty
 ++/
final class Asn1ClassNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Class, 
        Asn1UniversalNode,
        Asn1ApplicationNode,
        Asn1PrivateNode,
        Asn1EmptyNode,
    );
}

/++
    TaggedValue ::= Value
 ++/
final class Asn1TaggedValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TaggedValue, 
        Asn1ValueNode,
    );
}

/++
    ObjectIdentifierType ::=
        OBJECT IDENTIFIER
 ++/
alias Asn1ObjectIdentifierTypeNode = Asn1StaticNode!(Asn1NodeType.OBJECT_IDENTIFIER);

/++
    ObjectIdentifierValue ::=
                "{" ObjIdComponentsList "}"
        [Case1] | "{" DefinedValue ObjIdComponentsList "}"
 ++/
final class Asn1ObjectIdentifierValueNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1DefinedValueNode,
            Asn1ObjIdComponentsListNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ObjectIdentifierValue, 
        Asn1ObjIdComponentsListNode,
        Case1,
    );
}

/++
    ObjIdComponentsList ::=
        ObjIdComponents
        | ObjIdComponents ObjIdComponentsList
 ++/
final class Asn1ObjIdComponentsListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ObjIdComponentsList, 
        Asn1ObjIdComponentsNode,
    );
}

/++
    ObjIdComponents ::=
        NameForm
        | NumberForm
        | NameAndNumberForm
        | DefinedValue
 ++/
final class Asn1ObjIdComponentsNode : Asn1BaseNode
{
    // NOTE: Due to ambiguity:
    //      - NameForm instead becomes DefinedValue (ValueReference case)
    //      - NumberForm's DefinedValue case is never used
    mixin OneOf!(Asn1NodeType.ObjIdComponents, 
        // Asn1NameFormNode,
        Asn1NumberFormNode,
        Asn1NameAndNumberFormNode,
        Asn1DefinedValueNode,
    );
}

/++
    NameForm ::= identifier
 ++/
final class Asn1NameFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.NameForm, 
        Asn1IdentifierTokenNode,
    );
}

/++
    NumberForm ::= number | DefinedValue
 ++/
final class Asn1NumberFormNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.NumberForm, 
        Asn1NumberTokenNode,
        Asn1DefinedValueNode, // Fun fact, this is redundant since all references already include DefinedValue as an option...
    );
}

/++
    NameAndNumberForm ::=
        identifier "(" NumberForm ")"
 ++/
final class Asn1NameAndNumberFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.NameAndNumberForm, 
        Asn1IdentifierTokenNode,
        Asn1NumberFormNode,
    );
}

/++
    RelativeOIDType ::= RELATIVE-OID
 ++/
alias Asn1RelativeOIDTypeNode = Asn1StaticNode!(Asn1NodeType.RELATIVE_OID);

/++
    RelativeOIDValue ::=
        "{" RelativeOIDComponentsList "}"
 ++/
final class Asn1RelativeOIDValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.RelativeOIDValue, 
        Asn1RelativeOIDComponentsListNode,
    );
}

/++
    RelativeOIDComponentsList ::=
        RelativeOIDComponents
        | RelativeOIDComponents RelativeOIDComponentsList
 ++/
final class Asn1RelativeOIDComponentsListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.RelativeOIDComponentsList, 
        Asn1RelativeOIDComponentsNode,
    );
}

/++
    RelativeOIDComponents ::=
        NumberForm
        | NameAndNumberForm
        | DefinedValue
 ++/
final class Asn1RelativeOIDComponentsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.RelativeOIDComponents, 
        Asn1NumberFormNode,
        Asn1NameAndNumberFormNode,
        Asn1DefinedValueNode,
    );
}

/++
    EmbeddedPDVType ::= EMBEDDED PDV
 + ++/
alias Asn1EmbeddedPDVTypeNode = Asn1StaticNode!(Asn1NodeType.EMBEDDED_PDV);

/++
    EmbeddedPdvValue ::= SequenceValue
 + ++/
final class Asn1EmbeddedPdvValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.EmbeddedPdvValue,
        Asn1SequenceValueNode,
    );
}

/++
    ExternalType ::= EXTERNAL
 + ++/
alias Asn1ExternalTypeNode = Asn1StaticNode!(Asn1NodeType.EXTERNAL);

/++
    ExternalValue ::= SequenceValue
 + ++/
final class Asn1ExternalValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalValue,
        Asn1SequenceValueNode,
    );
}

/++
    CharacterStringType ::=
        RestrictedCharacterStringType
        | UnrestrictedCharacterStringType
 + ++/
final class Asn1CharacterStringTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.CharacterStringType,
        Asn1RestrictedCharacterStringTypeNode,
        Asn1UnrestrictedCharacterStringTypeNode,
    );
}

/++
    CharacterStringValue ::=
        RestrictedCharacterStringValue
        | UnrestrictedCharacterStringValue
 + ++/
final class Asn1CharacterStringValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.CharacterStringValue,
        Asn1RestrictedCharacterStringValueNode,
        Asn1UnrestrictedCharacterStringValueNode,
    );
}

/++
    RestrictedCharacterStringType ::=
        BMPString
        | GeneralString
        | GraphicString
        | IA5String
        | ISO646String
        | NumericString
        | PrintableString
        | TeletexString
        | T61String
        | UniversalString
        | UTF8String
        | VideotexString
        | VisibleString
 + ++/
final class Asn1RestrictedCharacterStringTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.RestrictedCharacterStringType,
        Asn1BMPStringNode,
        Asn1GeneralStringNode,
        Asn1GraphicStringNode,
        Asn1IA5StringNode,
        Asn1ISO646StringNode,
        Asn1NumericStringNode,
        Asn1PrintableStringNode,
        Asn1TeletexStringNode,
        Asn1T61StringNode,
        Asn1UniversalStringNode,
        Asn1UTF8StringNode,
        Asn1VideotexStringNode,
        Asn1VisibleStringNode,
    );
}

/++
    RestrictedCharacterStringValue ::=
        cstring
        | CharacterStringList
        | Quadruple
        | Tuple
 + ++/
final class Asn1RestrictedCharacterStringValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.RestrictedCharacterStringValue,
        Asn1CstringTokenNode,
        Asn1CharacterStringListNode,
        Asn1QuadrupleNode,
        Asn1TupleNode,
    );
}

/++
    CharacterStringList ::= "{" CharSyms "}"
 + ++/
final class Asn1CharacterStringListNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.CharacterStringList,
        Asn1CharSymsNode,
    );
}

/++
    CharSyms ::=
        CharsDefn
        | CharSyms "," CharsDefn
 + ++/
final class Asn1CharSymsNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.CharSyms,
        Asn1CharsDefnNode,
    );
}

/++
    CharsDefn ::=
        cstring
        | Quadruple
        | Tuple
        | DefinedValue
 + ++/
final class Asn1CharsDefnNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.CharsDefn,
        Asn1CstringTokenNode,
        Asn1QuadrupleNode,
        Asn1TupleNode,
        Asn1DefinedValueNode,
    );
}

/++
    Quadruple ::= "{" Group "," Plane "," Row "," Cell "}"
 + ++/
final class Asn1QuadrupleNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Quadruple,
        Asn1GroupNode,
        Asn1PlaneNode,
        Asn1RowNode,
        Asn1CellNode,
    );
}

/++
    Group ::= number
 + ++/
final class Asn1GroupNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Group,
        Asn1NumberTokenNode,
    );
}

/++
    Plane ::= number
 + ++/
final class Asn1PlaneNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Plane,
        Asn1NumberTokenNode,
    );
}

/++
    Row ::= number
 + ++/
final class Asn1RowNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Row,
        Asn1NumberTokenNode,
    );
}

/++
    Cell ::= number
 + ++/
final class Asn1CellNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Cell,
        Asn1NumberTokenNode,
    );
}

/++
    Tuple ::= "{" TableColumn "," TableRow "}"
 + ++/
final class Asn1TupleNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Tuple,
        Asn1TableColumnNode,
        Asn1TableRowNode,
    );
}

/++
    TableColumn ::= number
 + ++/
final class Asn1TableColumnNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TableColumn,
        Asn1NumberTokenNode,
    );
}

/++
    TableRow ::= number
 + ++/
final class Asn1TableRowNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TableRow,
        Asn1NumberTokenNode,
    );
}

/++
    UnrestrictedCharacterStringType ::= CHARACTER STRING
 + ++/
alias Asn1UnrestrictedCharacterStringTypeNode = Asn1StaticNode!(Asn1NodeType.CHARACTER_STRING);

/++
    UnrestrictedCharacterStringValue ::= SequenceValue
 + ++/
final class Asn1UnrestrictedCharacterStringValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.UnrestrictedCharacterStringValue,
        Asn1SequenceValueNode,
    );
}

/++
    UsefulType ::= typereference
 + ++/
final class Asn1UsefulTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.UsefulType,
        Asn1TypeReferenceTokenNode,
    );
}

/++
    ConstrainedType ::=
        [Case1] Type Constraint
        | TypeWithConstraint
 + ++/
final class Asn1ConstrainedTypeNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TypeNode,
            Asn1ConstraintNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ConstrainedType,
        Case1,
        Asn1TypeWithConstraintNode,
    );
}

/++
    TypeWithConstraint ::=
        SET Constraint OF Type
        | SET SizeConstraint OF Type
        | SEQUENCE Constraint OF Type
        | SEQUENCE SizeConstraint OF Type
        | SET Constraint OF NamedType
        | SET SizeConstraint OF NamedType
        | SEQUENCE Constraint OF NamedType
        | SEQUENCE SizeConstraint OF NamedType
 + ++/
final class Asn1TypeWithConstraintNode : Asn1BaseNode
{
    final static class SetConstraintType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ConstraintNode,
            Asn1TypeNode,
        );
    }
    final static class SetSizeConstraintType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1SizeConstraintNode,
            Asn1TypeNode,
        );
    }
    final static class SequenceConstraintType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ConstraintNode,
            Asn1TypeNode,
        );
    }
    final static class SequenceSizeConstraintType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1SizeConstraintNode,
            Asn1TypeNode,
        );
    }
    final static class SetConstraintNamedType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ConstraintNode,
            Asn1NamedTypeNode,
        );
    }
    final static class SetSizeConstraintNamedType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1SizeConstraintNode,
            Asn1NamedTypeNode,
        );
    }
    final static class SequenceConstraintNamedType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ConstraintNode,
            Asn1NamedTypeNode,
        );
    }
    final static class SequenceSizeConstraintNamedType : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1SizeConstraintNode,
            Asn1NamedTypeNode,
        );
    }

    mixin OneOf!(Asn1NodeType.TypeWithConstraint,
        SetConstraintType,
        SetSizeConstraintType,
        SequenceConstraintType,
        SequenceSizeConstraintType,
        SetConstraintNamedType,
        SetSizeConstraintNamedType,
        SequenceConstraintNamedType,
        SequenceSizeConstraintNamedType,
    );
}

/++
    Constraint ::= "(" ConstraintSpec ExceptionSpec ")"
 + ++/
final class Asn1ConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Constraint,
        Asn1ConstraintSpecNode,
        Asn1ExceptionSpecNode,
    );
}

/++
    ConstraintSpec ::=
        SubtypeConstraint
        | GeneralConstraint
 + ++/
final class Asn1ConstraintSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Constraint,
        Asn1SubtypeConstraintNode,
        Asn1GeneralConstraintNode,
    );
}

/++
    SubtypeConstraint ::= ElementSetSpecs
 + ++/
final class Asn1SubtypeConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SubtypeConstraint,
        Asn1ElementSetSpecsNode,
    );
}

/++
    ElementSetSpecs ::=
                RootElementSetSpec
        [Case1] | RootElementSetSpec "," "..."
        [Case2] | RootElementSetSpec "," "..." "," AdditionalElementSetSpec
 + ++/
final class Asn1ElementSetSpecsNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootElementSetSpecNode,
        );
    }

    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootElementSetSpecNode,
            Asn1AdditionalElementSetSpecNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ElementSetSpecs,
        Asn1RootElementSetSpecNode,
        Case1,
        Case2,
    );
}

/++
    RootElementSetSpec ::= ElementSetSpec
 + ++/
final class Asn1RootElementSetSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.RootElementSetSpec,
        Asn1ElementSetSpecNode,
    );
}

/++
    AdditionalElementSetSpec ::= ElementSetSpec
 + ++/
final class Asn1AdditionalElementSetSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.AdditionalElementSetSpec,
        Asn1ElementSetSpecNode,
    );
}

/++
    ElementSetSpec ::= 
        Unions
        | ALL Exclusions
 + ++/
final class Asn1ElementSetSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ElementSetSpec,
        Asn1UnionsNode,
        Asn1ExclusionsNode,
    );
}

/++
    Unions ::= 
        Intersections
        | UElems UnionMark Intersections
 + ++/
final class Asn1UnionsNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.Unions, Asn1IntersectionsNode);
}

/++
    Intersections ::= 
        IntersectionElements
        | IElems IntersectionMark IntersectionElements
 + ++/
final class Asn1IntersectionsNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.Intersections, Asn1IntersectionElementsNode);
}

/++
    IntersectionElements ::= Elements | [Case1] Elems Exclusions
 + ++/
final class Asn1IntersectionElementsNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ElemsNode,
            Asn1ExclusionsNode,
        );
    }

    mixin OneOf!(Asn1NodeType.IntersectionElements, 
        Asn1ElementsNode,
        Case1,
    );
}

/++
    Elems ::= Elements
 + ++/
final class Asn1ElemsNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Elems, 
        Asn1ElementsNode,
    );
}

/++
    Exclusions ::= EXCEPT Elements
 + ++/
final class Asn1ExclusionsNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.Exclusions, 
        Asn1ElementsNode,
    );
}

/++
    Elements ::=
        SubtypeElements
        | ObjectSetElements
        | "(" ElementSetSpec ")"
 + ++/
final class Asn1ElementsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Elements, 
        Asn1SubtypeElementsNode,
        Asn1ObjectSetElementsNode,
        Asn1ElementSetSpecNode,
    );
}

/++
    SubtypeElements ::=
        SingleValue
        | ContainedSubtype
        | ValueRange
        | PermittedAlphabet
        | SizeConstraint
        | TypeConstraint
        | InnerTypeConstraints
        | PatternConstraint
 + ++/
final class Asn1SubtypeElementsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SubtypeElements,
        Asn1SingleValueNode,
        Asn1ContainedSubtypeNode,
        Asn1ValueRangeNode,
        Asn1PermittedAlphabetNode,
        Asn1SizeConstraintNode,
        Asn1TypeConstraintNode,
        Asn1InnerTypeConstraintsNode,
        Asn1PatternConstraintNode,
    );
}

/++
    SingleValue ::= Value
 + ++/
final class Asn1SingleValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SingleValue,
        Asn1ValueNode,
    );
}

/++
    ContainedSubtype ::= Includes Type
 + ++/
final class Asn1ContainedSubtypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ContainedSubtype,
        Asn1IncludesNode,
        Asn1TypeNode,
    );
}

/++
    Includes ::= INCLUDES | empty
 + ++/
final class Asn1IncludesNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Includes,
        Asn1IncludesMarkNode,
        Asn1EmptyNode,
    );
}

/++
    ValueRange ::= LowerEndpoint ".." UpperEndpoint
 + ++/
final class Asn1ValueRangeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueRange,
        Asn1LowerEndpointNode,
        Asn1UpperEndpointNode,
    );
}

/++
    LowerEndpoint ::= LowerEndValue | [Case1] LowerEndValue "<"
 + ++/
final class Asn1LowerEndpointNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1LowerEndValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.LowerEndpoint,
        Asn1LowerEndValueNode,
        Case1,
    );
}

/++
    UpperEndpoint ::= UpperEndValue | [Case1] "<" UpperEndValue
 + ++/
final class Asn1UpperEndpointNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1UpperEndValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.UpperEndpoint,
        Asn1UpperEndValueNode,
        Case1,
    );
}

/++
    LowerEndValue ::= Value | MIN
 + ++/
final class Asn1LowerEndValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.LowerEndValue,
        Asn1ValueNode,
        Asn1MinNode,
    );
}

/++
    UpperEndValue ::= Value | MAX
 + ++/
final class Asn1UpperEndValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.UpperEndValue,
        Asn1ValueNode,
        Asn1MaxNode,
    );
}

/++
    SizeConstraint ::= SIZE Constraint
 + ++/
final class Asn1SizeConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SizeConstraint,
        Asn1ConstraintNode,
    );
}

/++
    TypeConstraint ::= Type
 + ++/
final class Asn1TypeConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TypeConstraint,
        Asn1TypeNode,
    );
}

/++
    PermittedAlphabet ::= FROM Constraint
 + ++/
final class Asn1PermittedAlphabetNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.PermittedAlphabet,
        Asn1ConstraintNode,
    );
}

/++
    InnerTypeConstraints ::=
        WITH COMPONENT SingleTypeConstraint
        | WITH COMPONENTS MultipleTypeConstraints
 + ++/
final class Asn1InnerTypeConstraintsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.InnerTypeConstraints,
        Asn1SingleTypeConstraintNode,
        Asn1MultipleTypeConstraintsNode,
    );
}

/++
    SingleTypeConstraint ::= Constraint
 + ++/
final class Asn1SingleTypeConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SingleTypeConstraint,
        Asn1ConstraintNode,
    );
}

/++
    MultipleTypeConstraints ::=
        FullSpecification
        | PartialSpecification
 + ++/
final class Asn1MultipleTypeConstraintsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.MultipleTypeConstraints,
        Asn1FullSpecificationNode,
        Asn1PartialSpecificationNode,
    );
}

/++
    FullSpecification ::= "{" TypeConstraints "}"
 + ++/
final class Asn1FullSpecificationNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.FullSpecification,
        Asn1TypeConstraintsNode,
    );
}

/++
    PartialSpecification ::= "{" "..." "," TypeConstraints "}"
 + ++/
final class Asn1PartialSpecificationNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.PartialSpecification,
        Asn1TypeConstraintsNode,
    );
}

/++
    TypeConstraints ::=
        NamedConstraint
        | NamedConstraint "," TypeConstraints
 + ++/
final class Asn1TypeConstraintsNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.TypeConstraints,
        Asn1NamedConstraintNode,
    );
}

/++
    NamedConstraint ::=
        identifier ComponentConstraint
 + ++/
final class Asn1NamedConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.NamedConstraint,
        Asn1IdentifierTokenNode,
        Asn1ComponentConstraintNode,
    );
}

/++
    ComponentConstraint ::= ValueConstraint PresenceConstraint
 + ++/
final class Asn1ComponentConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ComponentConstraint,
        Asn1ValueConstraintNode,
        Asn1PresenceConstraintNode,
    );
}

/++
    ValueConstraint ::= Constraint | empty
 + ++/
final class Asn1ValueConstraintNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ValueConstraint,
        Asn1ConstraintNode,
        Asn1EmptyNode,
    );
}

/++
    PresenceConstraint ::= PRESENT | ABSENT | OPTIONAL | empty
 + ++/
final class Asn1PresenceConstraintNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.PresenceConstraint,
        Asn1PresentNode,
        Asn1AbsentNode,
        Asn1OptionalNode,
        Asn1EmptyNode,
    );
}

/++
    PatternConstraint ::= PATTERN Value
 + ++/
final class Asn1PatternConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.PatternConstraint,
        Asn1ValueNode,
    );
}

/++
    ExceptionSpec ::= "!" ExceptionIdentification | empty
 + ++/
final class Asn1ExceptionSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ExceptionSpec,
        Asn1ExceptionIdentificationNode,
        Asn1EmptyNode,
    );
}

/++
    ExceptionIdentification ::=
        SignedNumber
        | DefinedValue
        | Type ":" Value
 + ++/
final class Asn1ExceptionIdentificationNode : Asn1BaseNode
{
    final static class TypeValue : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TypeNode,
            Asn1ValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ExceptionIdentification,
        Asn1SignedNumberNode,
        Asn1DefinedValueNode,
        TypeValue,
    );
}

/++
    DefinedObjectClass ::=
        ExternalObjectClassReference | objectclassreference | UsefulObjectClassReference
 + ++/
final class Asn1DefinedObjectClassNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedObjectClass,
        Asn1ExternalObjectClassReferenceNode,
        Asn1ObjectClassReferenceTokenNode,
        Asn1UsefulObjectClassReferenceNode,
    );
}

/++
    DefinedObject ::=
        ExternalObjectReference
        | objectreference
 + ++/
final class Asn1DefinedObjectNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedObject,
        Asn1ExternalObjectReferenceNode,
        Asn1ObjectReferenceTokenNode,
    );
}

/++
    DefinedObjectSet ::=
        ExternalObjectSetReference
        | objectsetreference
 + ++/
final class Asn1DefinedObjectSetNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedObjectSet,
        Asn1ExternalObjectSetReferenceNode,
        Asn1ObjectSetReferenceTokenNode,
    );
}

/++
    ExternalObjectClassReference ::= modulereference "." objectclassreference
 + ++/
final class Asn1ExternalObjectClassReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalObjectClassReference,
        Asn1ModuleReferenceTokenNode,
        Asn1ObjectClassReferenceTokenNode,
    );
}

/++
    ExternalObjectReference ::=
        modulereference
        "."
        objectreference
 + ++/
final class Asn1ExternalObjectReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalObjectReference,
        Asn1ModuleReferenceTokenNode,
        Asn1ObjectReferenceTokenNode,
    );
}

/++
    ExternalObjectSetReference ::=
        modulereference
        "."
        objectsetreference
 + ++/
final class Asn1ExternalObjectSetReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ExternalObjectSetReference,
        Asn1ModuleReferenceTokenNode,
        Asn1ObjectSetReferenceTokenNode,
    );
}

/++
    UsefulObjectClassReference ::=
        TYPE-IDENTIFIER
        | ABSTRACT-SYNTAX
 + ++/
final class Asn1UsefulObjectClassReferenceNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.UsefulObjectClassReference,
        Asn1TypeIdentifierNode,
        Asn1AbstractSyntaxNode,
    );
}

/++
    ObjectClassAssignment ::= objectclassreference "::=" ObjectClass
 + ++/
final class Asn1ObjectClassAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectClassAssignment,
        Asn1ObjectClassReferenceTokenNode,
        Asn1ObjectClassNode,
    );
}

/++
    ObjectClass ::= DefinedObjectClass | ObjectClassDefn | ParameterizedObjectClass
 + ++/
final class Asn1ObjectClassNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectClass,
        Asn1DefinedObjectClassNode,
        Asn1ObjectClassDefnNode,
        Asn1ParameterizedObjectClassNode,
    );
}

/++
    ObjectClassDefn ::= CLASS "{" FieldSpecList "}" WithSyntaxSpec
 + ++/
final class Asn1ObjectClassDefnNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectClassDefn,
        Asn1FieldSpecListNode,
        Asn1WithSyntaxSpecNode,
    );
}

/++
    Unrolled: FieldSpec "," +
 + ++/
final class Asn1FieldSpecListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ObjectClass,
        Asn1FieldSpecNode,
    );
}

/++
    WithSyntaxSpec ::= WITH SYNTAX "{" SyntaxList "}" | empty
 + ++/
final class Asn1WithSyntaxSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.WithSyntaxSpec,
        Asn1SyntaxListNode,
        Asn1EmptyNode,
    );
}

/++
    FieldSpec ::=
        TypeFieldSpec
        | FixedTypeValueFieldSpec
        | VariableTypeValueFieldSpec
        | FixedTypeValueSetFieldSpec
        | VariableTypeValueSetFieldSpec
        | ObjectFieldSpec
        | ObjectSetFieldSpec
 + ++/
final class Asn1FieldSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.FieldSpec,
        Asn1TypeFieldSpecNode,
        Asn1FixedTypeValueFieldSpecNode,
        Asn1VariableTypeValueFieldSpecNode,
        Asn1FixedTypeValueSetFieldSpecNode,
        Asn1VariableTypeValueSetFieldSpecNode,
        Asn1ObjectFieldSpecNode,
        Asn1ObjectSetFieldSpecNode,
    );
}

/++
    TypeFieldSpec ::=
        typefieldreference
        TypeOptionalitySpec
 + ++/
final class Asn1TypeFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TypeFieldSpec,
        Asn1TypeFieldReferenceTokenNode,
        Asn1TypeOptionalitySpecNode,
    );
}

/++
    TypeOptionalitySpec ::= OPTIONAL | DEFAULT Type | empty
 + ++/
final class Asn1TypeOptionalitySpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.TypeOptionalitySpec,
        Asn1OptionalNode,
        Asn1TypeNode,
        Asn1EmptyNode,
    );
}

/++
    FixedTypeValueFieldSpec ::=
        valuefieldreference
        Type
        OptionalUniqueMark
        ValueOptionalitySpec
 + ++/
final class Asn1FixedTypeValueFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.FixedTypeValueFieldSpec,
        Asn1ValueFieldReferenceTokenNode,
        Asn1TypeNode,
        Asn1OptionalUniqueMarkNode,
        Asn1ValueOptionalitySpecNode,
    );
}

/++
    OptionalUniqueMark ::= UNIQUE | empty
 + ++/
final class Asn1OptionalUniqueMarkNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.OptionalUniqueMark,
        Asn1UniqueNode,
        Asn1EmptyNode,
    );
}

/++
    ValueOptionalitySpec ::= OPTIONAL | DEFAULT Value | empty
 + ++/
final class Asn1ValueOptionalitySpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ValueOptionalitySpec,
        Asn1OptionalNode,
        Asn1ValueNode,
        Asn1EmptyNode,
    );
}

/++
    VariableTypeValueFieldSpec ::=
        valuefieldreference
        FieldName
        ValueOptionalitySpec
 + ++/
final class Asn1VariableTypeValueFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.VariableTypeValueFieldSpec,
        Asn1ValueFieldReferenceTokenNode,
        Asn1FieldNameNode,
        Asn1ValueOptionalitySpecNode,
    );
}

/++
    FixedTypeValueSetFieldSpec ::=
        valuesetfieldreference
        Type
        ValueSetOptionalitySpec
 + ++/
final class Asn1FixedTypeValueSetFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.FixedTypeValueSetFieldSpec,
        Asn1ValueSetFieldReferenceTokenNode,
        Asn1TypeNode,
        Asn1ValueSetOptionalitySpecNode,
    );
}

/++
    ValueSetOptionalitySpec ::= OPTIONAL | DEFAULT ValueSet | empty
 + ++/
final class Asn1ValueSetOptionalitySpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ValueSetOptionalitySpec,
        Asn1OptionalNode,
        Asn1ValueSetNode,
        Asn1EmptyNode,
    );
}

/++
    VariableTypeValueSetFieldSpec ::=
        valuesetfieldreference
        FieldName
        ValueSetOptionalitySpec
 + ++/
final class Asn1VariableTypeValueSetFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.VariableTypeValueSetFieldSpec,
        Asn1ValueSetFieldReferenceTokenNode,
        Asn1FieldNameNode,
        Asn1ValueSetOptionalitySpecNode,
    );
}

/++
    ObjectFieldSpec ::=
        objectfieldreference
        DefinedObjectClass
        ObjectOptionalitySpec
 + ++/
final class Asn1ObjectFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectFieldSpec,
        Asn1ObjectFieldReferenceTokenNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectOptionalitySpecNode,
    );
}

/++
    ObjectOptionalitySpec ::= OPTIONAL | DEFAULT Object | empty
 + ++/
final class Asn1ObjectOptionalitySpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectOptionalitySpec,
        Asn1OptionalNode,
        Asn1ObjectNode,
        Asn1EmptyNode,
    );
}

/++
    ObjectSetFieldSpec ::=
        objectsetfieldreference
        DefinedObjectClass
        ObjectSetOptionalitySpec
 + ++/
final class Asn1ObjectSetFieldSpecNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectSetFieldSpec,
        Asn1ObjectSetFieldReferenceTokenNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectSetOptionalitySpecNode,
    );
}

/++
    ObjectSetOptionalitySpec ::= OPTIONAL | DEFAULT ObjectSet | empty
 + ++/
final class Asn1ObjectSetOptionalitySpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectSetOptionalitySpec,
        Asn1OptionalNode,
        Asn1ObjectSetNode,
        Asn1EmptyNode,
    );
}

/++
    PrimitiveFieldName ::=
        typefieldreference
        | valuefieldreference
        | valuesetfieldreference
        | objectfieldreference
        | objectsetfieldreference
 + ++/
final class Asn1PrimitiveFieldNameNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.PrimitiveFieldName,
        Asn1TypeFieldReferenceTokenNode,
        Asn1ValueFieldReferenceTokenNode,
        Asn1ValueSetFieldReferenceTokenNode,
        Asn1ObjectFieldReferenceTokenNode,
        Asn1ObjectSetFieldReferenceTokenNode,
    );
}

/++
    FieldName ::= PrimitiveFieldName "." +
 + ++/
final class Asn1FieldNameNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.FieldName,
        Asn1PrimitiveFieldNameNode,
    );
}

/++
    SyntaxList ::= TokenOrGroupSpec empty +
 + ++/
final class Asn1SyntaxListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.SyntaxList,
        Asn1TokenOrGroupSpecNode,
    );
}

/++
    TokenOrGroupSpec ::= RequiredToken | "[" OptionalGroup "]"
 + ++/
final class Asn1TokenOrGroupSpecNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.TokenOrGroupSpec,
        Asn1RequiredTokenNode,
        Asn1OptionalGroupNode,
    );
}

/++
    OptionalGroup ::= TokenOrGroupSpec empty +
 + ++/
final class Asn1OptionalGroupNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.OptionalGroup,
        Asn1TokenOrGroupSpecNode,
    );
}

/++
    RequiredToken ::=
        Literal
        | PrimitiveFieldName
 + ++/
final class Asn1RequiredTokenNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.RequiredToken,
        Asn1LiteralNode,
        Asn1PrimitiveFieldNameNode,
    );
}

/++
    Literal ::=
        word
        | ","
 + ++/
final class Asn1LiteralNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Literal,
        Asn1WordTokenNode,
        Asn1CommaNode,
    );
}

/++
    ObjectAssignment ::=
        objectreference
        DefinedObjectClass
        "::="
        Object
 + ++/
final class Asn1ObjectAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectAssignment,
        Asn1ObjectReferenceTokenNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectNode,
    );
}

/++
    Object ::=
        DefinedObject
        | ObjectDefn
        | ObjectFromObject
        | ParameterizedObject
 + ++/
final class Asn1ObjectNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Object,
        Asn1DefinedObjectNode,
        Asn1ObjectDefnNode,
        Asn1ObjectFromObjectNode,
        Asn1ParameterizedObjectNode,
    );
}

/++
    ObjectDefn ::=
        "{" DefaultSyntax "}"
        | "{" DefinedSyntax "}"
 + ++/
final class Asn1ObjectDefnNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectDefn,
        Asn1DefaultSyntaxNode,
        Asn1DefinedSyntaxNode,
    );
}

/++
    DefaultSyntax ::= FieldSetting "," *
 + ++/
final class Asn1DefaultSyntaxNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.DefaultSyntax,
        Asn1FieldSettingNode,
    );
}

/++
    FieldSetting ::= PrimitiveFieldName Setting
 + ++/
final class Asn1FieldSettingNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.FieldSetting,
        Asn1PrimitiveFieldNameNode,
        Asn1SettingNode,
    );
}

/++
    DefinedSyntax ::= DefinedSyntaxToken empty *
 + ++/
final class Asn1DefinedSyntaxNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.DefinedSyntax,
        Asn1DefinedSyntaxTokenNode,
    );
}

/++
    DefinedSyntaxToken ::=
        Literal
        | Setting
 + ++/
final class Asn1DefinedSyntaxTokenNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.DefinedSyntaxToken,
        Asn1LiteralNode,
        Asn1SettingNode,
    );
}

/++
    Setting ::=
        Type
        | Value
        | ValueSet
        | Object
        | ObjectSet
 + ++/
final class Asn1SettingNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Setting,
        Asn1TypeNode,
        Asn1ValueNode,
        Asn1ValueSetNode,
        Asn1ObjectNode,
        Asn1ObjectSetNode,
    );
}

/++
    ObjectSetAssignment ::=
        objectsetreference
        DefinedObjectClass
        "::="
        ObjectSet
 + ++/
final class Asn1ObjectSetAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectSetAssignment,
        Asn1ObjectSetReferenceTokenNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectSetNode,
    );
}

/++
    ObjectSet ::= "{" ObjectSetSpec "}"
 + ++/
final class Asn1ObjectSetNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectSet,
        Asn1ObjectSetSpecNode,
    );
}

/++
    ObjectSetSpec ::=
                RootElementSetSpec
        [Case1] | RootElementSetSpec "," "..."
                | "..."
        [Case3] | "..." "," AdditionalElementSetSpec
        [Case4] | RootElementSetSpec "," "..." "," AdditionalElementSetSpec
 + ++/
final class Asn1ObjectSetSpecNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootElementSetSpecNode,
        );
    }

    final static class Case3 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1AdditionalElementSetSpecNode,
        );
    }

    final static class Case4 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1RootElementSetSpecNode,
            Asn1AdditionalElementSetSpecNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ObjectSetSpec,
        Asn1RootElementSetSpecNode,
        Case1,
        Asn1ElipsisNode,
        Case3,
        Case4
    );
}

/++
    ObjectSetElements ::=
        Object
        | DefinedObjectSet
        | ObjectSetFromObjects
        | ParameterizedObjectSet
 + ++/
final class Asn1ObjectSetElementsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectSetElements,
        Asn1ObjectNode,
        Asn1DefinedObjectSetNode,
        Asn1ObjectSetFromObjectsNode,
        Asn1ParameterizedObjectSetNode,
    );
}

/++
    ObjectClassFieldType ::=
        DefinedObjectClass
        "."
        FieldName
 + ++/
final class Asn1ObjectClassFieldTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectClassFieldType,
        Asn1DefinedObjectClassNode,
        Asn1FieldNameNode,
    );
}

/++
    ObjectClassFieldValue ::=
        OpenTypeFieldVal
        | FixedTypeFieldVal
 + ++/
final class Asn1ObjectClassFieldValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ObjectClassFieldValue,
        Asn1OpenTypeFieldValNode,
        Asn1FixedTypeFieldValNode,
    );
}

/++
    OpenTypeFieldVal ::= Type ":" Value
 + ++/
final class Asn1OpenTypeFieldValNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.OpenTypeFieldVal,
        Asn1TypeNode,
        Asn1ValueNode,
    );
}

/++
    FixedTypeFieldVal ::= BuiltinValue | ReferencedValue
 + ++/
final class Asn1FixedTypeFieldValNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.FixedTypeFieldVal,
        Asn1BuiltinValueNode,
        Asn1ReferencedValueNode,
    );
}

/++
    InformationFromObjects ::=
        ValueFromObject
        | ValueSetFromObjects
        | TypeFromObject
        | ObjectFromObject
        | ObjectSetFromObjects
 + ++/
final class Asn1InformationFromObjectsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.InformationFromObjects,
        Asn1ValueFromObjectNode,
        Asn1ValueSetFromObjectsNode,
        Asn1TypeFromObjectNode,
        Asn1ObjectFromObjectNode,
        Asn1ObjectSetFromObjectsNode,
    );
}

/++
    ValueFromObject ::=
        ReferencedObjects
        "."
        FieldName
 + ++/
final class Asn1ValueFromObjectNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueFromObject,
        Asn1ReferencedObjectsNode,
        Asn1FieldNameNode,
    );
}

/++
    ValueSetFromObjects ::=
        ReferencedObjects
        "."
        FieldName
 + ++/
final class Asn1ValueSetFromObjectsNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ValueSetFromObjects,
        Asn1ReferencedObjectsNode,
        Asn1FieldNameNode,
    );
}

/++
    TypeFromObject ::=
        ReferencedObjects
        "."
        FieldName
 + ++/
final class Asn1TypeFromObjectNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.TypeFromObject,
        Asn1ReferencedObjectsNode,
        Asn1FieldNameNode,
    );
}

/++
    ObjectFromObject ::=
        ReferencedObjects
        "."
        FieldName
 + ++/
final class Asn1ObjectFromObjectNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectFromObject,
        Asn1ReferencedObjectsNode,
        Asn1FieldNameNode,
    );
}

/++
    ObjectSetFromObjects ::=
        ReferencedObjects
        "."
        FieldName
 + ++/
final class Asn1ObjectSetFromObjectsNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ObjectSetFromObjects,
        Asn1ReferencedObjectsNode,
        Asn1FieldNameNode,
    );
}

/++
    ReferencedObjects ::=
        DefinedObject
        | ParameterizedObject
        | DefinedObjectSet
        | ParameterizedObjectSet
 + ++/
final class Asn1ReferencedObjectsNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ReferencedObjects,
        Asn1DefinedObjectNode,
        Asn1ParameterizedObjectNode,
        Asn1DefinedObjectSetNode,
        Asn1ParameterizedObjectSetNode,
    );
}

/++
    InstanceOfType ::= INSTANCE OF DefinedObjectClass
 + ++/
final class Asn1InstanceOfTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.InstanceOfType,
        Asn1DefinedObjectClassNode,
    );
}

/++
    InstanceOfValue ::= Value
 + ++/
final class Asn1InstanceOfValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.InstanceOfValue,
        Asn1ValueNode,
    );
}

/++
    ParameterizedAssignment ::=
        ParameterizedTypeAssignment
        | ParameterizedValueAssignment
        | ParameterizedValueSetTypeAssignment
        | ParameterizedObjectClassAssignment
        | ParameterizedObjectAssignment
        | ParameterizedObjectSetAssignment
 + ++/
final class Asn1ParameterizedAssignmentNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ParameterizedAssignment,
        Asn1ParameterizedTypeAssignmentNode,
        Asn1ParameterizedValueAssignmentNode,
        Asn1ParameterizedValueSetTypeAssignmentNode,
        Asn1ParameterizedObjectClassAssignmentNode,
        Asn1ParameterizedObjectAssignmentNode,
        Asn1ParameterizedObjectSetAssignmentNode,
    );
}

/++
    ParameterizedTypeAssignment ::=
        typereference
        ParameterList
        "::="
        Type
 + ++/
final class Asn1ParameterizedTypeAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedTypeAssignment,
        Asn1TypeReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1TypeNode,
    );
}

/++
    ParameterizedValueAssignment ::=
        valuereference
        ParameterList
        Type
        "::="
        Value
 + ++/
final class Asn1ParameterizedValueAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedValueAssignment,
        Asn1ValueReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1TypeNode,
        Asn1ValueNode,
    );
}

/++
    ParameterizedValueSetTypeAssignment ::=
        typereference
        ParameterList
        Type
        "::="
        ValueSet
 + ++/
final class Asn1ParameterizedValueSetTypeAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedValueSetTypeAssignment,
        Asn1TypeReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1TypeNode,
        Asn1ValueSetNode,
    );
}

/++
    ParameterizedObjectClassAssignment ::=
        objectclassreference
        ParameterList
        "::="
        ObjectClass
 + ++/
final class Asn1ParameterizedObjectClassAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObjectClassAssignment,
        Asn1ObjectClassReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1ObjectClassNode,
    );
}

/++
    ParameterizedObjectAssignment ::=
        objectreference
        ParameterList
        DefinedObjectClass
        "::="
        Object
 + ++/
final class Asn1ParameterizedObjectAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObjectAssignment,
        Asn1ObjectReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectNode,
    );
}

/++
    ParameterizedObjectSetAssignment ::=
        objectsetreference
        ParameterList
        DefinedObjectClass
        "::="
        ObjectSet
 + ++/
final class Asn1ParameterizedObjectSetAssignmentNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObjectSetAssignment,
        Asn1ObjectSetReferenceTokenNode,
        Asn1ParameterListNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectSetNode,
    );
}

/++
    ParameterList ::= "{" ParameterListValues "}"
 + ++/
final class Asn1ParameterListNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterList,
        Asn1ParameterListValuesNode,
    );
}

/++
    ParameterListValues ::= Parameter "," +
 + ++/
final class Asn1ParameterListValuesNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ParameterListValues,
        Asn1ParameterNode,
    );
}

/++
    Parameter ::= [Case1] ParamGovernor ":" DummyReference | DummyReference
 + ++/
final class Asn1ParameterNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ParamGovernorNode,
            Asn1DummyReferenceNode,
        );
    }

    mixin OneOf!(Asn1NodeType.Parameter,
        Case1,
        Asn1DummyReferenceNode,
    );
}

/++
    ParamGovernor ::= Governor | DummyGovernor
 + ++/
final class Asn1ParamGovernorNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ParamGovernor,
        Asn1GovernorNode,
        Asn1DummyGovernorNode,
    );
}

/++
    Governor ::= Type | DefinedObjectClass
 + ++/
final class Asn1GovernorNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.Governor,
        Asn1TypeNode,
        Asn1DefinedObjectClassNode,
    );
}

/++
    DummyGovernor ::= DummyReference
 + ++/
final class Asn1DummyGovernorNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DummyGovernor,
        Asn1DummyReferenceNode,
    );
}

/++
    DummyReference ::= Reference
 + ++/
final class Asn1DummyReferenceNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DummyReference,
        Asn1ReferenceNode,
    );
}

/++
    ParameterizedReference ::= Reference | [Case2] Reference "{" "}"
 + ++/
final class Asn1ParameterizedReferenceNode : Asn1BaseNode
{
    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1ReferenceNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ParameterizedReference,
        Asn1ReferenceNode,
        Case2,
    );
}

/++
    ParameterizedType ::=
        SimpleDefinedType
        ActualParameterList
 + ++/
final class Asn1ParameterizedTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedType,
        Asn1SimpleDefinedTypeNode,
        Asn1ActualParameterListNode,
    );
}

/++
    SimpleDefinedType ::=
        ExternalTypeReference |
        typereference
 + ++/
final class Asn1SimpleDefinedTypeNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SimpleDefinedType,
        Asn1ExternalTypeReferenceNode,
        Asn1TypeReferenceTokenNode,
    );
}

/++
    ParameterizedValue ::=
        SimpleDefinedValue
        ActualParameterList
 + ++/
final class Asn1ParameterizedValueNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedValue,
        Asn1SimpleDefinedValueNode,
        Asn1ActualParameterListNode,
    );
}

/++
    SimpleDefinedValue ::=
        ExternalValueReference |
        valuereference
 + ++/
final class Asn1SimpleDefinedValueNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.SimpleDefinedValue,
        Asn1ExternalValueReferenceNode,
        Asn1ValueReferenceTokenNode,
    );
}

/++
    ParameterizedValueSetType ::=
        SimpleDefinedType
        ActualParameterList
 + ++/
final class Asn1ParameterizedValueSetTypeNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedValueSetType,
        Asn1SimpleDefinedTypeNode,
        Asn1ActualParameterListNode,
    );
}

/++
    ParameterizedObjectClass ::=
        DefinedObjectClass
        ActualParameterList
 + ++/
final class Asn1ParameterizedObjectClassNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObjectClass,
        Asn1DefinedObjectClassNode,
        Asn1ActualParameterListNode,
    );
}

/++
    ParameterizedObjectSet ::=
        DefinedObjectSet
        ActualParameterList
 + ++/
final class Asn1ParameterizedObjectSetNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObjectSet,
        Asn1DefinedObjectSetNode,
        Asn1ActualParameterListNode,
    );
}

/++
    ParameterizedObject ::=
        DefinedObject
        ActualParameterList
 + ++/
final class Asn1ParameterizedObjectNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ParameterizedObject,
        Asn1DefinedObjectNode,
        Asn1ActualParameterListNode,
    );
}

/++
    ActualParameterList ::=
        "{" ActualParameterListValues "}"
 + ++/
final class Asn1ActualParameterListNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ActualParameterList,
        Asn1ActualParameterListValuesNode,
    );
}

/++
    ActualParameterListValues ::=
        ActualParameter "," +
 + ++/
final class Asn1ActualParameterListValuesNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ActualParameterListValues,
        Asn1ActualParameterNode,
    );
}

/++
    ActualParameter ::=
        Type
        | Value
        | ValueSet
        | DefinedObjectClass
        | Object
        | ObjectSet
 + ++/
final class Asn1ActualParameterNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.ActualParameter,
        Asn1TypeNode,
        Asn1ValueNode,
        Asn1ValueSetNode,
        Asn1DefinedObjectClassNode,
        Asn1ObjectNode,
        Asn1ObjectSetNode,
    );
}

/++
    GeneralConstraint ::=
        CONSTRAINED BY "{" UserDefinedConstraint "}"
        | TableConstraint
        | ContentsConstraint
 + ++/
final class Asn1GeneralConstraintNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.GeneralConstraint,
        Asn1UserDefinedConstraintNode,
        Asn1TableConstraintNode,
        Asn1ContentsConstraintNode,
    );
}

/++
    UserDefinedConstraint ::=
        UserDefinedConstraintParameter "," *
 + ++/
final class Asn1UserDefinedConstraintNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.UserDefinedConstraint,
        Asn1UserDefinedConstraintParameterNode,
    );
}

/++
    UserDefinedConstraintParameter ::=
        [Case1] Governor ":" Value
        [Case2] | Governor ":" ValueSet
        [Case3] | Governor ":" Object
        [Case4] | Governor ":" ObjectSet
                | Type
                | DefinedObjectClass
 + ++/
final class Asn1UserDefinedConstraintParameterNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1GovernorNode,
            Asn1ValueNode,
        );
    }
    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1GovernorNode,
            Asn1ValueSetNode,
        );
    }
    final static class Case3 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1GovernorNode,
            Asn1ObjectNode,
        );
    }
    final static class Case4 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1GovernorNode,
            Asn1ObjectSetNode,
        );
    }

    mixin OneOf!(Asn1NodeType.UserDefinedConstraintParameter,
        Case1,
        Case2,
        Case3,
        Case4,
        Asn1TypeNode,
        Asn1DefinedObjectClassNode,
    );
}

/++
    TableConstraint ::=
        SimpleTableConstraint |
        ComponentRelationConstraint
 + ++/
final class Asn1TableConstraintNode : Asn1BaseNode
{
    mixin OneOf!(Asn1NodeType.TableConstraint,
        Asn1SimpleTableConstraintNode,
        Asn1ComponentRelationConstraintNode,
    );
}

/++
    SimpleTableConstraint ::= ObjectSet
 + ++/
final class Asn1SimpleTableConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.SimpleTableConstraint,
        Asn1ObjectSetNode,
    );
}

/++
    ComponentRelationConstraint ::=
        "{" DefinedObjectSet "}" "{" AtNotationList "}
 + ++/
final class Asn1ComponentRelationConstraintNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.ComponentRelationConstraint,
        Asn1DefinedObjectSetNode,
        Asn1AtNotationListNode,
    );
}

/++
    AtNotationList ::= AtNotation "," +
 + ++/
final class Asn1AtNotationListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.AtNotationList,
        Asn1AtNotationNode,
    );
}

/++
    AtNotation ::=
                "@" ComponentIdList |
        [Case2] "@." Level ComponentIdList
 + ++/
final class Asn1AtNotationNode : Asn1BaseNode
{
    final static class Case2 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1LevelNode,
            Asn1ComponentIdListNode,
        );
    }

    mixin OneOf!(Asn1NodeType.AtNotation,
        Asn1ComponentIdListNode,
        Case2,
    );
}

/++
    Level ::= "." Level | empty
 + ++/
final class Asn1LevelNode : Asn1BaseNode
{
    final static class Case1 : Asn1BaseNode
    {
        uint _level;
        this(uint level) @safe @nogc nothrow pure
        {
            super(Asn1NodeType.FAILSAFE);
            this._level = level;
        }

        uint level() @safe @nogc nothrow pure const
        {
            return this._level;
        }
    }

    mixin OneOf!(Asn1NodeType.Level,
        Case1,
        Asn1EmptyNode
    );
}

/++
    ComponentIdList ::= identifier "." +
 + ++/
final class Asn1ComponentIdListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.ComponentIdList,
        Asn1IdentifierTokenNode
    );
}

/++
    ContentsConstraint ::=
                CONTAINING Type
                | ENCODED BY Value
        [Case3] | CONTAINING Type ENCODED BY Value
 + ++/
final class Asn1ContentsConstraintNode : Asn1BaseNode
{
    final static class Case3 : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1TypeNode,
            Asn1ValueNode,
        );
    }

    mixin OneOf!(Asn1NodeType.ContentsConstraint,
        Asn1TypeNode,
        Asn1ValueNode,
        Case3,
    );
}