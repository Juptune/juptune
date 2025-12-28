module tests.x509.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;

static import tcon = std.typecons;
static import asn1 = juptune.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier id_pkix(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_pe(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_qt(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ad(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 48, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_qt_cps(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 2, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_qt_unotice(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 2, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ad_ocsp(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 48, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ad_caIssuers(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 48, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ad_timeStamping(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 48, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ad_caRepository(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 48, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

struct AttributeType
{
    private
    {
        asn1.Asn1ObjectIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1ObjectIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1ObjectIdentifier get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1ObjectIdentifier, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct AttributeTypeAndValue
{
    private
    {
        bool _isSet_type;
        .AttributeType _type;
        bool _isSet_value;
        asn1.Asn1Any _value;
    }

    jres.Result setType(
        typeof(_type) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_type = true;
        _type = value;
        return jres.Result.noError;
    }

    typeof(_type) getType(
    ) @nogc nothrow
    {
        assert(_isSet_type, "Non-optional field 'type' has not been set yet - please use validate() to check!");
        return _type;
    }

    jres.Result setValue(
        typeof(_value) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_value = true;
        _value = value;
        return jres.Result.noError;
    }

    typeof(_value) getValue(
    ) @nogc nothrow
    {
        assert(_isSet_value, "Non-optional field 'value' has not been set yet - please use validate() to check!");
        return _value;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_type)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AttributeTypeAndValue non-optional field 'type' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_value)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AttributeTypeAndValue non-optional field 'value' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("type: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_type), "toString"))
            _type.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("value: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_value), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: type +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'type' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AttributeTypeAndValue when reading top level tag 6 for field 'type' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AttributeTypeAndValue when reading top level tag 6 for field 'type' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_type;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_type);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'type' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - type ++/
        typeof(_type) temp_type;
        result = temp_type.fromDecoding!ruleset(memory_type, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'type' in type "~__traits(identifier, typeof(this))~":");
        result = this.setType(temp_type);
        if(result.isError)
            return result.wrapError("when setting field 'type' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: value +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'value' in type "~__traits(identifier, typeof(this))~":");
        // Field is the intrinsic ANY type - any tag is allowed.
        jbuf.MemoryReader memory_value;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_value);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'value' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - value ++/
        typeof(_value) temp_value;
        result = typeof(temp_value).fromDecoding!ruleset(memory_value, temp_value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'value' in type "~__traits(identifier, typeof(this))~":");
        result = this.setValue(temp_value);
        if(result.isError)
            return result.wrapError("when setting field 'value' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AttributeTypeAndValue there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct Attribute
{
    private
    {
        bool _isSet_type;
        .AttributeType _type;
        bool _isSet_values;
        asn1.Asn1SetOf!(asn1.Asn1Any) _values;
    }

    jres.Result setType(
        typeof(_type) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_type = true;
        _type = value;
        return jres.Result.noError;
    }

    typeof(_type) getType(
    ) @nogc nothrow
    {
        assert(_isSet_type, "Non-optional field 'type' has not been set yet - please use validate() to check!");
        return _type;
    }

    jres.Result setValues(
        typeof(_values) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_values = true;
        _values = value;
        return jres.Result.noError;
    }

    typeof(_values) getValues(
    ) @nogc nothrow
    {
        assert(_isSet_values, "Non-optional field 'values' has not been set yet - please use validate() to check!");
        return _values;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_type)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Attribute non-optional field 'type' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_values)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Attribute non-optional field 'values' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("type: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_type), "toString"))
            _type.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("values: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_values), "toString"))
            _values.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: type +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'type' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Attribute when reading top level tag 6 for field 'type' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Attribute when reading top level tag 6 for field 'type' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_type;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_type);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'type' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - type ++/
        typeof(_type) temp_type;
        result = temp_type.fromDecoding!ruleset(memory_type, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'type' in type "~__traits(identifier, typeof(this))~":");
        result = this.setType(temp_type);
        if(result.isError)
            return result.wrapError("when setting field 'type' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: values +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'values' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Attribute when reading top level tag 17 for field 'values' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Attribute when reading top level tag 17 for field 'values' the tag's value was expected to be 17", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_values;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_values);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'values' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - values ++/
        typeof(_values) temp_values;
        result = typeof(temp_values).fromDecoding!ruleset(memory_values, temp_values, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'values' in type "~__traits(identifier, typeof(this))~":");
        result = this.setValues(temp_values);
        if(result.isError)
            return result.wrapError("when setting field 'values' in type "~__traits(identifier, typeof(this))~":");

        result = this._values.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SET OF field 'values' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Attribute there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_at(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

.AttributeType id_at_name(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 41, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

.AttributeType id_at_surname(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 4, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

.AttributeType id_at_givenName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 42, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

.AttributeType id_at_initials(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 43, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

.AttributeType id_at_generationQualifier(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 44, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520name
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520name!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520name!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 32768;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 32768;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520name the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_commonName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 3, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520CommonName
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520CommonName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520CommonName!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 64;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520CommonName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_localityName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 7, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520LocalityName
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520LocalityName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520LocalityName!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 128;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 128;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520LocalityName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_stateOrProvinceName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 8, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520StateOrProvinceName
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520StateOrProvinceName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520StateOrProvinceName!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 128;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 128;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520StateOrProvinceName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_organizationName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 10, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520OrganizationName
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520OrganizationName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520OrganizationName!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 64;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520OrganizationName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_organizationalUnitName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 11, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520OrganizationalUnitName
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520OrganizationalUnitName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520OrganizationalUnitName!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 64;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520OrganizationalUnitName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_title(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 12, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520Title
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520Title!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520Title!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 64;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520Title the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_at_dnQualifier(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 46, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520dnQualifier
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

.AttributeType id_at_countryName(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 6, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520countryName
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length == 2;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

.AttributeType id_at_serialNumber(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 5, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520SerialNumber
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

.AttributeType id_at_pseudonym(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            4, 65, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct X520Pseudonym
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520Pseudonym!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised X520Pseudonym!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 128;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 128;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type X520Pseudonym the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

.AttributeType id_domainComponent(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            /* 2342 */ 0x92, 0x26, /* 19200300 */ 0x89, 0x93, 0xF2, 0x2C, 100, 1, 25, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(0, 9, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct DomainComponent
{
    private
    {
        asn1.Asn1Ia5String _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Ia5String newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Ia5String get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Ia5String, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1ObjectIdentifier pkcs_9(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

.AttributeType id_emailAddress(
) @nogc nothrow
{
    .AttributeType mainValue;
        asn1.Asn1ObjectIdentifier mainValue__underlying;
        static immutable ubyte[] mainValue__underlying__value = [
            /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 1, 
        ];
        mainValue__underlying = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__underlying__value);
    jres.resultAssert(mainValue.set(mainValue__underlying));
    return mainValue;

}

struct EmailAddress
{
    private
    {
        asn1.Asn1Ia5String _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Ia5String newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 255;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Ia5String get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Ia5String, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct Name
{
    enum Choice
    {
        _FAILSAFE,
        rdnSequence,
    }

    union Value
    {
        .RDNSequence rdnSequence;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.RDNSequence), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.rdnSequence)) @nogc nothrow handle_rdnSequence,
    ) @nogc nothrow
    {
        if(_choice == Choice.rdnSequence)
            return handle_rdnSequence(_value.rdnSequence);
        assert(false, "attempted to use an uninitialised Name!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.rdnSequence))  handle_rdnSequence,
    ) 
    {
        if(_choice == Choice.rdnSequence)
            return handle_rdnSequence(_value.rdnSequence);
        assert(false, "attempted to use an uninitialised Name!");

    }

    jres.Result setRdnSequence(
        typeof(Value.rdnSequence) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.rdnSequence = value;
        _choice = Choice.rdnSequence;
        return jres.Result.noError;
    }

    typeof(Value.rdnSequence) getRdnSequence(
    ) @nogc nothrow
    {
        assert(_choice == Choice.rdnSequence, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'rdnSequence'");
        return _value.rdnSequence;
    }

    bool isRdnSequence(
    ) @nogc nothrow const
    {
        return _choice == Choice.rdnSequence;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 16)
        {
            /++ FIELD - rdnSequence ++/
            typeof(Value.rdnSequence) temp_rdnSequence;
            result = temp_rdnSequence.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'rdnSequence' in type "~__traits(identifier, typeof(this))~":");
            result = this.setRdnSequence(temp_rdnSequence);
            if(result.isError)
                return result.wrapError("when setting field 'rdnSequence' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type Name the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isRdnSequence)
        {
            depth++;
            putIndent();
            sink("rdnSequence: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getRdnSequence()), "toString"))
                _value.rdnSequence.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct RDNSequence
{
    private
    {
        asn1.Asn1SequenceOf!(.RelativeDistinguishedName) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.RelativeDistinguishedName) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.RelativeDistinguishedName) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.RelativeDistinguishedName), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SEQEUENCE OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct DistinguishedName
{
    private
    {
        .RDNSequence _value;
        bool _isSet;
    }

    jres.Result set(
        .RDNSequence newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .RDNSequence get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .RDNSequence, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct RelativeDistinguishedName
{
    private
    {
        asn1.Asn1SetOf!(.AttributeTypeAndValue) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.AttributeTypeAndValue) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.elementCount >= 1 && newValue.elementCount <= 18446744073709551615;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(.AttributeTypeAndValue) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SetOf!(.AttributeTypeAndValue), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SET OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct DirectoryString
{
    enum Choice
    {
        _FAILSAFE,
        printableString,
        utf8String,
    }

    union Value
    {
        asn1.Asn1PrintableString printableString;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.printableString)) @nogc nothrow handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised DirectoryString!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.printableString))  handle_printableString,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.printableString)
            return handle_printableString(_value.printableString);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised DirectoryString!");

    }

    jres.Result setPrintableString(
        typeof(Value.printableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 18446744073709551615;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printableString = value;
        _choice = Choice.printableString;
        return jres.Result.noError;
    }

    typeof(Value.printableString) getPrintableString(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printableString, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printableString'");
        return _value.printableString;
    }

    bool isPrintableString(
    ) @nogc nothrow const
    {
        return _choice == Choice.printableString;
    }

    jres.Result setUtf8String(
        typeof(Value.utf8String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            size_t _utf8string__length;
            result = utf8.utf8Length(value.asSlice, _utf8string__length);
            if(result.isError)
                return result.wrapError("when counting length of utf8 string in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 18446744073709551615;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.utf8String = value;
        _choice = Choice.utf8String;
        return jres.Result.noError;
    }

    typeof(Value.utf8String) getUtf8String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utf8String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utf8String'");
        return _value.utf8String;
    }

    bool isUtf8String(
    ) @nogc nothrow const
    {
        return _choice == Choice.utf8String;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printableString ++/
            typeof(Value.printableString) temp_printableString;
            result = typeof(temp_printableString).fromDecoding!ruleset(memory, temp_printableString, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printableString' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintableString(temp_printableString);
            if(result.isError)
                return result.wrapError("when setting field 'printableString' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 12)
        {
            /++ FIELD - utf8String ++/
            typeof(Value.utf8String) temp_utf8String;
            result = typeof(temp_utf8String).fromDecoding!ruleset(memory, temp_utf8String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utf8String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtf8String(temp_utf8String);
            if(result.isError)
                return result.wrapError("when setting field 'utf8String' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type DirectoryString the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isPrintableString)
        {
            depth++;
            putIndent();
            sink("printableString: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintableString()), "toString"))
                _value.printableString.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUtf8String)
        {
            depth++;
            putIndent();
            sink("utf8String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtf8String()), "toString"))
                _value.utf8String.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct AlgorithmIdentifier
{
    private
    {
        bool _isSet_algorithm;
        asn1.Asn1ObjectIdentifier _algorithm;
        bool _isSet_parameters;
        asn1.Asn1Any _parameters;
    }

    jres.Result setAlgorithm(
        typeof(_algorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_algorithm = true;
        _algorithm = value;
        return jres.Result.noError;
    }

    typeof(_algorithm) getAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_algorithm, "Non-optional field 'algorithm' has not been set yet - please use validate() to check!");
        return _algorithm;
    }

    jres.Result setParameters(
        typeof(_parameters) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_parameters = true;
        _parameters = value;
        return jres.Result.noError;
    }

    jres.Result setParameters(
        tcon.Nullable!(asn1.Asn1Any) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setParameters(value.get());
        }
        else
            _isSet_parameters = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Any) getParameters(
    ) @nogc nothrow
    {
        if(_isSet_parameters)
            return typeof(return)(_parameters);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_algorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AlgorithmIdentifier non-optional field 'algorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("algorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_algorithm), "toString"))
            _algorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("parameters: ");
        sink("\n");
        if(_isSet_parameters)
        {
            static if(__traits(hasMember, typeof(_parameters), "toString"))
                _parameters.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: algorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AlgorithmIdentifier when reading top level tag 6 for field 'algorithm' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AlgorithmIdentifier when reading top level tag 6 for field 'algorithm' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_algorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_algorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - algorithm ++/
        typeof(_algorithm) temp_algorithm;
        result = typeof(temp_algorithm).fromDecoding!ruleset(memory_algorithm, temp_algorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAlgorithm(temp_algorithm);
        if(result.isError)
            return result.wrapError("when setting field 'algorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: parameters +++/
        auto backtrack_parameters = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'parameters' in type "~__traits(identifier, typeof(this))~":");
            // Field is the intrinsic ANY type - any tag is allowed.
            jbuf.MemoryReader memory_parameters;
            result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_parameters);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'parameters' in type "~__traits(identifier, typeof(this))~":");
            /++ FIELD - parameters ++/
            typeof(_parameters) temp_parameters;
            result = typeof(temp_parameters).fromDecoding!ruleset(memory_parameters, temp_parameters, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'parameters' in type "~__traits(identifier, typeof(this))~":");
            result = this.setParameters(temp_parameters);
            if(result.isError)
                return result.wrapError("when setting field 'parameters' in type "~__traits(identifier, typeof(this))~":");

        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AlgorithmIdentifier there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct CertificateSerialNumber
{
    private
    {
        asn1.Asn1Integer _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Integer newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Integer get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Integer, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct Time
{
    enum Choice
    {
        _FAILSAFE,
        utcTime,
    }

    union Value
    {
        asn1.Asn1UtcTime utcTime;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1UtcTime), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.utcTime)) @nogc nothrow handle_utcTime,
    ) @nogc nothrow
    {
        if(_choice == Choice.utcTime)
            return handle_utcTime(_value.utcTime);
        assert(false, "attempted to use an uninitialised Time!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.utcTime))  handle_utcTime,
    ) 
    {
        if(_choice == Choice.utcTime)
            return handle_utcTime(_value.utcTime);
        assert(false, "attempted to use an uninitialised Time!");

    }

    jres.Result setUtcTime(
        typeof(Value.utcTime) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.utcTime = value;
        _choice = Choice.utcTime;
        return jres.Result.noError;
    }

    typeof(Value.utcTime) getUtcTime(
    ) @nogc nothrow
    {
        assert(_choice == Choice.utcTime, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'utcTime'");
        return _value.utcTime;
    }

    bool isUtcTime(
    ) @nogc nothrow const
    {
        return _choice == Choice.utcTime;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 23)
        {
            /++ FIELD - utcTime ++/
            typeof(Value.utcTime) temp_utcTime;
            result = typeof(temp_utcTime).fromDecoding!ruleset(memory, temp_utcTime, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'utcTime' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUtcTime(temp_utcTime);
            if(result.isError)
                return result.wrapError("when setting field 'utcTime' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type Time the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isUtcTime)
        {
            depth++;
            putIndent();
            sink("utcTime: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUtcTime()), "toString"))
                _value.utcTime.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct Validity
{
    private
    {
        bool _isSet_notBefore;
        .Time _notBefore;
        bool _isSet_notAfter;
        .Time _notAfter;
    }

    jres.Result setNotBefore(
        typeof(_notBefore) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_notBefore = true;
        _notBefore = value;
        return jres.Result.noError;
    }

    typeof(_notBefore) getNotBefore(
    ) @nogc nothrow
    {
        assert(_isSet_notBefore, "Non-optional field 'notBefore' has not been set yet - please use validate() to check!");
        return _notBefore;
    }

    jres.Result setNotAfter(
        typeof(_notAfter) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_notAfter = true;
        _notAfter = value;
        return jres.Result.noError;
    }

    typeof(_notAfter) getNotAfter(
    ) @nogc nothrow
    {
        assert(_isSet_notAfter, "Non-optional field 'notAfter' has not been set yet - please use validate() to check!");
        return _notAfter;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_notBefore)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Validity non-optional field 'notBefore' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_notAfter)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Validity non-optional field 'notAfter' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("notBefore: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_notBefore), "toString"))
            _notBefore.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("notAfter: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_notAfter), "toString"))
            _notAfter.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: notBefore +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'notBefore' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_notBefore;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_notBefore);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'notBefore' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - notBefore ++/
        typeof(_notBefore) temp_notBefore;
        result = temp_notBefore.fromDecoding!ruleset(memory_notBefore, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'notBefore' in type "~__traits(identifier, typeof(this))~":");
        result = this.setNotBefore(temp_notBefore);
        if(result.isError)
            return result.wrapError("when setting field 'notBefore' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: notAfter +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'notAfter' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_notAfter;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_notAfter);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'notAfter' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - notAfter ++/
        typeof(_notAfter) temp_notAfter;
        result = temp_notAfter.fromDecoding!ruleset(memory_notAfter, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'notAfter' in type "~__traits(identifier, typeof(this))~":");
        result = this.setNotAfter(temp_notAfter);
        if(result.isError)
            return result.wrapError("when setting field 'notAfter' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Validity there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SubjectPublicKeyInfo
{
    private
    {
        bool _isSet_algorithm;
        .AlgorithmIdentifier _algorithm;
        bool _isSet_subjectPublicKey;
        asn1.Asn1BitString _subjectPublicKey;
    }

    jres.Result setAlgorithm(
        typeof(_algorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_algorithm = true;
        _algorithm = value;
        return jres.Result.noError;
    }

    typeof(_algorithm) getAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_algorithm, "Non-optional field 'algorithm' has not been set yet - please use validate() to check!");
        return _algorithm;
    }

    jres.Result setSubjectPublicKey(
        typeof(_subjectPublicKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subjectPublicKey = true;
        _subjectPublicKey = value;
        return jres.Result.noError;
    }

    typeof(_subjectPublicKey) getSubjectPublicKey(
    ) @nogc nothrow
    {
        assert(_isSet_subjectPublicKey, "Non-optional field 'subjectPublicKey' has not been set yet - please use validate() to check!");
        return _subjectPublicKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_algorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SubjectPublicKeyInfo non-optional field 'algorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_subjectPublicKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SubjectPublicKeyInfo non-optional field 'subjectPublicKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("algorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_algorithm), "toString"))
            _algorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("subjectPublicKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_subjectPublicKey), "toString"))
            _subjectPublicKey.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: algorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SubjectPublicKeyInfo when reading top level tag 16 for field 'algorithm' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SubjectPublicKeyInfo when reading top level tag 16 for field 'algorithm' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_algorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_algorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - algorithm ++/
        typeof(_algorithm) temp_algorithm;
        result = temp_algorithm.fromDecoding!ruleset(memory_algorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'algorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAlgorithm(temp_algorithm);
        if(result.isError)
            return result.wrapError("when setting field 'algorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: subjectPublicKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'subjectPublicKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SubjectPublicKeyInfo when reading top level tag 3 for field 'subjectPublicKey' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SubjectPublicKeyInfo when reading top level tag 3 for field 'subjectPublicKey' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_subjectPublicKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subjectPublicKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'subjectPublicKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - subjectPublicKey ++/
        typeof(_subjectPublicKey) temp_subjectPublicKey;
        result = typeof(temp_subjectPublicKey).fromDecoding!ruleset(memory_subjectPublicKey, temp_subjectPublicKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'subjectPublicKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSubjectPublicKey(temp_subjectPublicKey);
        if(result.isError)
            return result.wrapError("when setting field 'subjectPublicKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE SubjectPublicKeyInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct UniqueIdentifier
{
    private
    {
        asn1.Asn1BitString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1BitString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1BitString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1BitString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct Extension
{
    private
    {
        bool _isSet_extnID;
        asn1.Asn1ObjectIdentifier _extnID;
        bool _isSet_critical;
        asn1.Asn1Bool _critical;
        bool _isSet_extnValue;
        asn1.Asn1OctetString _extnValue;
    }

    jres.Result setExtnID(
        typeof(_extnID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extnID = true;
        _extnID = value;
        return jres.Result.noError;
    }

    typeof(_extnID) getExtnID(
    ) @nogc nothrow
    {
        assert(_isSet_extnID, "Non-optional field 'extnID' has not been set yet - please use validate() to check!");
        return _extnID;
    }

    jres.Result setCritical(
        typeof(_critical) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_critical = true;
        _critical = value;
        return jres.Result.noError;
    }

    typeof(_critical) getCritical(
    ) @nogc nothrow
    {
        assert(_isSet_critical, "Non-optional field 'critical' has not been set yet - please use validate() to check!");
        return _critical;
    }

    static typeof(_critical) defaultOfCritical(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result setExtnValue(
        typeof(_extnValue) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extnValue = true;
        _extnValue = value;
        return jres.Result.noError;
    }

    typeof(_extnValue) getExtnValue(
    ) @nogc nothrow
    {
        assert(_isSet_extnValue, "Non-optional field 'extnValue' has not been set yet - please use validate() to check!");
        return _extnValue;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_extnID)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Extension non-optional field 'extnID' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_critical)
        {
            auto result = this.setCritical(defaultOfCritical());
            if(result.isError)
                return result.wrapError("when setting field 'critical' in type "~__traits(identifier, typeof(this))~":");
        }
        if(!_isSet_extnValue)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Extension non-optional field 'extnValue' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("extnID: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_extnID), "toString"))
            _extnID.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("critical: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_critical), "toString"))
            _critical.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("extnValue: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_extnValue), "toString"))
            _extnValue.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: extnID +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'extnID' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Extension when reading top level tag 6 for field 'extnID' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Extension when reading top level tag 6 for field 'extnID' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_extnID;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extnID);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'extnID' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - extnID ++/
        typeof(_extnID) temp_extnID;
        result = typeof(temp_extnID).fromDecoding!ruleset(memory_extnID, temp_extnID, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'extnID' in type "~__traits(identifier, typeof(this))~":");
        result = this.setExtnID(temp_extnID);
        if(result.isError)
            return result.wrapError("when setting field 'extnID' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: critical +++/
        auto backtrack_critical = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'critical' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_critical;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_critical);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'critical' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - critical ++/
                typeof(_critical) temp_critical;
                result = typeof(temp_critical).fromDecoding!ruleset(memory_critical, temp_critical, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'critical' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCritical(temp_critical);
                if(result.isError)
                    return result.wrapError("when setting field 'critical' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_critical.buffer, backtrack_critical.cursor);
                result = this.setCritical(defaultOfCritical());
                if(result.isError)
                    return result.wrapError("when setting field 'critical' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setCritical(defaultOfCritical());
            if(result.isError)
                return result.wrapError("when setting field 'critical' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: extnValue +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'extnValue' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Extension when reading top level tag 4 for field 'extnValue' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Extension when reading top level tag 4 for field 'extnValue' the tag's value was expected to be 4", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_extnValue;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extnValue);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'extnValue' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - extnValue ++/
        typeof(_extnValue) temp_extnValue;
        result = typeof(temp_extnValue).fromDecoding!ruleset(memory_extnValue, temp_extnValue, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'extnValue' in type "~__traits(identifier, typeof(this))~":");
        result = this.setExtnValue(temp_extnValue);
        if(result.isError)
            return result.wrapError("when setting field 'extnValue' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Extension there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct Extensions
{
    private
    {
        asn1.Asn1SequenceOf!(.Extension) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.Extension) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.elementCount >= 1 && newValue.elementCount <= 18446744073709551615;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.Extension) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.Extension), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SEQEUENCE OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct Version
{
    enum NamedNumber
    {
        v1 = 0,
        v2 = 1,
        v3 = 2,
    }
    private
    {
        asn1.Asn1Integer _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Integer newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Integer get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Integer, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct TBSCertificate
{
    private
    {
        bool _isSet_dasn1_RawBytes;
        asn1.Asn1OctetString _dasn1_RawBytes;
        bool _isSet_version;
        .Version _version;
        bool _isSet_serialNumber;
        .CertificateSerialNumber _serialNumber;
        bool _isSet_signature;
        .AlgorithmIdentifier _signature;
        bool _isSet_issuer;
        .Name _issuer;
        bool _isSet_validity;
        .Validity _validity;
        bool _isSet_subject;
        .Name _subject;
        bool _isSet_subjectPublicKeyInfo;
        .SubjectPublicKeyInfo _subjectPublicKeyInfo;
        bool _isSet_issuerUniqueID;
        .UniqueIdentifier _issuerUniqueID;
        bool _isSet_subjectUniqueID;
        .UniqueIdentifier _subjectUniqueID;
        bool _isSet_extensions;
        .Extensions _extensions;
    }

    jres.Result setDasn1_RawBytes(
        typeof(_dasn1_RawBytes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_dasn1_RawBytes = true;
        _dasn1_RawBytes = value;
        return jres.Result.noError;
    }

    jres.Result setDasn1_RawBytes(
        tcon.Nullable!(asn1.Asn1OctetString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setDasn1_RawBytes(value.get());
        }
        else
            _isSet_dasn1_RawBytes = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1OctetString) getDasn1_RawBytes(
    ) @nogc nothrow
    {
        if(_isSet_dasn1_RawBytes)
            return typeof(return)(_dasn1_RawBytes);
        return typeof(return).init;
    }

    jres.Result setVersion(
        typeof(_version) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_version = true;
        _version = value;
        return jres.Result.noError;
    }

    typeof(_version) getVersion(
    ) @nogc nothrow
    {
        assert(_isSet_version, "Non-optional field 'version' has not been set yet - please use validate() to check!");
        return _version;
    }

    static typeof(_version) defaultOfVersion(
    ) @nogc nothrow
    {
        .Version mainValue;
            asn1.Asn1Integer mainValue__underlying;
            static immutable ubyte[] mainValue__underlying__underlying = [
                /* 0 */ 
            ];
            mainValue__underlying = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying__underlying);
        jres.resultAssert(mainValue.set(mainValue__underlying));
        return mainValue;

    }

    jres.Result setSerialNumber(
        typeof(_serialNumber) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_serialNumber = true;
        _serialNumber = value;
        return jres.Result.noError;
    }

    typeof(_serialNumber) getSerialNumber(
    ) @nogc nothrow
    {
        assert(_isSet_serialNumber, "Non-optional field 'serialNumber' has not been set yet - please use validate() to check!");
        return _serialNumber;
    }

    jres.Result setSignature(
        typeof(_signature) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signature = true;
        _signature = value;
        return jres.Result.noError;
    }

    typeof(_signature) getSignature(
    ) @nogc nothrow
    {
        assert(_isSet_signature, "Non-optional field 'signature' has not been set yet - please use validate() to check!");
        return _signature;
    }

    jres.Result setIssuer(
        typeof(_issuer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_issuer = true;
        _issuer = value;
        return jres.Result.noError;
    }

    typeof(_issuer) getIssuer(
    ) @nogc nothrow
    {
        assert(_isSet_issuer, "Non-optional field 'issuer' has not been set yet - please use validate() to check!");
        return _issuer;
    }

    jres.Result setValidity(
        typeof(_validity) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_validity = true;
        _validity = value;
        return jres.Result.noError;
    }

    typeof(_validity) getValidity(
    ) @nogc nothrow
    {
        assert(_isSet_validity, "Non-optional field 'validity' has not been set yet - please use validate() to check!");
        return _validity;
    }

    jres.Result setSubject(
        typeof(_subject) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subject = true;
        _subject = value;
        return jres.Result.noError;
    }

    typeof(_subject) getSubject(
    ) @nogc nothrow
    {
        assert(_isSet_subject, "Non-optional field 'subject' has not been set yet - please use validate() to check!");
        return _subject;
    }

    jres.Result setSubjectPublicKeyInfo(
        typeof(_subjectPublicKeyInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subjectPublicKeyInfo = true;
        _subjectPublicKeyInfo = value;
        return jres.Result.noError;
    }

    typeof(_subjectPublicKeyInfo) getSubjectPublicKeyInfo(
    ) @nogc nothrow
    {
        assert(_isSet_subjectPublicKeyInfo, "Non-optional field 'subjectPublicKeyInfo' has not been set yet - please use validate() to check!");
        return _subjectPublicKeyInfo;
    }

    jres.Result setIssuerUniqueID(
        typeof(_issuerUniqueID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_issuerUniqueID = true;
        _issuerUniqueID = value;
        return jres.Result.noError;
    }

    jres.Result setIssuerUniqueID(
        tcon.Nullable!(.UniqueIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setIssuerUniqueID(value.get());
        }
        else
            _isSet_issuerUniqueID = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UniqueIdentifier) getIssuerUniqueID(
    ) @nogc nothrow
    {
        if(_isSet_issuerUniqueID)
            return typeof(return)(_issuerUniqueID);
        return typeof(return).init;
    }

    jres.Result setSubjectUniqueID(
        typeof(_subjectUniqueID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subjectUniqueID = true;
        _subjectUniqueID = value;
        return jres.Result.noError;
    }

    jres.Result setSubjectUniqueID(
        tcon.Nullable!(.UniqueIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setSubjectUniqueID(value.get());
        }
        else
            _isSet_subjectUniqueID = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UniqueIdentifier) getSubjectUniqueID(
    ) @nogc nothrow
    {
        if(_isSet_subjectUniqueID)
            return typeof(return)(_subjectUniqueID);
        return typeof(return).init;
    }

    jres.Result setExtensions(
        typeof(_extensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extensions = true;
        _extensions = value;
        return jres.Result.noError;
    }

    jres.Result setExtensions(
        tcon.Nullable!(.Extensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setExtensions(value.get());
        }
        else
            _isSet_extensions = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.Extensions) getExtensions(
    ) @nogc nothrow
    {
        if(_isSet_extensions)
            return typeof(return)(_extensions);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
        {
            auto result = this.setVersion(defaultOfVersion());
            if(result.isError)
                return result.wrapError("when setting field 'version' in type "~__traits(identifier, typeof(this))~":");
        }
        if(!_isSet_serialNumber)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'serialNumber' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_issuer)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'issuer' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_validity)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'validity' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_subject)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'subject' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_subjectPublicKeyInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertificate non-optional field 'subjectPublicKeyInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("dasn1-RawBytes: ");
        sink("\n");
        if(_isSet_dasn1_RawBytes)
        {
            static if(__traits(hasMember, typeof(_dasn1_RawBytes), "toString"))
                _dasn1_RawBytes.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("version: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_version), "toString"))
            _version.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("serialNumber: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_serialNumber), "toString"))
            _serialNumber.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signature: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signature), "toString"))
            _signature.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("issuer: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_issuer), "toString"))
            _issuer.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("validity: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_validity), "toString"))
            _validity.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("subject: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_subject), "toString"))
            _subject.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("subjectPublicKeyInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_subjectPublicKeyInfo), "toString"))
            _subjectPublicKeyInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("issuerUniqueID: ");
        sink("\n");
        if(_isSet_issuerUniqueID)
        {
            static if(__traits(hasMember, typeof(_issuerUniqueID), "toString"))
                _issuerUniqueID.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("subjectUniqueID: ");
        sink("\n");
        if(_isSet_subjectUniqueID)
        {
            static if(__traits(hasMember, typeof(_subjectUniqueID), "toString"))
                _subjectUniqueID.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("extensions: ");
        sink("\n");
        if(_isSet_extensions)
        {
            static if(__traits(hasMember, typeof(_extensions), "toString"))
                _extensions.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        // -- Suppressed putRawType for RawBytes special case --
        /+++ TAG FOR FIELD: version +++/
        auto backtrack_version = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_version;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_version);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'version' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - version ++/
                jbuf.MemoryReader memory_0version;
                    // EXPLICIT TAG - 0
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field version a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'version' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 0)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'version' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_version, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_version, componentHeader.length, memory_0version);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'version' in type "~__traits(identifier, typeof(this))~":");
                typeof(_version) temp_version;
                result = temp_version.fromDecoding!ruleset(memory_0version, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'version' in type "~__traits(identifier, typeof(this))~":");
                result = this.setVersion(temp_version);
                if(result.isError)
                    return result.wrapError("when setting field 'version' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_version.buffer, backtrack_version.cursor);
                result = this.setVersion(defaultOfVersion());
                if(result.isError)
                    return result.wrapError("when setting field 'version' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setVersion(defaultOfVersion());
            if(result.isError)
                return result.wrapError("when setting field 'version' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: serialNumber +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'serialNumber' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertificate when reading top level tag 2 for field 'serialNumber' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertificate when reading top level tag 2 for field 'serialNumber' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_serialNumber;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_serialNumber);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'serialNumber' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - serialNumber ++/
        typeof(_serialNumber) temp_serialNumber;
        result = temp_serialNumber.fromDecoding!ruleset(memory_serialNumber, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'serialNumber' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSerialNumber(temp_serialNumber);
        if(result.isError)
            return result.wrapError("when setting field 'serialNumber' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signature +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'signature' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'signature' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signature;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signature);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signature ++/
        typeof(_signature) temp_signature;
        result = temp_signature.fromDecoding!ruleset(memory_signature, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signature' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignature(temp_signature);
        if(result.isError)
            return result.wrapError("when setting field 'signature' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: issuer +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_issuer;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_issuer);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - issuer ++/
        typeof(_issuer) temp_issuer;
        result = temp_issuer.fromDecoding!ruleset(memory_issuer, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        result = this.setIssuer(temp_issuer);
        if(result.isError)
            return result.wrapError("when setting field 'issuer' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: validity +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'validity' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'validity' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'validity' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_validity;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_validity);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'validity' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - validity ++/
        typeof(_validity) temp_validity;
        result = temp_validity.fromDecoding!ruleset(memory_validity, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'validity' in type "~__traits(identifier, typeof(this))~":");
        result = this.setValidity(temp_validity);
        if(result.isError)
            return result.wrapError("when setting field 'validity' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: subject +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'subject' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_subject;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subject);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'subject' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - subject ++/
        typeof(_subject) temp_subject;
        result = temp_subject.fromDecoding!ruleset(memory_subject, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'subject' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSubject(temp_subject);
        if(result.isError)
            return result.wrapError("when setting field 'subject' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: subjectPublicKeyInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'subjectPublicKeyInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'subjectPublicKeyInfo' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertificate when reading top level tag 16 for field 'subjectPublicKeyInfo' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_subjectPublicKeyInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subjectPublicKeyInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'subjectPublicKeyInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - subjectPublicKeyInfo ++/
        typeof(_subjectPublicKeyInfo) temp_subjectPublicKeyInfo;
        result = temp_subjectPublicKeyInfo.fromDecoding!ruleset(memory_subjectPublicKeyInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'subjectPublicKeyInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSubjectPublicKeyInfo(temp_subjectPublicKeyInfo);
        if(result.isError)
            return result.wrapError("when setting field 'subjectPublicKeyInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: issuerUniqueID +++/
        auto backtrack_issuerUniqueID = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'issuerUniqueID' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_issuerUniqueID;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_issuerUniqueID);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'issuerUniqueID' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - issuerUniqueID ++/
                typeof(_issuerUniqueID) temp_issuerUniqueID;
                result = temp_issuerUniqueID.fromDecoding!ruleset(memory_issuerUniqueID, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'issuerUniqueID' in type "~__traits(identifier, typeof(this))~":");
                result = this.setIssuerUniqueID(temp_issuerUniqueID);
                if(result.isError)
                    return result.wrapError("when setting field 'issuerUniqueID' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_issuerUniqueID.buffer, backtrack_issuerUniqueID.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: subjectUniqueID +++/
        auto backtrack_subjectUniqueID = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'subjectUniqueID' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_subjectUniqueID;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subjectUniqueID);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'subjectUniqueID' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - subjectUniqueID ++/
                typeof(_subjectUniqueID) temp_subjectUniqueID;
                result = temp_subjectUniqueID.fromDecoding!ruleset(memory_subjectUniqueID, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'subjectUniqueID' in type "~__traits(identifier, typeof(this))~":");
                result = this.setSubjectUniqueID(temp_subjectUniqueID);
                if(result.isError)
                    return result.wrapError("when setting field 'subjectUniqueID' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_subjectUniqueID.buffer, backtrack_subjectUniqueID.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: extensions +++/
        auto backtrack_extensions = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'extensions' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 3)
            {
                jbuf.MemoryReader memory_extensions;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extensions);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'extensions' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - extensions ++/
                jbuf.MemoryReader memory_0extensions;
                    // EXPLICIT TAG - 3
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 3 for field extensions a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 3 for field 'extensions' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 3)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 3 for field 'extensions' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_extensions, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'extensions' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_extensions, componentHeader.length, memory_0extensions);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'extensions' in type "~__traits(identifier, typeof(this))~":");
                typeof(_extensions) temp_extensions;
                result = temp_extensions.fromDecoding!ruleset(memory_0extensions, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'extensions' in type "~__traits(identifier, typeof(this))~":");
                result = this.setExtensions(temp_extensions);
                if(result.isError)
                    return result.wrapError("when setting field 'extensions' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_extensions.buffer, backtrack_extensions.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE TBSCertificate there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct Certificate
{
    private
    {
        bool _isSet_tbsCertificate;
        .TBSCertificate _tbsCertificate;
        bool _isSet_signatureAlgorithm;
        .AlgorithmIdentifier _signatureAlgorithm;
        bool _isSet_signature;
        asn1.Asn1BitString _signature;
    }

    jres.Result setTbsCertificate(
        typeof(_tbsCertificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_tbsCertificate = true;
        _tbsCertificate = value;
        return jres.Result.noError;
    }

    typeof(_tbsCertificate) getTbsCertificate(
    ) @nogc nothrow
    {
        assert(_isSet_tbsCertificate, "Non-optional field 'tbsCertificate' has not been set yet - please use validate() to check!");
        return _tbsCertificate;
    }

    jres.Result setSignatureAlgorithm(
        typeof(_signatureAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signatureAlgorithm = true;
        _signatureAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_signatureAlgorithm) getSignatureAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_signatureAlgorithm, "Non-optional field 'signatureAlgorithm' has not been set yet - please use validate() to check!");
        return _signatureAlgorithm;
    }

    jres.Result setSignature(
        typeof(_signature) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signature = true;
        _signature = value;
        return jres.Result.noError;
    }

    typeof(_signature) getSignature(
    ) @nogc nothrow
    {
        assert(_isSet_signature, "Non-optional field 'signature' has not been set yet - please use validate() to check!");
        return _signature;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_tbsCertificate)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Certificate non-optional field 'tbsCertificate' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signatureAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Certificate non-optional field 'signatureAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Certificate non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("tbsCertificate: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_tbsCertificate), "toString"))
            _tbsCertificate.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signatureAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signatureAlgorithm), "toString"))
            _signatureAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signature: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signature), "toString"))
            _signature.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        // -- RawBytes special case, preserving DER bytes --
        auto rawBytes_tbsCertificate = memory.cursor;
        /+++ TAG FOR FIELD: tbsCertificate +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'tbsCertificate' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Certificate when reading top level tag 16 for field 'tbsCertificate' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Certificate when reading top level tag 16 for field 'tbsCertificate' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_tbsCertificate;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_tbsCertificate);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'tbsCertificate' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - tbsCertificate ++/
        typeof(_tbsCertificate) temp_tbsCertificate;
        result = temp_tbsCertificate.fromDecoding!ruleset(memory_tbsCertificate, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'tbsCertificate' in type "~__traits(identifier, typeof(this))~":");
        result = this.setTbsCertificate(temp_tbsCertificate);
        if(result.isError)
            return result.wrapError("when setting field 'tbsCertificate' in type "~__traits(identifier, typeof(this))~":");

        // -- RawBytes special case, setting raw DER bytes --
        result = this._tbsCertificate.setDasn1_RawBytes(asn1.Asn1OctetString.fromUnownedBytes(memory.buffer[rawBytes_tbsCertificate..memory.cursor]));
        if(result.isError)
            return result.wrapError("when handling RawBytes special case in type "~__traits(identifier, typeof(this))~":");
        
        /+++ TAG FOR FIELD: signatureAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Certificate when reading top level tag 16 for field 'signatureAlgorithm' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Certificate when reading top level tag 16 for field 'signatureAlgorithm' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signatureAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signatureAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signatureAlgorithm ++/
        typeof(_signatureAlgorithm) temp_signatureAlgorithm;
        result = temp_signatureAlgorithm.fromDecoding!ruleset(memory_signatureAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignatureAlgorithm(temp_signatureAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signature +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Certificate when reading top level tag 3 for field 'signature' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Certificate when reading top level tag 3 for field 'signature' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signature;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signature);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signature ++/
        typeof(_signature) temp_signature;
        result = typeof(temp_signature).fromDecoding!ruleset(memory_signature, temp_signature, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signature' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignature(temp_signature);
        if(result.isError)
            return result.wrapError("when setting field 'signature' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Certificate there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct CertificateList
{
    private
    {
        bool _isSet_tbsCertList;
        .TBSCertList _tbsCertList;
        bool _isSet_signatureAlgorithm;
        .AlgorithmIdentifier _signatureAlgorithm;
        bool _isSet_signature;
        asn1.Asn1BitString _signature;
    }

    jres.Result setTbsCertList(
        typeof(_tbsCertList) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_tbsCertList = true;
        _tbsCertList = value;
        return jres.Result.noError;
    }

    typeof(_tbsCertList) getTbsCertList(
    ) @nogc nothrow
    {
        assert(_isSet_tbsCertList, "Non-optional field 'tbsCertList' has not been set yet - please use validate() to check!");
        return _tbsCertList;
    }

    jres.Result setSignatureAlgorithm(
        typeof(_signatureAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signatureAlgorithm = true;
        _signatureAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_signatureAlgorithm) getSignatureAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_signatureAlgorithm, "Non-optional field 'signatureAlgorithm' has not been set yet - please use validate() to check!");
        return _signatureAlgorithm;
    }

    jres.Result setSignature(
        typeof(_signature) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signature = true;
        _signature = value;
        return jres.Result.noError;
    }

    typeof(_signature) getSignature(
    ) @nogc nothrow
    {
        assert(_isSet_signature, "Non-optional field 'signature' has not been set yet - please use validate() to check!");
        return _signature;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_tbsCertList)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type CertificateList non-optional field 'tbsCertList' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signatureAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type CertificateList non-optional field 'signatureAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type CertificateList non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("tbsCertList: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_tbsCertList), "toString"))
            _tbsCertList.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signatureAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signatureAlgorithm), "toString"))
            _signatureAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signature: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signature), "toString"))
            _signature.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: tbsCertList +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'tbsCertList' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE CertificateList when reading top level tag 16 for field 'tbsCertList' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE CertificateList when reading top level tag 16 for field 'tbsCertList' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_tbsCertList;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_tbsCertList);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'tbsCertList' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - tbsCertList ++/
        typeof(_tbsCertList) temp_tbsCertList;
        result = temp_tbsCertList.fromDecoding!ruleset(memory_tbsCertList, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'tbsCertList' in type "~__traits(identifier, typeof(this))~":");
        result = this.setTbsCertList(temp_tbsCertList);
        if(result.isError)
            return result.wrapError("when setting field 'tbsCertList' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signatureAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE CertificateList when reading top level tag 16 for field 'signatureAlgorithm' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE CertificateList when reading top level tag 16 for field 'signatureAlgorithm' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signatureAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signatureAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signatureAlgorithm ++/
        typeof(_signatureAlgorithm) temp_signatureAlgorithm;
        result = temp_signatureAlgorithm.fromDecoding!ruleset(memory_signatureAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignatureAlgorithm(temp_signatureAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signature +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE CertificateList when reading top level tag 3 for field 'signature' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE CertificateList when reading top level tag 3 for field 'signature' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signature;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signature);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signature ++/
        typeof(_signature) temp_signature;
        result = typeof(temp_signature).fromDecoding!ruleset(memory_signature, temp_signature, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signature' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignature(temp_signature);
        if(result.isError)
            return result.wrapError("when setting field 'signature' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE CertificateList there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct TBSCertList_RevokedCertificate
{
    private
    {
        bool _isSet_userCertificate;
        .CertificateSerialNumber _userCertificate;
        bool _isSet_revocationDate;
        .Time _revocationDate;
        bool _isSet_crlEntryExtensions;
        .Extensions _crlEntryExtensions;
    }

    jres.Result setUserCertificate(
        typeof(_userCertificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_userCertificate = true;
        _userCertificate = value;
        return jres.Result.noError;
    }

    typeof(_userCertificate) getUserCertificate(
    ) @nogc nothrow
    {
        assert(_isSet_userCertificate, "Non-optional field 'userCertificate' has not been set yet - please use validate() to check!");
        return _userCertificate;
    }

    jres.Result setRevocationDate(
        typeof(_revocationDate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_revocationDate = true;
        _revocationDate = value;
        return jres.Result.noError;
    }

    typeof(_revocationDate) getRevocationDate(
    ) @nogc nothrow
    {
        assert(_isSet_revocationDate, "Non-optional field 'revocationDate' has not been set yet - please use validate() to check!");
        return _revocationDate;
    }

    jres.Result setCrlEntryExtensions(
        typeof(_crlEntryExtensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_crlEntryExtensions = true;
        _crlEntryExtensions = value;
        return jres.Result.noError;
    }

    jres.Result setCrlEntryExtensions(
        tcon.Nullable!(.Extensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCrlEntryExtensions(value.get());
        }
        else
            _isSet_crlEntryExtensions = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.Extensions) getCrlEntryExtensions(
    ) @nogc nothrow
    {
        if(_isSet_crlEntryExtensions)
            return typeof(return)(_crlEntryExtensions);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_userCertificate)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertList-RevokedCertificate non-optional field 'userCertificate' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_revocationDate)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertList-RevokedCertificate non-optional field 'revocationDate' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("userCertificate: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_userCertificate), "toString"))
            _userCertificate.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("revocationDate: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_revocationDate), "toString"))
            _revocationDate.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("crlEntryExtensions: ");
        sink("\n");
        if(_isSet_crlEntryExtensions)
        {
            static if(__traits(hasMember, typeof(_crlEntryExtensions), "toString"))
                _crlEntryExtensions.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: userCertificate +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'userCertificate' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertList-RevokedCertificate when reading top level tag 2 for field 'userCertificate' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertList-RevokedCertificate when reading top level tag 2 for field 'userCertificate' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_userCertificate;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_userCertificate);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'userCertificate' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - userCertificate ++/
        typeof(_userCertificate) temp_userCertificate;
        result = temp_userCertificate.fromDecoding!ruleset(memory_userCertificate, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'userCertificate' in type "~__traits(identifier, typeof(this))~":");
        result = this.setUserCertificate(temp_userCertificate);
        if(result.isError)
            return result.wrapError("when setting field 'userCertificate' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: revocationDate +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'revocationDate' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_revocationDate;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_revocationDate);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'revocationDate' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - revocationDate ++/
        typeof(_revocationDate) temp_revocationDate;
        result = temp_revocationDate.fromDecoding!ruleset(memory_revocationDate, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'revocationDate' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRevocationDate(temp_revocationDate);
        if(result.isError)
            return result.wrapError("when setting field 'revocationDate' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: crlEntryExtensions +++/
        auto backtrack_crlEntryExtensions = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'crlEntryExtensions' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_crlEntryExtensions;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_crlEntryExtensions);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'crlEntryExtensions' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - crlEntryExtensions ++/
                typeof(_crlEntryExtensions) temp_crlEntryExtensions;
                result = temp_crlEntryExtensions.fromDecoding!ruleset(memory_crlEntryExtensions, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'crlEntryExtensions' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCrlEntryExtensions(temp_crlEntryExtensions);
                if(result.isError)
                    return result.wrapError("when setting field 'crlEntryExtensions' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_crlEntryExtensions.buffer, backtrack_crlEntryExtensions.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE TBSCertList-RevokedCertificate there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct TBSCertList
{
    private
    {
        bool _isSet_version;
        .Version _version;
        bool _isSet_signature;
        .AlgorithmIdentifier _signature;
        bool _isSet_issuer;
        .Name _issuer;
        bool _isSet_thisUpdate;
        .Time _thisUpdate;
        bool _isSet_nextUpdate;
        .Time _nextUpdate;
        bool _isSet_revokedCertificates;
        asn1.Asn1SequenceOf!(.TBSCertList_RevokedCertificate) _revokedCertificates;
        bool _isSet_crlExtensions;
        .Extensions _crlExtensions;
    }

    jres.Result setVersion(
        typeof(_version) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_version = true;
        _version = value;
        return jres.Result.noError;
    }

    jres.Result setVersion(
        tcon.Nullable!(.Version) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setVersion(value.get());
        }
        else
            _isSet_version = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.Version) getVersion(
    ) @nogc nothrow
    {
        if(_isSet_version)
            return typeof(return)(_version);
        return typeof(return).init;
    }

    jres.Result setSignature(
        typeof(_signature) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signature = true;
        _signature = value;
        return jres.Result.noError;
    }

    typeof(_signature) getSignature(
    ) @nogc nothrow
    {
        assert(_isSet_signature, "Non-optional field 'signature' has not been set yet - please use validate() to check!");
        return _signature;
    }

    jres.Result setIssuer(
        typeof(_issuer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_issuer = true;
        _issuer = value;
        return jres.Result.noError;
    }

    typeof(_issuer) getIssuer(
    ) @nogc nothrow
    {
        assert(_isSet_issuer, "Non-optional field 'issuer' has not been set yet - please use validate() to check!");
        return _issuer;
    }

    jres.Result setThisUpdate(
        typeof(_thisUpdate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_thisUpdate = true;
        _thisUpdate = value;
        return jres.Result.noError;
    }

    typeof(_thisUpdate) getThisUpdate(
    ) @nogc nothrow
    {
        assert(_isSet_thisUpdate, "Non-optional field 'thisUpdate' has not been set yet - please use validate() to check!");
        return _thisUpdate;
    }

    jres.Result setNextUpdate(
        typeof(_nextUpdate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_nextUpdate = true;
        _nextUpdate = value;
        return jres.Result.noError;
    }

    jres.Result setNextUpdate(
        tcon.Nullable!(.Time) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setNextUpdate(value.get());
        }
        else
            _isSet_nextUpdate = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.Time) getNextUpdate(
    ) @nogc nothrow
    {
        if(_isSet_nextUpdate)
            return typeof(return)(_nextUpdate);
        return typeof(return).init;
    }

    jres.Result setRevokedCertificates(
        typeof(_revokedCertificates) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_revokedCertificates = true;
        _revokedCertificates = value;
        return jres.Result.noError;
    }

    jres.Result setRevokedCertificates(
        tcon.Nullable!(asn1.Asn1SequenceOf!(.TBSCertList_RevokedCertificate)) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setRevokedCertificates(value.get());
        }
        else
            _isSet_revokedCertificates = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1SequenceOf!(.TBSCertList_RevokedCertificate)) getRevokedCertificates(
    ) @nogc nothrow
    {
        if(_isSet_revokedCertificates)
            return typeof(return)(_revokedCertificates);
        return typeof(return).init;
    }

    jres.Result setCrlExtensions(
        typeof(_crlExtensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_crlExtensions = true;
        _crlExtensions = value;
        return jres.Result.noError;
    }

    jres.Result setCrlExtensions(
        tcon.Nullable!(.Extensions) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCrlExtensions(value.get());
        }
        else
            _isSet_crlExtensions = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.Extensions) getCrlExtensions(
    ) @nogc nothrow
    {
        if(_isSet_crlExtensions)
            return typeof(return)(_crlExtensions);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertList non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_issuer)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertList non-optional field 'issuer' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_thisUpdate)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type TBSCertList non-optional field 'thisUpdate' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("version: ");
        sink("\n");
        if(_isSet_version)
        {
            static if(__traits(hasMember, typeof(_version), "toString"))
                _version.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signature: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signature), "toString"))
            _signature.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("issuer: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_issuer), "toString"))
            _issuer.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("thisUpdate: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_thisUpdate), "toString"))
            _thisUpdate.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("nextUpdate: ");
        sink("\n");
        if(_isSet_nextUpdate)
        {
            static if(__traits(hasMember, typeof(_nextUpdate), "toString"))
                _nextUpdate.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("revokedCertificates: ");
        sink("\n");
        if(_isSet_revokedCertificates)
        {
            static if(__traits(hasMember, typeof(_revokedCertificates), "toString"))
                _revokedCertificates.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("crlExtensions: ");
        sink("\n");
        if(_isSet_crlExtensions)
        {
            static if(__traits(hasMember, typeof(_crlExtensions), "toString"))
                _crlExtensions.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: version +++/
        auto backtrack_version = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_version;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_version);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'version' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - version ++/
                typeof(_version) temp_version;
                result = temp_version.fromDecoding!ruleset(memory_version, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'version' in type "~__traits(identifier, typeof(this))~":");
                result = this.setVersion(temp_version);
                if(result.isError)
                    return result.wrapError("when setting field 'version' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_version.buffer, backtrack_version.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: signature +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE TBSCertList when reading top level tag 16 for field 'signature' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE TBSCertList when reading top level tag 16 for field 'signature' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signature;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signature);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signature' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signature ++/
        typeof(_signature) temp_signature;
        result = temp_signature.fromDecoding!ruleset(memory_signature, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signature' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignature(temp_signature);
        if(result.isError)
            return result.wrapError("when setting field 'signature' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: issuer +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_issuer;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_issuer);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - issuer ++/
        typeof(_issuer) temp_issuer;
        result = temp_issuer.fromDecoding!ruleset(memory_issuer, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'issuer' in type "~__traits(identifier, typeof(this))~":");
        result = this.setIssuer(temp_issuer);
        if(result.isError)
            return result.wrapError("when setting field 'issuer' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: thisUpdate +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'thisUpdate' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_thisUpdate;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_thisUpdate);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'thisUpdate' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - thisUpdate ++/
        typeof(_thisUpdate) temp_thisUpdate;
        result = temp_thisUpdate.fromDecoding!ruleset(memory_thisUpdate, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'thisUpdate' in type "~__traits(identifier, typeof(this))~":");
        result = this.setThisUpdate(temp_thisUpdate);
        if(result.isError)
            return result.wrapError("when setting field 'thisUpdate' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: nextUpdate +++/
        auto backtrack_nextUpdate = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'nextUpdate' in type "~__traits(identifier, typeof(this))~":");
            jbuf.MemoryReader memory_nextUpdate;
            result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_nextUpdate);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'nextUpdate' in type "~__traits(identifier, typeof(this))~":");
            result = (){ // Field is OPTIONAL and has a variable starting tag
                /++ FIELD - nextUpdate ++/
                typeof(_nextUpdate) temp_nextUpdate;
                result = temp_nextUpdate.fromDecoding!ruleset(memory_nextUpdate, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'nextUpdate' in type "~__traits(identifier, typeof(this))~":");
                result = this.setNextUpdate(temp_nextUpdate);
                if(result.isError)
                    return result.wrapError("when setting field 'nextUpdate' in type "~__traits(identifier, typeof(this))~":");

                return jres.Result.noError;
            }();
            if(result.isError(asn1.Asn1DecodeError.choiceHasNoMatch))
                memory = jbuf.MemoryReader(backtrack_nextUpdate.buffer, backtrack_nextUpdate.cursor);
            else if(result.isError)
                return result.wrapError("For "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: revokedCertificates +++/
        auto backtrack_revokedCertificates = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'revokedCertificates' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_revokedCertificates;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_revokedCertificates);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'revokedCertificates' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - revokedCertificates ++/
                typeof(_revokedCertificates) temp_revokedCertificates;
                result = typeof(temp_revokedCertificates).fromDecoding!ruleset(memory_revokedCertificates, temp_revokedCertificates, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'revokedCertificates' in type "~__traits(identifier, typeof(this))~":");
                result = this.setRevokedCertificates(temp_revokedCertificates);
                if(result.isError)
                    return result.wrapError("when setting field 'revokedCertificates' in type "~__traits(identifier, typeof(this))~":");

                result = this._revokedCertificates.foreachElementAuto((element) => jres.Result.noError);
                if(result.isError)
                    return result.wrapError("when decoding subelements of SEQEUENCE OF field 'revokedCertificates' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_revokedCertificates.buffer, backtrack_revokedCertificates.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: crlExtensions +++/
        auto backtrack_crlExtensions = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_crlExtensions;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_crlExtensions);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - crlExtensions ++/
                jbuf.MemoryReader memory_0crlExtensions;
                    // EXPLICIT TAG - 0
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field crlExtensions a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'crlExtensions' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 0)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'crlExtensions' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_crlExtensions, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_crlExtensions, componentHeader.length, memory_0crlExtensions);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");
                typeof(_crlExtensions) temp_crlExtensions;
                result = temp_crlExtensions.fromDecoding!ruleset(memory_0crlExtensions, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCrlExtensions(temp_crlExtensions);
                if(result.isError)
                    return result.wrapError("when setting field 'crlExtensions' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_crlExtensions.buffer, backtrack_crlExtensions.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE TBSCertList there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct CountryName
{
    enum Choice
    {
        _FAILSAFE,
        x121_dcc_code,
        iso_3166_alpha2_code,
    }

    union Value
    {
        asn1.Asn1NumericString x121_dcc_code;
        asn1.Asn1PrintableString iso_3166_alpha2_code;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1NumericString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.x121_dcc_code)) @nogc nothrow handle_x121_dcc_code,
        scope jres.Result delegate(typeof(Value.iso_3166_alpha2_code)) @nogc nothrow handle_iso_3166_alpha2_code,
    ) @nogc nothrow
    {
        if(_choice == Choice.x121_dcc_code)
            return handle_x121_dcc_code(_value.x121_dcc_code);
        if(_choice == Choice.iso_3166_alpha2_code)
            return handle_iso_3166_alpha2_code(_value.iso_3166_alpha2_code);
        assert(false, "attempted to use an uninitialised CountryName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.x121_dcc_code))  handle_x121_dcc_code,
        scope jres.Result delegate(typeof(Value.iso_3166_alpha2_code))  handle_iso_3166_alpha2_code,
    ) 
    {
        if(_choice == Choice.x121_dcc_code)
            return handle_x121_dcc_code(_value.x121_dcc_code);
        if(_choice == Choice.iso_3166_alpha2_code)
            return handle_iso_3166_alpha2_code(_value.iso_3166_alpha2_code);
        assert(false, "attempted to use an uninitialised CountryName!");

    }

    jres.Result setX121_dcc_code(
        typeof(Value.x121_dcc_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length == 3;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.x121_dcc_code = value;
        _choice = Choice.x121_dcc_code;
        return jres.Result.noError;
    }

    typeof(Value.x121_dcc_code) getX121_dcc_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.x121_dcc_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'x121_dcc_code'");
        return _value.x121_dcc_code;
    }

    bool isX121_dcc_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.x121_dcc_code;
    }

    jres.Result setIso_3166_alpha2_code(
        typeof(Value.iso_3166_alpha2_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length == 2;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.iso_3166_alpha2_code = value;
        _choice = Choice.iso_3166_alpha2_code;
        return jres.Result.noError;
    }

    typeof(Value.iso_3166_alpha2_code) getIso_3166_alpha2_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.iso_3166_alpha2_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'iso_3166_alpha2_code'");
        return _value.iso_3166_alpha2_code;
    }

    bool isIso_3166_alpha2_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.iso_3166_alpha2_code;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 18)
        {
            /++ FIELD - x121-dcc-code ++/
            typeof(Value.x121_dcc_code) temp_x121_dcc_code;
            result = typeof(temp_x121_dcc_code).fromDecoding!ruleset(memory, temp_x121_dcc_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'x121_dcc_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setX121_dcc_code(temp_x121_dcc_code);
            if(result.isError)
                return result.wrapError("when setting field 'x121_dcc_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - iso-3166-alpha2-code ++/
            typeof(Value.iso_3166_alpha2_code) temp_iso_3166_alpha2_code;
            result = typeof(temp_iso_3166_alpha2_code).fromDecoding!ruleset(memory, temp_iso_3166_alpha2_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'iso_3166_alpha2_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setIso_3166_alpha2_code(temp_iso_3166_alpha2_code);
            if(result.isError)
                return result.wrapError("when setting field 'iso_3166_alpha2_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type CountryName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isX121_dcc_code)
        {
            depth++;
            putIndent();
            sink("x121-dcc-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getX121_dcc_code()), "toString"))
                _value.x121_dcc_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isIso_3166_alpha2_code)
        {
            depth++;
            putIndent();
            sink("iso-3166-alpha2-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getIso_3166_alpha2_code()), "toString"))
                _value.iso_3166_alpha2_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct AdministrationDomainName
{
    enum Choice
    {
        _FAILSAFE,
        numeric,
        printable,
    }

    union Value
    {
        asn1.Asn1NumericString numeric;
        asn1.Asn1PrintableString printable;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1NumericString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.numeric)) @nogc nothrow handle_numeric,
        scope jres.Result delegate(typeof(Value.printable)) @nogc nothrow handle_printable,
    ) @nogc nothrow
    {
        if(_choice == Choice.numeric)
            return handle_numeric(_value.numeric);
        if(_choice == Choice.printable)
            return handle_printable(_value.printable);
        assert(false, "attempted to use an uninitialised AdministrationDomainName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.numeric))  handle_numeric,
        scope jres.Result delegate(typeof(Value.printable))  handle_printable,
    ) 
    {
        if(_choice == Choice.numeric)
            return handle_numeric(_value.numeric);
        if(_choice == Choice.printable)
            return handle_printable(_value.printable);
        assert(false, "attempted to use an uninitialised AdministrationDomainName!");

    }

    jres.Result setNumeric(
        typeof(Value.numeric) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 0 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.numeric = value;
        _choice = Choice.numeric;
        return jres.Result.noError;
    }

    typeof(Value.numeric) getNumeric(
    ) @nogc nothrow
    {
        assert(_choice == Choice.numeric, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'numeric'");
        return _value.numeric;
    }

    bool isNumeric(
    ) @nogc nothrow const
    {
        return _choice == Choice.numeric;
    }

    jres.Result setPrintable(
        typeof(Value.printable) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 0 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printable = value;
        _choice = Choice.printable;
        return jres.Result.noError;
    }

    typeof(Value.printable) getPrintable(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printable, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printable'");
        return _value.printable;
    }

    bool isPrintable(
    ) @nogc nothrow const
    {
        return _choice == Choice.printable;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 18)
        {
            /++ FIELD - numeric ++/
            typeof(Value.numeric) temp_numeric;
            result = typeof(temp_numeric).fromDecoding!ruleset(memory, temp_numeric, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'numeric' in type "~__traits(identifier, typeof(this))~":");
            result = this.setNumeric(temp_numeric);
            if(result.isError)
                return result.wrapError("when setting field 'numeric' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printable ++/
            typeof(Value.printable) temp_printable;
            result = typeof(temp_printable).fromDecoding!ruleset(memory, temp_printable, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printable' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintable(temp_printable);
            if(result.isError)
                return result.wrapError("when setting field 'printable' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type AdministrationDomainName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isNumeric)
        {
            depth++;
            putIndent();
            sink("numeric: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getNumeric()), "toString"))
                _value.numeric.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isPrintable)
        {
            depth++;
            putIndent();
            sink("printable: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintable()), "toString"))
                _value.printable.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct NetworkAddress
{
    private
    {
        .X121Address _value;
        bool _isSet;
    }

    jres.Result set(
        .X121Address newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .X121Address get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .X121Address, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct X121Address
{
    private
    {
        asn1.Asn1NumericString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1NumericString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1NumericString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1NumericString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct TerminalIdentifier
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 24;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct PrivateDomainName
{
    enum Choice
    {
        _FAILSAFE,
        numeric,
        printable,
    }

    union Value
    {
        asn1.Asn1NumericString numeric;
        asn1.Asn1PrintableString printable;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1NumericString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.numeric)) @nogc nothrow handle_numeric,
        scope jres.Result delegate(typeof(Value.printable)) @nogc nothrow handle_printable,
    ) @nogc nothrow
    {
        if(_choice == Choice.numeric)
            return handle_numeric(_value.numeric);
        if(_choice == Choice.printable)
            return handle_printable(_value.printable);
        assert(false, "attempted to use an uninitialised PrivateDomainName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.numeric))  handle_numeric,
        scope jres.Result delegate(typeof(Value.printable))  handle_printable,
    ) 
    {
        if(_choice == Choice.numeric)
            return handle_numeric(_value.numeric);
        if(_choice == Choice.printable)
            return handle_printable(_value.printable);
        assert(false, "attempted to use an uninitialised PrivateDomainName!");

    }

    jres.Result setNumeric(
        typeof(Value.numeric) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.numeric = value;
        _choice = Choice.numeric;
        return jres.Result.noError;
    }

    typeof(Value.numeric) getNumeric(
    ) @nogc nothrow
    {
        assert(_choice == Choice.numeric, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'numeric'");
        return _value.numeric;
    }

    bool isNumeric(
    ) @nogc nothrow const
    {
        return _choice == Choice.numeric;
    }

    jres.Result setPrintable(
        typeof(Value.printable) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printable = value;
        _choice = Choice.printable;
        return jres.Result.noError;
    }

    typeof(Value.printable) getPrintable(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printable, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printable'");
        return _value.printable;
    }

    bool isPrintable(
    ) @nogc nothrow const
    {
        return _choice == Choice.printable;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 18)
        {
            /++ FIELD - numeric ++/
            typeof(Value.numeric) temp_numeric;
            result = typeof(temp_numeric).fromDecoding!ruleset(memory, temp_numeric, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'numeric' in type "~__traits(identifier, typeof(this))~":");
            result = this.setNumeric(temp_numeric);
            if(result.isError)
                return result.wrapError("when setting field 'numeric' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printable ++/
            typeof(Value.printable) temp_printable;
            result = typeof(temp_printable).fromDecoding!ruleset(memory, temp_printable, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printable' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintable(temp_printable);
            if(result.isError)
                return result.wrapError("when setting field 'printable' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type PrivateDomainName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isNumeric)
        {
            depth++;
            putIndent();
            sink("numeric: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getNumeric()), "toString"))
                _value.numeric.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isPrintable)
        {
            depth++;
            putIndent();
            sink("printable: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintable()), "toString"))
                _value.printable.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct OrganizationName
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct NumericUserIdentifier
{
    private
    {
        asn1.Asn1NumericString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1NumericString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 32;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1NumericString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1NumericString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct PersonalName
{
    private
    {
        bool _isSet_surname;
        asn1.Asn1PrintableString _surname;
        bool _isSet_given_name;
        asn1.Asn1PrintableString _given_name;
        bool _isSet_initials;
        asn1.Asn1PrintableString _initials;
        bool _isSet_generation_qualifier;
        asn1.Asn1PrintableString _generation_qualifier;
    }

    jres.Result setSurname(
        typeof(_surname) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_surname = true;
        _surname = value;
        return jres.Result.noError;
    }

    typeof(_surname) getSurname(
    ) @nogc nothrow
    {
        assert(_isSet_surname, "Non-optional field 'surname' has not been set yet - please use validate() to check!");
        return _surname;
    }

    jres.Result setGiven_name(
        typeof(_given_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_given_name = true;
        _given_name = value;
        return jres.Result.noError;
    }

    jres.Result setGiven_name(
        tcon.Nullable!(asn1.Asn1PrintableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setGiven_name(value.get());
        }
        else
            _isSet_given_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1PrintableString) getGiven_name(
    ) @nogc nothrow
    {
        if(_isSet_given_name)
            return typeof(return)(_given_name);
        return typeof(return).init;
    }

    jres.Result setInitials(
        typeof(_initials) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_initials = true;
        _initials = value;
        return jres.Result.noError;
    }

    jres.Result setInitials(
        tcon.Nullable!(asn1.Asn1PrintableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setInitials(value.get());
        }
        else
            _isSet_initials = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1PrintableString) getInitials(
    ) @nogc nothrow
    {
        if(_isSet_initials)
            return typeof(return)(_initials);
        return typeof(return).init;
    }

    jres.Result setGeneration_qualifier(
        typeof(_generation_qualifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_generation_qualifier = true;
        _generation_qualifier = value;
        return jres.Result.noError;
    }

    jres.Result setGeneration_qualifier(
        tcon.Nullable!(asn1.Asn1PrintableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setGeneration_qualifier(value.get());
        }
        else
            _isSet_generation_qualifier = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1PrintableString) getGeneration_qualifier(
    ) @nogc nothrow
    {
        if(_isSet_generation_qualifier)
            return typeof(return)(_generation_qualifier);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_surname)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PersonalName non-optional field 'surname' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("surname: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_surname), "toString"))
            _surname.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("given-name: ");
        sink("\n");
        if(_isSet_given_name)
        {
            static if(__traits(hasMember, typeof(_given_name), "toString"))
                _given_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("initials: ");
        sink("\n");
        if(_isSet_initials)
        {
            static if(__traits(hasMember, typeof(_initials), "toString"))
                _initials.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("generation-qualifier: ");
        sink("\n");
        if(_isSet_generation_qualifier)
        {
            static if(__traits(hasMember, typeof(_generation_qualifier), "toString"))
                _generation_qualifier.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        static assert(ruleset == asn1.Asn1Ruleset.der, "TODO: Support non-DER SET encodings");
        /+++ TAG FOR FIELD: surname +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'surname' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PersonalName when reading top level tag 0 for field 'surname' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PersonalName when reading top level tag 0 for field 'surname' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_surname;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_surname);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'surname' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - surname ++/
        typeof(_surname) temp_surname;
        result = typeof(temp_surname).fromDecoding!ruleset(memory_surname, temp_surname, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'surname' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSurname(temp_surname);
        if(result.isError)
            return result.wrapError("when setting field 'surname' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: given-name +++/
        auto backtrack_given_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'given-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_given_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_given_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'given-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - given-name ++/
                typeof(_given_name) temp_given_name;
                result = typeof(temp_given_name).fromDecoding!ruleset(memory_given_name, temp_given_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'given_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setGiven_name(temp_given_name);
                if(result.isError)
                    return result.wrapError("when setting field 'given_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_given_name.buffer, backtrack_given_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: initials +++/
        auto backtrack_initials = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'initials' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_initials;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_initials);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'initials' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - initials ++/
                typeof(_initials) temp_initials;
                result = typeof(temp_initials).fromDecoding!ruleset(memory_initials, temp_initials, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'initials' in type "~__traits(identifier, typeof(this))~":");
                result = this.setInitials(temp_initials);
                if(result.isError)
                    return result.wrapError("when setting field 'initials' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_initials.buffer, backtrack_initials.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: generation-qualifier +++/
        auto backtrack_generation_qualifier = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'generation-qualifier' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 3)
            {
                jbuf.MemoryReader memory_generation_qualifier;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_generation_qualifier);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'generation-qualifier' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - generation-qualifier ++/
                typeof(_generation_qualifier) temp_generation_qualifier;
                result = typeof(temp_generation_qualifier).fromDecoding!ruleset(memory_generation_qualifier, temp_generation_qualifier, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'generation_qualifier' in type "~__traits(identifier, typeof(this))~":");
                result = this.setGeneration_qualifier(temp_generation_qualifier);
                if(result.isError)
                    return result.wrapError("when setting field 'generation_qualifier' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_generation_qualifier.buffer, backtrack_generation_qualifier.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.setHasExtraData, "when decoding non-extensible SET PersonalName there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ExtensionAttributes
{
    private
    {
        asn1.Asn1SetOf!(.ExtensionAttribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.ExtensionAttribute) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.elementCount >= 1 && newValue.elementCount <= 256;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(.ExtensionAttribute) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SetOf!(.ExtensionAttribute), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SET OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct ExtensionAttribute
{
    private
    {
        bool _isSet_extension_attribute_type;
        asn1.Asn1Integer _extension_attribute_type;
        bool _isSet_extension_attribute_value;
        asn1.Asn1Any _extension_attribute_value;
    }

    jres.Result setExtension_attribute_type(
        typeof(_extension_attribute_type) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extension_attribute_type = true;
        _extension_attribute_type = value;
        return jres.Result.noError;
    }

    typeof(_extension_attribute_type) getExtension_attribute_type(
    ) @nogc nothrow
    {
        assert(_isSet_extension_attribute_type, "Non-optional field 'extension-attribute-type' has not been set yet - please use validate() to check!");
        return _extension_attribute_type;
    }

    jres.Result setExtension_attribute_value(
        typeof(_extension_attribute_value) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extension_attribute_value = true;
        _extension_attribute_value = value;
        return jres.Result.noError;
    }

    typeof(_extension_attribute_value) getExtension_attribute_value(
    ) @nogc nothrow
    {
        assert(_isSet_extension_attribute_value, "Non-optional field 'extension-attribute-value' has not been set yet - please use validate() to check!");
        return _extension_attribute_value;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_extension_attribute_type)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtensionAttribute non-optional field 'extension-attribute-type' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_extension_attribute_value)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtensionAttribute non-optional field 'extension-attribute-value' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("extension-attribute-type: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_extension_attribute_type), "toString"))
            _extension_attribute_type.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("extension-attribute-value: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_extension_attribute_value), "toString"))
            _extension_attribute_value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: extension-attribute-type +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'extension-attribute-type' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtensionAttribute when reading top level tag 0 for field 'extension-attribute-type' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtensionAttribute when reading top level tag 0 for field 'extension-attribute-type' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_extension_attribute_type;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extension_attribute_type);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'extension-attribute-type' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - extension-attribute-type ++/
        typeof(_extension_attribute_type) temp_extension_attribute_type;
        result = typeof(temp_extension_attribute_type).fromDecoding!ruleset(memory_extension_attribute_type, temp_extension_attribute_type, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'extension_attribute_type' in type "~__traits(identifier, typeof(this))~":");
        result = this.setExtension_attribute_type(temp_extension_attribute_type);
        if(result.isError)
            return result.wrapError("when setting field 'extension_attribute_type' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: extension-attribute-value +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'extension-attribute-value' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtensionAttribute when reading top level tag 1 for field 'extension-attribute-value' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 1)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtensionAttribute when reading top level tag 1 for field 'extension-attribute-value' the tag's value was expected to be 1", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_extension_attribute_value;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extension_attribute_value);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'extension-attribute-value' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - extension-attribute-value ++/
        jbuf.MemoryReader memory_0extension_attribute_value;
            // EXPLICIT TAG - 1
            if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 1 for field extension_attribute_value a primitive tag was found when a constructed one was expected");
            if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 1 for field 'extension_attribute_value' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
            if(componentHeader.identifier.tag != 1)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 1 for field 'extension_attribute_value' the tag's value was expected to be 1", jstr.String2("tag value was ", componentHeader.identifier.tag));
            result = asn1.asn1DecodeComponentHeader!ruleset(memory_extension_attribute_value, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'extension_attribute_value' in type "~__traits(identifier, typeof(this))~":");
            result = asn1.asn1ReadContentBytes(memory_extension_attribute_value, componentHeader.length, memory_0extension_attribute_value);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'extension_attribute_value' in type "~__traits(identifier, typeof(this))~":");
        typeof(_extension_attribute_value) temp_extension_attribute_value;
        result = typeof(temp_extension_attribute_value).fromDecoding!ruleset(memory_0extension_attribute_value, temp_extension_attribute_value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'extension_attribute_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.setExtension_attribute_value(temp_extension_attribute_value);
        if(result.isError)
            return result.wrapError("when setting field 'extension_attribute_value' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ExtensionAttribute there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct BuiltInDomainDefinedAttributes
{
    private
    {
        asn1.Asn1SequenceOf!(.BuiltInDomainDefinedAttribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.BuiltInDomainDefinedAttribute) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.elementCount >= 1 && newValue.elementCount <= 4;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.BuiltInDomainDefinedAttribute) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.BuiltInDomainDefinedAttribute), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SEQEUENCE OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct BuiltInDomainDefinedAttribute
{
    private
    {
        bool _isSet_type;
        asn1.Asn1PrintableString _type;
        bool _isSet_value;
        asn1.Asn1PrintableString _value;
    }

    jres.Result setType(
        typeof(_type) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 8;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _isSet_type = true;
        _type = value;
        return jres.Result.noError;
    }

    typeof(_type) getType(
    ) @nogc nothrow
    {
        assert(_isSet_type, "Non-optional field 'type' has not been set yet - please use validate() to check!");
        return _type;
    }

    jres.Result setValue(
        typeof(_value) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 128;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _isSet_value = true;
        _value = value;
        return jres.Result.noError;
    }

    typeof(_value) getValue(
    ) @nogc nothrow
    {
        assert(_isSet_value, "Non-optional field 'value' has not been set yet - please use validate() to check!");
        return _value;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_type)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type BuiltInDomainDefinedAttribute non-optional field 'type' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_value)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type BuiltInDomainDefinedAttribute non-optional field 'value' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("type: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_type), "toString"))
            _type.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("value: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_value), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: type +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'type' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE BuiltInDomainDefinedAttribute when reading top level tag 19 for field 'type' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 19)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE BuiltInDomainDefinedAttribute when reading top level tag 19 for field 'type' the tag's value was expected to be 19", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_type;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_type);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'type' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - type ++/
        typeof(_type) temp_type;
        result = typeof(temp_type).fromDecoding!ruleset(memory_type, temp_type, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'type' in type "~__traits(identifier, typeof(this))~":");
        result = this.setType(temp_type);
        if(result.isError)
            return result.wrapError("when setting field 'type' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: value +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'value' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE BuiltInDomainDefinedAttribute when reading top level tag 19 for field 'value' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 19)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE BuiltInDomainDefinedAttribute when reading top level tag 19 for field 'value' the tag's value was expected to be 19", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_value;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_value);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'value' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - value ++/
        typeof(_value) temp_value;
        result = typeof(temp_value).fromDecoding!ruleset(memory_value, temp_value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'value' in type "~__traits(identifier, typeof(this))~":");
        result = this.setValue(temp_value);
        if(result.isError)
            return result.wrapError("when setting field 'value' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE BuiltInDomainDefinedAttribute there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct OrganizationalUnitNames
{
    private
    {
        asn1.Asn1SequenceOf!(.OrganizationalUnitName) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.OrganizationalUnitName) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.elementCount >= 1 && newValue.elementCount <= 4;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.OrganizationalUnitName) get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.OrganizationalUnitName), "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        result = this._value.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SEQEUENCE OF field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct OrganizationalUnitName
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 32;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct BuiltInStandardAttributes
{
    private
    {
        bool _isSet_country_name;
        .CountryName _country_name;
        bool _isSet_administration_domain_name;
        .AdministrationDomainName _administration_domain_name;
        bool _isSet_network_address;
        .NetworkAddress _network_address;
        bool _isSet_terminal_identifier;
        .TerminalIdentifier _terminal_identifier;
        bool _isSet_private_domain_name;
        .PrivateDomainName _private_domain_name;
        bool _isSet_organization_name;
        .OrganizationName _organization_name;
        bool _isSet_numeric_user_identifier;
        .NumericUserIdentifier _numeric_user_identifier;
        bool _isSet_personal_name;
        .PersonalName _personal_name;
        bool _isSet_organizational_unit_names;
        .OrganizationalUnitNames _organizational_unit_names;
    }

    jres.Result setCountry_name(
        typeof(_country_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_country_name = true;
        _country_name = value;
        return jres.Result.noError;
    }

    jres.Result setCountry_name(
        tcon.Nullable!(.CountryName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCountry_name(value.get());
        }
        else
            _isSet_country_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.CountryName) getCountry_name(
    ) @nogc nothrow
    {
        if(_isSet_country_name)
            return typeof(return)(_country_name);
        return typeof(return).init;
    }

    jres.Result setAdministration_domain_name(
        typeof(_administration_domain_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_administration_domain_name = true;
        _administration_domain_name = value;
        return jres.Result.noError;
    }

    jres.Result setAdministration_domain_name(
        tcon.Nullable!(.AdministrationDomainName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setAdministration_domain_name(value.get());
        }
        else
            _isSet_administration_domain_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.AdministrationDomainName) getAdministration_domain_name(
    ) @nogc nothrow
    {
        if(_isSet_administration_domain_name)
            return typeof(return)(_administration_domain_name);
        return typeof(return).init;
    }

    jres.Result setNetwork_address(
        typeof(_network_address) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_network_address = true;
        _network_address = value;
        return jres.Result.noError;
    }

    jres.Result setNetwork_address(
        tcon.Nullable!(.NetworkAddress) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setNetwork_address(value.get());
        }
        else
            _isSet_network_address = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.NetworkAddress) getNetwork_address(
    ) @nogc nothrow
    {
        if(_isSet_network_address)
            return typeof(return)(_network_address);
        return typeof(return).init;
    }

    jres.Result setTerminal_identifier(
        typeof(_terminal_identifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_terminal_identifier = true;
        _terminal_identifier = value;
        return jres.Result.noError;
    }

    jres.Result setTerminal_identifier(
        tcon.Nullable!(.TerminalIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setTerminal_identifier(value.get());
        }
        else
            _isSet_terminal_identifier = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.TerminalIdentifier) getTerminal_identifier(
    ) @nogc nothrow
    {
        if(_isSet_terminal_identifier)
            return typeof(return)(_terminal_identifier);
        return typeof(return).init;
    }

    jres.Result setPrivate_domain_name(
        typeof(_private_domain_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_private_domain_name = true;
        _private_domain_name = value;
        return jres.Result.noError;
    }

    jres.Result setPrivate_domain_name(
        tcon.Nullable!(.PrivateDomainName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setPrivate_domain_name(value.get());
        }
        else
            _isSet_private_domain_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.PrivateDomainName) getPrivate_domain_name(
    ) @nogc nothrow
    {
        if(_isSet_private_domain_name)
            return typeof(return)(_private_domain_name);
        return typeof(return).init;
    }

    jres.Result setOrganization_name(
        typeof(_organization_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_organization_name = true;
        _organization_name = value;
        return jres.Result.noError;
    }

    jres.Result setOrganization_name(
        tcon.Nullable!(.OrganizationName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOrganization_name(value.get());
        }
        else
            _isSet_organization_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OrganizationName) getOrganization_name(
    ) @nogc nothrow
    {
        if(_isSet_organization_name)
            return typeof(return)(_organization_name);
        return typeof(return).init;
    }

    jres.Result setNumeric_user_identifier(
        typeof(_numeric_user_identifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_numeric_user_identifier = true;
        _numeric_user_identifier = value;
        return jres.Result.noError;
    }

    jres.Result setNumeric_user_identifier(
        tcon.Nullable!(.NumericUserIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setNumeric_user_identifier(value.get());
        }
        else
            _isSet_numeric_user_identifier = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.NumericUserIdentifier) getNumeric_user_identifier(
    ) @nogc nothrow
    {
        if(_isSet_numeric_user_identifier)
            return typeof(return)(_numeric_user_identifier);
        return typeof(return).init;
    }

    jres.Result setPersonal_name(
        typeof(_personal_name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_personal_name = true;
        _personal_name = value;
        return jres.Result.noError;
    }

    jres.Result setPersonal_name(
        tcon.Nullable!(.PersonalName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setPersonal_name(value.get());
        }
        else
            _isSet_personal_name = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.PersonalName) getPersonal_name(
    ) @nogc nothrow
    {
        if(_isSet_personal_name)
            return typeof(return)(_personal_name);
        return typeof(return).init;
    }

    jres.Result setOrganizational_unit_names(
        typeof(_organizational_unit_names) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_organizational_unit_names = true;
        _organizational_unit_names = value;
        return jres.Result.noError;
    }

    jres.Result setOrganizational_unit_names(
        tcon.Nullable!(.OrganizationalUnitNames) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOrganizational_unit_names(value.get());
        }
        else
            _isSet_organizational_unit_names = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OrganizationalUnitNames) getOrganizational_unit_names(
    ) @nogc nothrow
    {
        if(_isSet_organizational_unit_names)
            return typeof(return)(_organizational_unit_names);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("country-name: ");
        sink("\n");
        if(_isSet_country_name)
        {
            static if(__traits(hasMember, typeof(_country_name), "toString"))
                _country_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("administration-domain-name: ");
        sink("\n");
        if(_isSet_administration_domain_name)
        {
            static if(__traits(hasMember, typeof(_administration_domain_name), "toString"))
                _administration_domain_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("network-address: ");
        sink("\n");
        if(_isSet_network_address)
        {
            static if(__traits(hasMember, typeof(_network_address), "toString"))
                _network_address.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("terminal-identifier: ");
        sink("\n");
        if(_isSet_terminal_identifier)
        {
            static if(__traits(hasMember, typeof(_terminal_identifier), "toString"))
                _terminal_identifier.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("private-domain-name: ");
        sink("\n");
        if(_isSet_private_domain_name)
        {
            static if(__traits(hasMember, typeof(_private_domain_name), "toString"))
                _private_domain_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("organization-name: ");
        sink("\n");
        if(_isSet_organization_name)
        {
            static if(__traits(hasMember, typeof(_organization_name), "toString"))
                _organization_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("numeric-user-identifier: ");
        sink("\n");
        if(_isSet_numeric_user_identifier)
        {
            static if(__traits(hasMember, typeof(_numeric_user_identifier), "toString"))
                _numeric_user_identifier.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("personal-name: ");
        sink("\n");
        if(_isSet_personal_name)
        {
            static if(__traits(hasMember, typeof(_personal_name), "toString"))
                _personal_name.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("organizational-unit-names: ");
        sink("\n");
        if(_isSet_organizational_unit_names)
        {
            static if(__traits(hasMember, typeof(_organizational_unit_names), "toString"))
                _organizational_unit_names.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: country-name +++/
        auto backtrack_country_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'country-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.application && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_country_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_country_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'country-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - country-name ++/
                jbuf.MemoryReader memory_0country_name;
                    // EXPLICIT TAG - 1
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 1 for field country_name a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.application)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 1 for field 'country_name' the tag's class was expected to be application", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 1)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 1 for field 'country_name' the tag's value was expected to be 1", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_country_name, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'country_name' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_country_name, componentHeader.length, memory_0country_name);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'country_name' in type "~__traits(identifier, typeof(this))~":");
                typeof(_country_name) temp_country_name;
                result = temp_country_name.fromDecoding!ruleset(memory_0country_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'country_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCountry_name(temp_country_name);
                if(result.isError)
                    return result.wrapError("when setting field 'country_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_country_name.buffer, backtrack_country_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: administration-domain-name +++/
        auto backtrack_administration_domain_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'administration-domain-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.application && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_administration_domain_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_administration_domain_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'administration-domain-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - administration-domain-name ++/
                jbuf.MemoryReader memory_0administration_domain_name;
                    // EXPLICIT TAG - 2
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 2 for field administration_domain_name a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.application)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 2 for field 'administration_domain_name' the tag's class was expected to be application", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 2)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 2 for field 'administration_domain_name' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_administration_domain_name, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'administration_domain_name' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_administration_domain_name, componentHeader.length, memory_0administration_domain_name);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'administration_domain_name' in type "~__traits(identifier, typeof(this))~":");
                typeof(_administration_domain_name) temp_administration_domain_name;
                result = temp_administration_domain_name.fromDecoding!ruleset(memory_0administration_domain_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'administration_domain_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setAdministration_domain_name(temp_administration_domain_name);
                if(result.isError)
                    return result.wrapError("when setting field 'administration_domain_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_administration_domain_name.buffer, backtrack_administration_domain_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: network-address +++/
        auto backtrack_network_address = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'network-address' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_network_address;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_network_address);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'network-address' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - network-address ++/
                typeof(_network_address) temp_network_address;
                result = temp_network_address.fromDecoding!ruleset(memory_network_address, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'network_address' in type "~__traits(identifier, typeof(this))~":");
                result = this.setNetwork_address(temp_network_address);
                if(result.isError)
                    return result.wrapError("when setting field 'network_address' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_network_address.buffer, backtrack_network_address.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: terminal-identifier +++/
        auto backtrack_terminal_identifier = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'terminal-identifier' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_terminal_identifier;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_terminal_identifier);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'terminal-identifier' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - terminal-identifier ++/
                typeof(_terminal_identifier) temp_terminal_identifier;
                result = temp_terminal_identifier.fromDecoding!ruleset(memory_terminal_identifier, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'terminal_identifier' in type "~__traits(identifier, typeof(this))~":");
                result = this.setTerminal_identifier(temp_terminal_identifier);
                if(result.isError)
                    return result.wrapError("when setting field 'terminal_identifier' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_terminal_identifier.buffer, backtrack_terminal_identifier.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: private-domain-name +++/
        auto backtrack_private_domain_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'private-domain-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_private_domain_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_private_domain_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'private-domain-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - private-domain-name ++/
                jbuf.MemoryReader memory_0private_domain_name;
                    // EXPLICIT TAG - 2
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 2 for field private_domain_name a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 2 for field 'private_domain_name' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 2)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 2 for field 'private_domain_name' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_private_domain_name, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'private_domain_name' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_private_domain_name, componentHeader.length, memory_0private_domain_name);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'private_domain_name' in type "~__traits(identifier, typeof(this))~":");
                typeof(_private_domain_name) temp_private_domain_name;
                result = temp_private_domain_name.fromDecoding!ruleset(memory_0private_domain_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'private_domain_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPrivate_domain_name(temp_private_domain_name);
                if(result.isError)
                    return result.wrapError("when setting field 'private_domain_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_private_domain_name.buffer, backtrack_private_domain_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: organization-name +++/
        auto backtrack_organization_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'organization-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 3)
            {
                jbuf.MemoryReader memory_organization_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_organization_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'organization-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - organization-name ++/
                typeof(_organization_name) temp_organization_name;
                result = temp_organization_name.fromDecoding!ruleset(memory_organization_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'organization_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOrganization_name(temp_organization_name);
                if(result.isError)
                    return result.wrapError("when setting field 'organization_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_organization_name.buffer, backtrack_organization_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: numeric-user-identifier +++/
        auto backtrack_numeric_user_identifier = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'numeric-user-identifier' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 4)
            {
                jbuf.MemoryReader memory_numeric_user_identifier;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_numeric_user_identifier);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'numeric-user-identifier' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - numeric-user-identifier ++/
                typeof(_numeric_user_identifier) temp_numeric_user_identifier;
                result = temp_numeric_user_identifier.fromDecoding!ruleset(memory_numeric_user_identifier, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'numeric_user_identifier' in type "~__traits(identifier, typeof(this))~":");
                result = this.setNumeric_user_identifier(temp_numeric_user_identifier);
                if(result.isError)
                    return result.wrapError("when setting field 'numeric_user_identifier' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_numeric_user_identifier.buffer, backtrack_numeric_user_identifier.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: personal-name +++/
        auto backtrack_personal_name = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'personal-name' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 5)
            {
                jbuf.MemoryReader memory_personal_name;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_personal_name);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'personal-name' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - personal-name ++/
                typeof(_personal_name) temp_personal_name;
                result = temp_personal_name.fromDecoding!ruleset(memory_personal_name, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'personal_name' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPersonal_name(temp_personal_name);
                if(result.isError)
                    return result.wrapError("when setting field 'personal_name' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_personal_name.buffer, backtrack_personal_name.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: organizational-unit-names +++/
        auto backtrack_organizational_unit_names = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'organizational-unit-names' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 6)
            {
                jbuf.MemoryReader memory_organizational_unit_names;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_organizational_unit_names);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'organizational-unit-names' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - organizational-unit-names ++/
                typeof(_organizational_unit_names) temp_organizational_unit_names;
                result = temp_organizational_unit_names.fromDecoding!ruleset(memory_organizational_unit_names, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'organizational_unit_names' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOrganizational_unit_names(temp_organizational_unit_names);
                if(result.isError)
                    return result.wrapError("when setting field 'organizational_unit_names' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_organizational_unit_names.buffer, backtrack_organizational_unit_names.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE BuiltInStandardAttributes there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ORAddress
{
    private
    {
        bool _isSet_built_in_standard_attributes;
        .BuiltInStandardAttributes _built_in_standard_attributes;
        bool _isSet_built_in_domain_defined_attributes;
        .BuiltInDomainDefinedAttributes _built_in_domain_defined_attributes;
        bool _isSet_extension_attributes;
        .ExtensionAttributes _extension_attributes;
    }

    jres.Result setBuilt_in_standard_attributes(
        typeof(_built_in_standard_attributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_built_in_standard_attributes = true;
        _built_in_standard_attributes = value;
        return jres.Result.noError;
    }

    typeof(_built_in_standard_attributes) getBuilt_in_standard_attributes(
    ) @nogc nothrow
    {
        assert(_isSet_built_in_standard_attributes, "Non-optional field 'built-in-standard-attributes' has not been set yet - please use validate() to check!");
        return _built_in_standard_attributes;
    }

    jres.Result setBuilt_in_domain_defined_attributes(
        typeof(_built_in_domain_defined_attributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_built_in_domain_defined_attributes = true;
        _built_in_domain_defined_attributes = value;
        return jres.Result.noError;
    }

    jres.Result setBuilt_in_domain_defined_attributes(
        tcon.Nullable!(.BuiltInDomainDefinedAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setBuilt_in_domain_defined_attributes(value.get());
        }
        else
            _isSet_built_in_domain_defined_attributes = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.BuiltInDomainDefinedAttributes) getBuilt_in_domain_defined_attributes(
    ) @nogc nothrow
    {
        if(_isSet_built_in_domain_defined_attributes)
            return typeof(return)(_built_in_domain_defined_attributes);
        return typeof(return).init;
    }

    jres.Result setExtension_attributes(
        typeof(_extension_attributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extension_attributes = true;
        _extension_attributes = value;
        return jres.Result.noError;
    }

    jres.Result setExtension_attributes(
        tcon.Nullable!(.ExtensionAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setExtension_attributes(value.get());
        }
        else
            _isSet_extension_attributes = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.ExtensionAttributes) getExtension_attributes(
    ) @nogc nothrow
    {
        if(_isSet_extension_attributes)
            return typeof(return)(_extension_attributes);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_built_in_standard_attributes)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ORAddress non-optional field 'built-in-standard-attributes' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("built-in-standard-attributes: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_built_in_standard_attributes), "toString"))
            _built_in_standard_attributes.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("built-in-domain-defined-attributes: ");
        sink("\n");
        if(_isSet_built_in_domain_defined_attributes)
        {
            static if(__traits(hasMember, typeof(_built_in_domain_defined_attributes), "toString"))
                _built_in_domain_defined_attributes.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("extension-attributes: ");
        sink("\n");
        if(_isSet_extension_attributes)
        {
            static if(__traits(hasMember, typeof(_extension_attributes), "toString"))
                _extension_attributes.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: built-in-standard-attributes +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'built-in-standard-attributes' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ORAddress when reading top level tag 16 for field 'built-in-standard-attributes' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ORAddress when reading top level tag 16 for field 'built-in-standard-attributes' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_built_in_standard_attributes;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_built_in_standard_attributes);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'built-in-standard-attributes' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - built-in-standard-attributes ++/
        typeof(_built_in_standard_attributes) temp_built_in_standard_attributes;
        result = temp_built_in_standard_attributes.fromDecoding!ruleset(memory_built_in_standard_attributes, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'built_in_standard_attributes' in type "~__traits(identifier, typeof(this))~":");
        result = this.setBuilt_in_standard_attributes(temp_built_in_standard_attributes);
        if(result.isError)
            return result.wrapError("when setting field 'built_in_standard_attributes' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: built-in-domain-defined-attributes +++/
        auto backtrack_built_in_domain_defined_attributes = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'built-in-domain-defined-attributes' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_built_in_domain_defined_attributes;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_built_in_domain_defined_attributes);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'built-in-domain-defined-attributes' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - built-in-domain-defined-attributes ++/
                typeof(_built_in_domain_defined_attributes) temp_built_in_domain_defined_attributes;
                result = temp_built_in_domain_defined_attributes.fromDecoding!ruleset(memory_built_in_domain_defined_attributes, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'built_in_domain_defined_attributes' in type "~__traits(identifier, typeof(this))~":");
                result = this.setBuilt_in_domain_defined_attributes(temp_built_in_domain_defined_attributes);
                if(result.isError)
                    return result.wrapError("when setting field 'built_in_domain_defined_attributes' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_built_in_domain_defined_attributes.buffer, backtrack_built_in_domain_defined_attributes.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: extension-attributes +++/
        auto backtrack_extension_attributes = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'extension-attributes' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 17)
            {
                jbuf.MemoryReader memory_extension_attributes;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extension_attributes);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'extension-attributes' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - extension-attributes ++/
                typeof(_extension_attributes) temp_extension_attributes;
                result = temp_extension_attributes.fromDecoding!ruleset(memory_extension_attributes, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'extension_attributes' in type "~__traits(identifier, typeof(this))~":");
                result = this.setExtension_attributes(temp_extension_attributes);
                if(result.isError)
                    return result.wrapError("when setting field 'extension_attributes' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_extension_attributes.buffer, backtrack_extension_attributes.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ORAddress there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1Integer common_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 1 */ 0x1, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct CommonName
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 64;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer teletex_common_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 2 */ 0x2, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer teletex_organization_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 3 */ 0x3, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer teletex_personal_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 4 */ 0x4, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer teletex_organizational_unit_names(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 5 */ 0x5, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer pds_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 7 */ 0x7, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct PDSName
{
    private
    {
        asn1.Asn1PrintableString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1PrintableString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = newValue.asSlice.length >= 1 && newValue.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1PrintableString get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1PrintableString, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer physical_delivery_country_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 8 */ 0x8, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct PhysicalDeliveryCountryName
{
    enum Choice
    {
        _FAILSAFE,
        x121_dcc_code,
        iso_3166_alpha2_code,
    }

    union Value
    {
        asn1.Asn1NumericString x121_dcc_code;
        asn1.Asn1PrintableString iso_3166_alpha2_code;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1NumericString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.x121_dcc_code)) @nogc nothrow handle_x121_dcc_code,
        scope jres.Result delegate(typeof(Value.iso_3166_alpha2_code)) @nogc nothrow handle_iso_3166_alpha2_code,
    ) @nogc nothrow
    {
        if(_choice == Choice.x121_dcc_code)
            return handle_x121_dcc_code(_value.x121_dcc_code);
        if(_choice == Choice.iso_3166_alpha2_code)
            return handle_iso_3166_alpha2_code(_value.iso_3166_alpha2_code);
        assert(false, "attempted to use an uninitialised PhysicalDeliveryCountryName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.x121_dcc_code))  handle_x121_dcc_code,
        scope jres.Result delegate(typeof(Value.iso_3166_alpha2_code))  handle_iso_3166_alpha2_code,
    ) 
    {
        if(_choice == Choice.x121_dcc_code)
            return handle_x121_dcc_code(_value.x121_dcc_code);
        if(_choice == Choice.iso_3166_alpha2_code)
            return handle_iso_3166_alpha2_code(_value.iso_3166_alpha2_code);
        assert(false, "attempted to use an uninitialised PhysicalDeliveryCountryName!");

    }

    jres.Result setX121_dcc_code(
        typeof(Value.x121_dcc_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length == 3;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.x121_dcc_code = value;
        _choice = Choice.x121_dcc_code;
        return jres.Result.noError;
    }

    typeof(Value.x121_dcc_code) getX121_dcc_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.x121_dcc_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'x121_dcc_code'");
        return _value.x121_dcc_code;
    }

    bool isX121_dcc_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.x121_dcc_code;
    }

    jres.Result setIso_3166_alpha2_code(
        typeof(Value.iso_3166_alpha2_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length == 2;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.iso_3166_alpha2_code = value;
        _choice = Choice.iso_3166_alpha2_code;
        return jres.Result.noError;
    }

    typeof(Value.iso_3166_alpha2_code) getIso_3166_alpha2_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.iso_3166_alpha2_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'iso_3166_alpha2_code'");
        return _value.iso_3166_alpha2_code;
    }

    bool isIso_3166_alpha2_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.iso_3166_alpha2_code;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 18)
        {
            /++ FIELD - x121-dcc-code ++/
            typeof(Value.x121_dcc_code) temp_x121_dcc_code;
            result = typeof(temp_x121_dcc_code).fromDecoding!ruleset(memory, temp_x121_dcc_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'x121_dcc_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setX121_dcc_code(temp_x121_dcc_code);
            if(result.isError)
                return result.wrapError("when setting field 'x121_dcc_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - iso-3166-alpha2-code ++/
            typeof(Value.iso_3166_alpha2_code) temp_iso_3166_alpha2_code;
            result = typeof(temp_iso_3166_alpha2_code).fromDecoding!ruleset(memory, temp_iso_3166_alpha2_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'iso_3166_alpha2_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setIso_3166_alpha2_code(temp_iso_3166_alpha2_code);
            if(result.isError)
                return result.wrapError("when setting field 'iso_3166_alpha2_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type PhysicalDeliveryCountryName the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isX121_dcc_code)
        {
            depth++;
            putIndent();
            sink("x121-dcc-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getX121_dcc_code()), "toString"))
                _value.x121_dcc_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isIso_3166_alpha2_code)
        {
            depth++;
            putIndent();
            sink("iso-3166-alpha2-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getIso_3166_alpha2_code()), "toString"))
                _value.iso_3166_alpha2_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

asn1.Asn1Integer postal_code(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 9 */ 0x9, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct PostalCode
{
    enum Choice
    {
        _FAILSAFE,
        numeric_code,
        printable_code,
    }

    union Value
    {
        asn1.Asn1NumericString numeric_code;
        asn1.Asn1PrintableString printable_code;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1NumericString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1PrintableString), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.numeric_code)) @nogc nothrow handle_numeric_code,
        scope jres.Result delegate(typeof(Value.printable_code)) @nogc nothrow handle_printable_code,
    ) @nogc nothrow
    {
        if(_choice == Choice.numeric_code)
            return handle_numeric_code(_value.numeric_code);
        if(_choice == Choice.printable_code)
            return handle_printable_code(_value.printable_code);
        assert(false, "attempted to use an uninitialised PostalCode!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.numeric_code))  handle_numeric_code,
        scope jres.Result delegate(typeof(Value.printable_code))  handle_printable_code,
    ) 
    {
        if(_choice == Choice.numeric_code)
            return handle_numeric_code(_value.numeric_code);
        if(_choice == Choice.printable_code)
            return handle_printable_code(_value.printable_code);
        assert(false, "attempted to use an uninitialised PostalCode!");

    }

    jres.Result setNumeric_code(
        typeof(Value.numeric_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.numeric_code = value;
        _choice = Choice.numeric_code;
        return jres.Result.noError;
    }

    typeof(Value.numeric_code) getNumeric_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.numeric_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'numeric_code'");
        return _value.numeric_code;
    }

    bool isNumeric_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.numeric_code;
    }

    jres.Result setPrintable_code(
        typeof(Value.printable_code) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 16;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.printable_code = value;
        _choice = Choice.printable_code;
        return jres.Result.noError;
    }

    typeof(Value.printable_code) getPrintable_code(
    ) @nogc nothrow
    {
        assert(_choice == Choice.printable_code, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'printable_code'");
        return _value.printable_code;
    }

    bool isPrintable_code(
    ) @nogc nothrow const
    {
        return _choice == Choice.printable_code;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 18)
        {
            /++ FIELD - numeric-code ++/
            typeof(Value.numeric_code) temp_numeric_code;
            result = typeof(temp_numeric_code).fromDecoding!ruleset(memory, temp_numeric_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'numeric_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setNumeric_code(temp_numeric_code);
            if(result.isError)
                return result.wrapError("when setting field 'numeric_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 19)
        {
            /++ FIELD - printable-code ++/
            typeof(Value.printable_code) temp_printable_code;
            result = typeof(temp_printable_code).fromDecoding!ruleset(memory, temp_printable_code, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'printable_code' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPrintable_code(temp_printable_code);
            if(result.isError)
                return result.wrapError("when setting field 'printable_code' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type PostalCode the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isNumeric_code)
        {
            depth++;
            putIndent();
            sink("numeric-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getNumeric_code()), "toString"))
                _value.numeric_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isPrintable_code)
        {
            depth++;
            putIndent();
            sink("printable-code: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPrintable_code()), "toString"))
                _value.printable_code.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

asn1.Asn1Integer street_address(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 17 */ 0x11, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct StreetAddress
{
    private
    {
        .PDSParameter _value;
        bool _isSet;
    }

    jres.Result set(
        .PDSParameter newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .PDSParameter get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .PDSParameter, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer post_office_box_address(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 18 */ 0x12, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct PostOfficeBoxAddress
{
    private
    {
        .PDSParameter _value;
        bool _isSet;
    }

    jres.Result set(
        .PDSParameter newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .PDSParameter get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .PDSParameter, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer poste_restante_address(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 19 */ 0x13, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct PosteRestanteAddress
{
    private
    {
        .PDSParameter _value;
        bool _isSet;
    }

    jres.Result set(
        .PDSParameter newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .PDSParameter get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .PDSParameter, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer unique_postal_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 20 */ 0x14, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct UniquePostalName
{
    private
    {
        .PDSParameter _value;
        bool _isSet;
    }

    jres.Result set(
        .PDSParameter newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .PDSParameter get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .PDSParameter, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer local_postal_attributes(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 21 */ 0x15, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct LocalPostalAttributes
{
    private
    {
        .PDSParameter _value;
        bool _isSet;
    }

    jres.Result set(
        .PDSParameter newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .PDSParameter get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, .PDSParameter, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = temp__value.fromDecoding!ruleset(memory, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

struct PDSParameter
{
    private
    {
        bool _isSet_printable_string;
        asn1.Asn1PrintableString _printable_string;
    }

    jres.Result setPrintable_string(
        typeof(_printable_string) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 30;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _isSet_printable_string = true;
        _printable_string = value;
        return jres.Result.noError;
    }

    jres.Result setPrintable_string(
        tcon.Nullable!(asn1.Asn1PrintableString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            bool _successFlag;
            _successFlag = value.get.asSlice.length >= 1 && value.get.asSlice.length <= 30;
            if(!_successFlag)
                return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
            return setPrintable_string(value.get());
        }
        else
            _isSet_printable_string = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1PrintableString) getPrintable_string(
    ) @nogc nothrow
    {
        if(_isSet_printable_string)
            return typeof(return)(_printable_string);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("printable-string: ");
        sink("\n");
        if(_isSet_printable_string)
        {
            static if(__traits(hasMember, typeof(_printable_string), "toString"))
                _printable_string.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        static assert(ruleset == asn1.Asn1Ruleset.der, "TODO: Support non-DER SET encodings");
        /+++ TAG FOR FIELD: printable-string +++/
        auto backtrack_printable_string = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'printable-string' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 19)
            {
                jbuf.MemoryReader memory_printable_string;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_printable_string);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'printable-string' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - printable-string ++/
                typeof(_printable_string) temp_printable_string;
                result = typeof(temp_printable_string).fromDecoding!ruleset(memory_printable_string, temp_printable_string, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'printable_string' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPrintable_string(temp_printable_string);
                if(result.isError)
                    return result.wrapError("when setting field 'printable_string' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_printable_string.buffer, backtrack_printable_string.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.setHasExtraData, "when decoding non-extensible SET PDSParameter there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1Integer extended_network_address(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 22 */ 0x16, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct ExtendedNetworkAddress_e163_4_address
{
    private
    {
        bool _isSet_number;
        asn1.Asn1NumericString _number;
        bool _isSet_sub_address;
        asn1.Asn1NumericString _sub_address;
    }

    jres.Result setNumber(
        typeof(_number) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_number = true;
        _number = value;
        return jres.Result.noError;
    }

    typeof(_number) getNumber(
    ) @nogc nothrow
    {
        assert(_isSet_number, "Non-optional field 'number' has not been set yet - please use validate() to check!");
        return _number;
    }

    jres.Result setSub_address(
        typeof(_sub_address) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_sub_address = true;
        _sub_address = value;
        return jres.Result.noError;
    }

    jres.Result setSub_address(
        tcon.Nullable!(asn1.Asn1NumericString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setSub_address(value.get());
        }
        else
            _isSet_sub_address = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1NumericString) getSub_address(
    ) @nogc nothrow
    {
        if(_isSet_sub_address)
            return typeof(return)(_sub_address);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_number)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedNetworkAddress-e163-4-address non-optional field 'number' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("number: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_number), "toString"))
            _number.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("sub-address: ");
        sink("\n");
        if(_isSet_sub_address)
        {
            static if(__traits(hasMember, typeof(_sub_address), "toString"))
                _sub_address.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: number +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'number' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedNetworkAddress-e163-4-address when reading top level tag 0 for field 'number' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedNetworkAddress-e163-4-address when reading top level tag 0 for field 'number' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_number;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_number);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'number' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - number ++/
        typeof(_number) temp_number;
        result = typeof(temp_number).fromDecoding!ruleset(memory_number, temp_number, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'number' in type "~__traits(identifier, typeof(this))~":");
        result = this.setNumber(temp_number);
        if(result.isError)
            return result.wrapError("when setting field 'number' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: sub-address +++/
        auto backtrack_sub_address = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'sub-address' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_sub_address;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_sub_address);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'sub-address' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - sub-address ++/
                typeof(_sub_address) temp_sub_address;
                result = typeof(temp_sub_address).fromDecoding!ruleset(memory_sub_address, temp_sub_address, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'sub_address' in type "~__traits(identifier, typeof(this))~":");
                result = this.setSub_address(temp_sub_address);
                if(result.isError)
                    return result.wrapError("when setting field 'sub_address' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_sub_address.buffer, backtrack_sub_address.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ExtendedNetworkAddress-e163-4-address there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ExtendedNetworkAddress
{
    enum Choice
    {
        _FAILSAFE,
        e163_4_address,
        psap_address,
    }

    union Value
    {
        .ExtendedNetworkAddress_e163_4_address e163_4_address;
        .PresentationAddress psap_address;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.ExtendedNetworkAddress_e163_4_address), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.PresentationAddress), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.e163_4_address)) @nogc nothrow handle_e163_4_address,
        scope jres.Result delegate(typeof(Value.psap_address)) @nogc nothrow handle_psap_address,
    ) @nogc nothrow
    {
        if(_choice == Choice.e163_4_address)
            return handle_e163_4_address(_value.e163_4_address);
        if(_choice == Choice.psap_address)
            return handle_psap_address(_value.psap_address);
        assert(false, "attempted to use an uninitialised ExtendedNetworkAddress!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.e163_4_address))  handle_e163_4_address,
        scope jres.Result delegate(typeof(Value.psap_address))  handle_psap_address,
    ) 
    {
        if(_choice == Choice.e163_4_address)
            return handle_e163_4_address(_value.e163_4_address);
        if(_choice == Choice.psap_address)
            return handle_psap_address(_value.psap_address);
        assert(false, "attempted to use an uninitialised ExtendedNetworkAddress!");

    }

    jres.Result setE163_4_address(
        typeof(Value.e163_4_address) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.e163_4_address = value;
        _choice = Choice.e163_4_address;
        return jres.Result.noError;
    }

    typeof(Value.e163_4_address) getE163_4_address(
    ) @nogc nothrow
    {
        assert(_choice == Choice.e163_4_address, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'e163_4_address'");
        return _value.e163_4_address;
    }

    bool isE163_4_address(
    ) @nogc nothrow const
    {
        return _choice == Choice.e163_4_address;
    }

    jres.Result setPsap_address(
        typeof(Value.psap_address) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.psap_address = value;
        _choice = Choice.psap_address;
        return jres.Result.noError;
    }

    typeof(Value.psap_address) getPsap_address(
    ) @nogc nothrow
    {
        assert(_choice == Choice.psap_address, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'psap_address'");
        return _value.psap_address;
    }

    bool isPsap_address(
    ) @nogc nothrow const
    {
        return _choice == Choice.psap_address;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 16)
        {
            /++ FIELD - e163-4-address ++/
            typeof(Value.e163_4_address) temp_e163_4_address;
            result = temp_e163_4_address.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'e163_4_address' in type "~__traits(identifier, typeof(this))~":");
            result = this.setE163_4_address(temp_e163_4_address);
            if(result.isError)
                return result.wrapError("when setting field 'e163_4_address' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - psap-address ++/
            typeof(Value.psap_address) temp_psap_address;
            result = temp_psap_address.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'psap_address' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPsap_address(temp_psap_address);
            if(result.isError)
                return result.wrapError("when setting field 'psap_address' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type ExtendedNetworkAddress the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isE163_4_address)
        {
            depth++;
            putIndent();
            sink("e163-4-address: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getE163_4_address()), "toString"))
                _value.e163_4_address.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isPsap_address)
        {
            depth++;
            putIndent();
            sink("psap-address: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPsap_address()), "toString"))
                _value.psap_address.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct PresentationAddress
{
    private
    {
        bool _isSet_pSelector;
        asn1.Asn1OctetString _pSelector;
        bool _isSet_sSelector;
        asn1.Asn1OctetString _sSelector;
        bool _isSet_tSelector;
        asn1.Asn1OctetString _tSelector;
        bool _isSet_nAddresses;
        asn1.Asn1SetOf!(asn1.Asn1OctetString) _nAddresses;
    }

    jres.Result setPSelector(
        typeof(_pSelector) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_pSelector = true;
        _pSelector = value;
        return jres.Result.noError;
    }

    jres.Result setPSelector(
        tcon.Nullable!(asn1.Asn1OctetString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setPSelector(value.get());
        }
        else
            _isSet_pSelector = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1OctetString) getPSelector(
    ) @nogc nothrow
    {
        if(_isSet_pSelector)
            return typeof(return)(_pSelector);
        return typeof(return).init;
    }

    jres.Result setSSelector(
        typeof(_sSelector) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_sSelector = true;
        _sSelector = value;
        return jres.Result.noError;
    }

    jres.Result setSSelector(
        tcon.Nullable!(asn1.Asn1OctetString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setSSelector(value.get());
        }
        else
            _isSet_sSelector = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1OctetString) getSSelector(
    ) @nogc nothrow
    {
        if(_isSet_sSelector)
            return typeof(return)(_sSelector);
        return typeof(return).init;
    }

    jres.Result setTSelector(
        typeof(_tSelector) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_tSelector = true;
        _tSelector = value;
        return jres.Result.noError;
    }

    jres.Result setTSelector(
        tcon.Nullable!(asn1.Asn1OctetString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setTSelector(value.get());
        }
        else
            _isSet_tSelector = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1OctetString) getTSelector(
    ) @nogc nothrow
    {
        if(_isSet_tSelector)
            return typeof(return)(_tSelector);
        return typeof(return).init;
    }

    jres.Result setNAddresses(
        typeof(_nAddresses) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_nAddresses = true;
        _nAddresses = value;
        return jres.Result.noError;
    }

    typeof(_nAddresses) getNAddresses(
    ) @nogc nothrow
    {
        assert(_isSet_nAddresses, "Non-optional field 'nAddresses' has not been set yet - please use validate() to check!");
        return _nAddresses;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_nAddresses)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PresentationAddress non-optional field 'nAddresses' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("pSelector: ");
        sink("\n");
        if(_isSet_pSelector)
        {
            static if(__traits(hasMember, typeof(_pSelector), "toString"))
                _pSelector.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("sSelector: ");
        sink("\n");
        if(_isSet_sSelector)
        {
            static if(__traits(hasMember, typeof(_sSelector), "toString"))
                _sSelector.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("tSelector: ");
        sink("\n");
        if(_isSet_tSelector)
        {
            static if(__traits(hasMember, typeof(_tSelector), "toString"))
                _tSelector.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("nAddresses: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_nAddresses), "toString"))
            _nAddresses.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: pSelector +++/
        auto backtrack_pSelector = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'pSelector' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_pSelector;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_pSelector);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'pSelector' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - pSelector ++/
                jbuf.MemoryReader memory_0pSelector;
                    // EXPLICIT TAG - 0
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field pSelector a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'pSelector' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 0)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'pSelector' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_pSelector, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'pSelector' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_pSelector, componentHeader.length, memory_0pSelector);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'pSelector' in type "~__traits(identifier, typeof(this))~":");
                typeof(_pSelector) temp_pSelector;
                result = typeof(temp_pSelector).fromDecoding!ruleset(memory_0pSelector, temp_pSelector, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'pSelector' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPSelector(temp_pSelector);
                if(result.isError)
                    return result.wrapError("when setting field 'pSelector' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_pSelector.buffer, backtrack_pSelector.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: sSelector +++/
        auto backtrack_sSelector = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'sSelector' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_sSelector;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_sSelector);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'sSelector' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - sSelector ++/
                jbuf.MemoryReader memory_0sSelector;
                    // EXPLICIT TAG - 1
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 1 for field sSelector a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 1 for field 'sSelector' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 1)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 1 for field 'sSelector' the tag's value was expected to be 1", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_sSelector, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'sSelector' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_sSelector, componentHeader.length, memory_0sSelector);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'sSelector' in type "~__traits(identifier, typeof(this))~":");
                typeof(_sSelector) temp_sSelector;
                result = typeof(temp_sSelector).fromDecoding!ruleset(memory_0sSelector, temp_sSelector, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'sSelector' in type "~__traits(identifier, typeof(this))~":");
                result = this.setSSelector(temp_sSelector);
                if(result.isError)
                    return result.wrapError("when setting field 'sSelector' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_sSelector.buffer, backtrack_sSelector.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: tSelector +++/
        auto backtrack_tSelector = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'tSelector' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_tSelector;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_tSelector);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'tSelector' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - tSelector ++/
                jbuf.MemoryReader memory_0tSelector;
                    // EXPLICIT TAG - 2
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 2 for field tSelector a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 2 for field 'tSelector' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 2)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 2 for field 'tSelector' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_tSelector, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'tSelector' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_tSelector, componentHeader.length, memory_0tSelector);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'tSelector' in type "~__traits(identifier, typeof(this))~":");
                typeof(_tSelector) temp_tSelector;
                result = typeof(temp_tSelector).fromDecoding!ruleset(memory_0tSelector, temp_tSelector, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'tSelector' in type "~__traits(identifier, typeof(this))~":");
                result = this.setTSelector(temp_tSelector);
                if(result.isError)
                    return result.wrapError("when setting field 'tSelector' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_tSelector.buffer, backtrack_tSelector.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: nAddresses +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PresentationAddress when reading top level tag 3 for field 'nAddresses' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PresentationAddress when reading top level tag 3 for field 'nAddresses' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_nAddresses;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_nAddresses);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - nAddresses ++/
        jbuf.MemoryReader memory_0nAddresses;
            // EXPLICIT TAG - 3
            if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 3 for field nAddresses a primitive tag was found when a constructed one was expected");
            if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 3 for field 'nAddresses' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
            if(componentHeader.identifier.tag != 3)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 3 for field 'nAddresses' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
            result = asn1.asn1DecodeComponentHeader!ruleset(memory_nAddresses, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");
            result = asn1.asn1ReadContentBytes(memory_nAddresses, componentHeader.length, memory_0nAddresses);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");
        typeof(_nAddresses) temp_nAddresses;
        result = typeof(temp_nAddresses).fromDecoding!ruleset(memory_0nAddresses, temp_nAddresses, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");
        result = this.setNAddresses(temp_nAddresses);
        if(result.isError)
            return result.wrapError("when setting field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");

        result = this._nAddresses.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SET OF field 'nAddresses' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PresentationAddress there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1Integer terminal_type(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 23 */ 0x17, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

struct TerminalType
{
    enum NamedNumber
    {
        telex = 3,
        teletex = 4,
        ia5_terminal = 7,
        g3_facsimile = 5,
        videotex = 8,
        g4_facsimile = 6,
    }
    private
    {
        asn1.Asn1Integer _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Integer newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            long _integer__value;
            result = newValue.asInt!long(_integer__value);
            if(result.isError)
                return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _integer__value >= 0 && _integer__value <= 256;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Integer get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Integer, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

        return jres.Result.noError;
    }

}

asn1.Asn1Integer teletex_domain_defined_attributes(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 6 */ 0x6, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 32768 */ 0x80, 0x0, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_common_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_locality_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 128 */ 0x80, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_state_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 128 */ 0x80, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_organization_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_organizational_unit_name(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_title(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_serial_number(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_match(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 128 */ 0x80, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_emailaddress_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 255 */ 0xFF, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_common_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_country_name_alpha_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 2 */ 0x2, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_country_name_numeric_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 3 */ 0x3, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_domain_defined_attributes(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 4 */ 0x4, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_domain_defined_attribute_type_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 8 */ 0x8, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_domain_defined_attribute_value_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 128 */ 0x80, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_domain_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 16 */ 0x10, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_extension_attributes(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 256 */ 0x1, 0x0, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_e163_4_number_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 15 */ 0xF, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_e163_4_sub_address_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 40 */ 0x28, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_generation_qualifier_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 3 */ 0x3, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_given_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 16 */ 0x10, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_initials_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 5 */ 0x5, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_integer_options(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 256 */ 0x1, 0x0, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_numeric_user_id_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 32 */ 0x20, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_organization_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 64 */ 0x40, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_organizational_unit_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 32 */ 0x20, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_organizational_units(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 4 */ 0x4, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_pds_name_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 16 */ 0x10, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_pds_parameter_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 30 */ 0x1E, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_pds_physical_address_lines(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 6 */ 0x6, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_postal_code_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 16 */ 0x10, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_pseudonym(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 128 */ 0x80, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_surname_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 40 */ 0x28, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_terminal_id_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 24 */ 0x18, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_unformatted_address_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 180 */ 0xB4, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}

asn1.Asn1Integer ub_x121_address_length(
) @nogc nothrow
{
    asn1.Asn1Integer mainValue;
    static immutable ubyte[] mainValue__underlying = [
        /* 16 */ 0x10, 
    ];
    mainValue = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying);
    return mainValue;

}
