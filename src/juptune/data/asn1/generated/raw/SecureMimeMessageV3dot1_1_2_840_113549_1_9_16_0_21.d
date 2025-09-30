module juptune.data.asn1.generated.raw.SecureMimeMessageV3dot1_1_2_840_113549_1_9_16_0_21;
static import CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14 = juptune.data.asn1.generated.raw.CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14;

static import tcon = std.typecons;
static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier id_aa(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 16, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier smimeCapabilities(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 15, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct SMIMECapability
{
    private
    {
        bool _isSet_capabilityID;
        asn1.Asn1ObjectIdentifier _capabilityID;
        bool _isSet_parameters;
        asn1.Asn1Any _parameters;
    }

    jres.Result setCapabilityID(
        typeof(_capabilityID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_capabilityID = true;
        _capabilityID = value;
        return jres.Result.noError;
    }

    typeof(_capabilityID) getCapabilityID(
    ) @nogc nothrow
    {
        assert(_isSet_capabilityID, "Non-optional field 'capabilityID' has not been set yet - please use validate() to check!");
        return _capabilityID;
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
        if(!_isSet_capabilityID)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SMIMECapability non-optional field 'capabilityID' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("capabilityID: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_capabilityID), "toString"))
            _capabilityID.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: capabilityID +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'capabilityID' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SMIMECapability when reading top level tag 6 for field 'capabilityID' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SMIMECapability when reading top level tag 6 for field 'capabilityID' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_capabilityID;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_capabilityID);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'capabilityID' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - capabilityID ++/
        typeof(_capabilityID) temp_capabilityID;
        result = typeof(temp_capabilityID).fromDecoding!ruleset(memory_capabilityID, temp_capabilityID, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'capabilityID' in type "~__traits(identifier, typeof(this))~":");
        result = this.setCapabilityID(temp_capabilityID);
        if(result.isError)
            return result.wrapError("when setting field 'capabilityID' in type "~__traits(identifier, typeof(this))~":");

        
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
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE SMIMECapability there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SMIMECapabilities
{
    private
    {
        asn1.Asn1SequenceOf!(.SMIMECapability) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.SMIMECapability) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.SMIMECapability) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.SMIMECapability), "toString"))
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

asn1.Asn1ObjectIdentifier id_aa_encrypKeyPref(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 16, 2, 11, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct SMIMEEncryptionKeyPreference
{
    enum Choice
    {
        _FAILSAFE,
        issuerAndSerialNumber,
        receipentKeyId,
        subjectAltKeyIdentifier,
    }

    union Value
    {
        CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.IssuerAndSerialNumber issuerAndSerialNumber;
        CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.RecipientKeyIdentifier receipentKeyId;
        CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.SubjectKeyIdentifier subjectAltKeyIdentifier;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.IssuerAndSerialNumber), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.RecipientKeyIdentifier), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.SubjectKeyIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber)) @nogc nothrow handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.receipentKeyId)) @nogc nothrow handle_receipentKeyId,
        scope jres.Result delegate(typeof(Value.subjectAltKeyIdentifier)) @nogc nothrow handle_subjectAltKeyIdentifier,
    ) @nogc nothrow
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.receipentKeyId)
            return handle_receipentKeyId(_value.receipentKeyId);
        if(_choice == Choice.subjectAltKeyIdentifier)
            return handle_subjectAltKeyIdentifier(_value.subjectAltKeyIdentifier);
        assert(false, "attempted to use an uninitialised SMIMEEncryptionKeyPreference!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber))  handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.receipentKeyId))  handle_receipentKeyId,
        scope jres.Result delegate(typeof(Value.subjectAltKeyIdentifier))  handle_subjectAltKeyIdentifier,
    ) 
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.receipentKeyId)
            return handle_receipentKeyId(_value.receipentKeyId);
        if(_choice == Choice.subjectAltKeyIdentifier)
            return handle_subjectAltKeyIdentifier(_value.subjectAltKeyIdentifier);
        assert(false, "attempted to use an uninitialised SMIMEEncryptionKeyPreference!");

    }

    jres.Result setIssuerAndSerialNumber(
        typeof(Value.issuerAndSerialNumber) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.issuerAndSerialNumber = value;
        _choice = Choice.issuerAndSerialNumber;
        return jres.Result.noError;
    }

    typeof(Value.issuerAndSerialNumber) getIssuerAndSerialNumber(
    ) @nogc nothrow
    {
        assert(_choice == Choice.issuerAndSerialNumber, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'issuerAndSerialNumber'");
        return _value.issuerAndSerialNumber;
    }

    bool isIssuerAndSerialNumber(
    ) @nogc nothrow const
    {
        return _choice == Choice.issuerAndSerialNumber;
    }

    jres.Result setReceipentKeyId(
        typeof(Value.receipentKeyId) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.receipentKeyId = value;
        _choice = Choice.receipentKeyId;
        return jres.Result.noError;
    }

    typeof(Value.receipentKeyId) getReceipentKeyId(
    ) @nogc nothrow
    {
        assert(_choice == Choice.receipentKeyId, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'receipentKeyId'");
        return _value.receipentKeyId;
    }

    bool isReceipentKeyId(
    ) @nogc nothrow const
    {
        return _choice == Choice.receipentKeyId;
    }

    jres.Result setSubjectAltKeyIdentifier(
        typeof(Value.subjectAltKeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.subjectAltKeyIdentifier = value;
        _choice = Choice.subjectAltKeyIdentifier;
        return jres.Result.noError;
    }

    typeof(Value.subjectAltKeyIdentifier) getSubjectAltKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_choice == Choice.subjectAltKeyIdentifier, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'subjectAltKeyIdentifier'");
        return _value.subjectAltKeyIdentifier;
    }

    bool isSubjectAltKeyIdentifier(
    ) @nogc nothrow const
    {
        return _choice == Choice.subjectAltKeyIdentifier;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - issuerAndSerialNumber ++/
            typeof(Value.issuerAndSerialNumber) temp_issuerAndSerialNumber;
            result = temp_issuerAndSerialNumber.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'issuerAndSerialNumber' in type "~__traits(identifier, typeof(this))~":");
            result = this.setIssuerAndSerialNumber(temp_issuerAndSerialNumber);
            if(result.isError)
                return result.wrapError("when setting field 'issuerAndSerialNumber' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 1)
        {
            /++ FIELD - receipentKeyId ++/
            typeof(Value.receipentKeyId) temp_receipentKeyId;
            result = temp_receipentKeyId.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'receipentKeyId' in type "~__traits(identifier, typeof(this))~":");
            result = this.setReceipentKeyId(temp_receipentKeyId);
            if(result.isError)
                return result.wrapError("when setting field 'receipentKeyId' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 2)
        {
            /++ FIELD - subjectAltKeyIdentifier ++/
            typeof(Value.subjectAltKeyIdentifier) temp_subjectAltKeyIdentifier;
            result = temp_subjectAltKeyIdentifier.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'subjectAltKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
            result = this.setSubjectAltKeyIdentifier(temp_subjectAltKeyIdentifier);
            if(result.isError)
                return result.wrapError("when setting field 'subjectAltKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type SMIMEEncryptionKeyPreference the identifier tag & class were unable to match any known option");
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
        if(isIssuerAndSerialNumber)
        {
            depth++;
            putIndent();
            sink("issuerAndSerialNumber: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getIssuerAndSerialNumber()), "toString"))
                _value.issuerAndSerialNumber.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isReceipentKeyId)
        {
            depth++;
            putIndent();
            sink("receipentKeyId: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getReceipentKeyId()), "toString"))
                _value.receipentKeyId.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isSubjectAltKeyIdentifier)
        {
            depth++;
            putIndent();
            sink("subjectAltKeyIdentifier: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getSubjectAltKeyIdentifier()), "toString"))
                _value.subjectAltKeyIdentifier.toString(sink, depth+1);
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

asn1.Asn1ObjectIdentifier id_smime(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 16, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_cap(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 16, 11, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_cap_preferBinaryInside(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 16, 11, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct SMIMECapabilitiesParametersForRC2CBC
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
