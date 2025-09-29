module juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19;
static import PKIX1Explicit88_1_3_6_1_5_5_7_0_18 = juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;

static import tcon = std.typecons;
static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier id_ce(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ce_authorityKeyIdentifier(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 35, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct AuthorityKeyIdentifier
{
    private
    {
        bool _isSet_keyIdentifier;
        .KeyIdentifier _keyIdentifier;
        bool _isSet_authorityCertIssuer;
        .GeneralNames _authorityCertIssuer;
        bool _isSet_authorityCertSerialNumber;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateSerialNumber _authorityCertSerialNumber;
    }

    jres.Result setKeyIdentifier(
        typeof(_keyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyIdentifier = true;
        _keyIdentifier = value;
        return jres.Result.noError;
    }

    jres.Result setKeyIdentifier(
        tcon.Nullable!(.KeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setKeyIdentifier(value.get());
        }
        else
            _isSet_keyIdentifier = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.KeyIdentifier) getKeyIdentifier(
    ) @nogc nothrow
    {
        if(_isSet_keyIdentifier)
            return typeof(return)(_keyIdentifier);
        return typeof(return).init;
    }

    jres.Result setAuthorityCertIssuer(
        typeof(_authorityCertIssuer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_authorityCertIssuer = true;
        _authorityCertIssuer = value;
        return jres.Result.noError;
    }

    jres.Result setAuthorityCertIssuer(
        tcon.Nullable!(.GeneralNames) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setAuthorityCertIssuer(value.get());
        }
        else
            _isSet_authorityCertIssuer = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.GeneralNames) getAuthorityCertIssuer(
    ) @nogc nothrow
    {
        if(_isSet_authorityCertIssuer)
            return typeof(return)(_authorityCertIssuer);
        return typeof(return).init;
    }

    jres.Result setAuthorityCertSerialNumber(
        typeof(_authorityCertSerialNumber) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_authorityCertSerialNumber = true;
        _authorityCertSerialNumber = value;
        return jres.Result.noError;
    }

    jres.Result setAuthorityCertSerialNumber(
        tcon.Nullable!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateSerialNumber) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setAuthorityCertSerialNumber(value.get());
        }
        else
            _isSet_authorityCertSerialNumber = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateSerialNumber) getAuthorityCertSerialNumber(
    ) @nogc nothrow
    {
        if(_isSet_authorityCertSerialNumber)
            return typeof(return)(_authorityCertSerialNumber);
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
        sink("keyIdentifier: ");
        sink("\n");
        if(_isSet_keyIdentifier)
        {
            static if(__traits(hasMember, typeof(_keyIdentifier), "toString"))
                _keyIdentifier.toString(sink, depth+1);
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
        sink("authorityCertIssuer: ");
        sink("\n");
        if(_isSet_authorityCertIssuer)
        {
            static if(__traits(hasMember, typeof(_authorityCertIssuer), "toString"))
                _authorityCertIssuer.toString(sink, depth+1);
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
        sink("authorityCertSerialNumber: ");
        sink("\n");
        if(_isSet_authorityCertSerialNumber)
        {
            static if(__traits(hasMember, typeof(_authorityCertSerialNumber), "toString"))
                _authorityCertSerialNumber.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: keyIdentifier +++/
        auto backtrack_keyIdentifier = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_keyIdentifier;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyIdentifier);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - keyIdentifier ++/
                typeof(_keyIdentifier) temp_keyIdentifier;
                result = temp_keyIdentifier.fromDecoding!ruleset(memory_keyIdentifier, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
                result = this.setKeyIdentifier(temp_keyIdentifier);
                if(result.isError)
                    return result.wrapError("when setting field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_keyIdentifier.buffer, backtrack_keyIdentifier.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: authorityCertIssuer +++/
        auto backtrack_authorityCertIssuer = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'authorityCertIssuer' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_authorityCertIssuer;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_authorityCertIssuer);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'authorityCertIssuer' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - authorityCertIssuer ++/
                typeof(_authorityCertIssuer) temp_authorityCertIssuer;
                result = temp_authorityCertIssuer.fromDecoding!ruleset(memory_authorityCertIssuer, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'authorityCertIssuer' in type "~__traits(identifier, typeof(this))~":");
                result = this.setAuthorityCertIssuer(temp_authorityCertIssuer);
                if(result.isError)
                    return result.wrapError("when setting field 'authorityCertIssuer' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_authorityCertIssuer.buffer, backtrack_authorityCertIssuer.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: authorityCertSerialNumber +++/
        auto backtrack_authorityCertSerialNumber = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'authorityCertSerialNumber' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_authorityCertSerialNumber;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_authorityCertSerialNumber);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'authorityCertSerialNumber' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - authorityCertSerialNumber ++/
                typeof(_authorityCertSerialNumber) temp_authorityCertSerialNumber;
                result = temp_authorityCertSerialNumber.fromDecoding!ruleset(memory_authorityCertSerialNumber, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'authorityCertSerialNumber' in type "~__traits(identifier, typeof(this))~":");
                result = this.setAuthorityCertSerialNumber(temp_authorityCertSerialNumber);
                if(result.isError)
                    return result.wrapError("when setting field 'authorityCertSerialNumber' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_authorityCertSerialNumber.buffer, backtrack_authorityCertSerialNumber.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AuthorityKeyIdentifier there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct KeyIdentifier
{
    private
    {
        asn1.Asn1OctetString _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1OctetString newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1OctetString get(
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
        static if(__traits(hasMember, asn1.Asn1OctetString, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_subjectKeyIdentifier(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 14, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct SubjectKeyIdentifier
{
    private
    {
        .KeyIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        .KeyIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .KeyIdentifier get(
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
        static if(__traits(hasMember, .KeyIdentifier, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_keyUsage(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 15, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct KeyUsage
{
    enum NamedBit
    {
        digitalSignature = 0,
        encipherOnly = 7,
        keyAgreement = 4,
        decipherOnly = 8,
        dataEncipherment = 3,
        keyCertSign = 5,
        cRLSign = 6,
        keyEncipherment = 2,
        nonRepudiation = 1,
    }
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

asn1.Asn1ObjectIdentifier id_ce_certificatePolicies(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 32, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier anyPolicy(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 32, 0, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct CertificatePolicies
{
    private
    {
        asn1.Asn1SequenceOf!(.PolicyInformation) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.PolicyInformation) newValue,
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

    asn1.Asn1SequenceOf!(.PolicyInformation) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.PolicyInformation), "toString"))
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

struct PolicyInformation
{
    private
    {
        bool _isSet_policyIdentifier;
        .CertPolicyId _policyIdentifier;
        bool _isSet_policyQualifiers;
        asn1.Asn1SequenceOf!(.PolicyQualifierInfo) _policyQualifiers;
    }

    jres.Result setPolicyIdentifier(
        typeof(_policyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_policyIdentifier = true;
        _policyIdentifier = value;
        return jres.Result.noError;
    }

    typeof(_policyIdentifier) getPolicyIdentifier(
    ) @nogc nothrow
    {
        assert(_isSet_policyIdentifier, "Non-optional field 'policyIdentifier' has not been set yet - please use validate() to check!");
        return _policyIdentifier;
    }

    jres.Result setPolicyQualifiers(
        typeof(_policyQualifiers) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.elementCount >= 1 && value.elementCount <= 18446744073709551615;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _isSet_policyQualifiers = true;
        _policyQualifiers = value;
        return jres.Result.noError;
    }

    jres.Result setPolicyQualifiers(
        tcon.Nullable!(asn1.Asn1SequenceOf!(.PolicyQualifierInfo)) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            bool _successFlag;
            _successFlag = value.get.elementCount >= 1 && value.get.elementCount <= 18446744073709551615;
            if(!_successFlag)
                return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
            return setPolicyQualifiers(value.get());
        }
        else
            _isSet_policyQualifiers = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1SequenceOf!(.PolicyQualifierInfo)) getPolicyQualifiers(
    ) @nogc nothrow
    {
        if(_isSet_policyQualifiers)
            return typeof(return)(_policyQualifiers);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_policyIdentifier)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PolicyInformation non-optional field 'policyIdentifier' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("policyIdentifier: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_policyIdentifier), "toString"))
            _policyIdentifier.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("policyQualifiers: ");
        sink("\n");
        if(_isSet_policyQualifiers)
        {
            static if(__traits(hasMember, typeof(_policyQualifiers), "toString"))
                _policyQualifiers.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: policyIdentifier +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'policyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PolicyInformation when reading top level tag 6 for field 'policyIdentifier' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PolicyInformation when reading top level tag 6 for field 'policyIdentifier' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_policyIdentifier;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_policyIdentifier);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'policyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - policyIdentifier ++/
        typeof(_policyIdentifier) temp_policyIdentifier;
        result = temp_policyIdentifier.fromDecoding!ruleset(memory_policyIdentifier, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'policyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPolicyIdentifier(temp_policyIdentifier);
        if(result.isError)
            return result.wrapError("when setting field 'policyIdentifier' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: policyQualifiers +++/
        auto backtrack_policyQualifiers = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'policyQualifiers' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_policyQualifiers;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_policyQualifiers);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'policyQualifiers' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - policyQualifiers ++/
                typeof(_policyQualifiers) temp_policyQualifiers;
                result = typeof(temp_policyQualifiers).fromDecoding!ruleset(memory_policyQualifiers, temp_policyQualifiers, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'policyQualifiers' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPolicyQualifiers(temp_policyQualifiers);
                if(result.isError)
                    return result.wrapError("when setting field 'policyQualifiers' in type "~__traits(identifier, typeof(this))~":");

                result = this._policyQualifiers.foreachElementAuto((element) => jres.Result.noError);
                if(result.isError)
                    return result.wrapError("when decoding subelements of SEQEUENCE OF field 'policyQualifiers' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_policyQualifiers.buffer, backtrack_policyQualifiers.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PolicyInformation there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct CertPolicyId
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

struct PolicyQualifierInfo
{
    private
    {
        bool _isSet_policyQualifierId;
        .PolicyQualifierId _policyQualifierId;
        bool _isSet_qualifier;
        asn1.Asn1OctetString _qualifier;
    }

    jres.Result setPolicyQualifierId(
        typeof(_policyQualifierId) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_policyQualifierId = true;
        _policyQualifierId = value;
        return jres.Result.noError;
    }

    typeof(_policyQualifierId) getPolicyQualifierId(
    ) @nogc nothrow
    {
        assert(_isSet_policyQualifierId, "Non-optional field 'policyQualifierId' has not been set yet - please use validate() to check!");
        return _policyQualifierId;
    }

    jres.Result setQualifier(
        typeof(_qualifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_qualifier = true;
        _qualifier = value;
        return jres.Result.noError;
    }

    typeof(_qualifier) getQualifier(
    ) @nogc nothrow
    {
        assert(_isSet_qualifier, "Non-optional field 'qualifier' has not been set yet - please use validate() to check!");
        return _qualifier;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_policyQualifierId)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PolicyQualifierInfo non-optional field 'policyQualifierId' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_qualifier)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PolicyQualifierInfo non-optional field 'qualifier' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("policyQualifierId: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_policyQualifierId), "toString"))
            _policyQualifierId.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("qualifier: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_qualifier), "toString"))
            _qualifier.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: policyQualifierId +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'policyQualifierId' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PolicyQualifierInfo when reading top level tag 6 for field 'policyQualifierId' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PolicyQualifierInfo when reading top level tag 6 for field 'policyQualifierId' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_policyQualifierId;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_policyQualifierId);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'policyQualifierId' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - policyQualifierId ++/
        typeof(_policyQualifierId) temp_policyQualifierId;
        result = temp_policyQualifierId.fromDecoding!ruleset(memory_policyQualifierId, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'policyQualifierId' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPolicyQualifierId(temp_policyQualifierId);
        if(result.isError)
            return result.wrapError("when setting field 'policyQualifierId' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: qualifier +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'qualifier' in type "~__traits(identifier, typeof(this))~":");
        // Field is the intrinsic ANY type - any tag is allowed.
        jbuf.MemoryReader memory_qualifier;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_qualifier);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'qualifier' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - qualifier ++/
        typeof(_qualifier) temp_qualifier;
        result = typeof(temp_qualifier).fromDecoding!ruleset(memory_qualifier, temp_qualifier, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'qualifier' in type "~__traits(identifier, typeof(this))~":");
        result = this.setQualifier(temp_qualifier);
        if(result.isError)
            return result.wrapError("when setting field 'qualifier' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PolicyQualifierInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct PolicyQualifierId
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

struct CPSuri
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

struct UserNotice
{
    private
    {
        bool _isSet_noticeRef;
        .NoticeReference _noticeRef;
        bool _isSet_explicitText;
        .DisplayText _explicitText;
    }

    jres.Result setNoticeRef(
        typeof(_noticeRef) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_noticeRef = true;
        _noticeRef = value;
        return jres.Result.noError;
    }

    jres.Result setNoticeRef(
        tcon.Nullable!(.NoticeReference) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setNoticeRef(value.get());
        }
        else
            _isSet_noticeRef = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.NoticeReference) getNoticeRef(
    ) @nogc nothrow
    {
        if(_isSet_noticeRef)
            return typeof(return)(_noticeRef);
        return typeof(return).init;
    }

    jres.Result setExplicitText(
        typeof(_explicitText) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_explicitText = true;
        _explicitText = value;
        return jres.Result.noError;
    }

    jres.Result setExplicitText(
        tcon.Nullable!(.DisplayText) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setExplicitText(value.get());
        }
        else
            _isSet_explicitText = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.DisplayText) getExplicitText(
    ) @nogc nothrow
    {
        if(_isSet_explicitText)
            return typeof(return)(_explicitText);
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
        sink("noticeRef: ");
        sink("\n");
        if(_isSet_noticeRef)
        {
            static if(__traits(hasMember, typeof(_noticeRef), "toString"))
                _noticeRef.toString(sink, depth+1);
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
        sink("explicitText: ");
        sink("\n");
        if(_isSet_explicitText)
        {
            static if(__traits(hasMember, typeof(_explicitText), "toString"))
                _explicitText.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: noticeRef +++/
        auto backtrack_noticeRef = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'noticeRef' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_noticeRef;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_noticeRef);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'noticeRef' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - noticeRef ++/
                typeof(_noticeRef) temp_noticeRef;
                result = temp_noticeRef.fromDecoding!ruleset(memory_noticeRef, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'noticeRef' in type "~__traits(identifier, typeof(this))~":");
                result = this.setNoticeRef(temp_noticeRef);
                if(result.isError)
                    return result.wrapError("when setting field 'noticeRef' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_noticeRef.buffer, backtrack_noticeRef.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: explicitText +++/
        auto backtrack_explicitText = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'explicitText' in type "~__traits(identifier, typeof(this))~":");
            jbuf.MemoryReader memory_explicitText;
            result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_explicitText);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'explicitText' in type "~__traits(identifier, typeof(this))~":");
            result = (){ // Field is OPTIONAL and has a variable starting tag
                /++ FIELD - explicitText ++/
                typeof(_explicitText) temp_explicitText;
                result = temp_explicitText.fromDecoding!ruleset(memory_explicitText, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'explicitText' in type "~__traits(identifier, typeof(this))~":");
                result = this.setExplicitText(temp_explicitText);
                if(result.isError)
                    return result.wrapError("when setting field 'explicitText' in type "~__traits(identifier, typeof(this))~":");

                return jres.Result.noError;
            }();
            if(result.isError(asn1.Asn1DecodeError.choiceHasNoMatch))
                memory = jbuf.MemoryReader(backtrack_explicitText.buffer, backtrack_explicitText.cursor);
            else if(result.isError)
                return result.wrapError("For "~__traits(identifier, typeof(this))~":");
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE UserNotice there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct NoticeReference
{
    private
    {
        bool _isSet_organization;
        .DisplayText _organization;
        bool _isSet_noticeNumbers;
        asn1.Asn1SequenceOf!(asn1.Asn1Integer) _noticeNumbers;
    }

    jres.Result setOrganization(
        typeof(_organization) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_organization = true;
        _organization = value;
        return jres.Result.noError;
    }

    typeof(_organization) getOrganization(
    ) @nogc nothrow
    {
        assert(_isSet_organization, "Non-optional field 'organization' has not been set yet - please use validate() to check!");
        return _organization;
    }

    jres.Result setNoticeNumbers(
        typeof(_noticeNumbers) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_noticeNumbers = true;
        _noticeNumbers = value;
        return jres.Result.noError;
    }

    typeof(_noticeNumbers) getNoticeNumbers(
    ) @nogc nothrow
    {
        assert(_isSet_noticeNumbers, "Non-optional field 'noticeNumbers' has not been set yet - please use validate() to check!");
        return _noticeNumbers;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_organization)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type NoticeReference non-optional field 'organization' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_noticeNumbers)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type NoticeReference non-optional field 'noticeNumbers' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("organization: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_organization), "toString"))
            _organization.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("noticeNumbers: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_noticeNumbers), "toString"))
            _noticeNumbers.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: organization +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'organization' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_organization;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_organization);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'organization' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - organization ++/
        typeof(_organization) temp_organization;
        result = temp_organization.fromDecoding!ruleset(memory_organization, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'organization' in type "~__traits(identifier, typeof(this))~":");
        result = this.setOrganization(temp_organization);
        if(result.isError)
            return result.wrapError("when setting field 'organization' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: noticeNumbers +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'noticeNumbers' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE NoticeReference when reading top level tag 16 for field 'noticeNumbers' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE NoticeReference when reading top level tag 16 for field 'noticeNumbers' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_noticeNumbers;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_noticeNumbers);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'noticeNumbers' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - noticeNumbers ++/
        typeof(_noticeNumbers) temp_noticeNumbers;
        result = typeof(temp_noticeNumbers).fromDecoding!ruleset(memory_noticeNumbers, temp_noticeNumbers, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'noticeNumbers' in type "~__traits(identifier, typeof(this))~":");
        result = this.setNoticeNumbers(temp_noticeNumbers);
        if(result.isError)
            return result.wrapError("when setting field 'noticeNumbers' in type "~__traits(identifier, typeof(this))~":");

        result = this._noticeNumbers.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SEQEUENCE OF field 'noticeNumbers' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE NoticeReference there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct DisplayText
{
    enum Choice
    {
        _FAILSAFE,
        ia5String,
        utf8String,
    }

    union Value
    {
        asn1.Asn1Ia5String ia5String;
        asn1.Asn1Utf8String utf8String;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1Ia5String), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Utf8String), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.ia5String)) @nogc nothrow handle_ia5String,
        scope jres.Result delegate(typeof(Value.utf8String)) @nogc nothrow handle_utf8String,
    ) @nogc nothrow
    {
        if(_choice == Choice.ia5String)
            return handle_ia5String(_value.ia5String);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised DisplayText!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.ia5String))  handle_ia5String,
        scope jres.Result delegate(typeof(Value.utf8String))  handle_utf8String,
    ) 
    {
        if(_choice == Choice.ia5String)
            return handle_ia5String(_value.ia5String);
        if(_choice == Choice.utf8String)
            return handle_utf8String(_value.utf8String);
        assert(false, "attempted to use an uninitialised DisplayText!");

    }

    jres.Result setIa5String(
        typeof(Value.ia5String) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        _successFlag = value.asSlice.length >= 1 && value.asSlice.length <= 200;
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _value.ia5String = value;
        _choice = Choice.ia5String;
        return jres.Result.noError;
    }

    typeof(Value.ia5String) getIa5String(
    ) @nogc nothrow
    {
        assert(_choice == Choice.ia5String, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'ia5String'");
        return _value.ia5String;
    }

    bool isIa5String(
    ) @nogc nothrow const
    {
        return _choice == Choice.ia5String;
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
            _successFlag = _utf8string__length >= 1 && _utf8string__length <= 200;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 22)
        {
            /++ FIELD - ia5String ++/
            typeof(Value.ia5String) temp_ia5String;
            result = typeof(temp_ia5String).fromDecoding!ruleset(memory, temp_ia5String, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'ia5String' in type "~__traits(identifier, typeof(this))~":");
            result = this.setIa5String(temp_ia5String);
            if(result.isError)
                return result.wrapError("when setting field 'ia5String' in type "~__traits(identifier, typeof(this))~":");

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

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type DisplayText the identifier tag & class were unable to match any known option");
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
        if(isIa5String)
        {
            depth++;
            putIndent();
            sink("ia5String: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getIa5String()), "toString"))
                _value.ia5String.toString(sink, depth+1);
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

asn1.Asn1ObjectIdentifier id_ce_policyMappings(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 33, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct PolicyMappingItem
{
    private
    {
        bool _isSet_issuerDomainPolicy;
        .CertPolicyId _issuerDomainPolicy;
        bool _isSet_subjectDomainPolicy;
        .CertPolicyId _subjectDomainPolicy;
    }

    jres.Result setIssuerDomainPolicy(
        typeof(_issuerDomainPolicy) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_issuerDomainPolicy = true;
        _issuerDomainPolicy = value;
        return jres.Result.noError;
    }

    typeof(_issuerDomainPolicy) getIssuerDomainPolicy(
    ) @nogc nothrow
    {
        assert(_isSet_issuerDomainPolicy, "Non-optional field 'issuerDomainPolicy' has not been set yet - please use validate() to check!");
        return _issuerDomainPolicy;
    }

    jres.Result setSubjectDomainPolicy(
        typeof(_subjectDomainPolicy) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subjectDomainPolicy = true;
        _subjectDomainPolicy = value;
        return jres.Result.noError;
    }

    typeof(_subjectDomainPolicy) getSubjectDomainPolicy(
    ) @nogc nothrow
    {
        assert(_isSet_subjectDomainPolicy, "Non-optional field 'subjectDomainPolicy' has not been set yet - please use validate() to check!");
        return _subjectDomainPolicy;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_issuerDomainPolicy)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PolicyMappingItem non-optional field 'issuerDomainPolicy' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_subjectDomainPolicy)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PolicyMappingItem non-optional field 'subjectDomainPolicy' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("issuerDomainPolicy: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_issuerDomainPolicy), "toString"))
            _issuerDomainPolicy.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("subjectDomainPolicy: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_subjectDomainPolicy), "toString"))
            _subjectDomainPolicy.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: issuerDomainPolicy +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'issuerDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PolicyMappingItem when reading top level tag 6 for field 'issuerDomainPolicy' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PolicyMappingItem when reading top level tag 6 for field 'issuerDomainPolicy' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_issuerDomainPolicy;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_issuerDomainPolicy);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'issuerDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - issuerDomainPolicy ++/
        typeof(_issuerDomainPolicy) temp_issuerDomainPolicy;
        result = temp_issuerDomainPolicy.fromDecoding!ruleset(memory_issuerDomainPolicy, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'issuerDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        result = this.setIssuerDomainPolicy(temp_issuerDomainPolicy);
        if(result.isError)
            return result.wrapError("when setting field 'issuerDomainPolicy' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: subjectDomainPolicy +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'subjectDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PolicyMappingItem when reading top level tag 6 for field 'subjectDomainPolicy' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PolicyMappingItem when reading top level tag 6 for field 'subjectDomainPolicy' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_subjectDomainPolicy;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subjectDomainPolicy);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'subjectDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - subjectDomainPolicy ++/
        typeof(_subjectDomainPolicy) temp_subjectDomainPolicy;
        result = temp_subjectDomainPolicy.fromDecoding!ruleset(memory_subjectDomainPolicy, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'subjectDomainPolicy' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSubjectDomainPolicy(temp_subjectDomainPolicy);
        if(result.isError)
            return result.wrapError("when setting field 'subjectDomainPolicy' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PolicyMappingItem there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct PolicyMappings
{
    private
    {
        asn1.Asn1SequenceOf!(.PolicyMappingItem) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.PolicyMappingItem) newValue,
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

    asn1.Asn1SequenceOf!(.PolicyMappingItem) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.PolicyMappingItem), "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_subjectAltName(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 17, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct SubjectAltName
{
    private
    {
        .GeneralNames _value;
        bool _isSet;
    }

    jres.Result set(
        .GeneralNames newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .GeneralNames get(
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
        static if(__traits(hasMember, .GeneralNames, "toString"))
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

struct GeneralNames
{
    private
    {
        asn1.Asn1SequenceOf!(.GeneralName) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.GeneralName) newValue,
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

    asn1.Asn1SequenceOf!(.GeneralName) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.GeneralName), "toString"))
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

struct GeneralName
{
    enum Choice
    {
        _FAILSAFE,
        otherName,
        rfc822Name,
        dNSName,
        x400Address,
        directoryName,
        ediPartyName,
        uniformResourceIdentifier,
        iPAddress,
        registeredID,
    }

    union Value
    {
        .AnotherName otherName;
        asn1.Asn1Ia5String rfc822Name;
        asn1.Asn1Ia5String dNSName;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.ORAddress x400Address;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Name directoryName;
        .EDIPartyName ediPartyName;
        asn1.Asn1Ia5String uniformResourceIdentifier;
        asn1.Asn1OctetString iPAddress;
        asn1.Asn1ObjectIdentifier registeredID;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.AnotherName), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Ia5String), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Ia5String), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.ORAddress), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Name), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.EDIPartyName), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Ia5String), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1OctetString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1ObjectIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.otherName)) @nogc nothrow handle_otherName,
        scope jres.Result delegate(typeof(Value.rfc822Name)) @nogc nothrow handle_rfc822Name,
        scope jres.Result delegate(typeof(Value.dNSName)) @nogc nothrow handle_dNSName,
        scope jres.Result delegate(typeof(Value.x400Address)) @nogc nothrow handle_x400Address,
        scope jres.Result delegate(typeof(Value.directoryName)) @nogc nothrow handle_directoryName,
        scope jres.Result delegate(typeof(Value.ediPartyName)) @nogc nothrow handle_ediPartyName,
        scope jres.Result delegate(typeof(Value.uniformResourceIdentifier)) @nogc nothrow handle_uniformResourceIdentifier,
        scope jres.Result delegate(typeof(Value.iPAddress)) @nogc nothrow handle_iPAddress,
        scope jres.Result delegate(typeof(Value.registeredID)) @nogc nothrow handle_registeredID,
    ) @nogc nothrow
    {
        if(_choice == Choice.otherName)
            return handle_otherName(_value.otherName);
        if(_choice == Choice.rfc822Name)
            return handle_rfc822Name(_value.rfc822Name);
        if(_choice == Choice.dNSName)
            return handle_dNSName(_value.dNSName);
        if(_choice == Choice.x400Address)
            return handle_x400Address(_value.x400Address);
        if(_choice == Choice.directoryName)
            return handle_directoryName(_value.directoryName);
        if(_choice == Choice.ediPartyName)
            return handle_ediPartyName(_value.ediPartyName);
        if(_choice == Choice.uniformResourceIdentifier)
            return handle_uniformResourceIdentifier(_value.uniformResourceIdentifier);
        if(_choice == Choice.iPAddress)
            return handle_iPAddress(_value.iPAddress);
        if(_choice == Choice.registeredID)
            return handle_registeredID(_value.registeredID);
        assert(false, "attempted to use an uninitialised GeneralName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.otherName))  handle_otherName,
        scope jres.Result delegate(typeof(Value.rfc822Name))  handle_rfc822Name,
        scope jres.Result delegate(typeof(Value.dNSName))  handle_dNSName,
        scope jres.Result delegate(typeof(Value.x400Address))  handle_x400Address,
        scope jres.Result delegate(typeof(Value.directoryName))  handle_directoryName,
        scope jres.Result delegate(typeof(Value.ediPartyName))  handle_ediPartyName,
        scope jres.Result delegate(typeof(Value.uniformResourceIdentifier))  handle_uniformResourceIdentifier,
        scope jres.Result delegate(typeof(Value.iPAddress))  handle_iPAddress,
        scope jres.Result delegate(typeof(Value.registeredID))  handle_registeredID,
    ) 
    {
        if(_choice == Choice.otherName)
            return handle_otherName(_value.otherName);
        if(_choice == Choice.rfc822Name)
            return handle_rfc822Name(_value.rfc822Name);
        if(_choice == Choice.dNSName)
            return handle_dNSName(_value.dNSName);
        if(_choice == Choice.x400Address)
            return handle_x400Address(_value.x400Address);
        if(_choice == Choice.directoryName)
            return handle_directoryName(_value.directoryName);
        if(_choice == Choice.ediPartyName)
            return handle_ediPartyName(_value.ediPartyName);
        if(_choice == Choice.uniformResourceIdentifier)
            return handle_uniformResourceIdentifier(_value.uniformResourceIdentifier);
        if(_choice == Choice.iPAddress)
            return handle_iPAddress(_value.iPAddress);
        if(_choice == Choice.registeredID)
            return handle_registeredID(_value.registeredID);
        assert(false, "attempted to use an uninitialised GeneralName!");

    }

    jres.Result setOtherName(
        typeof(Value.otherName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.otherName = value;
        _choice = Choice.otherName;
        return jres.Result.noError;
    }

    typeof(Value.otherName) getOtherName(
    ) @nogc nothrow
    {
        assert(_choice == Choice.otherName, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'otherName'");
        return _value.otherName;
    }

    bool isOtherName(
    ) @nogc nothrow const
    {
        return _choice == Choice.otherName;
    }

    jres.Result setRfc822Name(
        typeof(Value.rfc822Name) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.rfc822Name = value;
        _choice = Choice.rfc822Name;
        return jres.Result.noError;
    }

    typeof(Value.rfc822Name) getRfc822Name(
    ) @nogc nothrow
    {
        assert(_choice == Choice.rfc822Name, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'rfc822Name'");
        return _value.rfc822Name;
    }

    bool isRfc822Name(
    ) @nogc nothrow const
    {
        return _choice == Choice.rfc822Name;
    }

    jres.Result setDNSName(
        typeof(Value.dNSName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.dNSName = value;
        _choice = Choice.dNSName;
        return jres.Result.noError;
    }

    typeof(Value.dNSName) getDNSName(
    ) @nogc nothrow
    {
        assert(_choice == Choice.dNSName, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'dNSName'");
        return _value.dNSName;
    }

    bool isDNSName(
    ) @nogc nothrow const
    {
        return _choice == Choice.dNSName;
    }

    jres.Result setX400Address(
        typeof(Value.x400Address) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.x400Address = value;
        _choice = Choice.x400Address;
        return jres.Result.noError;
    }

    typeof(Value.x400Address) getX400Address(
    ) @nogc nothrow
    {
        assert(_choice == Choice.x400Address, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'x400Address'");
        return _value.x400Address;
    }

    bool isX400Address(
    ) @nogc nothrow const
    {
        return _choice == Choice.x400Address;
    }

    jres.Result setDirectoryName(
        typeof(Value.directoryName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.directoryName = value;
        _choice = Choice.directoryName;
        return jres.Result.noError;
    }

    typeof(Value.directoryName) getDirectoryName(
    ) @nogc nothrow
    {
        assert(_choice == Choice.directoryName, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'directoryName'");
        return _value.directoryName;
    }

    bool isDirectoryName(
    ) @nogc nothrow const
    {
        return _choice == Choice.directoryName;
    }

    jres.Result setEdiPartyName(
        typeof(Value.ediPartyName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.ediPartyName = value;
        _choice = Choice.ediPartyName;
        return jres.Result.noError;
    }

    typeof(Value.ediPartyName) getEdiPartyName(
    ) @nogc nothrow
    {
        assert(_choice == Choice.ediPartyName, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'ediPartyName'");
        return _value.ediPartyName;
    }

    bool isEdiPartyName(
    ) @nogc nothrow const
    {
        return _choice == Choice.ediPartyName;
    }

    jres.Result setUniformResourceIdentifier(
        typeof(Value.uniformResourceIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.uniformResourceIdentifier = value;
        _choice = Choice.uniformResourceIdentifier;
        return jres.Result.noError;
    }

    typeof(Value.uniformResourceIdentifier) getUniformResourceIdentifier(
    ) @nogc nothrow
    {
        assert(_choice == Choice.uniformResourceIdentifier, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'uniformResourceIdentifier'");
        return _value.uniformResourceIdentifier;
    }

    bool isUniformResourceIdentifier(
    ) @nogc nothrow const
    {
        return _choice == Choice.uniformResourceIdentifier;
    }

    jres.Result setIPAddress(
        typeof(Value.iPAddress) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.iPAddress = value;
        _choice = Choice.iPAddress;
        return jres.Result.noError;
    }

    typeof(Value.iPAddress) getIPAddress(
    ) @nogc nothrow
    {
        assert(_choice == Choice.iPAddress, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'iPAddress'");
        return _value.iPAddress;
    }

    bool isIPAddress(
    ) @nogc nothrow const
    {
        return _choice == Choice.iPAddress;
    }

    jres.Result setRegisteredID(
        typeof(Value.registeredID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.registeredID = value;
        _choice = Choice.registeredID;
        return jres.Result.noError;
    }

    typeof(Value.registeredID) getRegisteredID(
    ) @nogc nothrow
    {
        assert(_choice == Choice.registeredID, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'registeredID'");
        return _value.registeredID;
    }

    bool isRegisteredID(
    ) @nogc nothrow const
    {
        return _choice == Choice.registeredID;
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
            /++ FIELD - otherName ++/
            typeof(Value.otherName) temp_otherName;
            result = temp_otherName.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'otherName' in type "~__traits(identifier, typeof(this))~":");
            result = this.setOtherName(temp_otherName);
            if(result.isError)
                return result.wrapError("when setting field 'otherName' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 1)
        {
            /++ FIELD - rfc822Name ++/
            typeof(Value.rfc822Name) temp_rfc822Name;
            result = typeof(temp_rfc822Name).fromDecoding!ruleset(memory, temp_rfc822Name, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'rfc822Name' in type "~__traits(identifier, typeof(this))~":");
            result = this.setRfc822Name(temp_rfc822Name);
            if(result.isError)
                return result.wrapError("when setting field 'rfc822Name' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 2)
        {
            /++ FIELD - dNSName ++/
            typeof(Value.dNSName) temp_dNSName;
            result = typeof(temp_dNSName).fromDecoding!ruleset(memory, temp_dNSName, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'dNSName' in type "~__traits(identifier, typeof(this))~":");
            result = this.setDNSName(temp_dNSName);
            if(result.isError)
                return result.wrapError("when setting field 'dNSName' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 3)
        {
            /++ FIELD - x400Address ++/
            typeof(Value.x400Address) temp_x400Address;
            result = temp_x400Address.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'x400Address' in type "~__traits(identifier, typeof(this))~":");
            result = this.setX400Address(temp_x400Address);
            if(result.isError)
                return result.wrapError("when setting field 'x400Address' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 4)
        {
            /++ FIELD - directoryName ++/
            typeof(Value.directoryName) temp_directoryName;
            result = temp_directoryName.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'directoryName' in type "~__traits(identifier, typeof(this))~":");
            result = this.setDirectoryName(temp_directoryName);
            if(result.isError)
                return result.wrapError("when setting field 'directoryName' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 5)
        {
            /++ FIELD - ediPartyName ++/
            typeof(Value.ediPartyName) temp_ediPartyName;
            result = temp_ediPartyName.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'ediPartyName' in type "~__traits(identifier, typeof(this))~":");
            result = this.setEdiPartyName(temp_ediPartyName);
            if(result.isError)
                return result.wrapError("when setting field 'ediPartyName' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 6)
        {
            /++ FIELD - uniformResourceIdentifier ++/
            typeof(Value.uniformResourceIdentifier) temp_uniformResourceIdentifier;
            result = typeof(temp_uniformResourceIdentifier).fromDecoding!ruleset(memory, temp_uniformResourceIdentifier, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'uniformResourceIdentifier' in type "~__traits(identifier, typeof(this))~":");
            result = this.setUniformResourceIdentifier(temp_uniformResourceIdentifier);
            if(result.isError)
                return result.wrapError("when setting field 'uniformResourceIdentifier' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 7)
        {
            /++ FIELD - iPAddress ++/
            typeof(Value.iPAddress) temp_iPAddress;
            result = typeof(temp_iPAddress).fromDecoding!ruleset(memory, temp_iPAddress, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'iPAddress' in type "~__traits(identifier, typeof(this))~":");
            result = this.setIPAddress(temp_iPAddress);
            if(result.isError)
                return result.wrapError("when setting field 'iPAddress' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 8)
        {
            /++ FIELD - registeredID ++/
            typeof(Value.registeredID) temp_registeredID;
            result = typeof(temp_registeredID).fromDecoding!ruleset(memory, temp_registeredID, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'registeredID' in type "~__traits(identifier, typeof(this))~":");
            result = this.setRegisteredID(temp_registeredID);
            if(result.isError)
                return result.wrapError("when setting field 'registeredID' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type GeneralName the identifier tag & class were unable to match any known option");
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
        if(isOtherName)
        {
            depth++;
            putIndent();
            sink("otherName: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getOtherName()), "toString"))
                _value.otherName.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isRfc822Name)
        {
            depth++;
            putIndent();
            sink("rfc822Name: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getRfc822Name()), "toString"))
                _value.rfc822Name.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isDNSName)
        {
            depth++;
            putIndent();
            sink("dNSName: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getDNSName()), "toString"))
                _value.dNSName.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isX400Address)
        {
            depth++;
            putIndent();
            sink("x400Address: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getX400Address()), "toString"))
                _value.x400Address.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isDirectoryName)
        {
            depth++;
            putIndent();
            sink("directoryName: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getDirectoryName()), "toString"))
                _value.directoryName.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isEdiPartyName)
        {
            depth++;
            putIndent();
            sink("ediPartyName: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getEdiPartyName()), "toString"))
                _value.ediPartyName.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isUniformResourceIdentifier)
        {
            depth++;
            putIndent();
            sink("uniformResourceIdentifier: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getUniformResourceIdentifier()), "toString"))
                _value.uniformResourceIdentifier.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isIPAddress)
        {
            depth++;
            putIndent();
            sink("iPAddress: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getIPAddress()), "toString"))
                _value.iPAddress.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isRegisteredID)
        {
            depth++;
            putIndent();
            sink("registeredID: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getRegisteredID()), "toString"))
                _value.registeredID.toString(sink, depth+1);
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

struct AnotherName
{
    private
    {
        bool _isSet_type_id;
        asn1.Asn1ObjectIdentifier _type_id;
        bool _isSet_value;
        asn1.Asn1OctetString _value;
    }

    jres.Result setType_id(
        typeof(_type_id) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_type_id = true;
        _type_id = value;
        return jres.Result.noError;
    }

    typeof(_type_id) getType_id(
    ) @nogc nothrow
    {
        assert(_isSet_type_id, "Non-optional field 'type-id' has not been set yet - please use validate() to check!");
        return _type_id;
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
        if(!_isSet_type_id)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AnotherName non-optional field 'type-id' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_value)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AnotherName non-optional field 'value' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("type-id: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_type_id), "toString"))
            _type_id.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: type-id +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'type-id' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AnotherName when reading top level tag 6 for field 'type-id' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AnotherName when reading top level tag 6 for field 'type-id' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_type_id;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_type_id);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'type-id' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - type-id ++/
        typeof(_type_id) temp_type_id;
        result = typeof(temp_type_id).fromDecoding!ruleset(memory_type_id, temp_type_id, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'type_id' in type "~__traits(identifier, typeof(this))~":");
        result = this.setType_id(temp_type_id);
        if(result.isError)
            return result.wrapError("when setting field 'type_id' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: value +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'value' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AnotherName when reading top level tag 0 for field 'value' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AnotherName when reading top level tag 0 for field 'value' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_value;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_value);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'value' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - value ++/
        jbuf.MemoryReader memory_0value;
            // EXPLICIT TAG - 0
            if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field value a primitive tag was found when a constructed one was expected");
            if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'value' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
            if(componentHeader.identifier.tag != 0)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'value' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
            result = asn1.asn1DecodeComponentHeader!ruleset(memory_value, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'value' in type "~__traits(identifier, typeof(this))~":");
            result = asn1.asn1ReadContentBytes(memory_value, componentHeader.length, memory_0value);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'value' in type "~__traits(identifier, typeof(this))~":");
        typeof(_value) temp_value;
        result = typeof(temp_value).fromDecoding!ruleset(memory_0value, temp_value, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'value' in type "~__traits(identifier, typeof(this))~":");
        result = this.setValue(temp_value);
        if(result.isError)
            return result.wrapError("when setting field 'value' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AnotherName there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct EDIPartyName
{
    private
    {
        bool _isSet_nameAssigner;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.DirectoryString _nameAssigner;
        bool _isSet_partyName;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.DirectoryString _partyName;
    }

    jres.Result setNameAssigner(
        typeof(_nameAssigner) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_nameAssigner = true;
        _nameAssigner = value;
        return jres.Result.noError;
    }

    jres.Result setNameAssigner(
        tcon.Nullable!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.DirectoryString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setNameAssigner(value.get());
        }
        else
            _isSet_nameAssigner = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.DirectoryString) getNameAssigner(
    ) @nogc nothrow
    {
        if(_isSet_nameAssigner)
            return typeof(return)(_nameAssigner);
        return typeof(return).init;
    }

    jres.Result setPartyName(
        typeof(_partyName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_partyName = true;
        _partyName = value;
        return jres.Result.noError;
    }

    typeof(_partyName) getPartyName(
    ) @nogc nothrow
    {
        assert(_isSet_partyName, "Non-optional field 'partyName' has not been set yet - please use validate() to check!");
        return _partyName;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_partyName)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EDIPartyName non-optional field 'partyName' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("nameAssigner: ");
        sink("\n");
        if(_isSet_nameAssigner)
        {
            static if(__traits(hasMember, typeof(_nameAssigner), "toString"))
                _nameAssigner.toString(sink, depth+1);
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
        sink("partyName: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_partyName), "toString"))
            _partyName.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: nameAssigner +++/
        auto backtrack_nameAssigner = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'nameAssigner' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_nameAssigner;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_nameAssigner);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'nameAssigner' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - nameAssigner ++/
                typeof(_nameAssigner) temp_nameAssigner;
                result = temp_nameAssigner.fromDecoding!ruleset(memory_nameAssigner, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'nameAssigner' in type "~__traits(identifier, typeof(this))~":");
                result = this.setNameAssigner(temp_nameAssigner);
                if(result.isError)
                    return result.wrapError("when setting field 'nameAssigner' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_nameAssigner.buffer, backtrack_nameAssigner.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: partyName +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'partyName' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EDIPartyName when reading top level tag 1 for field 'partyName' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 1)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EDIPartyName when reading top level tag 1 for field 'partyName' the tag's value was expected to be 1", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_partyName;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_partyName);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'partyName' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - partyName ++/
        typeof(_partyName) temp_partyName;
        result = temp_partyName.fromDecoding!ruleset(memory_partyName, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'partyName' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPartyName(temp_partyName);
        if(result.isError)
            return result.wrapError("when setting field 'partyName' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE EDIPartyName there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_ce_issuerAltName(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 18, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct IssuerAltName
{
    private
    {
        .GeneralNames _value;
        bool _isSet;
    }

    jres.Result set(
        .GeneralNames newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .GeneralNames get(
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
        static if(__traits(hasMember, .GeneralNames, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_subjectDirectoryAttributes(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 9, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct SubjectDirectoryAttributes
{
    private
    {
        asn1.Asn1SequenceOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Attribute) newValue,
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

    asn1.Asn1SequenceOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Attribute), "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_basicConstraints(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 19, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct BasicConstraints
{
    private
    {
        bool _isSet_cA;
        asn1.Asn1Bool _cA;
        bool _isSet_pathLenConstraint;
        asn1.Asn1Integer _pathLenConstraint;
    }

    jres.Result setCA(
        typeof(_cA) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_cA = true;
        _cA = value;
        return jres.Result.noError;
    }

    typeof(_cA) getCA(
    ) @nogc nothrow
    {
        assert(_isSet_cA, "Non-optional field 'cA' has not been set yet - please use validate() to check!");
        return _cA;
    }

    static typeof(_cA) defaultOfCA(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result setPathLenConstraint(
        typeof(_pathLenConstraint) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        bool _successFlag;
        {
            long _integer__value;
            result = value.asInt!long(_integer__value);
            if(result.isError)
                return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _integer__value >= 0 && _integer__value <= 18446744073709551615;
        }
        if(!_successFlag)
            return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
        _isSet_pathLenConstraint = true;
        _pathLenConstraint = value;
        return jres.Result.noError;
    }

    jres.Result setPathLenConstraint(
        tcon.Nullable!(asn1.Asn1Integer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            bool _successFlag;
            {
                long _integer__value;
                result = value.get.asInt!long(_integer__value);
                if(result.isError)
                    return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
                _successFlag = _integer__value >= 0 && _integer__value <= 18446744073709551615;
            }
            if(!_successFlag)
                return jres.Result.make(asn1.Asn1DecodeError.constraintFailed, "Value failed to match against type's constraint (TODO: A much more specific error message)");
            return setPathLenConstraint(value.get());
        }
        else
            _isSet_pathLenConstraint = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Integer) getPathLenConstraint(
    ) @nogc nothrow
    {
        if(_isSet_pathLenConstraint)
            return typeof(return)(_pathLenConstraint);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_cA)
        {
            auto result = this.setCA(defaultOfCA());
            if(result.isError)
                return result.wrapError("when setting field 'cA' in type "~__traits(identifier, typeof(this))~":");
        }
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
        sink("cA: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_cA), "toString"))
            _cA.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("pathLenConstraint: ");
        sink("\n");
        if(_isSet_pathLenConstraint)
        {
            static if(__traits(hasMember, typeof(_pathLenConstraint), "toString"))
                _pathLenConstraint.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: cA +++/
        auto backtrack_cA = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'cA' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_cA;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_cA);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'cA' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - cA ++/
                typeof(_cA) temp_cA;
                result = typeof(temp_cA).fromDecoding!ruleset(memory_cA, temp_cA, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'cA' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCA(temp_cA);
                if(result.isError)
                    return result.wrapError("when setting field 'cA' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_cA.buffer, backtrack_cA.cursor);
                result = this.setCA(defaultOfCA());
                if(result.isError)
                    return result.wrapError("when setting field 'cA' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setCA(defaultOfCA());
            if(result.isError)
                return result.wrapError("when setting field 'cA' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: pathLenConstraint +++/
        auto backtrack_pathLenConstraint = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'pathLenConstraint' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_pathLenConstraint;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_pathLenConstraint);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'pathLenConstraint' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - pathLenConstraint ++/
                typeof(_pathLenConstraint) temp_pathLenConstraint;
                result = typeof(temp_pathLenConstraint).fromDecoding!ruleset(memory_pathLenConstraint, temp_pathLenConstraint, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'pathLenConstraint' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPathLenConstraint(temp_pathLenConstraint);
                if(result.isError)
                    return result.wrapError("when setting field 'pathLenConstraint' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_pathLenConstraint.buffer, backtrack_pathLenConstraint.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE BasicConstraints there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_ce_nameConstraints(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 30, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct NameConstraints
{
    private
    {
        bool _isSet_permittedSubtrees;
        .GeneralSubtrees _permittedSubtrees;
        bool _isSet_excludedSubtrees;
        .GeneralSubtrees _excludedSubtrees;
    }

    jres.Result setPermittedSubtrees(
        typeof(_permittedSubtrees) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_permittedSubtrees = true;
        _permittedSubtrees = value;
        return jres.Result.noError;
    }

    jres.Result setPermittedSubtrees(
        tcon.Nullable!(.GeneralSubtrees) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setPermittedSubtrees(value.get());
        }
        else
            _isSet_permittedSubtrees = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.GeneralSubtrees) getPermittedSubtrees(
    ) @nogc nothrow
    {
        if(_isSet_permittedSubtrees)
            return typeof(return)(_permittedSubtrees);
        return typeof(return).init;
    }

    jres.Result setExcludedSubtrees(
        typeof(_excludedSubtrees) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_excludedSubtrees = true;
        _excludedSubtrees = value;
        return jres.Result.noError;
    }

    jres.Result setExcludedSubtrees(
        tcon.Nullable!(.GeneralSubtrees) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setExcludedSubtrees(value.get());
        }
        else
            _isSet_excludedSubtrees = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.GeneralSubtrees) getExcludedSubtrees(
    ) @nogc nothrow
    {
        if(_isSet_excludedSubtrees)
            return typeof(return)(_excludedSubtrees);
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
        sink("permittedSubtrees: ");
        sink("\n");
        if(_isSet_permittedSubtrees)
        {
            static if(__traits(hasMember, typeof(_permittedSubtrees), "toString"))
                _permittedSubtrees.toString(sink, depth+1);
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
        sink("excludedSubtrees: ");
        sink("\n");
        if(_isSet_excludedSubtrees)
        {
            static if(__traits(hasMember, typeof(_excludedSubtrees), "toString"))
                _excludedSubtrees.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: permittedSubtrees +++/
        auto backtrack_permittedSubtrees = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'permittedSubtrees' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_permittedSubtrees;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_permittedSubtrees);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'permittedSubtrees' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - permittedSubtrees ++/
                typeof(_permittedSubtrees) temp_permittedSubtrees;
                result = temp_permittedSubtrees.fromDecoding!ruleset(memory_permittedSubtrees, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'permittedSubtrees' in type "~__traits(identifier, typeof(this))~":");
                result = this.setPermittedSubtrees(temp_permittedSubtrees);
                if(result.isError)
                    return result.wrapError("when setting field 'permittedSubtrees' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_permittedSubtrees.buffer, backtrack_permittedSubtrees.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: excludedSubtrees +++/
        auto backtrack_excludedSubtrees = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'excludedSubtrees' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_excludedSubtrees;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_excludedSubtrees);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'excludedSubtrees' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - excludedSubtrees ++/
                typeof(_excludedSubtrees) temp_excludedSubtrees;
                result = temp_excludedSubtrees.fromDecoding!ruleset(memory_excludedSubtrees, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'excludedSubtrees' in type "~__traits(identifier, typeof(this))~":");
                result = this.setExcludedSubtrees(temp_excludedSubtrees);
                if(result.isError)
                    return result.wrapError("when setting field 'excludedSubtrees' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_excludedSubtrees.buffer, backtrack_excludedSubtrees.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE NameConstraints there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct GeneralSubtrees
{
    private
    {
        asn1.Asn1SequenceOf!(.GeneralSubtree) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.GeneralSubtree) newValue,
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

    asn1.Asn1SequenceOf!(.GeneralSubtree) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.GeneralSubtree), "toString"))
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

struct GeneralSubtree
{
    private
    {
        bool _isSet_base;
        .GeneralName _base;
        bool _isSet_minimum;
        .BaseDistance _minimum;
        bool _isSet_maximum;
        .BaseDistance _maximum;
    }

    jres.Result setBase(
        typeof(_base) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_base = true;
        _base = value;
        return jres.Result.noError;
    }

    typeof(_base) getBase(
    ) @nogc nothrow
    {
        assert(_isSet_base, "Non-optional field 'base' has not been set yet - please use validate() to check!");
        return _base;
    }

    jres.Result setMinimum(
        typeof(_minimum) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_minimum = true;
        _minimum = value;
        return jres.Result.noError;
    }

    typeof(_minimum) getMinimum(
    ) @nogc nothrow
    {
        assert(_isSet_minimum, "Non-optional field 'minimum' has not been set yet - please use validate() to check!");
        return _minimum;
    }

    static typeof(_minimum) defaultOfMinimum(
    ) @nogc nothrow
    {
        .BaseDistance mainValue;
            asn1.Asn1Integer mainValue__underlying;
            static immutable ubyte[] mainValue__underlying__underlying = [
                /* 0 */ 
            ];
            mainValue__underlying = asn1.Asn1Integer.fromUnownedBytes(mainValue__underlying__underlying);
        jres.resultAssert(mainValue.set(mainValue__underlying));
        return mainValue;

    }

    jres.Result setMaximum(
        typeof(_maximum) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_maximum = true;
        _maximum = value;
        return jres.Result.noError;
    }

    jres.Result setMaximum(
        tcon.Nullable!(.BaseDistance) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setMaximum(value.get());
        }
        else
            _isSet_maximum = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.BaseDistance) getMaximum(
    ) @nogc nothrow
    {
        if(_isSet_maximum)
            return typeof(return)(_maximum);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_base)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type GeneralSubtree non-optional field 'base' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_minimum)
        {
            auto result = this.setMinimum(defaultOfMinimum());
            if(result.isError)
                return result.wrapError("when setting field 'minimum' in type "~__traits(identifier, typeof(this))~":");
        }
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
        sink("base: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_base), "toString"))
            _base.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("minimum: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_minimum), "toString"))
            _minimum.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("maximum: ");
        sink("\n");
        if(_isSet_maximum)
        {
            static if(__traits(hasMember, typeof(_maximum), "toString"))
                _maximum.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: base +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'base' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_base;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_base);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'base' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - base ++/
        typeof(_base) temp_base;
        result = temp_base.fromDecoding!ruleset(memory_base, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'base' in type "~__traits(identifier, typeof(this))~":");
        result = this.setBase(temp_base);
        if(result.isError)
            return result.wrapError("when setting field 'base' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: minimum +++/
        auto backtrack_minimum = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'minimum' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_minimum;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_minimum);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'minimum' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - minimum ++/
                typeof(_minimum) temp_minimum;
                result = temp_minimum.fromDecoding!ruleset(memory_minimum, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'minimum' in type "~__traits(identifier, typeof(this))~":");
                result = this.setMinimum(temp_minimum);
                if(result.isError)
                    return result.wrapError("when setting field 'minimum' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_minimum.buffer, backtrack_minimum.cursor);
                result = this.setMinimum(defaultOfMinimum());
                if(result.isError)
                    return result.wrapError("when setting field 'minimum' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setMinimum(defaultOfMinimum());
            if(result.isError)
                return result.wrapError("when setting field 'minimum' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: maximum +++/
        auto backtrack_maximum = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'maximum' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_maximum;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_maximum);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'maximum' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - maximum ++/
                typeof(_maximum) temp_maximum;
                result = temp_maximum.fromDecoding!ruleset(memory_maximum, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'maximum' in type "~__traits(identifier, typeof(this))~":");
                result = this.setMaximum(temp_maximum);
                if(result.isError)
                    return result.wrapError("when setting field 'maximum' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_maximum.buffer, backtrack_maximum.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE GeneralSubtree there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct BaseDistance
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
        bool _successFlag;
        {
            long _integer__value;
            result = newValue.asInt!long(_integer__value);
            if(result.isError)
                return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _integer__value >= 0 && _integer__value <= 18446744073709551615;
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

asn1.Asn1ObjectIdentifier id_ce_policyConstraints(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 36, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct PolicyConstraints
{
    private
    {
        bool _isSet_requireExplicitPolicy;
        .SkipCerts _requireExplicitPolicy;
        bool _isSet_inhibitPolicyMapping;
        .SkipCerts _inhibitPolicyMapping;
    }

    jres.Result setRequireExplicitPolicy(
        typeof(_requireExplicitPolicy) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_requireExplicitPolicy = true;
        _requireExplicitPolicy = value;
        return jres.Result.noError;
    }

    jres.Result setRequireExplicitPolicy(
        tcon.Nullable!(.SkipCerts) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setRequireExplicitPolicy(value.get());
        }
        else
            _isSet_requireExplicitPolicy = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.SkipCerts) getRequireExplicitPolicy(
    ) @nogc nothrow
    {
        if(_isSet_requireExplicitPolicy)
            return typeof(return)(_requireExplicitPolicy);
        return typeof(return).init;
    }

    jres.Result setInhibitPolicyMapping(
        typeof(_inhibitPolicyMapping) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_inhibitPolicyMapping = true;
        _inhibitPolicyMapping = value;
        return jres.Result.noError;
    }

    jres.Result setInhibitPolicyMapping(
        tcon.Nullable!(.SkipCerts) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setInhibitPolicyMapping(value.get());
        }
        else
            _isSet_inhibitPolicyMapping = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.SkipCerts) getInhibitPolicyMapping(
    ) @nogc nothrow
    {
        if(_isSet_inhibitPolicyMapping)
            return typeof(return)(_inhibitPolicyMapping);
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
        sink("requireExplicitPolicy: ");
        sink("\n");
        if(_isSet_requireExplicitPolicy)
        {
            static if(__traits(hasMember, typeof(_requireExplicitPolicy), "toString"))
                _requireExplicitPolicy.toString(sink, depth+1);
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
        sink("inhibitPolicyMapping: ");
        sink("\n");
        if(_isSet_inhibitPolicyMapping)
        {
            static if(__traits(hasMember, typeof(_inhibitPolicyMapping), "toString"))
                _inhibitPolicyMapping.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: requireExplicitPolicy +++/
        auto backtrack_requireExplicitPolicy = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'requireExplicitPolicy' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_requireExplicitPolicy;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_requireExplicitPolicy);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'requireExplicitPolicy' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - requireExplicitPolicy ++/
                typeof(_requireExplicitPolicy) temp_requireExplicitPolicy;
                result = temp_requireExplicitPolicy.fromDecoding!ruleset(memory_requireExplicitPolicy, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'requireExplicitPolicy' in type "~__traits(identifier, typeof(this))~":");
                result = this.setRequireExplicitPolicy(temp_requireExplicitPolicy);
                if(result.isError)
                    return result.wrapError("when setting field 'requireExplicitPolicy' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_requireExplicitPolicy.buffer, backtrack_requireExplicitPolicy.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: inhibitPolicyMapping +++/
        auto backtrack_inhibitPolicyMapping = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'inhibitPolicyMapping' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_inhibitPolicyMapping;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_inhibitPolicyMapping);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'inhibitPolicyMapping' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - inhibitPolicyMapping ++/
                typeof(_inhibitPolicyMapping) temp_inhibitPolicyMapping;
                result = temp_inhibitPolicyMapping.fromDecoding!ruleset(memory_inhibitPolicyMapping, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'inhibitPolicyMapping' in type "~__traits(identifier, typeof(this))~":");
                result = this.setInhibitPolicyMapping(temp_inhibitPolicyMapping);
                if(result.isError)
                    return result.wrapError("when setting field 'inhibitPolicyMapping' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_inhibitPolicyMapping.buffer, backtrack_inhibitPolicyMapping.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PolicyConstraints there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SkipCerts
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
        bool _successFlag;
        {
            long _integer__value;
            result = newValue.asInt!long(_integer__value);
            if(result.isError)
                return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _integer__value >= 0 && _integer__value <= 18446744073709551615;
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

asn1.Asn1ObjectIdentifier id_ce_cRLDistributionPoints(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 31, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct CRLDistributionPoints
{
    private
    {
        asn1.Asn1SequenceOf!(.DistributionPoint) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.DistributionPoint) newValue,
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

    asn1.Asn1SequenceOf!(.DistributionPoint) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.DistributionPoint), "toString"))
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

struct DistributionPoint
{
    private
    {
        bool _isSet_distributionPoint;
        .DistributionPointName _distributionPoint;
        bool _isSet_reasons;
        .ReasonFlags _reasons;
        bool _isSet_cRLIssuer;
        .GeneralNames _cRLIssuer;
    }

    jres.Result setDistributionPoint(
        typeof(_distributionPoint) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_distributionPoint = true;
        _distributionPoint = value;
        return jres.Result.noError;
    }

    jres.Result setDistributionPoint(
        tcon.Nullable!(.DistributionPointName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setDistributionPoint(value.get());
        }
        else
            _isSet_distributionPoint = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.DistributionPointName) getDistributionPoint(
    ) @nogc nothrow
    {
        if(_isSet_distributionPoint)
            return typeof(return)(_distributionPoint);
        return typeof(return).init;
    }

    jres.Result setReasons(
        typeof(_reasons) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_reasons = true;
        _reasons = value;
        return jres.Result.noError;
    }

    jres.Result setReasons(
        tcon.Nullable!(.ReasonFlags) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setReasons(value.get());
        }
        else
            _isSet_reasons = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.ReasonFlags) getReasons(
    ) @nogc nothrow
    {
        if(_isSet_reasons)
            return typeof(return)(_reasons);
        return typeof(return).init;
    }

    jres.Result setCRLIssuer(
        typeof(_cRLIssuer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_cRLIssuer = true;
        _cRLIssuer = value;
        return jres.Result.noError;
    }

    jres.Result setCRLIssuer(
        tcon.Nullable!(.GeneralNames) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCRLIssuer(value.get());
        }
        else
            _isSet_cRLIssuer = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.GeneralNames) getCRLIssuer(
    ) @nogc nothrow
    {
        if(_isSet_cRLIssuer)
            return typeof(return)(_cRLIssuer);
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
        sink("distributionPoint: ");
        sink("\n");
        if(_isSet_distributionPoint)
        {
            static if(__traits(hasMember, typeof(_distributionPoint), "toString"))
                _distributionPoint.toString(sink, depth+1);
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
        sink("reasons: ");
        sink("\n");
        if(_isSet_reasons)
        {
            static if(__traits(hasMember, typeof(_reasons), "toString"))
                _reasons.toString(sink, depth+1);
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
        sink("cRLIssuer: ");
        sink("\n");
        if(_isSet_cRLIssuer)
        {
            static if(__traits(hasMember, typeof(_cRLIssuer), "toString"))
                _cRLIssuer.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: distributionPoint +++/
        auto backtrack_distributionPoint = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_distributionPoint;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_distributionPoint);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - distributionPoint ++/
                jbuf.MemoryReader memory_0distributionPoint;
                    // EXPLICIT TAG - 0
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field distributionPoint a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'distributionPoint' the tag's class was expected to be contextSpecific", jstr.String2("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 0)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'distributionPoint' the tag's value was expected to be 0", jstr.String2("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_distributionPoint, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_distributionPoint, componentHeader.length, memory_0distributionPoint);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                typeof(_distributionPoint) temp_distributionPoint;
                result = temp_distributionPoint.fromDecoding!ruleset(memory_0distributionPoint, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                result = this.setDistributionPoint(temp_distributionPoint);
                if(result.isError)
                    return result.wrapError("when setting field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_distributionPoint.buffer, backtrack_distributionPoint.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: reasons +++/
        auto backtrack_reasons = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'reasons' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_reasons;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_reasons);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'reasons' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - reasons ++/
                typeof(_reasons) temp_reasons;
                result = temp_reasons.fromDecoding!ruleset(memory_reasons, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'reasons' in type "~__traits(identifier, typeof(this))~":");
                result = this.setReasons(temp_reasons);
                if(result.isError)
                    return result.wrapError("when setting field 'reasons' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_reasons.buffer, backtrack_reasons.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: cRLIssuer +++/
        auto backtrack_cRLIssuer = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'cRLIssuer' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_cRLIssuer;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_cRLIssuer);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'cRLIssuer' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - cRLIssuer ++/
                typeof(_cRLIssuer) temp_cRLIssuer;
                result = temp_cRLIssuer.fromDecoding!ruleset(memory_cRLIssuer, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'cRLIssuer' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCRLIssuer(temp_cRLIssuer);
                if(result.isError)
                    return result.wrapError("when setting field 'cRLIssuer' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_cRLIssuer.buffer, backtrack_cRLIssuer.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE DistributionPoint there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct DistributionPointName
{
    enum Choice
    {
        _FAILSAFE,
        fullName,
        nameRelativeToCRLIssuer,
    }

    union Value
    {
        .GeneralNames fullName;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.RelativeDistinguishedName nameRelativeToCRLIssuer;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.GeneralNames), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.RelativeDistinguishedName), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.fullName)) @nogc nothrow handle_fullName,
        scope jres.Result delegate(typeof(Value.nameRelativeToCRLIssuer)) @nogc nothrow handle_nameRelativeToCRLIssuer,
    ) @nogc nothrow
    {
        if(_choice == Choice.fullName)
            return handle_fullName(_value.fullName);
        if(_choice == Choice.nameRelativeToCRLIssuer)
            return handle_nameRelativeToCRLIssuer(_value.nameRelativeToCRLIssuer);
        assert(false, "attempted to use an uninitialised DistributionPointName!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.fullName))  handle_fullName,
        scope jres.Result delegate(typeof(Value.nameRelativeToCRLIssuer))  handle_nameRelativeToCRLIssuer,
    ) 
    {
        if(_choice == Choice.fullName)
            return handle_fullName(_value.fullName);
        if(_choice == Choice.nameRelativeToCRLIssuer)
            return handle_nameRelativeToCRLIssuer(_value.nameRelativeToCRLIssuer);
        assert(false, "attempted to use an uninitialised DistributionPointName!");

    }

    jres.Result setFullName(
        typeof(Value.fullName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.fullName = value;
        _choice = Choice.fullName;
        return jres.Result.noError;
    }

    typeof(Value.fullName) getFullName(
    ) @nogc nothrow
    {
        assert(_choice == Choice.fullName, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'fullName'");
        return _value.fullName;
    }

    bool isFullName(
    ) @nogc nothrow const
    {
        return _choice == Choice.fullName;
    }

    jres.Result setNameRelativeToCRLIssuer(
        typeof(Value.nameRelativeToCRLIssuer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.nameRelativeToCRLIssuer = value;
        _choice = Choice.nameRelativeToCRLIssuer;
        return jres.Result.noError;
    }

    typeof(Value.nameRelativeToCRLIssuer) getNameRelativeToCRLIssuer(
    ) @nogc nothrow
    {
        assert(_choice == Choice.nameRelativeToCRLIssuer, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'nameRelativeToCRLIssuer'");
        return _value.nameRelativeToCRLIssuer;
    }

    bool isNameRelativeToCRLIssuer(
    ) @nogc nothrow const
    {
        return _choice == Choice.nameRelativeToCRLIssuer;
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
            /++ FIELD - fullName ++/
            typeof(Value.fullName) temp_fullName;
            result = temp_fullName.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'fullName' in type "~__traits(identifier, typeof(this))~":");
            result = this.setFullName(temp_fullName);
            if(result.isError)
                return result.wrapError("when setting field 'fullName' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 1)
        {
            /++ FIELD - nameRelativeToCRLIssuer ++/
            typeof(Value.nameRelativeToCRLIssuer) temp_nameRelativeToCRLIssuer;
            result = temp_nameRelativeToCRLIssuer.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'nameRelativeToCRLIssuer' in type "~__traits(identifier, typeof(this))~":");
            result = this.setNameRelativeToCRLIssuer(temp_nameRelativeToCRLIssuer);
            if(result.isError)
                return result.wrapError("when setting field 'nameRelativeToCRLIssuer' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type DistributionPointName the identifier tag & class were unable to match any known option");
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
        if(isFullName)
        {
            depth++;
            putIndent();
            sink("fullName: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getFullName()), "toString"))
                _value.fullName.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isNameRelativeToCRLIssuer)
        {
            depth++;
            putIndent();
            sink("nameRelativeToCRLIssuer: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getNameRelativeToCRLIssuer()), "toString"))
                _value.nameRelativeToCRLIssuer.toString(sink, depth+1);
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

struct ReasonFlags
{
    enum NamedBit
    {
        aACompromise = 8,
        cessationOfOperation = 5,
        cACompromise = 2,
        superseded = 4,
        unused = 0,
        certificateHold = 6,
        privilegeWithdrawn = 7,
        keyCompromise = 1,
        affiliationChanged = 3,
    }
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

asn1.Asn1ObjectIdentifier id_ce_extKeyUsage(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 37, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct ExtKeyUsageSyntax
{
    private
    {
        asn1.Asn1SequenceOf!(.KeyPurposeId) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.KeyPurposeId) newValue,
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

    asn1.Asn1SequenceOf!(.KeyPurposeId) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.KeyPurposeId), "toString"))
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

struct KeyPurposeId
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

asn1.Asn1ObjectIdentifier anyExtendedKeyUsage(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 37, 0, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_serverAuth(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_clientAuth(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_codeSigning(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_emailProtection(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_timeStamping(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 8, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_kp_OCSPSigning(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 3, 9, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ce_inhibitAnyPolicy(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 54, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct InhibitAnyPolicy
{
    private
    {
        .SkipCerts _value;
        bool _isSet;
    }

    jres.Result set(
        .SkipCerts newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .SkipCerts get(
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
        static if(__traits(hasMember, .SkipCerts, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_freshestCRL(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 46, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct FreshestCRL
{
    private
    {
        .CRLDistributionPoints _value;
        bool _isSet;
    }

    jres.Result set(
        .CRLDistributionPoints newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .CRLDistributionPoints get(
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
        static if(__traits(hasMember, .CRLDistributionPoints, "toString"))
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

asn1.Asn1ObjectIdentifier id_pe_authorityInfoAccess(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

struct AuthorityInfoAccessSyntax
{
    private
    {
        asn1.Asn1SequenceOf!(.AccessDescription) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.AccessDescription) newValue,
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

    asn1.Asn1SequenceOf!(.AccessDescription) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.AccessDescription), "toString"))
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

struct AccessDescription
{
    private
    {
        bool _isSet_accessMethod;
        asn1.Asn1ObjectIdentifier _accessMethod;
        bool _isSet_accessLocation;
        .GeneralName _accessLocation;
    }

    jres.Result setAccessMethod(
        typeof(_accessMethod) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_accessMethod = true;
        _accessMethod = value;
        return jres.Result.noError;
    }

    typeof(_accessMethod) getAccessMethod(
    ) @nogc nothrow
    {
        assert(_isSet_accessMethod, "Non-optional field 'accessMethod' has not been set yet - please use validate() to check!");
        return _accessMethod;
    }

    jres.Result setAccessLocation(
        typeof(_accessLocation) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_accessLocation = true;
        _accessLocation = value;
        return jres.Result.noError;
    }

    typeof(_accessLocation) getAccessLocation(
    ) @nogc nothrow
    {
        assert(_isSet_accessLocation, "Non-optional field 'accessLocation' has not been set yet - please use validate() to check!");
        return _accessLocation;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_accessMethod)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AccessDescription non-optional field 'accessMethod' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_accessLocation)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AccessDescription non-optional field 'accessLocation' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("accessMethod: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_accessMethod), "toString"))
            _accessMethod.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("accessLocation: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_accessLocation), "toString"))
            _accessLocation.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: accessMethod +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'accessMethod' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AccessDescription when reading top level tag 6 for field 'accessMethod' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AccessDescription when reading top level tag 6 for field 'accessMethod' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_accessMethod;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_accessMethod);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'accessMethod' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - accessMethod ++/
        typeof(_accessMethod) temp_accessMethod;
        result = typeof(temp_accessMethod).fromDecoding!ruleset(memory_accessMethod, temp_accessMethod, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'accessMethod' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAccessMethod(temp_accessMethod);
        if(result.isError)
            return result.wrapError("when setting field 'accessMethod' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: accessLocation +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'accessLocation' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_accessLocation;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_accessLocation);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'accessLocation' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - accessLocation ++/
        typeof(_accessLocation) temp_accessLocation;
        result = temp_accessLocation.fromDecoding!ruleset(memory_accessLocation, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'accessLocation' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAccessLocation(temp_accessLocation);
        if(result.isError)
            return result.wrapError("when setting field 'accessLocation' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AccessDescription there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_pe_subjectInfoAccess(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 11, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

struct SubjectInfoAccessSyntax
{
    private
    {
        asn1.Asn1SequenceOf!(.AccessDescription) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.AccessDescription) newValue,
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

    asn1.Asn1SequenceOf!(.AccessDescription) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.AccessDescription), "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_cRLNumber(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 20, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct CRLNumber
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
        bool _successFlag;
        {
            long _integer__value;
            result = newValue.asInt!long(_integer__value);
            if(result.isError)
                return result.wrapError("when converting ASN.1 integer into native integer in type "~__traits(identifier, typeof(this))~":");
            _successFlag = _integer__value >= 0 && _integer__value <= 18446744073709551615;
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

asn1.Asn1ObjectIdentifier id_ce_issuingDistributionPoint(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 28, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct IssuingDistributionPoint
{
    private
    {
        bool _isSet_distributionPoint;
        .DistributionPointName _distributionPoint;
        bool _isSet_onlyContainsUserCerts;
        asn1.Asn1Bool _onlyContainsUserCerts;
        bool _isSet_onlyContainsCACerts;
        asn1.Asn1Bool _onlyContainsCACerts;
        bool _isSet_onlySomeReasons;
        .ReasonFlags _onlySomeReasons;
        bool _isSet_indirectCRL;
        asn1.Asn1Bool _indirectCRL;
        bool _isSet_onlyContainsAttributeCerts;
        asn1.Asn1Bool _onlyContainsAttributeCerts;
    }

    jres.Result setDistributionPoint(
        typeof(_distributionPoint) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_distributionPoint = true;
        _distributionPoint = value;
        return jres.Result.noError;
    }

    jres.Result setDistributionPoint(
        tcon.Nullable!(.DistributionPointName) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setDistributionPoint(value.get());
        }
        else
            _isSet_distributionPoint = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.DistributionPointName) getDistributionPoint(
    ) @nogc nothrow
    {
        if(_isSet_distributionPoint)
            return typeof(return)(_distributionPoint);
        return typeof(return).init;
    }

    jres.Result setOnlyContainsUserCerts(
        typeof(_onlyContainsUserCerts) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_onlyContainsUserCerts = true;
        _onlyContainsUserCerts = value;
        return jres.Result.noError;
    }

    typeof(_onlyContainsUserCerts) getOnlyContainsUserCerts(
    ) @nogc nothrow
    {
        assert(_isSet_onlyContainsUserCerts, "Non-optional field 'onlyContainsUserCerts' has not been set yet - please use validate() to check!");
        return _onlyContainsUserCerts;
    }

    static typeof(_onlyContainsUserCerts) defaultOfOnlyContainsUserCerts(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result setOnlyContainsCACerts(
        typeof(_onlyContainsCACerts) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_onlyContainsCACerts = true;
        _onlyContainsCACerts = value;
        return jres.Result.noError;
    }

    typeof(_onlyContainsCACerts) getOnlyContainsCACerts(
    ) @nogc nothrow
    {
        assert(_isSet_onlyContainsCACerts, "Non-optional field 'onlyContainsCACerts' has not been set yet - please use validate() to check!");
        return _onlyContainsCACerts;
    }

    static typeof(_onlyContainsCACerts) defaultOfOnlyContainsCACerts(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result setOnlySomeReasons(
        typeof(_onlySomeReasons) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_onlySomeReasons = true;
        _onlySomeReasons = value;
        return jres.Result.noError;
    }

    jres.Result setOnlySomeReasons(
        tcon.Nullable!(.ReasonFlags) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOnlySomeReasons(value.get());
        }
        else
            _isSet_onlySomeReasons = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.ReasonFlags) getOnlySomeReasons(
    ) @nogc nothrow
    {
        if(_isSet_onlySomeReasons)
            return typeof(return)(_onlySomeReasons);
        return typeof(return).init;
    }

    jres.Result setIndirectCRL(
        typeof(_indirectCRL) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_indirectCRL = true;
        _indirectCRL = value;
        return jres.Result.noError;
    }

    typeof(_indirectCRL) getIndirectCRL(
    ) @nogc nothrow
    {
        assert(_isSet_indirectCRL, "Non-optional field 'indirectCRL' has not been set yet - please use validate() to check!");
        return _indirectCRL;
    }

    static typeof(_indirectCRL) defaultOfIndirectCRL(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result setOnlyContainsAttributeCerts(
        typeof(_onlyContainsAttributeCerts) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_onlyContainsAttributeCerts = true;
        _onlyContainsAttributeCerts = value;
        return jres.Result.noError;
    }

    typeof(_onlyContainsAttributeCerts) getOnlyContainsAttributeCerts(
    ) @nogc nothrow
    {
        assert(_isSet_onlyContainsAttributeCerts, "Non-optional field 'onlyContainsAttributeCerts' has not been set yet - please use validate() to check!");
        return _onlyContainsAttributeCerts;
    }

    static typeof(_onlyContainsAttributeCerts) defaultOfOnlyContainsAttributeCerts(
    ) @nogc nothrow
    {
        asn1.Asn1Bool mainValue;
        mainValue = asn1.Asn1Bool(0);
        return mainValue;

    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_onlyContainsUserCerts)
        {
            auto result = this.setOnlyContainsUserCerts(defaultOfOnlyContainsUserCerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsUserCerts' in type "~__traits(identifier, typeof(this))~":");
        }
        if(!_isSet_onlyContainsCACerts)
        {
            auto result = this.setOnlyContainsCACerts(defaultOfOnlyContainsCACerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsCACerts' in type "~__traits(identifier, typeof(this))~":");
        }
        if(!_isSet_indirectCRL)
        {
            auto result = this.setIndirectCRL(defaultOfIndirectCRL());
            if(result.isError)
                return result.wrapError("when setting field 'indirectCRL' in type "~__traits(identifier, typeof(this))~":");
        }
        if(!_isSet_onlyContainsAttributeCerts)
        {
            auto result = this.setOnlyContainsAttributeCerts(defaultOfOnlyContainsAttributeCerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsAttributeCerts' in type "~__traits(identifier, typeof(this))~":");
        }
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
        sink("distributionPoint: ");
        sink("\n");
        if(_isSet_distributionPoint)
        {
            static if(__traits(hasMember, typeof(_distributionPoint), "toString"))
                _distributionPoint.toString(sink, depth+1);
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
        sink("onlyContainsUserCerts: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_onlyContainsUserCerts), "toString"))
            _onlyContainsUserCerts.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("onlyContainsCACerts: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_onlyContainsCACerts), "toString"))
            _onlyContainsCACerts.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("onlySomeReasons: ");
        sink("\n");
        if(_isSet_onlySomeReasons)
        {
            static if(__traits(hasMember, typeof(_onlySomeReasons), "toString"))
                _onlySomeReasons.toString(sink, depth+1);
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
        sink("indirectCRL: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_indirectCRL), "toString"))
            _indirectCRL.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("onlyContainsAttributeCerts: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_onlyContainsAttributeCerts), "toString"))
            _onlyContainsAttributeCerts.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: distributionPoint +++/
        auto backtrack_distributionPoint = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_distributionPoint;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_distributionPoint);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - distributionPoint ++/
                typeof(_distributionPoint) temp_distributionPoint;
                result = temp_distributionPoint.fromDecoding!ruleset(memory_distributionPoint, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");
                result = this.setDistributionPoint(temp_distributionPoint);
                if(result.isError)
                    return result.wrapError("when setting field 'distributionPoint' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_distributionPoint.buffer, backtrack_distributionPoint.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: onlyContainsUserCerts +++/
        auto backtrack_onlyContainsUserCerts = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'onlyContainsUserCerts' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_onlyContainsUserCerts;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_onlyContainsUserCerts);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'onlyContainsUserCerts' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - onlyContainsUserCerts ++/
                typeof(_onlyContainsUserCerts) temp_onlyContainsUserCerts;
                result = typeof(temp_onlyContainsUserCerts).fromDecoding!ruleset(memory_onlyContainsUserCerts, temp_onlyContainsUserCerts, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'onlyContainsUserCerts' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOnlyContainsUserCerts(temp_onlyContainsUserCerts);
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsUserCerts' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_onlyContainsUserCerts.buffer, backtrack_onlyContainsUserCerts.cursor);
                result = this.setOnlyContainsUserCerts(defaultOfOnlyContainsUserCerts());
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsUserCerts' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setOnlyContainsUserCerts(defaultOfOnlyContainsUserCerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsUserCerts' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: onlyContainsCACerts +++/
        auto backtrack_onlyContainsCACerts = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'onlyContainsCACerts' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_onlyContainsCACerts;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_onlyContainsCACerts);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'onlyContainsCACerts' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - onlyContainsCACerts ++/
                typeof(_onlyContainsCACerts) temp_onlyContainsCACerts;
                result = typeof(temp_onlyContainsCACerts).fromDecoding!ruleset(memory_onlyContainsCACerts, temp_onlyContainsCACerts, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'onlyContainsCACerts' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOnlyContainsCACerts(temp_onlyContainsCACerts);
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsCACerts' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_onlyContainsCACerts.buffer, backtrack_onlyContainsCACerts.cursor);
                result = this.setOnlyContainsCACerts(defaultOfOnlyContainsCACerts());
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsCACerts' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setOnlyContainsCACerts(defaultOfOnlyContainsCACerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsCACerts' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: onlySomeReasons +++/
        auto backtrack_onlySomeReasons = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'onlySomeReasons' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 3)
            {
                jbuf.MemoryReader memory_onlySomeReasons;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_onlySomeReasons);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'onlySomeReasons' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - onlySomeReasons ++/
                typeof(_onlySomeReasons) temp_onlySomeReasons;
                result = temp_onlySomeReasons.fromDecoding!ruleset(memory_onlySomeReasons, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'onlySomeReasons' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOnlySomeReasons(temp_onlySomeReasons);
                if(result.isError)
                    return result.wrapError("when setting field 'onlySomeReasons' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_onlySomeReasons.buffer, backtrack_onlySomeReasons.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: indirectCRL +++/
        auto backtrack_indirectCRL = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'indirectCRL' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 4)
            {
                jbuf.MemoryReader memory_indirectCRL;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_indirectCRL);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'indirectCRL' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - indirectCRL ++/
                typeof(_indirectCRL) temp_indirectCRL;
                result = typeof(temp_indirectCRL).fromDecoding!ruleset(memory_indirectCRL, temp_indirectCRL, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'indirectCRL' in type "~__traits(identifier, typeof(this))~":");
                result = this.setIndirectCRL(temp_indirectCRL);
                if(result.isError)
                    return result.wrapError("when setting field 'indirectCRL' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_indirectCRL.buffer, backtrack_indirectCRL.cursor);
                result = this.setIndirectCRL(defaultOfIndirectCRL());
                if(result.isError)
                    return result.wrapError("when setting field 'indirectCRL' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setIndirectCRL(defaultOfIndirectCRL());
            if(result.isError)
                return result.wrapError("when setting field 'indirectCRL' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        /+++ TAG FOR FIELD: onlyContainsAttributeCerts +++/
        auto backtrack_onlyContainsAttributeCerts = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'onlyContainsAttributeCerts' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 5)
            {
                jbuf.MemoryReader memory_onlyContainsAttributeCerts;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_onlyContainsAttributeCerts);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'onlyContainsAttributeCerts' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - onlyContainsAttributeCerts ++/
                typeof(_onlyContainsAttributeCerts) temp_onlyContainsAttributeCerts;
                result = typeof(temp_onlyContainsAttributeCerts).fromDecoding!ruleset(memory_onlyContainsAttributeCerts, temp_onlyContainsAttributeCerts, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'onlyContainsAttributeCerts' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOnlyContainsAttributeCerts(temp_onlyContainsAttributeCerts);
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsAttributeCerts' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_onlyContainsAttributeCerts.buffer, backtrack_onlyContainsAttributeCerts.cursor);
                result = this.setOnlyContainsAttributeCerts(defaultOfOnlyContainsAttributeCerts());
                if(result.isError)
                    return result.wrapError("when setting field 'onlyContainsAttributeCerts' to default value in type "~__traits(identifier, typeof(this))~":");
            }
        }
        else
        {
            result = this.setOnlyContainsAttributeCerts(defaultOfOnlyContainsAttributeCerts());
            if(result.isError)
                return result.wrapError("when setting field 'onlyContainsAttributeCerts' to default value in type "~__traits(identifier, typeof(this))~":");
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE IssuingDistributionPoint there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_ce_deltaCRLIndicator(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 27, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct BaseCRLNumber
{
    private
    {
        .CRLNumber _value;
        bool _isSet;
    }

    jres.Result set(
        .CRLNumber newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .CRLNumber get(
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
        static if(__traits(hasMember, .CRLNumber, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_cRLReasons(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 21, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ce_certificateIssuer(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 29, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct CertificateIssuer
{
    private
    {
        .GeneralNames _value;
        bool _isSet;
    }

    jres.Result set(
        .GeneralNames newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .GeneralNames get(
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
        static if(__traits(hasMember, .GeneralNames, "toString"))
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

asn1.Asn1ObjectIdentifier id_ce_holdInstructionCode(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 23, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

struct HoldInstructionCode
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

asn1.Asn1ObjectIdentifier holdInstruction(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_holdinstruction_none(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 2, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_holdinstruction_callissuer(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 2, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_holdinstruction_reject(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 2, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ce_invalidityDate(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 24, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}
