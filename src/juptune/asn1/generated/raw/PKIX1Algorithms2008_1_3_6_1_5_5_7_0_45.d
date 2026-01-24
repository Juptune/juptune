module juptune.asn1.generated.raw.PKIX1Algorithms2008_1_3_6_1_5_5_7_0_45;
static import PKIX1Algorithms88_1_3_6_1_5_5_7_0_17 = juptune.asn1.generated.raw.PKIX1Algorithms88_1_3_6_1_5_5_7_0_17;

static import tcon = std.typecons;
static import asn1 = juptune.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier id_md2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 2, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_md5(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 2, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_sha1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        14, 3, 2, 26, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier rsaEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct RSAPublicKey
{
    private
    {
        bool _isSet_modulus;
        asn1.Asn1Integer _modulus;
        bool _isSet_publicExponent;
        asn1.Asn1Integer _publicExponent;
    }

    jres.Result setModulus(
        typeof(_modulus) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_modulus = true;
        _modulus = value;
        return jres.Result.noError;
    }

    typeof(_modulus) getModulus(
    ) @nogc nothrow
    {
        assert(_isSet_modulus, "Non-optional field 'modulus' has not been set yet - please use validate() to check!");
        return _modulus;
    }

    jres.Result setPublicExponent(
        typeof(_publicExponent) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_publicExponent = true;
        _publicExponent = value;
        return jres.Result.noError;
    }

    typeof(_publicExponent) getPublicExponent(
    ) @nogc nothrow
    {
        assert(_isSet_publicExponent, "Non-optional field 'publicExponent' has not been set yet - please use validate() to check!");
        return _publicExponent;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_modulus)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type RSAPublicKey non-optional field 'modulus' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_publicExponent)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type RSAPublicKey non-optional field 'publicExponent' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("modulus: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_modulus), "toString"))
            _modulus.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("publicExponent: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_publicExponent), "toString"))
            _publicExponent.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: modulus +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'modulus' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE RSAPublicKey when reading top level tag 2 for field 'modulus' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE RSAPublicKey when reading top level tag 2 for field 'modulus' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_modulus;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_modulus);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'modulus' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - modulus ++/
        typeof(_modulus) temp_modulus;
        result = typeof(temp_modulus).fromDecoding!ruleset(memory_modulus, temp_modulus, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'modulus' in type "~__traits(identifier, typeof(this))~":");
        result = this.setModulus(temp_modulus);
        if(result.isError)
            return result.wrapError("when setting field 'modulus' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: publicExponent +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'publicExponent' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE RSAPublicKey when reading top level tag 2 for field 'publicExponent' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE RSAPublicKey when reading top level tag 2 for field 'publicExponent' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_publicExponent;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_publicExponent);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'publicExponent' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - publicExponent ++/
        typeof(_publicExponent) temp_publicExponent;
        result = typeof(temp_publicExponent).fromDecoding!ruleset(memory_publicExponent, temp_publicExponent, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'publicExponent' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPublicExponent(temp_publicExponent);
        if(result.isError)
            return result.wrapError("when setting field 'publicExponent' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE RSAPublicKey there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_dsa(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 4, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct DSAPublicKey
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

struct DSS_Parms
{
    private
    {
        bool _isSet_p;
        asn1.Asn1Integer _p;
        bool _isSet_q;
        asn1.Asn1Integer _q;
        bool _isSet_g;
        asn1.Asn1Integer _g;
    }

    jres.Result setP(
        typeof(_p) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_p = true;
        _p = value;
        return jres.Result.noError;
    }

    typeof(_p) getP(
    ) @nogc nothrow
    {
        assert(_isSet_p, "Non-optional field 'p' has not been set yet - please use validate() to check!");
        return _p;
    }

    jres.Result setQ(
        typeof(_q) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_q = true;
        _q = value;
        return jres.Result.noError;
    }

    typeof(_q) getQ(
    ) @nogc nothrow
    {
        assert(_isSet_q, "Non-optional field 'q' has not been set yet - please use validate() to check!");
        return _q;
    }

    jres.Result setG(
        typeof(_g) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_g = true;
        _g = value;
        return jres.Result.noError;
    }

    typeof(_g) getG(
    ) @nogc nothrow
    {
        assert(_isSet_g, "Non-optional field 'g' has not been set yet - please use validate() to check!");
        return _g;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_p)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DSS-Parms non-optional field 'p' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_q)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DSS-Parms non-optional field 'q' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_g)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DSS-Parms non-optional field 'g' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("p: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_p), "toString"))
            _p.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("q: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_q), "toString"))
            _q.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("g: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_g), "toString"))
            _g.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: p +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'p' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'p' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'p' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_p;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_p);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'p' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - p ++/
        typeof(_p) temp_p;
        result = typeof(temp_p).fromDecoding!ruleset(memory_p, temp_p, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'p' in type "~__traits(identifier, typeof(this))~":");
        result = this.setP(temp_p);
        if(result.isError)
            return result.wrapError("when setting field 'p' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: q +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'q' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'q' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'q' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_q;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_q);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'q' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - q ++/
        typeof(_q) temp_q;
        result = typeof(temp_q).fromDecoding!ruleset(memory_q, temp_q, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'q' in type "~__traits(identifier, typeof(this))~":");
        result = this.setQ(temp_q);
        if(result.isError)
            return result.wrapError("when setting field 'q' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: g +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'g' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'g' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DSS-Parms when reading top level tag 2 for field 'g' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_g;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_g);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'g' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - g ++/
        typeof(_g) temp_g;
        result = typeof(temp_g).fromDecoding!ruleset(memory_g, temp_g, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'g' in type "~__traits(identifier, typeof(this))~":");
        result = this.setG(temp_g);
        if(result.isError)
            return result.wrapError("when setting field 'g' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE DSS-Parms there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier dhpublicnumber(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10046 */ 0xCE, 0x3E, 2, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct DHPublicKey
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

struct DomainParameters
{
    private
    {
        bool _isSet_p;
        asn1.Asn1Integer _p;
        bool _isSet_g;
        asn1.Asn1Integer _g;
        bool _isSet_q;
        asn1.Asn1Integer _q;
        bool _isSet_j;
        asn1.Asn1Integer _j;
        bool _isSet_validationParms;
        .ValidationParms _validationParms;
    }

    jres.Result setP(
        typeof(_p) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_p = true;
        _p = value;
        return jres.Result.noError;
    }

    typeof(_p) getP(
    ) @nogc nothrow
    {
        assert(_isSet_p, "Non-optional field 'p' has not been set yet - please use validate() to check!");
        return _p;
    }

    jres.Result setG(
        typeof(_g) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_g = true;
        _g = value;
        return jres.Result.noError;
    }

    typeof(_g) getG(
    ) @nogc nothrow
    {
        assert(_isSet_g, "Non-optional field 'g' has not been set yet - please use validate() to check!");
        return _g;
    }

    jres.Result setQ(
        typeof(_q) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_q = true;
        _q = value;
        return jres.Result.noError;
    }

    typeof(_q) getQ(
    ) @nogc nothrow
    {
        assert(_isSet_q, "Non-optional field 'q' has not been set yet - please use validate() to check!");
        return _q;
    }

    jres.Result setJ(
        typeof(_j) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_j = true;
        _j = value;
        return jres.Result.noError;
    }

    jres.Result setJ(
        tcon.Nullable!(asn1.Asn1Integer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setJ(value.get());
        }
        else
            _isSet_j = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Integer) getJ(
    ) @nogc nothrow
    {
        if(_isSet_j)
            return typeof(return)(_j);
        return typeof(return).init;
    }

    jres.Result setValidationParms(
        typeof(_validationParms) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_validationParms = true;
        _validationParms = value;
        return jres.Result.noError;
    }

    jres.Result setValidationParms(
        tcon.Nullable!(.ValidationParms) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setValidationParms(value.get());
        }
        else
            _isSet_validationParms = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.ValidationParms) getValidationParms(
    ) @nogc nothrow
    {
        if(_isSet_validationParms)
            return typeof(return)(_validationParms);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_p)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DomainParameters non-optional field 'p' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_g)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DomainParameters non-optional field 'g' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_q)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DomainParameters non-optional field 'q' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("p: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_p), "toString"))
            _p.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("g: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_g), "toString"))
            _g.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("q: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_q), "toString"))
            _q.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("j: ");
        sink("\n");
        if(_isSet_j)
        {
            static if(__traits(hasMember, typeof(_j), "toString"))
                _j.toString(sink, depth+1);
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
        sink("validationParms: ");
        sink("\n");
        if(_isSet_validationParms)
        {
            static if(__traits(hasMember, typeof(_validationParms), "toString"))
                _validationParms.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: p +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'p' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'p' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'p' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_p;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_p);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'p' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - p ++/
        typeof(_p) temp_p;
        result = typeof(temp_p).fromDecoding!ruleset(memory_p, temp_p, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'p' in type "~__traits(identifier, typeof(this))~":");
        result = this.setP(temp_p);
        if(result.isError)
            return result.wrapError("when setting field 'p' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: g +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'g' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'g' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'g' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_g;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_g);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'g' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - g ++/
        typeof(_g) temp_g;
        result = typeof(temp_g).fromDecoding!ruleset(memory_g, temp_g, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'g' in type "~__traits(identifier, typeof(this))~":");
        result = this.setG(temp_g);
        if(result.isError)
            return result.wrapError("when setting field 'g' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: q +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'q' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'q' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DomainParameters when reading top level tag 2 for field 'q' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_q;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_q);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'q' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - q ++/
        typeof(_q) temp_q;
        result = typeof(temp_q).fromDecoding!ruleset(memory_q, temp_q, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'q' in type "~__traits(identifier, typeof(this))~":");
        result = this.setQ(temp_q);
        if(result.isError)
            return result.wrapError("when setting field 'q' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: j +++/
        auto backtrack_j = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'j' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_j;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_j);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'j' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - j ++/
                typeof(_j) temp_j;
                result = typeof(temp_j).fromDecoding!ruleset(memory_j, temp_j, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'j' in type "~__traits(identifier, typeof(this))~":");
                result = this.setJ(temp_j);
                if(result.isError)
                    return result.wrapError("when setting field 'j' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_j.buffer, backtrack_j.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: validationParms +++/
        auto backtrack_validationParms = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'validationParms' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_validationParms;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_validationParms);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'validationParms' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - validationParms ++/
                typeof(_validationParms) temp_validationParms;
                result = temp_validationParms.fromDecoding!ruleset(memory_validationParms, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'validationParms' in type "~__traits(identifier, typeof(this))~":");
                result = this.setValidationParms(temp_validationParms);
                if(result.isError)
                    return result.wrapError("when setting field 'validationParms' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_validationParms.buffer, backtrack_validationParms.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE DomainParameters there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ValidationParms
{
    private
    {
        bool _isSet_seed;
        asn1.Asn1BitString _seed;
        bool _isSet_pgenCounter;
        asn1.Asn1Integer _pgenCounter;
    }

    jres.Result setSeed(
        typeof(_seed) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_seed = true;
        _seed = value;
        return jres.Result.noError;
    }

    typeof(_seed) getSeed(
    ) @nogc nothrow
    {
        assert(_isSet_seed, "Non-optional field 'seed' has not been set yet - please use validate() to check!");
        return _seed;
    }

    jres.Result setPgenCounter(
        typeof(_pgenCounter) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_pgenCounter = true;
        _pgenCounter = value;
        return jres.Result.noError;
    }

    typeof(_pgenCounter) getPgenCounter(
    ) @nogc nothrow
    {
        assert(_isSet_pgenCounter, "Non-optional field 'pgenCounter' has not been set yet - please use validate() to check!");
        return _pgenCounter;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_seed)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ValidationParms non-optional field 'seed' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_pgenCounter)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ValidationParms non-optional field 'pgenCounter' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("seed: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_seed), "toString"))
            _seed.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("pgenCounter: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_pgenCounter), "toString"))
            _pgenCounter.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: seed +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'seed' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ValidationParms when reading top level tag 3 for field 'seed' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ValidationParms when reading top level tag 3 for field 'seed' the tag's value was expected to be 3", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_seed;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_seed);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'seed' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - seed ++/
        typeof(_seed) temp_seed;
        result = typeof(temp_seed).fromDecoding!ruleset(memory_seed, temp_seed, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'seed' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSeed(temp_seed);
        if(result.isError)
            return result.wrapError("when setting field 'seed' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: pgenCounter +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'pgenCounter' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ValidationParms when reading top level tag 2 for field 'pgenCounter' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ValidationParms when reading top level tag 2 for field 'pgenCounter' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_pgenCounter;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_pgenCounter);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'pgenCounter' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - pgenCounter ++/
        typeof(_pgenCounter) temp_pgenCounter;
        result = typeof(temp_pgenCounter).fromDecoding!ruleset(memory_pgenCounter, temp_pgenCounter, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'pgenCounter' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPgenCounter(temp_pgenCounter);
        if(result.isError)
            return result.wrapError("when setting field 'pgenCounter' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ValidationParms there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_keyExchangeAlgorithm(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 2, 1, 1, 22, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

struct KEA_Parms_Id
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

asn1.Asn1ObjectIdentifier id_ecPublicKey(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 2, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct ECPoint
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

struct ECParameters
{
    enum Choice
    {
        _FAILSAFE,
        namedCurve,
    }

    union Value
    {
        asn1.Asn1ObjectIdentifier namedCurve;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1ObjectIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.namedCurve)) @nogc nothrow handle_namedCurve,
    ) @nogc nothrow
    {
        if(_choice == Choice.namedCurve)
            return handle_namedCurve(_value.namedCurve);
        assert(false, "attempted to use an uninitialised ECParameters!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.namedCurve))  handle_namedCurve,
    ) 
    {
        if(_choice == Choice.namedCurve)
            return handle_namedCurve(_value.namedCurve);
        assert(false, "attempted to use an uninitialised ECParameters!");

    }

    jres.Result setNamedCurve(
        typeof(Value.namedCurve) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.namedCurve = value;
        _choice = Choice.namedCurve;
        return jres.Result.noError;
    }

    typeof(Value.namedCurve) getNamedCurve(
    ) @nogc nothrow
    {
        assert(_choice == Choice.namedCurve, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'namedCurve'");
        return _value.namedCurve;
    }

    bool isNamedCurve(
    ) @nogc nothrow const
    {
        return _choice == Choice.namedCurve;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 6)
        {
            /++ FIELD - namedCurve ++/
            typeof(Value.namedCurve) temp_namedCurve;
            result = typeof(temp_namedCurve).fromDecoding!ruleset(memory, temp_namedCurve, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'namedCurve' in type "~__traits(identifier, typeof(this))~":");
            result = this.setNamedCurve(temp_namedCurve);
            if(result.isError)
                return result.wrapError("when setting field 'namedCurve' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type ECParameters the identifier tag & class were unable to match any known option");
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
        if(isNamedCurve)
        {
            depth++;
            putIndent();
            sink("namedCurve: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getNamedCurve()), "toString"))
                _value.namedCurve.toString(sink, depth+1);
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

asn1.Asn1ObjectIdentifier id_ecDH(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 1, 12, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ecMQV(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 1, 13, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier md2WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier md5WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sha1WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_dsa_with_sha1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10040 */ 0xCE, 0x38, 4, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_dsa_with_sha224(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 3, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_dsa_with_sha256(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 3, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier ecdsa_with_SHA1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier ecdsa_with_SHA224(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 3, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier ecdsa_with_SHA256(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 3, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier ecdsa_with_SHA384(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 3, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier ecdsa_with_SHA512(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 3, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct DSA_Sig_Value
{
    private
    {
        bool _isSet_r;
        asn1.Asn1Integer _r;
        bool _isSet_s;
        asn1.Asn1Integer _s;
    }

    jres.Result setR(
        typeof(_r) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_r = true;
        _r = value;
        return jres.Result.noError;
    }

    typeof(_r) getR(
    ) @nogc nothrow
    {
        assert(_isSet_r, "Non-optional field 'r' has not been set yet - please use validate() to check!");
        return _r;
    }

    jres.Result setS(
        typeof(_s) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_s = true;
        _s = value;
        return jres.Result.noError;
    }

    typeof(_s) getS(
    ) @nogc nothrow
    {
        assert(_isSet_s, "Non-optional field 's' has not been set yet - please use validate() to check!");
        return _s;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_r)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DSA-Sig-Value non-optional field 'r' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_s)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DSA-Sig-Value non-optional field 's' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("r: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_r), "toString"))
            _r.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("s: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_s), "toString"))
            _s.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: r +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'r' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DSA-Sig-Value when reading top level tag 2 for field 'r' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DSA-Sig-Value when reading top level tag 2 for field 'r' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_r;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_r);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'r' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - r ++/
        typeof(_r) temp_r;
        result = typeof(temp_r).fromDecoding!ruleset(memory_r, temp_r, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'r' in type "~__traits(identifier, typeof(this))~":");
        result = this.setR(temp_r);
        if(result.isError)
            return result.wrapError("when setting field 'r' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: s +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 's' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DSA-Sig-Value when reading top level tag 2 for field 's' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DSA-Sig-Value when reading top level tag 2 for field 's' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_s;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_s);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 's' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - s ++/
        typeof(_s) temp_s;
        result = typeof(temp_s).fromDecoding!ruleset(memory_s, temp_s, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 's' in type "~__traits(identifier, typeof(this))~":");
        result = this.setS(temp_s);
        if(result.isError)
            return result.wrapError("when setting field 's' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE DSA-Sig-Value there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ECDSA_Sig_Value
{
    private
    {
        bool _isSet_r;
        asn1.Asn1Integer _r;
        bool _isSet_s;
        asn1.Asn1Integer _s;
    }

    jres.Result setR(
        typeof(_r) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_r = true;
        _r = value;
        return jres.Result.noError;
    }

    typeof(_r) getR(
    ) @nogc nothrow
    {
        assert(_isSet_r, "Non-optional field 'r' has not been set yet - please use validate() to check!");
        return _r;
    }

    jres.Result setS(
        typeof(_s) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_s = true;
        _s = value;
        return jres.Result.noError;
    }

    typeof(_s) getS(
    ) @nogc nothrow
    {
        assert(_isSet_s, "Non-optional field 's' has not been set yet - please use validate() to check!");
        return _s;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_r)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECDSA-Sig-Value non-optional field 'r' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_s)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECDSA-Sig-Value non-optional field 's' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("r: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_r), "toString"))
            _r.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("s: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_s), "toString"))
            _s.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: r +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'r' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECDSA-Sig-Value when reading top level tag 2 for field 'r' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECDSA-Sig-Value when reading top level tag 2 for field 'r' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_r;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_r);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'r' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - r ++/
        typeof(_r) temp_r;
        result = typeof(temp_r).fromDecoding!ruleset(memory_r, temp_r, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'r' in type "~__traits(identifier, typeof(this))~":");
        result = this.setR(temp_r);
        if(result.isError)
            return result.wrapError("when setting field 'r' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: s +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 's' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECDSA-Sig-Value when reading top level tag 2 for field 's' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECDSA-Sig-Value when reading top level tag 2 for field 's' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_s;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_s);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 's' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - s ++/
        typeof(_s) temp_s;
        result = typeof(temp_s).fromDecoding!ruleset(memory_s, temp_s, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 's' in type "~__traits(identifier, typeof(this))~":");
        result = this.setS(temp_s);
        if(result.isError)
            return result.wrapError("when setting field 's' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ECDSA-Sig-Value there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier secp192r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect163k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect163r2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 15, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp224r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 33, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect233k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 26, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect233r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 27, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp256r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 7, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect283k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 16, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect283r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 17, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp384r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 34, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect409k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 36, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect409r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 37, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp521r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 35, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect571k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 38, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sect571r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 132 */ 0x81, 0x4, 0, 39, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}
