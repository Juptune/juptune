module juptune.data.asn1.generated.raw.PKIX1Algorithms88_1_3_6_1_5_5_7_0_17;

static import tcon = std.typecons;
static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier md2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 2, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier md5(
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

struct Dss_Parms
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
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Dss-Parms non-optional field 'p' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_q)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Dss-Parms non-optional field 'q' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_g)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Dss-Parms non-optional field 'g' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'p' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'p' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'q' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'q' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'g' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Dss-Parms when reading top level tag 2 for field 'g' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Dss-Parms there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

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

struct Dss_Sig_Value
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
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Dss-Sig-Value non-optional field 'r' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_s)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Dss-Sig-Value non-optional field 's' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Dss-Sig-Value when reading top level tag 2 for field 'r' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Dss-Sig-Value when reading top level tag 2 for field 'r' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Dss-Sig-Value when reading top level tag 2 for field 's' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Dss-Sig-Value when reading top level tag 2 for field 's' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Dss-Sig-Value there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier pkcs_1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
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

asn1.Asn1ObjectIdentifier ansi_X9_62(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct FieldID
{
    private
    {
        bool _isSet_fieldType;
        asn1.Asn1ObjectIdentifier _fieldType;
        bool _isSet_parameters;
        asn1.Asn1Any _parameters;
    }

    jres.Result setFieldType(
        typeof(_fieldType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_fieldType = true;
        _fieldType = value;
        return jres.Result.noError;
    }

    typeof(_fieldType) getFieldType(
    ) @nogc nothrow
    {
        assert(_isSet_fieldType, "Non-optional field 'fieldType' has not been set yet - please use validate() to check!");
        return _fieldType;
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

    typeof(_parameters) getParameters(
    ) @nogc nothrow
    {
        assert(_isSet_parameters, "Non-optional field 'parameters' has not been set yet - please use validate() to check!");
        return _parameters;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_fieldType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type FieldID non-optional field 'fieldType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_parameters)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type FieldID non-optional field 'parameters' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("fieldType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_fieldType), "toString"))
            _fieldType.toString(sink, depth+1);
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
        static if(__traits(hasMember, typeof(_parameters), "toString"))
            _parameters.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: fieldType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'fieldType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE FieldID when reading top level tag 6 for field 'fieldType' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE FieldID when reading top level tag 6 for field 'fieldType' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_fieldType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_fieldType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'fieldType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - fieldType ++/
        typeof(_fieldType) temp_fieldType;
        result = typeof(temp_fieldType).fromDecoding!ruleset(memory_fieldType, temp_fieldType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'fieldType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setFieldType(temp_fieldType);
        if(result.isError)
            return result.wrapError("when setting field 'fieldType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: parameters +++/
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

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE FieldID there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_ecSigType(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
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

asn1.Asn1ObjectIdentifier id_fieldType(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime_field(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct Prime_p
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

asn1.Asn1ObjectIdentifier characteristic_two_field(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct Characteristic_two
{
    private
    {
        bool _isSet_m;
        asn1.Asn1Integer _m;
        bool _isSet_basis;
        asn1.Asn1ObjectIdentifier _basis;
        bool _isSet_parameters;
        asn1.Asn1Any _parameters;
    }

    jres.Result setM(
        typeof(_m) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_m = true;
        _m = value;
        return jres.Result.noError;
    }

    typeof(_m) getM(
    ) @nogc nothrow
    {
        assert(_isSet_m, "Non-optional field 'm' has not been set yet - please use validate() to check!");
        return _m;
    }

    jres.Result setBasis(
        typeof(_basis) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_basis = true;
        _basis = value;
        return jres.Result.noError;
    }

    typeof(_basis) getBasis(
    ) @nogc nothrow
    {
        assert(_isSet_basis, "Non-optional field 'basis' has not been set yet - please use validate() to check!");
        return _basis;
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

    typeof(_parameters) getParameters(
    ) @nogc nothrow
    {
        assert(_isSet_parameters, "Non-optional field 'parameters' has not been set yet - please use validate() to check!");
        return _parameters;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_m)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Characteristic-two non-optional field 'm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_basis)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Characteristic-two non-optional field 'basis' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_parameters)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Characteristic-two non-optional field 'parameters' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("m: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_m), "toString"))
            _m.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("basis: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_basis), "toString"))
            _basis.toString(sink, depth+1);
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
        static if(__traits(hasMember, typeof(_parameters), "toString"))
            _parameters.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: m +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Characteristic-two when reading top level tag 2 for field 'm' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Characteristic-two when reading top level tag 2 for field 'm' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_m;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_m);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - m ++/
        typeof(_m) temp_m;
        result = typeof(temp_m).fromDecoding!ruleset(memory_m, temp_m, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setM(temp_m);
        if(result.isError)
            return result.wrapError("when setting field 'm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: basis +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'basis' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Characteristic-two when reading top level tag 6 for field 'basis' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Characteristic-two when reading top level tag 6 for field 'basis' the tag's value was expected to be 6", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_basis;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_basis);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'basis' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - basis ++/
        typeof(_basis) temp_basis;
        result = typeof(temp_basis).fromDecoding!ruleset(memory_basis, temp_basis, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'basis' in type "~__traits(identifier, typeof(this))~":");
        result = this.setBasis(temp_basis);
        if(result.isError)
            return result.wrapError("when setting field 'basis' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: parameters +++/
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

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Characteristic-two there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_characteristic_two_basis(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 2, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier gnBasis(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 2, 3, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier tpBasis(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 2, 3, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct Trinomial
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

asn1.Asn1ObjectIdentifier ppBasis(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 1, 2, 3, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct Pentanomial
{
    private
    {
        bool _isSet_k1;
        asn1.Asn1Integer _k1;
        bool _isSet_k2;
        asn1.Asn1Integer _k2;
        bool _isSet_k3;
        asn1.Asn1Integer _k3;
    }

    jres.Result setK1(
        typeof(_k1) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_k1 = true;
        _k1 = value;
        return jres.Result.noError;
    }

    typeof(_k1) getK1(
    ) @nogc nothrow
    {
        assert(_isSet_k1, "Non-optional field 'k1' has not been set yet - please use validate() to check!");
        return _k1;
    }

    jres.Result setK2(
        typeof(_k2) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_k2 = true;
        _k2 = value;
        return jres.Result.noError;
    }

    typeof(_k2) getK2(
    ) @nogc nothrow
    {
        assert(_isSet_k2, "Non-optional field 'k2' has not been set yet - please use validate() to check!");
        return _k2;
    }

    jres.Result setK3(
        typeof(_k3) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_k3 = true;
        _k3 = value;
        return jres.Result.noError;
    }

    typeof(_k3) getK3(
    ) @nogc nothrow
    {
        assert(_isSet_k3, "Non-optional field 'k3' has not been set yet - please use validate() to check!");
        return _k3;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_k1)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Pentanomial non-optional field 'k1' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_k2)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Pentanomial non-optional field 'k2' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_k3)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Pentanomial non-optional field 'k3' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("k1: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_k1), "toString"))
            _k1.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("k2: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_k2), "toString"))
            _k2.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("k3: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_k3), "toString"))
            _k3.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: k1 +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'k1' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k1' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k1' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_k1;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_k1);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'k1' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - k1 ++/
        typeof(_k1) temp_k1;
        result = typeof(temp_k1).fromDecoding!ruleset(memory_k1, temp_k1, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'k1' in type "~__traits(identifier, typeof(this))~":");
        result = this.setK1(temp_k1);
        if(result.isError)
            return result.wrapError("when setting field 'k1' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: k2 +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'k2' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k2' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k2' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_k2;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_k2);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'k2' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - k2 ++/
        typeof(_k2) temp_k2;
        result = typeof(temp_k2).fromDecoding!ruleset(memory_k2, temp_k2, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'k2' in type "~__traits(identifier, typeof(this))~":");
        result = this.setK2(temp_k2);
        if(result.isError)
            return result.wrapError("when setting field 'k2' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: k3 +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'k3' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k3' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Pentanomial when reading top level tag 2 for field 'k3' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_k3;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_k3);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'k3' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - k3 ++/
        typeof(_k3) temp_k3;
        result = typeof(temp_k3).fromDecoding!ruleset(memory_k3, temp_k3, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'k3' in type "~__traits(identifier, typeof(this))~":");
        result = this.setK3(temp_k3);
        if(result.isError)
            return result.wrapError("when setting field 'k3' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Pentanomial there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct FieldElement
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

struct EcpkParameters
{
    enum Choice
    {
        _FAILSAFE,
        ecParameters,
        namedCurve,
        implicitlyCA,
    }

    union Value
    {
        .ECParameters ecParameters;
        asn1.Asn1ObjectIdentifier namedCurve;
        asn1.Asn1Null implicitlyCA;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.ECParameters), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1ObjectIdentifier), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Null), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.ecParameters)) @nogc nothrow handle_ecParameters,
        scope jres.Result delegate(typeof(Value.namedCurve)) @nogc nothrow handle_namedCurve,
        scope jres.Result delegate(typeof(Value.implicitlyCA)) @nogc nothrow handle_implicitlyCA,
    ) @nogc nothrow
    {
        if(_choice == Choice.ecParameters)
            return handle_ecParameters(_value.ecParameters);
        if(_choice == Choice.namedCurve)
            return handle_namedCurve(_value.namedCurve);
        if(_choice == Choice.implicitlyCA)
            return handle_implicitlyCA(_value.implicitlyCA);
        assert(false, "attempted to use an uninitialised EcpkParameters!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.ecParameters))  handle_ecParameters,
        scope jres.Result delegate(typeof(Value.namedCurve))  handle_namedCurve,
        scope jres.Result delegate(typeof(Value.implicitlyCA))  handle_implicitlyCA,
    ) 
    {
        if(_choice == Choice.ecParameters)
            return handle_ecParameters(_value.ecParameters);
        if(_choice == Choice.namedCurve)
            return handle_namedCurve(_value.namedCurve);
        if(_choice == Choice.implicitlyCA)
            return handle_implicitlyCA(_value.implicitlyCA);
        assert(false, "attempted to use an uninitialised EcpkParameters!");

    }

    jres.Result setEcParameters(
        typeof(Value.ecParameters) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.ecParameters = value;
        _choice = Choice.ecParameters;
        return jres.Result.noError;
    }

    typeof(Value.ecParameters) getEcParameters(
    ) @nogc nothrow
    {
        assert(_choice == Choice.ecParameters, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'ecParameters'");
        return _value.ecParameters;
    }

    bool isEcParameters(
    ) @nogc nothrow const
    {
        return _choice == Choice.ecParameters;
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

    jres.Result setImplicitlyCA(
        typeof(Value.implicitlyCA) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.implicitlyCA = value;
        _choice = Choice.implicitlyCA;
        return jres.Result.noError;
    }

    typeof(Value.implicitlyCA) getImplicitlyCA(
    ) @nogc nothrow
    {
        assert(_choice == Choice.implicitlyCA, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'implicitlyCA'");
        return _value.implicitlyCA;
    }

    bool isImplicitlyCA(
    ) @nogc nothrow const
    {
        return _choice == Choice.implicitlyCA;
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
            /++ FIELD - ecParameters ++/
            typeof(Value.ecParameters) temp_ecParameters;
            result = temp_ecParameters.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'ecParameters' in type "~__traits(identifier, typeof(this))~":");
            result = this.setEcParameters(temp_ecParameters);
            if(result.isError)
                return result.wrapError("when setting field 'ecParameters' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

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

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 5)
        {
            /++ FIELD - implicitlyCA ++/
            typeof(Value.implicitlyCA) temp_implicitlyCA;
            result = typeof(temp_implicitlyCA).fromDecoding!ruleset(memory, temp_implicitlyCA, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'implicitlyCA' in type "~__traits(identifier, typeof(this))~":");
            result = this.setImplicitlyCA(temp_implicitlyCA);
            if(result.isError)
                return result.wrapError("when setting field 'implicitlyCA' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type EcpkParameters the identifier tag & class were unable to match any known option");
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
        if(isEcParameters)
        {
            depth++;
            putIndent();
            sink("ecParameters: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getEcParameters()), "toString"))
                _value.ecParameters.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
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
        if(isImplicitlyCA)
        {
            depth++;
            putIndent();
            sink("implicitlyCA: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getImplicitlyCA()), "toString"))
                _value.implicitlyCA.toString(sink, depth+1);
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

struct ECParameters
{
    private
    {
        bool _isSet_version;
        .ECPVer _version;
        bool _isSet_fieldID;
        .FieldID _fieldID;
        bool _isSet_curve;
        .Curve _curve;
        bool _isSet_base;
        .ECPoint _base;
        bool _isSet_order;
        asn1.Asn1Integer _order;
        bool _isSet_cofactor;
        asn1.Asn1Integer _cofactor;
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

    jres.Result setFieldID(
        typeof(_fieldID) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_fieldID = true;
        _fieldID = value;
        return jres.Result.noError;
    }

    typeof(_fieldID) getFieldID(
    ) @nogc nothrow
    {
        assert(_isSet_fieldID, "Non-optional field 'fieldID' has not been set yet - please use validate() to check!");
        return _fieldID;
    }

    jres.Result setCurve(
        typeof(_curve) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_curve = true;
        _curve = value;
        return jres.Result.noError;
    }

    typeof(_curve) getCurve(
    ) @nogc nothrow
    {
        assert(_isSet_curve, "Non-optional field 'curve' has not been set yet - please use validate() to check!");
        return _curve;
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

    jres.Result setOrder(
        typeof(_order) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_order = true;
        _order = value;
        return jres.Result.noError;
    }

    typeof(_order) getOrder(
    ) @nogc nothrow
    {
        assert(_isSet_order, "Non-optional field 'order' has not been set yet - please use validate() to check!");
        return _order;
    }

    jres.Result setCofactor(
        typeof(_cofactor) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_cofactor = true;
        _cofactor = value;
        return jres.Result.noError;
    }

    jres.Result setCofactor(
        tcon.Nullable!(asn1.Asn1Integer) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCofactor(value.get());
        }
        else
            _isSet_cofactor = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Integer) getCofactor(
    ) @nogc nothrow
    {
        if(_isSet_cofactor)
            return typeof(return)(_cofactor);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECParameters non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_fieldID)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECParameters non-optional field 'fieldID' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_curve)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECParameters non-optional field 'curve' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_base)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECParameters non-optional field 'base' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_order)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ECParameters non-optional field 'order' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("fieldID: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_fieldID), "toString"))
            _fieldID.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("curve: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_curve), "toString"))
            _curve.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
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
        sink("order: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_order), "toString"))
            _order.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("cofactor: ");
        sink("\n");
        if(_isSet_cofactor)
        {
            static if(__traits(hasMember, typeof(_cofactor), "toString"))
                _cofactor.toString(sink, depth+1);
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
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECParameters when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECParameters when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: fieldID +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'fieldID' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECParameters when reading top level tag 16 for field 'fieldID' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECParameters when reading top level tag 16 for field 'fieldID' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_fieldID;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_fieldID);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'fieldID' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - fieldID ++/
        typeof(_fieldID) temp_fieldID;
        result = temp_fieldID.fromDecoding!ruleset(memory_fieldID, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'fieldID' in type "~__traits(identifier, typeof(this))~":");
        result = this.setFieldID(temp_fieldID);
        if(result.isError)
            return result.wrapError("when setting field 'fieldID' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: curve +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'curve' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECParameters when reading top level tag 16 for field 'curve' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECParameters when reading top level tag 16 for field 'curve' the tag's value was expected to be 16", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_curve;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_curve);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'curve' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - curve ++/
        typeof(_curve) temp_curve;
        result = temp_curve.fromDecoding!ruleset(memory_curve, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'curve' in type "~__traits(identifier, typeof(this))~":");
        result = this.setCurve(temp_curve);
        if(result.isError)
            return result.wrapError("when setting field 'curve' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: base +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'base' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECParameters when reading top level tag 4 for field 'base' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECParameters when reading top level tag 4 for field 'base' the tag's value was expected to be 4", jstr.String2("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: order +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'order' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ECParameters when reading top level tag 2 for field 'order' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ECParameters when reading top level tag 2 for field 'order' the tag's value was expected to be 2", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_order;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_order);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'order' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - order ++/
        typeof(_order) temp_order;
        result = typeof(temp_order).fromDecoding!ruleset(memory_order, temp_order, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'order' in type "~__traits(identifier, typeof(this))~":");
        result = this.setOrder(temp_order);
        if(result.isError)
            return result.wrapError("when setting field 'order' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: cofactor +++/
        auto backtrack_cofactor = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'cofactor' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_cofactor;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_cofactor);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'cofactor' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - cofactor ++/
                typeof(_cofactor) temp_cofactor;
                result = typeof(temp_cofactor).fromDecoding!ruleset(memory_cofactor, temp_cofactor, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'cofactor' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCofactor(temp_cofactor);
                if(result.isError)
                    return result.wrapError("when setting field 'cofactor' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_cofactor.buffer, backtrack_cofactor.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ECParameters there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ECPVer
{
    enum NamedNumber
    {
        ecpVer1 = 1,
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

struct Curve
{
    private
    {
        bool _isSet_a;
        .FieldElement _a;
        bool _isSet_b;
        .FieldElement _b;
        bool _isSet_seed;
        asn1.Asn1BitString _seed;
    }

    jres.Result setA(
        typeof(_a) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_a = true;
        _a = value;
        return jres.Result.noError;
    }

    typeof(_a) getA(
    ) @nogc nothrow
    {
        assert(_isSet_a, "Non-optional field 'a' has not been set yet - please use validate() to check!");
        return _a;
    }

    jres.Result setB(
        typeof(_b) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_b = true;
        _b = value;
        return jres.Result.noError;
    }

    typeof(_b) getB(
    ) @nogc nothrow
    {
        assert(_isSet_b, "Non-optional field 'b' has not been set yet - please use validate() to check!");
        return _b;
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

    jres.Result setSeed(
        tcon.Nullable!(asn1.Asn1BitString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setSeed(value.get());
        }
        else
            _isSet_seed = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1BitString) getSeed(
    ) @nogc nothrow
    {
        if(_isSet_seed)
            return typeof(return)(_seed);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_a)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Curve non-optional field 'a' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_b)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Curve non-optional field 'b' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("a: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_a), "toString"))
            _a.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("b: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_b), "toString"))
            _b.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("seed: ");
        sink("\n");
        if(_isSet_seed)
        {
            static if(__traits(hasMember, typeof(_seed), "toString"))
                _seed.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: a +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'a' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Curve when reading top level tag 4 for field 'a' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Curve when reading top level tag 4 for field 'a' the tag's value was expected to be 4", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_a;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_a);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'a' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - a ++/
        typeof(_a) temp_a;
        result = temp_a.fromDecoding!ruleset(memory_a, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'a' in type "~__traits(identifier, typeof(this))~":");
        result = this.setA(temp_a);
        if(result.isError)
            return result.wrapError("when setting field 'a' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: b +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'b' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Curve when reading top level tag 4 for field 'b' the tag's class was expected to be universal", jstr.String2("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Curve when reading top level tag 4 for field 'b' the tag's value was expected to be 4", jstr.String2("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_b;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_b);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'b' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - b ++/
        typeof(_b) temp_b;
        result = temp_b.fromDecoding!ruleset(memory_b, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'b' in type "~__traits(identifier, typeof(this))~":");
        result = this.setB(temp_b);
        if(result.isError)
            return result.wrapError("when setting field 'b' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: seed +++/
        auto backtrack_seed = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'seed' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 3)
            {
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

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_seed.buffer, backtrack_seed.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Curve there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

asn1.Asn1ObjectIdentifier id_publicKeyType(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

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

asn1.Asn1ObjectIdentifier ellipticCurve(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c_TwoCurve(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb163v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb163v2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb163v3(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb176w1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb191v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb191v2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 6, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb191v3(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 7, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2onb191v4(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 8, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2onb191v5(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 9, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb208w1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 10, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb239v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 11, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb239v2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 12, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb239v3(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 13, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2onb239v4(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 14, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2onb239v5(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 15, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb272w1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 16, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb304w1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 17, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb359v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 18, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2pnb368w1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 19, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier c2tnb431r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 0, 20, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier primeCurve(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime192v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime192v2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime192v3(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime239v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime239v2(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime239v3(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 6, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier prime256v1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 1, 7, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_sha224(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 2, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_sha256(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 2, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_sha384(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 2, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_sha512(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, 1, 101, 3, 4, 2, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 16, mainValue__value);
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

asn1.Asn1ObjectIdentifier sha224WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 14, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sha256WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 11, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sha384WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 12, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier sha512WithRSAEncryption(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 1, 13, 
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

asn1.Asn1ObjectIdentifier secp192k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 31, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

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

asn1.Asn1ObjectIdentifier secp224k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 32, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp224r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 33, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp256k1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 10, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
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

asn1.Asn1ObjectIdentifier secp384r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 34, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier secp521r1(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 10045 */ 0xCE, 0x3D, 3, 35, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}
