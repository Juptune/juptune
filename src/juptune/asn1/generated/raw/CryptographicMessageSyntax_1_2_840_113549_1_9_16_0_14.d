module juptune.asn1.generated.raw.CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14;
static import PKIX1Explicit88_1_3_6_1_5_5_7_0_18 = juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;

static import tcon = std.typecons;
static import asn1 = juptune.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string;
static import utf8 = juptune.data.utf8;

struct ContentInfo
{
    private
    {
        bool _isSet_contentType;
        .ContentType _contentType;
        bool _isSet_content;
        asn1.Asn1Any _content;
    }

    jres.Result setContentType(
        typeof(_contentType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_contentType = true;
        _contentType = value;
        return jres.Result.noError;
    }

    typeof(_contentType) getContentType(
    ) @nogc nothrow
    {
        assert(_isSet_contentType, "Non-optional field 'contentType' has not been set yet - please use validate() to check!");
        return _contentType;
    }

    jres.Result setContent(
        typeof(_content) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_content = true;
        _content = value;
        return jres.Result.noError;
    }

    typeof(_content) getContent(
    ) @nogc nothrow
    {
        assert(_isSet_content, "Non-optional field 'content' has not been set yet - please use validate() to check!");
        return _content;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_contentType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ContentInfo non-optional field 'contentType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_content)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ContentInfo non-optional field 'content' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("contentType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_contentType), "toString"))
            _contentType.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("content: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_content), "toString"))
            _content.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: contentType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ContentInfo when reading top level tag 6 for field 'contentType' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ContentInfo when reading top level tag 6 for field 'contentType' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_contentType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_contentType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - contentType ++/
        typeof(_contentType) temp_contentType;
        result = temp_contentType.fromDecoding!ruleset(memory_contentType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setContentType(temp_contentType);
        if(result.isError)
            return result.wrapError("when setting field 'contentType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: content +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'content' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ContentInfo when reading top level tag 0 for field 'content' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ContentInfo when reading top level tag 0 for field 'content' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_content;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_content);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'content' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - content ++/
        jbuf.MemoryReader memory_0content;
            // EXPLICIT TAG - 0
            if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field content a primitive tag was found when a constructed one was expected");
            if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'content' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
            if(componentHeader.identifier.tag != 0)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'content' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
            result = asn1.asn1DecodeComponentHeader!ruleset(memory_content, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'content' in type "~__traits(identifier, typeof(this))~":");
            result = asn1.asn1ReadContentBytes(memory_content, componentHeader.length, memory_0content);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'content' in type "~__traits(identifier, typeof(this))~":");
        typeof(_content) temp_content;
        result = typeof(temp_content).fromDecoding!ruleset(memory_0content, temp_content, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'content' in type "~__traits(identifier, typeof(this))~":");
        result = this.setContent(temp_content);
        if(result.isError)
            return result.wrapError("when setting field 'content' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ContentInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ContentType
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

struct SignedData
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_digestAlgorithms;
        .DigestAlgorithmIdentifiers _digestAlgorithms;
        bool _isSet_encapContentInfo;
        .EncapsulatedContentInfo _encapContentInfo;
        bool _isSet_certificates;
        .CertificateSet _certificates;
        bool _isSet_crls;
        .CertificateRevocationLists _crls;
        bool _isSet_signerInfos;
        .SignerInfos _signerInfos;
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

    jres.Result setDigestAlgorithms(
        typeof(_digestAlgorithms) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_digestAlgorithms = true;
        _digestAlgorithms = value;
        return jres.Result.noError;
    }

    typeof(_digestAlgorithms) getDigestAlgorithms(
    ) @nogc nothrow
    {
        assert(_isSet_digestAlgorithms, "Non-optional field 'digestAlgorithms' has not been set yet - please use validate() to check!");
        return _digestAlgorithms;
    }

    jres.Result setEncapContentInfo(
        typeof(_encapContentInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encapContentInfo = true;
        _encapContentInfo = value;
        return jres.Result.noError;
    }

    typeof(_encapContentInfo) getEncapContentInfo(
    ) @nogc nothrow
    {
        assert(_isSet_encapContentInfo, "Non-optional field 'encapContentInfo' has not been set yet - please use validate() to check!");
        return _encapContentInfo;
    }

    jres.Result setCertificates(
        typeof(_certificates) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_certificates = true;
        _certificates = value;
        return jres.Result.noError;
    }

    jres.Result setCertificates(
        tcon.Nullable!(.CertificateSet) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCertificates(value.get());
        }
        else
            _isSet_certificates = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.CertificateSet) getCertificates(
    ) @nogc nothrow
    {
        if(_isSet_certificates)
            return typeof(return)(_certificates);
        return typeof(return).init;
    }

    jres.Result setCrls(
        typeof(_crls) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_crls = true;
        _crls = value;
        return jres.Result.noError;
    }

    jres.Result setCrls(
        tcon.Nullable!(.CertificateRevocationLists) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCrls(value.get());
        }
        else
            _isSet_crls = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.CertificateRevocationLists) getCrls(
    ) @nogc nothrow
    {
        if(_isSet_crls)
            return typeof(return)(_crls);
        return typeof(return).init;
    }

    jres.Result setSignerInfos(
        typeof(_signerInfos) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signerInfos = true;
        _signerInfos = value;
        return jres.Result.noError;
    }

    typeof(_signerInfos) getSignerInfos(
    ) @nogc nothrow
    {
        assert(_isSet_signerInfos, "Non-optional field 'signerInfos' has not been set yet - please use validate() to check!");
        return _signerInfos;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignedData non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_digestAlgorithms)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignedData non-optional field 'digestAlgorithms' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encapContentInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignedData non-optional field 'encapContentInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signerInfos)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignedData non-optional field 'signerInfos' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("digestAlgorithms: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_digestAlgorithms), "toString"))
            _digestAlgorithms.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encapContentInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encapContentInfo), "toString"))
            _encapContentInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("certificates: ");
        sink("\n");
        if(_isSet_certificates)
        {
            static if(__traits(hasMember, typeof(_certificates), "toString"))
                _certificates.toString(sink, depth+1);
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
        sink("crls: ");
        sink("\n");
        if(_isSet_crls)
        {
            static if(__traits(hasMember, typeof(_crls), "toString"))
                _crls.toString(sink, depth+1);
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
        sink("signerInfos: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_signerInfos), "toString"))
            _signerInfos.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignedData when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignedData when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: digestAlgorithms +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'digestAlgorithms' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignedData when reading top level tag 17 for field 'digestAlgorithms' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignedData when reading top level tag 17 for field 'digestAlgorithms' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_digestAlgorithms;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_digestAlgorithms);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'digestAlgorithms' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - digestAlgorithms ++/
        typeof(_digestAlgorithms) temp_digestAlgorithms;
        result = temp_digestAlgorithms.fromDecoding!ruleset(memory_digestAlgorithms, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'digestAlgorithms' in type "~__traits(identifier, typeof(this))~":");
        result = this.setDigestAlgorithms(temp_digestAlgorithms);
        if(result.isError)
            return result.wrapError("when setting field 'digestAlgorithms' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encapContentInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignedData when reading top level tag 16 for field 'encapContentInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignedData when reading top level tag 16 for field 'encapContentInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encapContentInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encapContentInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encapContentInfo ++/
        typeof(_encapContentInfo) temp_encapContentInfo;
        result = temp_encapContentInfo.fromDecoding!ruleset(memory_encapContentInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncapContentInfo(temp_encapContentInfo);
        if(result.isError)
            return result.wrapError("when setting field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: certificates +++/
        auto backtrack_certificates = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'certificates' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_certificates;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_certificates);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'certificates' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - certificates ++/
                typeof(_certificates) temp_certificates;
                result = temp_certificates.fromDecoding!ruleset(memory_certificates, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'certificates' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCertificates(temp_certificates);
                if(result.isError)
                    return result.wrapError("when setting field 'certificates' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_certificates.buffer, backtrack_certificates.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: crls +++/
        auto backtrack_crls = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'crls' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_crls;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_crls);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'crls' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - crls ++/
                typeof(_crls) temp_crls;
                result = temp_crls.fromDecoding!ruleset(memory_crls, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'crls' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCrls(temp_crls);
                if(result.isError)
                    return result.wrapError("when setting field 'crls' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_crls.buffer, backtrack_crls.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: signerInfos +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signerInfos' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignedData when reading top level tag 17 for field 'signerInfos' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignedData when reading top level tag 17 for field 'signerInfos' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_signerInfos;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signerInfos);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'signerInfos' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - signerInfos ++/
        typeof(_signerInfos) temp_signerInfos;
        result = temp_signerInfos.fromDecoding!ruleset(memory_signerInfos, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'signerInfos' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSignerInfos(temp_signerInfos);
        if(result.isError)
            return result.wrapError("when setting field 'signerInfos' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE SignedData there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct DigestAlgorithmIdentifiers
{
    private
    {
        asn1.Asn1SetOf!(.DigestAlgorithmIdentifier) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.DigestAlgorithmIdentifier) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(.DigestAlgorithmIdentifier) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.DigestAlgorithmIdentifier), "toString"))
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

struct SignerInfos
{
    private
    {
        asn1.Asn1SetOf!(.SignerInfo) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.SignerInfo) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(.SignerInfo) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.SignerInfo), "toString"))
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

struct EncapsulatedContentInfo
{
    private
    {
        bool _isSet_eContentType;
        .ContentType _eContentType;
        bool _isSet_eContent;
        asn1.Asn1OctetString _eContent;
    }

    jres.Result setEContentType(
        typeof(_eContentType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_eContentType = true;
        _eContentType = value;
        return jres.Result.noError;
    }

    typeof(_eContentType) getEContentType(
    ) @nogc nothrow
    {
        assert(_isSet_eContentType, "Non-optional field 'eContentType' has not been set yet - please use validate() to check!");
        return _eContentType;
    }

    jres.Result setEContent(
        typeof(_eContent) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_eContent = true;
        _eContent = value;
        return jres.Result.noError;
    }

    jres.Result setEContent(
        tcon.Nullable!(asn1.Asn1OctetString) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setEContent(value.get());
        }
        else
            _isSet_eContent = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1OctetString) getEContent(
    ) @nogc nothrow
    {
        if(_isSet_eContent)
            return typeof(return)(_eContent);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_eContentType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EncapsulatedContentInfo non-optional field 'eContentType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("eContentType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_eContentType), "toString"))
            _eContentType.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("eContent: ");
        sink("\n");
        if(_isSet_eContent)
        {
            static if(__traits(hasMember, typeof(_eContent), "toString"))
                _eContent.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: eContentType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'eContentType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EncapsulatedContentInfo when reading top level tag 6 for field 'eContentType' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EncapsulatedContentInfo when reading top level tag 6 for field 'eContentType' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_eContentType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_eContentType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'eContentType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - eContentType ++/
        typeof(_eContentType) temp_eContentType;
        result = temp_eContentType.fromDecoding!ruleset(memory_eContentType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'eContentType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEContentType(temp_eContentType);
        if(result.isError)
            return result.wrapError("when setting field 'eContentType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: eContent +++/
        auto backtrack_eContent = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'eContent' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_eContent;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_eContent);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'eContent' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - eContent ++/
                jbuf.MemoryReader memory_0eContent;
                    // EXPLICIT TAG - 0
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field eContent a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'eContent' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 0)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'eContent' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_eContent, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'eContent' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_eContent, componentHeader.length, memory_0eContent);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'eContent' in type "~__traits(identifier, typeof(this))~":");
                typeof(_eContent) temp_eContent;
                result = typeof(temp_eContent).fromDecoding!ruleset(memory_0eContent, temp_eContent, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'eContent' in type "~__traits(identifier, typeof(this))~":");
                result = this.setEContent(temp_eContent);
                if(result.isError)
                    return result.wrapError("when setting field 'eContent' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_eContent.buffer, backtrack_eContent.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE EncapsulatedContentInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SignerInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_sid;
        .SignerIdentifier _sid;
        bool _isSet_digestAlgorithm;
        .DigestAlgorithmIdentifier _digestAlgorithm;
        bool _isSet_signedAttrs;
        .SignedAttributes _signedAttrs;
        bool _isSet_signatureAlgorithm;
        .SignatureAlgorithmIdentifier _signatureAlgorithm;
        bool _isSet_signature;
        .SignatureValue _signature;
        bool _isSet_unsignedAttrs;
        .UnsignedAttributes _unsignedAttrs;
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

    jres.Result setSid(
        typeof(_sid) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_sid = true;
        _sid = value;
        return jres.Result.noError;
    }

    typeof(_sid) getSid(
    ) @nogc nothrow
    {
        assert(_isSet_sid, "Non-optional field 'sid' has not been set yet - please use validate() to check!");
        return _sid;
    }

    jres.Result setDigestAlgorithm(
        typeof(_digestAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_digestAlgorithm = true;
        _digestAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_digestAlgorithm) getDigestAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_digestAlgorithm, "Non-optional field 'digestAlgorithm' has not been set yet - please use validate() to check!");
        return _digestAlgorithm;
    }

    jres.Result setSignedAttrs(
        typeof(_signedAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_signedAttrs = true;
        _signedAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setSignedAttrs(
        tcon.Nullable!(.SignedAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setSignedAttrs(value.get());
        }
        else
            _isSet_signedAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.SignedAttributes) getSignedAttrs(
    ) @nogc nothrow
    {
        if(_isSet_signedAttrs)
            return typeof(return)(_signedAttrs);
        return typeof(return).init;
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

    jres.Result setUnsignedAttrs(
        typeof(_unsignedAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_unsignedAttrs = true;
        _unsignedAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setUnsignedAttrs(
        tcon.Nullable!(.UnsignedAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setUnsignedAttrs(value.get());
        }
        else
            _isSet_unsignedAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UnsignedAttributes) getUnsignedAttrs(
    ) @nogc nothrow
    {
        if(_isSet_unsignedAttrs)
            return typeof(return)(_unsignedAttrs);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignerInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_sid)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignerInfo non-optional field 'sid' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_digestAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignerInfo non-optional field 'digestAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signatureAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignerInfo non-optional field 'signatureAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type SignerInfo non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("sid: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_sid), "toString"))
            _sid.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("digestAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_digestAlgorithm), "toString"))
            _digestAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("signedAttrs: ");
        sink("\n");
        if(_isSet_signedAttrs)
        {
            static if(__traits(hasMember, typeof(_signedAttrs), "toString"))
                _signedAttrs.toString(sink, depth+1);
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
        putIndent();
        depth++;
        sink("unsignedAttrs: ");
        sink("\n");
        if(_isSet_unsignedAttrs)
        {
            static if(__traits(hasMember, typeof(_unsignedAttrs), "toString"))
                _unsignedAttrs.toString(sink, depth+1);
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignerInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignerInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: sid +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'sid' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_sid;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_sid);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'sid' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - sid ++/
        typeof(_sid) temp_sid;
        result = temp_sid.fromDecoding!ruleset(memory_sid, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'sid' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSid(temp_sid);
        if(result.isError)
            return result.wrapError("when setting field 'sid' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: digestAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignerInfo when reading top level tag 16 for field 'digestAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignerInfo when reading top level tag 16 for field 'digestAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_digestAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_digestAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - digestAlgorithm ++/
        typeof(_digestAlgorithm) temp_digestAlgorithm;
        result = temp_digestAlgorithm.fromDecoding!ruleset(memory_digestAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setDigestAlgorithm(temp_digestAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signedAttrs +++/
        auto backtrack_signedAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'signedAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_signedAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_signedAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'signedAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - signedAttrs ++/
                typeof(_signedAttrs) temp_signedAttrs;
                result = temp_signedAttrs.fromDecoding!ruleset(memory_signedAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'signedAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setSignedAttrs(temp_signedAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'signedAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_signedAttrs.buffer, backtrack_signedAttrs.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: signatureAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignerInfo when reading top level tag 16 for field 'signatureAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignerInfo when reading top level tag 16 for field 'signatureAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE SignerInfo when reading top level tag 4 for field 'signature' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE SignerInfo when reading top level tag 4 for field 'signature' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: unsignedAttrs +++/
        auto backtrack_unsignedAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'unsignedAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_unsignedAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_unsignedAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'unsignedAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - unsignedAttrs ++/
                typeof(_unsignedAttrs) temp_unsignedAttrs;
                result = temp_unsignedAttrs.fromDecoding!ruleset(memory_unsignedAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'unsignedAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setUnsignedAttrs(temp_unsignedAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'unsignedAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_unsignedAttrs.buffer, backtrack_unsignedAttrs.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE SignerInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SignerIdentifier
{
    enum Choice
    {
        _FAILSAFE,
        issuerAndSerialNumber,
        subjectKeyIdentifier,
    }

    union Value
    {
        .IssuerAndSerialNumber issuerAndSerialNumber;
        .SubjectKeyIdentifier subjectKeyIdentifier;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.IssuerAndSerialNumber), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.SubjectKeyIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber)) @nogc nothrow handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier)) @nogc nothrow handle_subjectKeyIdentifier,
    ) @nogc nothrow
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        assert(false, "attempted to use an uninitialised SignerIdentifier!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber))  handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier))  handle_subjectKeyIdentifier,
    ) 
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        assert(false, "attempted to use an uninitialised SignerIdentifier!");

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

    jres.Result setSubjectKeyIdentifier(
        typeof(Value.subjectKeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.subjectKeyIdentifier = value;
        _choice = Choice.subjectKeyIdentifier;
        return jres.Result.noError;
    }

    typeof(Value.subjectKeyIdentifier) getSubjectKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_choice == Choice.subjectKeyIdentifier, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'subjectKeyIdentifier'");
        return _value.subjectKeyIdentifier;
    }

    bool isSubjectKeyIdentifier(
    ) @nogc nothrow const
    {
        return _choice == Choice.subjectKeyIdentifier;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - subjectKeyIdentifier ++/
            typeof(Value.subjectKeyIdentifier) temp_subjectKeyIdentifier;
            result = temp_subjectKeyIdentifier.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
            result = this.setSubjectKeyIdentifier(temp_subjectKeyIdentifier);
            if(result.isError)
                return result.wrapError("when setting field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type SignerIdentifier the identifier tag & class were unable to match any known option");
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
        if(isSubjectKeyIdentifier)
        {
            depth++;
            putIndent();
            sink("subjectKeyIdentifier: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getSubjectKeyIdentifier()), "toString"))
                _value.subjectKeyIdentifier.toString(sink, depth+1);
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

struct SignedAttributes
{
    private
    {
        asn1.Asn1SetOf!(.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.Attribute) newValue,
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

    asn1.Asn1SetOf!(.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.Attribute), "toString"))
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

struct UnsignedAttributes
{
    private
    {
        asn1.Asn1SetOf!(.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.Attribute) newValue,
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

    asn1.Asn1SetOf!(.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.Attribute), "toString"))
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

struct Attribute
{
    private
    {
        bool _isSet_attrType;
        asn1.Asn1ObjectIdentifier _attrType;
        bool _isSet_attrValues;
        asn1.Asn1SetOf!(asn1.Asn1Any) _attrValues;
    }

    jres.Result setAttrType(
        typeof(_attrType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_attrType = true;
        _attrType = value;
        return jres.Result.noError;
    }

    typeof(_attrType) getAttrType(
    ) @nogc nothrow
    {
        assert(_isSet_attrType, "Non-optional field 'attrType' has not been set yet - please use validate() to check!");
        return _attrType;
    }

    jres.Result setAttrValues(
        typeof(_attrValues) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_attrValues = true;
        _attrValues = value;
        return jres.Result.noError;
    }

    typeof(_attrValues) getAttrValues(
    ) @nogc nothrow
    {
        assert(_isSet_attrValues, "Non-optional field 'attrValues' has not been set yet - please use validate() to check!");
        return _attrValues;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_attrType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Attribute non-optional field 'attrType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_attrValues)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type Attribute non-optional field 'attrValues' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("attrType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_attrType), "toString"))
            _attrType.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("attrValues: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_attrValues), "toString"))
            _attrValues.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: attrType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'attrType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Attribute when reading top level tag 6 for field 'attrType' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Attribute when reading top level tag 6 for field 'attrType' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_attrType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_attrType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'attrType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - attrType ++/
        typeof(_attrType) temp_attrType;
        result = typeof(temp_attrType).fromDecoding!ruleset(memory_attrType, temp_attrType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'attrType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAttrType(temp_attrType);
        if(result.isError)
            return result.wrapError("when setting field 'attrType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: attrValues +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'attrValues' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE Attribute when reading top level tag 17 for field 'attrValues' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE Attribute when reading top level tag 17 for field 'attrValues' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_attrValues;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_attrValues);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'attrValues' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - attrValues ++/
        typeof(_attrValues) temp_attrValues;
        result = typeof(temp_attrValues).fromDecoding!ruleset(memory_attrValues, temp_attrValues, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'attrValues' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAttrValues(temp_attrValues);
        if(result.isError)
            return result.wrapError("when setting field 'attrValues' in type "~__traits(identifier, typeof(this))~":");

        result = this._attrValues.foreachElementAuto((element) => jres.Result.noError);
        if(result.isError)
            return result.wrapError("when decoding subelements of SET OF field 'attrValues' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE Attribute there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SignatureValue
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

struct EnvelopedData
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_originatorInfo;
        .OriginatorInfo _originatorInfo;
        bool _isSet_recipientInfos;
        .RecipientInfos _recipientInfos;
        bool _isSet_encryptedContentInfo;
        .EncryptedContentInfo _encryptedContentInfo;
        bool _isSet_unprotectedAttrs;
        .UnprotectedAttributes _unprotectedAttrs;
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

    jres.Result setOriginatorInfo(
        typeof(_originatorInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_originatorInfo = true;
        _originatorInfo = value;
        return jres.Result.noError;
    }

    jres.Result setOriginatorInfo(
        tcon.Nullable!(.OriginatorInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOriginatorInfo(value.get());
        }
        else
            _isSet_originatorInfo = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OriginatorInfo) getOriginatorInfo(
    ) @nogc nothrow
    {
        if(_isSet_originatorInfo)
            return typeof(return)(_originatorInfo);
        return typeof(return).init;
    }

    jres.Result setRecipientInfos(
        typeof(_recipientInfos) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_recipientInfos = true;
        _recipientInfos = value;
        return jres.Result.noError;
    }

    typeof(_recipientInfos) getRecipientInfos(
    ) @nogc nothrow
    {
        assert(_isSet_recipientInfos, "Non-optional field 'recipientInfos' has not been set yet - please use validate() to check!");
        return _recipientInfos;
    }

    jres.Result setEncryptedContentInfo(
        typeof(_encryptedContentInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedContentInfo = true;
        _encryptedContentInfo = value;
        return jres.Result.noError;
    }

    typeof(_encryptedContentInfo) getEncryptedContentInfo(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedContentInfo, "Non-optional field 'encryptedContentInfo' has not been set yet - please use validate() to check!");
        return _encryptedContentInfo;
    }

    jres.Result setUnprotectedAttrs(
        typeof(_unprotectedAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_unprotectedAttrs = true;
        _unprotectedAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setUnprotectedAttrs(
        tcon.Nullable!(.UnprotectedAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setUnprotectedAttrs(value.get());
        }
        else
            _isSet_unprotectedAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UnprotectedAttributes) getUnprotectedAttrs(
    ) @nogc nothrow
    {
        if(_isSet_unprotectedAttrs)
            return typeof(return)(_unprotectedAttrs);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EnvelopedData non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_recipientInfos)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EnvelopedData non-optional field 'recipientInfos' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedContentInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EnvelopedData non-optional field 'encryptedContentInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("originatorInfo: ");
        sink("\n");
        if(_isSet_originatorInfo)
        {
            static if(__traits(hasMember, typeof(_originatorInfo), "toString"))
                _originatorInfo.toString(sink, depth+1);
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
        sink("recipientInfos: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_recipientInfos), "toString"))
            _recipientInfos.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedContentInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedContentInfo), "toString"))
            _encryptedContentInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("unprotectedAttrs: ");
        sink("\n");
        if(_isSet_unprotectedAttrs)
        {
            static if(__traits(hasMember, typeof(_unprotectedAttrs), "toString"))
                _unprotectedAttrs.toString(sink, depth+1);
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EnvelopedData when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EnvelopedData when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: originatorInfo +++/
        auto backtrack_originatorInfo = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_originatorInfo;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_originatorInfo);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - originatorInfo ++/
                typeof(_originatorInfo) temp_originatorInfo;
                result = temp_originatorInfo.fromDecoding!ruleset(memory_originatorInfo, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOriginatorInfo(temp_originatorInfo);
                if(result.isError)
                    return result.wrapError("when setting field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_originatorInfo.buffer, backtrack_originatorInfo.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: recipientInfos +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EnvelopedData when reading top level tag 17 for field 'recipientInfos' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EnvelopedData when reading top level tag 17 for field 'recipientInfos' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_recipientInfos;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_recipientInfos);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - recipientInfos ++/
        typeof(_recipientInfos) temp_recipientInfos;
        result = temp_recipientInfos.fromDecoding!ruleset(memory_recipientInfos, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRecipientInfos(temp_recipientInfos);
        if(result.isError)
            return result.wrapError("when setting field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedContentInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EnvelopedData when reading top level tag 16 for field 'encryptedContentInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EnvelopedData when reading top level tag 16 for field 'encryptedContentInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedContentInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedContentInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedContentInfo ++/
        typeof(_encryptedContentInfo) temp_encryptedContentInfo;
        result = temp_encryptedContentInfo.fromDecoding!ruleset(memory_encryptedContentInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedContentInfo(temp_encryptedContentInfo);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: unprotectedAttrs +++/
        auto backtrack_unprotectedAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_unprotectedAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_unprotectedAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - unprotectedAttrs ++/
                typeof(_unprotectedAttrs) temp_unprotectedAttrs;
                result = temp_unprotectedAttrs.fromDecoding!ruleset(memory_unprotectedAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setUnprotectedAttrs(temp_unprotectedAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_unprotectedAttrs.buffer, backtrack_unprotectedAttrs.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE EnvelopedData there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct OriginatorInfo
{
    private
    {
        bool _isSet_certs;
        .CertificateSet _certs;
        bool _isSet_crls;
        .CertificateRevocationLists _crls;
    }

    jres.Result setCerts(
        typeof(_certs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_certs = true;
        _certs = value;
        return jres.Result.noError;
    }

    jres.Result setCerts(
        tcon.Nullable!(.CertificateSet) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCerts(value.get());
        }
        else
            _isSet_certs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.CertificateSet) getCerts(
    ) @nogc nothrow
    {
        if(_isSet_certs)
            return typeof(return)(_certs);
        return typeof(return).init;
    }

    jres.Result setCrls(
        typeof(_crls) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_crls = true;
        _crls = value;
        return jres.Result.noError;
    }

    jres.Result setCrls(
        tcon.Nullable!(.CertificateRevocationLists) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setCrls(value.get());
        }
        else
            _isSet_crls = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.CertificateRevocationLists) getCrls(
    ) @nogc nothrow
    {
        if(_isSet_crls)
            return typeof(return)(_crls);
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
        sink("certs: ");
        sink("\n");
        if(_isSet_certs)
        {
            static if(__traits(hasMember, typeof(_certs), "toString"))
                _certs.toString(sink, depth+1);
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
        sink("crls: ");
        sink("\n");
        if(_isSet_crls)
        {
            static if(__traits(hasMember, typeof(_crls), "toString"))
                _crls.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: certs +++/
        auto backtrack_certs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'certs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_certs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_certs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'certs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - certs ++/
                typeof(_certs) temp_certs;
                result = temp_certs.fromDecoding!ruleset(memory_certs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'certs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCerts(temp_certs);
                if(result.isError)
                    return result.wrapError("when setting field 'certs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_certs.buffer, backtrack_certs.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: crls +++/
        auto backtrack_crls = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'crls' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_crls;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_crls);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'crls' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - crls ++/
                typeof(_crls) temp_crls;
                result = temp_crls.fromDecoding!ruleset(memory_crls, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'crls' in type "~__traits(identifier, typeof(this))~":");
                result = this.setCrls(temp_crls);
                if(result.isError)
                    return result.wrapError("when setting field 'crls' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_crls.buffer, backtrack_crls.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE OriginatorInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct RecipientInfos
{
    private
    {
        asn1.Asn1SetOf!(.RecipientInfo) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.RecipientInfo) newValue,
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

    asn1.Asn1SetOf!(.RecipientInfo) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.RecipientInfo), "toString"))
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

struct EncryptedContentInfo
{
    private
    {
        bool _isSet_contentType;
        .ContentType _contentType;
        bool _isSet_contentEncryptionAlgorithm;
        .ContentEncryptionAlgorithmIdentifier _contentEncryptionAlgorithm;
        bool _isSet_encryptedContent;
        .EncryptedContent _encryptedContent;
    }

    jres.Result setContentType(
        typeof(_contentType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_contentType = true;
        _contentType = value;
        return jres.Result.noError;
    }

    typeof(_contentType) getContentType(
    ) @nogc nothrow
    {
        assert(_isSet_contentType, "Non-optional field 'contentType' has not been set yet - please use validate() to check!");
        return _contentType;
    }

    jres.Result setContentEncryptionAlgorithm(
        typeof(_contentEncryptionAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_contentEncryptionAlgorithm = true;
        _contentEncryptionAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_contentEncryptionAlgorithm) getContentEncryptionAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_contentEncryptionAlgorithm, "Non-optional field 'contentEncryptionAlgorithm' has not been set yet - please use validate() to check!");
        return _contentEncryptionAlgorithm;
    }

    jres.Result setEncryptedContent(
        typeof(_encryptedContent) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedContent = true;
        _encryptedContent = value;
        return jres.Result.noError;
    }

    jres.Result setEncryptedContent(
        tcon.Nullable!(.EncryptedContent) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setEncryptedContent(value.get());
        }
        else
            _isSet_encryptedContent = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.EncryptedContent) getEncryptedContent(
    ) @nogc nothrow
    {
        if(_isSet_encryptedContent)
            return typeof(return)(_encryptedContent);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_contentType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EncryptedContentInfo non-optional field 'contentType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_contentEncryptionAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EncryptedContentInfo non-optional field 'contentEncryptionAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("contentType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_contentType), "toString"))
            _contentType.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("contentEncryptionAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_contentEncryptionAlgorithm), "toString"))
            _contentEncryptionAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedContent: ");
        sink("\n");
        if(_isSet_encryptedContent)
        {
            static if(__traits(hasMember, typeof(_encryptedContent), "toString"))
                _encryptedContent.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: contentType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EncryptedContentInfo when reading top level tag 6 for field 'contentType' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EncryptedContentInfo when reading top level tag 6 for field 'contentType' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_contentType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_contentType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - contentType ++/
        typeof(_contentType) temp_contentType;
        result = temp_contentType.fromDecoding!ruleset(memory_contentType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'contentType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setContentType(temp_contentType);
        if(result.isError)
            return result.wrapError("when setting field 'contentType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: contentEncryptionAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'contentEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EncryptedContentInfo when reading top level tag 16 for field 'contentEncryptionAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EncryptedContentInfo when reading top level tag 16 for field 'contentEncryptionAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_contentEncryptionAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_contentEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'contentEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - contentEncryptionAlgorithm ++/
        typeof(_contentEncryptionAlgorithm) temp_contentEncryptionAlgorithm;
        result = temp_contentEncryptionAlgorithm.fromDecoding!ruleset(memory_contentEncryptionAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'contentEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setContentEncryptionAlgorithm(temp_contentEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'contentEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedContent +++/
        auto backtrack_encryptedContent = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'encryptedContent' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_encryptedContent;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedContent);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'encryptedContent' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - encryptedContent ++/
                typeof(_encryptedContent) temp_encryptedContent;
                result = temp_encryptedContent.fromDecoding!ruleset(memory_encryptedContent, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'encryptedContent' in type "~__traits(identifier, typeof(this))~":");
                result = this.setEncryptedContent(temp_encryptedContent);
                if(result.isError)
                    return result.wrapError("when setting field 'encryptedContent' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_encryptedContent.buffer, backtrack_encryptedContent.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE EncryptedContentInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct EncryptedContent
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

struct UnprotectedAttributes
{
    private
    {
        asn1.Asn1SetOf!(.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.Attribute) newValue,
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

    asn1.Asn1SetOf!(.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.Attribute), "toString"))
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

struct RecipientInfo
{
    enum Choice
    {
        _FAILSAFE,
        ktri,
        kari,
        kekri,
        pwri,
        ori,
    }

    union Value
    {
        .KeyTransRecipientInfo ktri;
        .KeyAgreeRecipientInfo kari;
        .KEKRecipientInfo kekri;
        .PasswordRecipientInfo pwri;
        .OtherRecipientInfo ori;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.KeyTransRecipientInfo), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.KeyAgreeRecipientInfo), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.KEKRecipientInfo), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.PasswordRecipientInfo), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.OtherRecipientInfo), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.ktri)) @nogc nothrow handle_ktri,
        scope jres.Result delegate(typeof(Value.kari)) @nogc nothrow handle_kari,
        scope jres.Result delegate(typeof(Value.kekri)) @nogc nothrow handle_kekri,
        scope jres.Result delegate(typeof(Value.pwri)) @nogc nothrow handle_pwri,
        scope jres.Result delegate(typeof(Value.ori)) @nogc nothrow handle_ori,
    ) @nogc nothrow
    {
        if(_choice == Choice.ktri)
            return handle_ktri(_value.ktri);
        if(_choice == Choice.kari)
            return handle_kari(_value.kari);
        if(_choice == Choice.kekri)
            return handle_kekri(_value.kekri);
        if(_choice == Choice.pwri)
            return handle_pwri(_value.pwri);
        if(_choice == Choice.ori)
            return handle_ori(_value.ori);
        assert(false, "attempted to use an uninitialised RecipientInfo!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.ktri))  handle_ktri,
        scope jres.Result delegate(typeof(Value.kari))  handle_kari,
        scope jres.Result delegate(typeof(Value.kekri))  handle_kekri,
        scope jres.Result delegate(typeof(Value.pwri))  handle_pwri,
        scope jres.Result delegate(typeof(Value.ori))  handle_ori,
    ) 
    {
        if(_choice == Choice.ktri)
            return handle_ktri(_value.ktri);
        if(_choice == Choice.kari)
            return handle_kari(_value.kari);
        if(_choice == Choice.kekri)
            return handle_kekri(_value.kekri);
        if(_choice == Choice.pwri)
            return handle_pwri(_value.pwri);
        if(_choice == Choice.ori)
            return handle_ori(_value.ori);
        assert(false, "attempted to use an uninitialised RecipientInfo!");

    }

    jres.Result setKtri(
        typeof(Value.ktri) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.ktri = value;
        _choice = Choice.ktri;
        return jres.Result.noError;
    }

    typeof(Value.ktri) getKtri(
    ) @nogc nothrow
    {
        assert(_choice == Choice.ktri, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'ktri'");
        return _value.ktri;
    }

    bool isKtri(
    ) @nogc nothrow const
    {
        return _choice == Choice.ktri;
    }

    jres.Result setKari(
        typeof(Value.kari) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.kari = value;
        _choice = Choice.kari;
        return jres.Result.noError;
    }

    typeof(Value.kari) getKari(
    ) @nogc nothrow
    {
        assert(_choice == Choice.kari, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'kari'");
        return _value.kari;
    }

    bool isKari(
    ) @nogc nothrow const
    {
        return _choice == Choice.kari;
    }

    jres.Result setKekri(
        typeof(Value.kekri) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.kekri = value;
        _choice = Choice.kekri;
        return jres.Result.noError;
    }

    typeof(Value.kekri) getKekri(
    ) @nogc nothrow
    {
        assert(_choice == Choice.kekri, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'kekri'");
        return _value.kekri;
    }

    bool isKekri(
    ) @nogc nothrow const
    {
        return _choice == Choice.kekri;
    }

    jres.Result setPwri(
        typeof(Value.pwri) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.pwri = value;
        _choice = Choice.pwri;
        return jres.Result.noError;
    }

    typeof(Value.pwri) getPwri(
    ) @nogc nothrow
    {
        assert(_choice == Choice.pwri, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'pwri'");
        return _value.pwri;
    }

    bool isPwri(
    ) @nogc nothrow const
    {
        return _choice == Choice.pwri;
    }

    jres.Result setOri(
        typeof(Value.ori) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.ori = value;
        _choice = Choice.ori;
        return jres.Result.noError;
    }

    typeof(Value.ori) getOri(
    ) @nogc nothrow
    {
        assert(_choice == Choice.ori, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'ori'");
        return _value.ori;
    }

    bool isOri(
    ) @nogc nothrow const
    {
        return _choice == Choice.ori;
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
            /++ FIELD - ktri ++/
            typeof(Value.ktri) temp_ktri;
            result = temp_ktri.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'ktri' in type "~__traits(identifier, typeof(this))~":");
            result = this.setKtri(temp_ktri);
            if(result.isError)
                return result.wrapError("when setting field 'ktri' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 1)
        {
            /++ FIELD - kari ++/
            typeof(Value.kari) temp_kari;
            result = temp_kari.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'kari' in type "~__traits(identifier, typeof(this))~":");
            result = this.setKari(temp_kari);
            if(result.isError)
                return result.wrapError("when setting field 'kari' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 2)
        {
            /++ FIELD - kekri ++/
            typeof(Value.kekri) temp_kekri;
            result = temp_kekri.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'kekri' in type "~__traits(identifier, typeof(this))~":");
            result = this.setKekri(temp_kekri);
            if(result.isError)
                return result.wrapError("when setting field 'kekri' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 3)
        {
            /++ FIELD - pwri ++/
            typeof(Value.pwri) temp_pwri;
            result = temp_pwri.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'pwri' in type "~__traits(identifier, typeof(this))~":");
            result = this.setPwri(temp_pwri);
            if(result.isError)
                return result.wrapError("when setting field 'pwri' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 4)
        {
            /++ FIELD - ori ++/
            typeof(Value.ori) temp_ori;
            result = temp_ori.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'ori' in type "~__traits(identifier, typeof(this))~":");
            result = this.setOri(temp_ori);
            if(result.isError)
                return result.wrapError("when setting field 'ori' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type RecipientInfo the identifier tag & class were unable to match any known option");
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
        if(isKtri)
        {
            depth++;
            putIndent();
            sink("ktri: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getKtri()), "toString"))
                _value.ktri.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isKari)
        {
            depth++;
            putIndent();
            sink("kari: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getKari()), "toString"))
                _value.kari.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isKekri)
        {
            depth++;
            putIndent();
            sink("kekri: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getKekri()), "toString"))
                _value.kekri.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isPwri)
        {
            depth++;
            putIndent();
            sink("pwri: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getPwri()), "toString"))
                _value.pwri.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isOri)
        {
            depth++;
            putIndent();
            sink("ori: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getOri()), "toString"))
                _value.ori.toString(sink, depth+1);
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

struct EncryptedKey
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

struct KeyTransRecipientInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_rid;
        .RecipientIdentifier _rid;
        bool _isSet_keyEncryptionAlgorithm;
        .KeyEncryptionAlgorithmIdentifier _keyEncryptionAlgorithm;
        bool _isSet_encryptedKey;
        .EncryptedKey _encryptedKey;
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

    jres.Result setRid(
        typeof(_rid) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_rid = true;
        _rid = value;
        return jres.Result.noError;
    }

    typeof(_rid) getRid(
    ) @nogc nothrow
    {
        assert(_isSet_rid, "Non-optional field 'rid' has not been set yet - please use validate() to check!");
        return _rid;
    }

    jres.Result setKeyEncryptionAlgorithm(
        typeof(_keyEncryptionAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyEncryptionAlgorithm = true;
        _keyEncryptionAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_keyEncryptionAlgorithm) getKeyEncryptionAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_keyEncryptionAlgorithm, "Non-optional field 'keyEncryptionAlgorithm' has not been set yet - please use validate() to check!");
        return _keyEncryptionAlgorithm;
    }

    jres.Result setEncryptedKey(
        typeof(_encryptedKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedKey = true;
        _encryptedKey = value;
        return jres.Result.noError;
    }

    typeof(_encryptedKey) getEncryptedKey(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedKey, "Non-optional field 'encryptedKey' has not been set yet - please use validate() to check!");
        return _encryptedKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyTransRecipientInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_rid)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyTransRecipientInfo non-optional field 'rid' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_keyEncryptionAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyTransRecipientInfo non-optional field 'keyEncryptionAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyTransRecipientInfo non-optional field 'encryptedKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("rid: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_rid), "toString"))
            _rid.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("keyEncryptionAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_keyEncryptionAlgorithm), "toString"))
            _keyEncryptionAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedKey), "toString"))
            _encryptedKey.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: rid +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'rid' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_rid;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_rid);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'rid' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - rid ++/
        typeof(_rid) temp_rid;
        result = temp_rid.fromDecoding!ruleset(memory_rid, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'rid' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRid(temp_rid);
        if(result.isError)
            return result.wrapError("when setting field 'rid' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: keyEncryptionAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyEncryptionAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyEncryptionAlgorithm ++/
        typeof(_keyEncryptionAlgorithm) temp_keyEncryptionAlgorithm;
        result = temp_keyEncryptionAlgorithm.fromDecoding!ruleset(memory_keyEncryptionAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyEncryptionAlgorithm(temp_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyTransRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedKey ++/
        typeof(_encryptedKey) temp_encryptedKey;
        result = temp_encryptedKey.fromDecoding!ruleset(memory_encryptedKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedKey(temp_encryptedKey);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE KeyTransRecipientInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct RecipientIdentifier
{
    enum Choice
    {
        _FAILSAFE,
        issuerAndSerialNumber,
        subjectKeyIdentifier,
    }

    union Value
    {
        .IssuerAndSerialNumber issuerAndSerialNumber;
        .SubjectKeyIdentifier subjectKeyIdentifier;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.IssuerAndSerialNumber), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.SubjectKeyIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber)) @nogc nothrow handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier)) @nogc nothrow handle_subjectKeyIdentifier,
    ) @nogc nothrow
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        assert(false, "attempted to use an uninitialised RecipientIdentifier!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber))  handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier))  handle_subjectKeyIdentifier,
    ) 
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        assert(false, "attempted to use an uninitialised RecipientIdentifier!");

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

    jres.Result setSubjectKeyIdentifier(
        typeof(Value.subjectKeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.subjectKeyIdentifier = value;
        _choice = Choice.subjectKeyIdentifier;
        return jres.Result.noError;
    }

    typeof(Value.subjectKeyIdentifier) getSubjectKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_choice == Choice.subjectKeyIdentifier, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'subjectKeyIdentifier'");
        return _value.subjectKeyIdentifier;
    }

    bool isSubjectKeyIdentifier(
    ) @nogc nothrow const
    {
        return _choice == Choice.subjectKeyIdentifier;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - subjectKeyIdentifier ++/
            typeof(Value.subjectKeyIdentifier) temp_subjectKeyIdentifier;
            result = temp_subjectKeyIdentifier.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
            result = this.setSubjectKeyIdentifier(temp_subjectKeyIdentifier);
            if(result.isError)
                return result.wrapError("when setting field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type RecipientIdentifier the identifier tag & class were unable to match any known option");
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
        if(isSubjectKeyIdentifier)
        {
            depth++;
            putIndent();
            sink("subjectKeyIdentifier: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getSubjectKeyIdentifier()), "toString"))
                _value.subjectKeyIdentifier.toString(sink, depth+1);
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

struct KeyAgreeRecipientInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_originator;
        .OriginatorIdentifierOrKey _originator;
        bool _isSet_ukm;
        .UserKeyingMaterial _ukm;
        bool _isSet_keyEncryptionAlgorithm;
        .KeyEncryptionAlgorithmIdentifier _keyEncryptionAlgorithm;
        bool _isSet_recipientEncryptedKeys;
        .RecipientEncryptedKeys _recipientEncryptedKeys;
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

    jres.Result setOriginator(
        typeof(_originator) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_originator = true;
        _originator = value;
        return jres.Result.noError;
    }

    typeof(_originator) getOriginator(
    ) @nogc nothrow
    {
        assert(_isSet_originator, "Non-optional field 'originator' has not been set yet - please use validate() to check!");
        return _originator;
    }

    jres.Result setUkm(
        typeof(_ukm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_ukm = true;
        _ukm = value;
        return jres.Result.noError;
    }

    jres.Result setUkm(
        tcon.Nullable!(.UserKeyingMaterial) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setUkm(value.get());
        }
        else
            _isSet_ukm = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UserKeyingMaterial) getUkm(
    ) @nogc nothrow
    {
        if(_isSet_ukm)
            return typeof(return)(_ukm);
        return typeof(return).init;
    }

    jres.Result setKeyEncryptionAlgorithm(
        typeof(_keyEncryptionAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyEncryptionAlgorithm = true;
        _keyEncryptionAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_keyEncryptionAlgorithm) getKeyEncryptionAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_keyEncryptionAlgorithm, "Non-optional field 'keyEncryptionAlgorithm' has not been set yet - please use validate() to check!");
        return _keyEncryptionAlgorithm;
    }

    jres.Result setRecipientEncryptedKeys(
        typeof(_recipientEncryptedKeys) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_recipientEncryptedKeys = true;
        _recipientEncryptedKeys = value;
        return jres.Result.noError;
    }

    typeof(_recipientEncryptedKeys) getRecipientEncryptedKeys(
    ) @nogc nothrow
    {
        assert(_isSet_recipientEncryptedKeys, "Non-optional field 'recipientEncryptedKeys' has not been set yet - please use validate() to check!");
        return _recipientEncryptedKeys;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyAgreeRecipientInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_originator)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyAgreeRecipientInfo non-optional field 'originator' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_keyEncryptionAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyAgreeRecipientInfo non-optional field 'keyEncryptionAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_recipientEncryptedKeys)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KeyAgreeRecipientInfo non-optional field 'recipientEncryptedKeys' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("originator: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_originator), "toString"))
            _originator.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("ukm: ");
        sink("\n");
        if(_isSet_ukm)
        {
            static if(__traits(hasMember, typeof(_ukm), "toString"))
                _ukm.toString(sink, depth+1);
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
        sink("keyEncryptionAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_keyEncryptionAlgorithm), "toString"))
            _keyEncryptionAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("recipientEncryptedKeys: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_recipientEncryptedKeys), "toString"))
            _recipientEncryptedKeys.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: originator +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'originator' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 0 for field 'originator' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 0)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 0 for field 'originator' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_originator;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_originator);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'originator' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - originator ++/
        jbuf.MemoryReader memory_0originator;
            // EXPLICIT TAG - 0
            if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field originator a primitive tag was found when a constructed one was expected");
            if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'originator' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
            if(componentHeader.identifier.tag != 0)
                return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'originator' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
            result = asn1.asn1DecodeComponentHeader!ruleset(memory_originator, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'originator' in type "~__traits(identifier, typeof(this))~":");
            result = asn1.asn1ReadContentBytes(memory_originator, componentHeader.length, memory_0originator);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'originator' in type "~__traits(identifier, typeof(this))~":");
        typeof(_originator) temp_originator;
        result = temp_originator.fromDecoding!ruleset(memory_0originator, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'originator' in type "~__traits(identifier, typeof(this))~":");
        result = this.setOriginator(temp_originator);
        if(result.isError)
            return result.wrapError("when setting field 'originator' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: ukm +++/
        auto backtrack_ukm = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'ukm' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_ukm;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_ukm);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'ukm' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - ukm ++/
                jbuf.MemoryReader memory_0ukm;
                    // EXPLICIT TAG - 1
                    if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                        return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 1 for field ukm a primitive tag was found when a constructed one was expected");
                    if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 1 for field 'ukm' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
                    if(componentHeader.identifier.tag != 1)
                        return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 1 for field 'ukm' the tag's value was expected to be 1", jstr.String("tag value was ", componentHeader.identifier.tag));
                    result = asn1.asn1DecodeComponentHeader!ruleset(memory_ukm, componentHeader);
                    if(result.isError)
                        return result.wrapError("when decoding header of field 'ukm' in type "~__traits(identifier, typeof(this))~":");
                    result = asn1.asn1ReadContentBytes(memory_ukm, componentHeader.length, memory_0ukm);
                    if(result.isError)
                        return result.wrapError("when reading content bytes of field 'ukm' in type "~__traits(identifier, typeof(this))~":");
                typeof(_ukm) temp_ukm;
                result = temp_ukm.fromDecoding!ruleset(memory_0ukm, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'ukm' in type "~__traits(identifier, typeof(this))~":");
                result = this.setUkm(temp_ukm);
                if(result.isError)
                    return result.wrapError("when setting field 'ukm' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_ukm.buffer, backtrack_ukm.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: keyEncryptionAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyEncryptionAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyEncryptionAlgorithm ++/
        typeof(_keyEncryptionAlgorithm) temp_keyEncryptionAlgorithm;
        result = temp_keyEncryptionAlgorithm.fromDecoding!ruleset(memory_keyEncryptionAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyEncryptionAlgorithm(temp_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: recipientEncryptedKeys +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'recipientEncryptedKeys' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 16 for field 'recipientEncryptedKeys' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KeyAgreeRecipientInfo when reading top level tag 16 for field 'recipientEncryptedKeys' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_recipientEncryptedKeys;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_recipientEncryptedKeys);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'recipientEncryptedKeys' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - recipientEncryptedKeys ++/
        typeof(_recipientEncryptedKeys) temp_recipientEncryptedKeys;
        result = temp_recipientEncryptedKeys.fromDecoding!ruleset(memory_recipientEncryptedKeys, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'recipientEncryptedKeys' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRecipientEncryptedKeys(temp_recipientEncryptedKeys);
        if(result.isError)
            return result.wrapError("when setting field 'recipientEncryptedKeys' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE KeyAgreeRecipientInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct OriginatorIdentifierOrKey
{
    enum Choice
    {
        _FAILSAFE,
        issuerAndSerialNumber,
        subjectKeyIdentifier,
        originatorKey,
    }

    union Value
    {
        .IssuerAndSerialNumber issuerAndSerialNumber;
        .SubjectKeyIdentifier subjectKeyIdentifier;
        .OriginatorPublicKey originatorKey;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.IssuerAndSerialNumber), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.SubjectKeyIdentifier), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.OriginatorPublicKey), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber)) @nogc nothrow handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier)) @nogc nothrow handle_subjectKeyIdentifier,
        scope jres.Result delegate(typeof(Value.originatorKey)) @nogc nothrow handle_originatorKey,
    ) @nogc nothrow
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        if(_choice == Choice.originatorKey)
            return handle_originatorKey(_value.originatorKey);
        assert(false, "attempted to use an uninitialised OriginatorIdentifierOrKey!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber))  handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.subjectKeyIdentifier))  handle_subjectKeyIdentifier,
        scope jres.Result delegate(typeof(Value.originatorKey))  handle_originatorKey,
    ) 
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.subjectKeyIdentifier)
            return handle_subjectKeyIdentifier(_value.subjectKeyIdentifier);
        if(_choice == Choice.originatorKey)
            return handle_originatorKey(_value.originatorKey);
        assert(false, "attempted to use an uninitialised OriginatorIdentifierOrKey!");

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

    jres.Result setSubjectKeyIdentifier(
        typeof(Value.subjectKeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.subjectKeyIdentifier = value;
        _choice = Choice.subjectKeyIdentifier;
        return jres.Result.noError;
    }

    typeof(Value.subjectKeyIdentifier) getSubjectKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_choice == Choice.subjectKeyIdentifier, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'subjectKeyIdentifier'");
        return _value.subjectKeyIdentifier;
    }

    bool isSubjectKeyIdentifier(
    ) @nogc nothrow const
    {
        return _choice == Choice.subjectKeyIdentifier;
    }

    jres.Result setOriginatorKey(
        typeof(Value.originatorKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.originatorKey = value;
        _choice = Choice.originatorKey;
        return jres.Result.noError;
    }

    typeof(Value.originatorKey) getOriginatorKey(
    ) @nogc nothrow
    {
        assert(_choice == Choice.originatorKey, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'originatorKey'");
        return _value.originatorKey;
    }

    bool isOriginatorKey(
    ) @nogc nothrow const
    {
        return _choice == Choice.originatorKey;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - subjectKeyIdentifier ++/
            typeof(Value.subjectKeyIdentifier) temp_subjectKeyIdentifier;
            result = temp_subjectKeyIdentifier.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
            result = this.setSubjectKeyIdentifier(temp_subjectKeyIdentifier);
            if(result.isError)
                return result.wrapError("when setting field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 1)
        {
            /++ FIELD - originatorKey ++/
            typeof(Value.originatorKey) temp_originatorKey;
            result = temp_originatorKey.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'originatorKey' in type "~__traits(identifier, typeof(this))~":");
            result = this.setOriginatorKey(temp_originatorKey);
            if(result.isError)
                return result.wrapError("when setting field 'originatorKey' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type OriginatorIdentifierOrKey the identifier tag & class were unable to match any known option");
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
        if(isSubjectKeyIdentifier)
        {
            depth++;
            putIndent();
            sink("subjectKeyIdentifier: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getSubjectKeyIdentifier()), "toString"))
                _value.subjectKeyIdentifier.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isOriginatorKey)
        {
            depth++;
            putIndent();
            sink("originatorKey: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getOriginatorKey()), "toString"))
                _value.originatorKey.toString(sink, depth+1);
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

struct OriginatorPublicKey
{
    private
    {
        bool _isSet_algorithm;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _algorithm;
        bool _isSet_publicKey;
        asn1.Asn1BitString _publicKey;
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

    jres.Result setPublicKey(
        typeof(_publicKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_publicKey = true;
        _publicKey = value;
        return jres.Result.noError;
    }

    typeof(_publicKey) getPublicKey(
    ) @nogc nothrow
    {
        assert(_isSet_publicKey, "Non-optional field 'publicKey' has not been set yet - please use validate() to check!");
        return _publicKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_algorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type OriginatorPublicKey non-optional field 'algorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_publicKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type OriginatorPublicKey non-optional field 'publicKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("publicKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_publicKey), "toString"))
            _publicKey.toString(sink, depth+1);
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE OriginatorPublicKey when reading top level tag 16 for field 'algorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE OriginatorPublicKey when reading top level tag 16 for field 'algorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: publicKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'publicKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE OriginatorPublicKey when reading top level tag 3 for field 'publicKey' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE OriginatorPublicKey when reading top level tag 3 for field 'publicKey' the tag's value was expected to be 3", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_publicKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_publicKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'publicKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - publicKey ++/
        typeof(_publicKey) temp_publicKey;
        result = typeof(temp_publicKey).fromDecoding!ruleset(memory_publicKey, temp_publicKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'publicKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setPublicKey(temp_publicKey);
        if(result.isError)
            return result.wrapError("when setting field 'publicKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE OriginatorPublicKey there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct RecipientEncryptedKeys
{
    private
    {
        asn1.Asn1SequenceOf!(.RecipientEncryptedKey) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SequenceOf!(.RecipientEncryptedKey) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SequenceOf!(.RecipientEncryptedKey) get(
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
        static if(__traits(hasMember, asn1.Asn1SequenceOf!(.RecipientEncryptedKey), "toString"))
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

struct RecipientEncryptedKey
{
    private
    {
        bool _isSet_rid;
        .KeyAgreeRecipientIdentifier _rid;
        bool _isSet_encryptedKey;
        .EncryptedKey _encryptedKey;
    }

    jres.Result setRid(
        typeof(_rid) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_rid = true;
        _rid = value;
        return jres.Result.noError;
    }

    typeof(_rid) getRid(
    ) @nogc nothrow
    {
        assert(_isSet_rid, "Non-optional field 'rid' has not been set yet - please use validate() to check!");
        return _rid;
    }

    jres.Result setEncryptedKey(
        typeof(_encryptedKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedKey = true;
        _encryptedKey = value;
        return jres.Result.noError;
    }

    typeof(_encryptedKey) getEncryptedKey(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedKey, "Non-optional field 'encryptedKey' has not been set yet - please use validate() to check!");
        return _encryptedKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_rid)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type RecipientEncryptedKey non-optional field 'rid' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type RecipientEncryptedKey non-optional field 'encryptedKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("rid: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_rid), "toString"))
            _rid.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedKey), "toString"))
            _encryptedKey.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: rid +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'rid' in type "~__traits(identifier, typeof(this))~":");
        jbuf.MemoryReader memory_rid;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_rid);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'rid' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - rid ++/
        typeof(_rid) temp_rid;
        result = temp_rid.fromDecoding!ruleset(memory_rid, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'rid' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRid(temp_rid);
        if(result.isError)
            return result.wrapError("when setting field 'rid' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE RecipientEncryptedKey when reading top level tag 4 for field 'encryptedKey' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE RecipientEncryptedKey when reading top level tag 4 for field 'encryptedKey' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedKey ++/
        typeof(_encryptedKey) temp_encryptedKey;
        result = temp_encryptedKey.fromDecoding!ruleset(memory_encryptedKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedKey(temp_encryptedKey);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE RecipientEncryptedKey there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct KeyAgreeRecipientIdentifier
{
    enum Choice
    {
        _FAILSAFE,
        issuerAndSerialNumber,
        rKeyId,
    }

    union Value
    {
        .IssuerAndSerialNumber issuerAndSerialNumber;
        .RecipientKeyIdentifier rKeyId;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(.IssuerAndSerialNumber), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.RecipientKeyIdentifier), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber)) @nogc nothrow handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.rKeyId)) @nogc nothrow handle_rKeyId,
    ) @nogc nothrow
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.rKeyId)
            return handle_rKeyId(_value.rKeyId);
        assert(false, "attempted to use an uninitialised KeyAgreeRecipientIdentifier!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.issuerAndSerialNumber))  handle_issuerAndSerialNumber,
        scope jres.Result delegate(typeof(Value.rKeyId))  handle_rKeyId,
    ) 
    {
        if(_choice == Choice.issuerAndSerialNumber)
            return handle_issuerAndSerialNumber(_value.issuerAndSerialNumber);
        if(_choice == Choice.rKeyId)
            return handle_rKeyId(_value.rKeyId);
        assert(false, "attempted to use an uninitialised KeyAgreeRecipientIdentifier!");

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

    jres.Result setRKeyId(
        typeof(Value.rKeyId) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.rKeyId = value;
        _choice = Choice.rKeyId;
        return jres.Result.noError;
    }

    typeof(Value.rKeyId) getRKeyId(
    ) @nogc nothrow
    {
        assert(_choice == Choice.rKeyId, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'rKeyId'");
        return _value.rKeyId;
    }

    bool isRKeyId(
    ) @nogc nothrow const
    {
        return _choice == Choice.rKeyId;
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

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - rKeyId ++/
            typeof(Value.rKeyId) temp_rKeyId;
            result = temp_rKeyId.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'rKeyId' in type "~__traits(identifier, typeof(this))~":");
            result = this.setRKeyId(temp_rKeyId);
            if(result.isError)
                return result.wrapError("when setting field 'rKeyId' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type KeyAgreeRecipientIdentifier the identifier tag & class were unable to match any known option");
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
        if(isRKeyId)
        {
            depth++;
            putIndent();
            sink("rKeyId: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getRKeyId()), "toString"))
                _value.rKeyId.toString(sink, depth+1);
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

struct RecipientKeyIdentifier
{
    private
    {
        bool _isSet_subjectKeyIdentifier;
        .SubjectKeyIdentifier _subjectKeyIdentifier;
        bool _isSet_other;
        .OtherKeyAttribute _other;
    }

    jres.Result setSubjectKeyIdentifier(
        typeof(_subjectKeyIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_subjectKeyIdentifier = true;
        _subjectKeyIdentifier = value;
        return jres.Result.noError;
    }

    typeof(_subjectKeyIdentifier) getSubjectKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_isSet_subjectKeyIdentifier, "Non-optional field 'subjectKeyIdentifier' has not been set yet - please use validate() to check!");
        return _subjectKeyIdentifier;
    }

    jres.Result setOther(
        typeof(_other) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_other = true;
        _other = value;
        return jres.Result.noError;
    }

    jres.Result setOther(
        tcon.Nullable!(.OtherKeyAttribute) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOther(value.get());
        }
        else
            _isSet_other = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OtherKeyAttribute) getOther(
    ) @nogc nothrow
    {
        if(_isSet_other)
            return typeof(return)(_other);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_subjectKeyIdentifier)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type RecipientKeyIdentifier non-optional field 'subjectKeyIdentifier' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("subjectKeyIdentifier: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_subjectKeyIdentifier), "toString"))
            _subjectKeyIdentifier.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("other: ");
        sink("\n");
        if(_isSet_other)
        {
            static if(__traits(hasMember, typeof(_other), "toString"))
                _other.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: subjectKeyIdentifier +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE RecipientKeyIdentifier when reading top level tag 4 for field 'subjectKeyIdentifier' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE RecipientKeyIdentifier when reading top level tag 4 for field 'subjectKeyIdentifier' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_subjectKeyIdentifier;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_subjectKeyIdentifier);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - subjectKeyIdentifier ++/
        typeof(_subjectKeyIdentifier) temp_subjectKeyIdentifier;
        result = temp_subjectKeyIdentifier.fromDecoding!ruleset(memory_subjectKeyIdentifier, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        result = this.setSubjectKeyIdentifier(temp_subjectKeyIdentifier);
        if(result.isError)
            return result.wrapError("when setting field 'subjectKeyIdentifier' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: other +++/
        auto backtrack_other = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'other' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_other;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_other);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'other' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - other ++/
                typeof(_other) temp_other;
                result = temp_other.fromDecoding!ruleset(memory_other, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'other' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOther(temp_other);
                if(result.isError)
                    return result.wrapError("when setting field 'other' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_other.buffer, backtrack_other.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE RecipientKeyIdentifier there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct SubjectKeyIdentifier
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

struct KEKRecipientInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_kekid;
        .KEKIdentifier _kekid;
        bool _isSet_keyEncryptionAlgorithm;
        .KeyEncryptionAlgorithmIdentifier _keyEncryptionAlgorithm;
        bool _isSet_encryptedKey;
        .EncryptedKey _encryptedKey;
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

    jres.Result setKekid(
        typeof(_kekid) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_kekid = true;
        _kekid = value;
        return jres.Result.noError;
    }

    typeof(_kekid) getKekid(
    ) @nogc nothrow
    {
        assert(_isSet_kekid, "Non-optional field 'kekid' has not been set yet - please use validate() to check!");
        return _kekid;
    }

    jres.Result setKeyEncryptionAlgorithm(
        typeof(_keyEncryptionAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyEncryptionAlgorithm = true;
        _keyEncryptionAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_keyEncryptionAlgorithm) getKeyEncryptionAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_keyEncryptionAlgorithm, "Non-optional field 'keyEncryptionAlgorithm' has not been set yet - please use validate() to check!");
        return _keyEncryptionAlgorithm;
    }

    jres.Result setEncryptedKey(
        typeof(_encryptedKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedKey = true;
        _encryptedKey = value;
        return jres.Result.noError;
    }

    typeof(_encryptedKey) getEncryptedKey(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedKey, "Non-optional field 'encryptedKey' has not been set yet - please use validate() to check!");
        return _encryptedKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KEKRecipientInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_kekid)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KEKRecipientInfo non-optional field 'kekid' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_keyEncryptionAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KEKRecipientInfo non-optional field 'keyEncryptionAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KEKRecipientInfo non-optional field 'encryptedKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("kekid: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_kekid), "toString"))
            _kekid.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("keyEncryptionAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_keyEncryptionAlgorithm), "toString"))
            _keyEncryptionAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedKey), "toString"))
            _encryptedKey.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KEKRecipientInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KEKRecipientInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: kekid +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'kekid' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KEKRecipientInfo when reading top level tag 16 for field 'kekid' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KEKRecipientInfo when reading top level tag 16 for field 'kekid' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_kekid;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_kekid);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'kekid' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - kekid ++/
        typeof(_kekid) temp_kekid;
        result = temp_kekid.fromDecoding!ruleset(memory_kekid, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'kekid' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKekid(temp_kekid);
        if(result.isError)
            return result.wrapError("when setting field 'kekid' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: keyEncryptionAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KEKRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KEKRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyEncryptionAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyEncryptionAlgorithm ++/
        typeof(_keyEncryptionAlgorithm) temp_keyEncryptionAlgorithm;
        result = temp_keyEncryptionAlgorithm.fromDecoding!ruleset(memory_keyEncryptionAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyEncryptionAlgorithm(temp_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KEKRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KEKRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedKey ++/
        typeof(_encryptedKey) temp_encryptedKey;
        result = temp_encryptedKey.fromDecoding!ruleset(memory_encryptedKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedKey(temp_encryptedKey);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE KEKRecipientInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct KEKIdentifier
{
    private
    {
        bool _isSet_keyIdentifier;
        asn1.Asn1OctetString _keyIdentifier;
        bool _isSet_other;
        .OtherKeyAttribute _other;
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

    typeof(_keyIdentifier) getKeyIdentifier(
    ) @nogc nothrow
    {
        assert(_isSet_keyIdentifier, "Non-optional field 'keyIdentifier' has not been set yet - please use validate() to check!");
        return _keyIdentifier;
    }

    jres.Result setOther(
        typeof(_other) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_other = true;
        _other = value;
        return jres.Result.noError;
    }

    jres.Result setOther(
        tcon.Nullable!(.OtherKeyAttribute) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOther(value.get());
        }
        else
            _isSet_other = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OtherKeyAttribute) getOther(
    ) @nogc nothrow
    {
        if(_isSet_other)
            return typeof(return)(_other);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_keyIdentifier)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type KEKIdentifier non-optional field 'keyIdentifier' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        static if(__traits(hasMember, typeof(_keyIdentifier), "toString"))
            _keyIdentifier.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("other: ");
        sink("\n");
        if(_isSet_other)
        {
            static if(__traits(hasMember, typeof(_other), "toString"))
                _other.toString(sink, depth+1);
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
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE KEKIdentifier when reading top level tag 4 for field 'keyIdentifier' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE KEKIdentifier when reading top level tag 4 for field 'keyIdentifier' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyIdentifier;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyIdentifier);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyIdentifier ++/
        typeof(_keyIdentifier) temp_keyIdentifier;
        result = typeof(temp_keyIdentifier).fromDecoding!ruleset(memory_keyIdentifier, temp_keyIdentifier, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyIdentifier(temp_keyIdentifier);
        if(result.isError)
            return result.wrapError("when setting field 'keyIdentifier' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: other +++/
        auto backtrack_other = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'other' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 16)
            {
                jbuf.MemoryReader memory_other;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_other);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'other' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - other ++/
                typeof(_other) temp_other;
                result = temp_other.fromDecoding!ruleset(memory_other, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'other' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOther(temp_other);
                if(result.isError)
                    return result.wrapError("when setting field 'other' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_other.buffer, backtrack_other.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE KEKIdentifier there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct PasswordRecipientInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_keyDerivationAlgorithm;
        .KeyDerivationAlgorithmIdentifier _keyDerivationAlgorithm;
        bool _isSet_keyEncryptionAlgorithm;
        .KeyEncryptionAlgorithmIdentifier _keyEncryptionAlgorithm;
        bool _isSet_encryptedKey;
        .EncryptedKey _encryptedKey;
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

    jres.Result setKeyDerivationAlgorithm(
        typeof(_keyDerivationAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyDerivationAlgorithm = true;
        _keyDerivationAlgorithm = value;
        return jres.Result.noError;
    }

    jres.Result setKeyDerivationAlgorithm(
        tcon.Nullable!(.KeyDerivationAlgorithmIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setKeyDerivationAlgorithm(value.get());
        }
        else
            _isSet_keyDerivationAlgorithm = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.KeyDerivationAlgorithmIdentifier) getKeyDerivationAlgorithm(
    ) @nogc nothrow
    {
        if(_isSet_keyDerivationAlgorithm)
            return typeof(return)(_keyDerivationAlgorithm);
        return typeof(return).init;
    }

    jres.Result setKeyEncryptionAlgorithm(
        typeof(_keyEncryptionAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyEncryptionAlgorithm = true;
        _keyEncryptionAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_keyEncryptionAlgorithm) getKeyEncryptionAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_keyEncryptionAlgorithm, "Non-optional field 'keyEncryptionAlgorithm' has not been set yet - please use validate() to check!");
        return _keyEncryptionAlgorithm;
    }

    jres.Result setEncryptedKey(
        typeof(_encryptedKey) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedKey = true;
        _encryptedKey = value;
        return jres.Result.noError;
    }

    typeof(_encryptedKey) getEncryptedKey(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedKey, "Non-optional field 'encryptedKey' has not been set yet - please use validate() to check!");
        return _encryptedKey;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PasswordRecipientInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_keyEncryptionAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PasswordRecipientInfo non-optional field 'keyEncryptionAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedKey)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type PasswordRecipientInfo non-optional field 'encryptedKey' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("keyDerivationAlgorithm: ");
        sink("\n");
        if(_isSet_keyDerivationAlgorithm)
        {
            static if(__traits(hasMember, typeof(_keyDerivationAlgorithm), "toString"))
                _keyDerivationAlgorithm.toString(sink, depth+1);
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
        sink("keyEncryptionAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_keyEncryptionAlgorithm), "toString"))
            _keyEncryptionAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encryptedKey: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedKey), "toString"))
            _encryptedKey.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PasswordRecipientInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PasswordRecipientInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: keyDerivationAlgorithm +++/
        auto backtrack_keyDerivationAlgorithm = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'keyDerivationAlgorithm' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_keyDerivationAlgorithm;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyDerivationAlgorithm);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'keyDerivationAlgorithm' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - keyDerivationAlgorithm ++/
                typeof(_keyDerivationAlgorithm) temp_keyDerivationAlgorithm;
                result = temp_keyDerivationAlgorithm.fromDecoding!ruleset(memory_keyDerivationAlgorithm, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'keyDerivationAlgorithm' in type "~__traits(identifier, typeof(this))~":");
                result = this.setKeyDerivationAlgorithm(temp_keyDerivationAlgorithm);
                if(result.isError)
                    return result.wrapError("when setting field 'keyDerivationAlgorithm' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_keyDerivationAlgorithm.buffer, backtrack_keyDerivationAlgorithm.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: keyEncryptionAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PasswordRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PasswordRecipientInfo when reading top level tag 16 for field 'keyEncryptionAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyEncryptionAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyEncryptionAlgorithm ++/
        typeof(_keyEncryptionAlgorithm) temp_keyEncryptionAlgorithm;
        result = temp_keyEncryptionAlgorithm.fromDecoding!ruleset(memory_keyEncryptionAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyEncryptionAlgorithm(temp_keyEncryptionAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'keyEncryptionAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encryptedKey +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE PasswordRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE PasswordRecipientInfo when reading top level tag 4 for field 'encryptedKey' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedKey;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedKey);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedKey ++/
        typeof(_encryptedKey) temp_encryptedKey;
        result = temp_encryptedKey.fromDecoding!ruleset(memory_encryptedKey, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedKey(temp_encryptedKey);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedKey' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE PasswordRecipientInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct OtherRecipientInfo
{
    private
    {
        bool _isSet_oriType;
        asn1.Asn1ObjectIdentifier _oriType;
        bool _isSet_oriValue;
        asn1.Asn1Any _oriValue;
    }

    jres.Result setOriType(
        typeof(_oriType) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_oriType = true;
        _oriType = value;
        return jres.Result.noError;
    }

    typeof(_oriType) getOriType(
    ) @nogc nothrow
    {
        assert(_isSet_oriType, "Non-optional field 'oriType' has not been set yet - please use validate() to check!");
        return _oriType;
    }

    jres.Result setOriValue(
        typeof(_oriValue) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_oriValue = true;
        _oriValue = value;
        return jres.Result.noError;
    }

    typeof(_oriValue) getOriValue(
    ) @nogc nothrow
    {
        assert(_isSet_oriValue, "Non-optional field 'oriValue' has not been set yet - please use validate() to check!");
        return _oriValue;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_oriType)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type OtherRecipientInfo non-optional field 'oriType' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_oriValue)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type OtherRecipientInfo non-optional field 'oriValue' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("oriType: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_oriType), "toString"))
            _oriType.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("oriValue: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_oriValue), "toString"))
            _oriValue.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: oriType +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'oriType' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE OtherRecipientInfo when reading top level tag 6 for field 'oriType' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE OtherRecipientInfo when reading top level tag 6 for field 'oriType' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_oriType;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_oriType);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'oriType' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - oriType ++/
        typeof(_oriType) temp_oriType;
        result = typeof(temp_oriType).fromDecoding!ruleset(memory_oriType, temp_oriType, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'oriType' in type "~__traits(identifier, typeof(this))~":");
        result = this.setOriType(temp_oriType);
        if(result.isError)
            return result.wrapError("when setting field 'oriType' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: oriValue +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'oriValue' in type "~__traits(identifier, typeof(this))~":");
        // Field is the intrinsic ANY type - any tag is allowed.
        jbuf.MemoryReader memory_oriValue;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_oriValue);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'oriValue' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - oriValue ++/
        typeof(_oriValue) temp_oriValue;
        result = typeof(temp_oriValue).fromDecoding!ruleset(memory_oriValue, temp_oriValue, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'oriValue' in type "~__traits(identifier, typeof(this))~":");
        result = this.setOriValue(temp_oriValue);
        if(result.isError)
            return result.wrapError("when setting field 'oriValue' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE OtherRecipientInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct DigestedData
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_digestAlgorithm;
        .DigestAlgorithmIdentifier _digestAlgorithm;
        bool _isSet_encapContentInfo;
        .EncapsulatedContentInfo _encapContentInfo;
        bool _isSet_digest;
        .Digest _digest;
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

    jres.Result setDigestAlgorithm(
        typeof(_digestAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_digestAlgorithm = true;
        _digestAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_digestAlgorithm) getDigestAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_digestAlgorithm, "Non-optional field 'digestAlgorithm' has not been set yet - please use validate() to check!");
        return _digestAlgorithm;
    }

    jres.Result setEncapContentInfo(
        typeof(_encapContentInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encapContentInfo = true;
        _encapContentInfo = value;
        return jres.Result.noError;
    }

    typeof(_encapContentInfo) getEncapContentInfo(
    ) @nogc nothrow
    {
        assert(_isSet_encapContentInfo, "Non-optional field 'encapContentInfo' has not been set yet - please use validate() to check!");
        return _encapContentInfo;
    }

    jres.Result setDigest(
        typeof(_digest) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_digest = true;
        _digest = value;
        return jres.Result.noError;
    }

    typeof(_digest) getDigest(
    ) @nogc nothrow
    {
        assert(_isSet_digest, "Non-optional field 'digest' has not been set yet - please use validate() to check!");
        return _digest;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DigestedData non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_digestAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DigestedData non-optional field 'digestAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encapContentInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DigestedData non-optional field 'encapContentInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_digest)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type DigestedData non-optional field 'digest' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("digestAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_digestAlgorithm), "toString"))
            _digestAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("encapContentInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encapContentInfo), "toString"))
            _encapContentInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("digest: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_digest), "toString"))
            _digest.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DigestedData when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DigestedData when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: digestAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DigestedData when reading top level tag 16 for field 'digestAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DigestedData when reading top level tag 16 for field 'digestAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_digestAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_digestAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - digestAlgorithm ++/
        typeof(_digestAlgorithm) temp_digestAlgorithm;
        result = temp_digestAlgorithm.fromDecoding!ruleset(memory_digestAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setDigestAlgorithm(temp_digestAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: encapContentInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DigestedData when reading top level tag 16 for field 'encapContentInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DigestedData when reading top level tag 16 for field 'encapContentInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encapContentInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encapContentInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encapContentInfo ++/
        typeof(_encapContentInfo) temp_encapContentInfo;
        result = temp_encapContentInfo.fromDecoding!ruleset(memory_encapContentInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncapContentInfo(temp_encapContentInfo);
        if(result.isError)
            return result.wrapError("when setting field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: digest +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'digest' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE DigestedData when reading top level tag 4 for field 'digest' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE DigestedData when reading top level tag 4 for field 'digest' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_digest;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_digest);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'digest' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - digest ++/
        typeof(_digest) temp_digest;
        result = temp_digest.fromDecoding!ruleset(memory_digest, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'digest' in type "~__traits(identifier, typeof(this))~":");
        result = this.setDigest(temp_digest);
        if(result.isError)
            return result.wrapError("when setting field 'digest' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE DigestedData there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct Digest
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

struct EncryptedData
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_encryptedContentInfo;
        .EncryptedContentInfo _encryptedContentInfo;
        bool _isSet_unprotectedAttrs;
        .UnprotectedAttributes _unprotectedAttrs;
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

    jres.Result setEncryptedContentInfo(
        typeof(_encryptedContentInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encryptedContentInfo = true;
        _encryptedContentInfo = value;
        return jres.Result.noError;
    }

    typeof(_encryptedContentInfo) getEncryptedContentInfo(
    ) @nogc nothrow
    {
        assert(_isSet_encryptedContentInfo, "Non-optional field 'encryptedContentInfo' has not been set yet - please use validate() to check!");
        return _encryptedContentInfo;
    }

    jres.Result setUnprotectedAttrs(
        typeof(_unprotectedAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_unprotectedAttrs = true;
        _unprotectedAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setUnprotectedAttrs(
        tcon.Nullable!(.UnprotectedAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setUnprotectedAttrs(value.get());
        }
        else
            _isSet_unprotectedAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UnprotectedAttributes) getUnprotectedAttrs(
    ) @nogc nothrow
    {
        if(_isSet_unprotectedAttrs)
            return typeof(return)(_unprotectedAttrs);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EncryptedData non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encryptedContentInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type EncryptedData non-optional field 'encryptedContentInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("encryptedContentInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encryptedContentInfo), "toString"))
            _encryptedContentInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("unprotectedAttrs: ");
        sink("\n");
        if(_isSet_unprotectedAttrs)
        {
            static if(__traits(hasMember, typeof(_unprotectedAttrs), "toString"))
                _unprotectedAttrs.toString(sink, depth+1);
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EncryptedData when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EncryptedData when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: encryptedContentInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE EncryptedData when reading top level tag 16 for field 'encryptedContentInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE EncryptedData when reading top level tag 16 for field 'encryptedContentInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encryptedContentInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encryptedContentInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encryptedContentInfo ++/
        typeof(_encryptedContentInfo) temp_encryptedContentInfo;
        result = temp_encryptedContentInfo.fromDecoding!ruleset(memory_encryptedContentInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncryptedContentInfo(temp_encryptedContentInfo);
        if(result.isError)
            return result.wrapError("when setting field 'encryptedContentInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: unprotectedAttrs +++/
        auto backtrack_unprotectedAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_unprotectedAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_unprotectedAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - unprotectedAttrs ++/
                typeof(_unprotectedAttrs) temp_unprotectedAttrs;
                result = temp_unprotectedAttrs.fromDecoding!ruleset(memory_unprotectedAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setUnprotectedAttrs(temp_unprotectedAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'unprotectedAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_unprotectedAttrs.buffer, backtrack_unprotectedAttrs.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE EncryptedData there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct AuthenticatedData
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_originatorInfo;
        .OriginatorInfo _originatorInfo;
        bool _isSet_recipientInfos;
        .RecipientInfos _recipientInfos;
        bool _isSet_macAlgorithm;
        .MessageAuthenticationCodeAlgorithm _macAlgorithm;
        bool _isSet_digestAlgorithm;
        .DigestAlgorithmIdentifier _digestAlgorithm;
        bool _isSet_encapContentInfo;
        .EncapsulatedContentInfo _encapContentInfo;
        bool _isSet_authAttrs;
        .AuthAttributes _authAttrs;
        bool _isSet_mac;
        .MessageAuthenticationCode _mac;
        bool _isSet_unauthAttrs;
        .UnauthAttributes _unauthAttrs;
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

    jres.Result setOriginatorInfo(
        typeof(_originatorInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_originatorInfo = true;
        _originatorInfo = value;
        return jres.Result.noError;
    }

    jres.Result setOriginatorInfo(
        tcon.Nullable!(.OriginatorInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setOriginatorInfo(value.get());
        }
        else
            _isSet_originatorInfo = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.OriginatorInfo) getOriginatorInfo(
    ) @nogc nothrow
    {
        if(_isSet_originatorInfo)
            return typeof(return)(_originatorInfo);
        return typeof(return).init;
    }

    jres.Result setRecipientInfos(
        typeof(_recipientInfos) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_recipientInfos = true;
        _recipientInfos = value;
        return jres.Result.noError;
    }

    typeof(_recipientInfos) getRecipientInfos(
    ) @nogc nothrow
    {
        assert(_isSet_recipientInfos, "Non-optional field 'recipientInfos' has not been set yet - please use validate() to check!");
        return _recipientInfos;
    }

    jres.Result setMacAlgorithm(
        typeof(_macAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_macAlgorithm = true;
        _macAlgorithm = value;
        return jres.Result.noError;
    }

    typeof(_macAlgorithm) getMacAlgorithm(
    ) @nogc nothrow
    {
        assert(_isSet_macAlgorithm, "Non-optional field 'macAlgorithm' has not been set yet - please use validate() to check!");
        return _macAlgorithm;
    }

    jres.Result setDigestAlgorithm(
        typeof(_digestAlgorithm) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_digestAlgorithm = true;
        _digestAlgorithm = value;
        return jres.Result.noError;
    }

    jres.Result setDigestAlgorithm(
        tcon.Nullable!(.DigestAlgorithmIdentifier) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setDigestAlgorithm(value.get());
        }
        else
            _isSet_digestAlgorithm = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.DigestAlgorithmIdentifier) getDigestAlgorithm(
    ) @nogc nothrow
    {
        if(_isSet_digestAlgorithm)
            return typeof(return)(_digestAlgorithm);
        return typeof(return).init;
    }

    jres.Result setEncapContentInfo(
        typeof(_encapContentInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_encapContentInfo = true;
        _encapContentInfo = value;
        return jres.Result.noError;
    }

    typeof(_encapContentInfo) getEncapContentInfo(
    ) @nogc nothrow
    {
        assert(_isSet_encapContentInfo, "Non-optional field 'encapContentInfo' has not been set yet - please use validate() to check!");
        return _encapContentInfo;
    }

    jres.Result setAuthAttrs(
        typeof(_authAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_authAttrs = true;
        _authAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setAuthAttrs(
        tcon.Nullable!(.AuthAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setAuthAttrs(value.get());
        }
        else
            _isSet_authAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.AuthAttributes) getAuthAttrs(
    ) @nogc nothrow
    {
        if(_isSet_authAttrs)
            return typeof(return)(_authAttrs);
        return typeof(return).init;
    }

    jres.Result setMac(
        typeof(_mac) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_mac = true;
        _mac = value;
        return jres.Result.noError;
    }

    typeof(_mac) getMac(
    ) @nogc nothrow
    {
        assert(_isSet_mac, "Non-optional field 'mac' has not been set yet - please use validate() to check!");
        return _mac;
    }

    jres.Result setUnauthAttrs(
        typeof(_unauthAttrs) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_unauthAttrs = true;
        _unauthAttrs = value;
        return jres.Result.noError;
    }

    jres.Result setUnauthAttrs(
        tcon.Nullable!(.UnauthAttributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setUnauthAttrs(value.get());
        }
        else
            _isSet_unauthAttrs = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(.UnauthAttributes) getUnauthAttrs(
    ) @nogc nothrow
    {
        if(_isSet_unauthAttrs)
            return typeof(return)(_unauthAttrs);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AuthenticatedData non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_recipientInfos)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AuthenticatedData non-optional field 'recipientInfos' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_macAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AuthenticatedData non-optional field 'macAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_encapContentInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AuthenticatedData non-optional field 'encapContentInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_mac)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type AuthenticatedData non-optional field 'mac' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("originatorInfo: ");
        sink("\n");
        if(_isSet_originatorInfo)
        {
            static if(__traits(hasMember, typeof(_originatorInfo), "toString"))
                _originatorInfo.toString(sink, depth+1);
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
        sink("recipientInfos: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_recipientInfos), "toString"))
            _recipientInfos.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("macAlgorithm: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_macAlgorithm), "toString"))
            _macAlgorithm.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("digestAlgorithm: ");
        sink("\n");
        if(_isSet_digestAlgorithm)
        {
            static if(__traits(hasMember, typeof(_digestAlgorithm), "toString"))
                _digestAlgorithm.toString(sink, depth+1);
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
        sink("encapContentInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_encapContentInfo), "toString"))
            _encapContentInfo.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("authAttrs: ");
        sink("\n");
        if(_isSet_authAttrs)
        {
            static if(__traits(hasMember, typeof(_authAttrs), "toString"))
                _authAttrs.toString(sink, depth+1);
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
        sink("mac: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_mac), "toString"))
            _mac.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("unauthAttrs: ");
        sink("\n");
        if(_isSet_unauthAttrs)
        {
            static if(__traits(hasMember, typeof(_unauthAttrs), "toString"))
                _unauthAttrs.toString(sink, depth+1);
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AuthenticatedData when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AuthenticatedData when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: originatorInfo +++/
        auto backtrack_originatorInfo = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 0)
            {
                jbuf.MemoryReader memory_originatorInfo;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_originatorInfo);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - originatorInfo ++/
                typeof(_originatorInfo) temp_originatorInfo;
                result = temp_originatorInfo.fromDecoding!ruleset(memory_originatorInfo, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");
                result = this.setOriginatorInfo(temp_originatorInfo);
                if(result.isError)
                    return result.wrapError("when setting field 'originatorInfo' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_originatorInfo.buffer, backtrack_originatorInfo.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: recipientInfos +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AuthenticatedData when reading top level tag 17 for field 'recipientInfos' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AuthenticatedData when reading top level tag 17 for field 'recipientInfos' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_recipientInfos;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_recipientInfos);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - recipientInfos ++/
        typeof(_recipientInfos) temp_recipientInfos;
        result = temp_recipientInfos.fromDecoding!ruleset(memory_recipientInfos, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");
        result = this.setRecipientInfos(temp_recipientInfos);
        if(result.isError)
            return result.wrapError("when setting field 'recipientInfos' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: macAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'macAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AuthenticatedData when reading top level tag 16 for field 'macAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AuthenticatedData when reading top level tag 16 for field 'macAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_macAlgorithm;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_macAlgorithm);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'macAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - macAlgorithm ++/
        typeof(_macAlgorithm) temp_macAlgorithm;
        result = temp_macAlgorithm.fromDecoding!ruleset(memory_macAlgorithm, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'macAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        result = this.setMacAlgorithm(temp_macAlgorithm);
        if(result.isError)
            return result.wrapError("when setting field 'macAlgorithm' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: digestAlgorithm +++/
        auto backtrack_digestAlgorithm = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_digestAlgorithm;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_digestAlgorithm);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - digestAlgorithm ++/
                typeof(_digestAlgorithm) temp_digestAlgorithm;
                result = temp_digestAlgorithm.fromDecoding!ruleset(memory_digestAlgorithm, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");
                result = this.setDigestAlgorithm(temp_digestAlgorithm);
                if(result.isError)
                    return result.wrapError("when setting field 'digestAlgorithm' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_digestAlgorithm.buffer, backtrack_digestAlgorithm.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: encapContentInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AuthenticatedData when reading top level tag 16 for field 'encapContentInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AuthenticatedData when reading top level tag 16 for field 'encapContentInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_encapContentInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_encapContentInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - encapContentInfo ++/
        typeof(_encapContentInfo) temp_encapContentInfo;
        result = temp_encapContentInfo.fromDecoding!ruleset(memory_encapContentInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setEncapContentInfo(temp_encapContentInfo);
        if(result.isError)
            return result.wrapError("when setting field 'encapContentInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: authAttrs +++/
        auto backtrack_authAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'authAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 2)
            {
                jbuf.MemoryReader memory_authAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_authAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'authAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - authAttrs ++/
                typeof(_authAttrs) temp_authAttrs;
                result = temp_authAttrs.fromDecoding!ruleset(memory_authAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'authAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setAuthAttrs(temp_authAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'authAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_authAttrs.buffer, backtrack_authAttrs.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: mac +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'mac' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE AuthenticatedData when reading top level tag 4 for field 'mac' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 4)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE AuthenticatedData when reading top level tag 4 for field 'mac' the tag's value was expected to be 4", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_mac;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_mac);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'mac' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - mac ++/
        typeof(_mac) temp_mac;
        result = temp_mac.fromDecoding!ruleset(memory_mac, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'mac' in type "~__traits(identifier, typeof(this))~":");
        result = this.setMac(temp_mac);
        if(result.isError)
            return result.wrapError("when setting field 'mac' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: unauthAttrs +++/
        auto backtrack_unauthAttrs = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'unauthAttrs' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.contextSpecific && componentHeader.identifier.tag == 3)
            {
                jbuf.MemoryReader memory_unauthAttrs;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_unauthAttrs);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'unauthAttrs' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - unauthAttrs ++/
                typeof(_unauthAttrs) temp_unauthAttrs;
                result = temp_unauthAttrs.fromDecoding!ruleset(memory_unauthAttrs, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'unauthAttrs' in type "~__traits(identifier, typeof(this))~":");
                result = this.setUnauthAttrs(temp_unauthAttrs);
                if(result.isError)
                    return result.wrapError("when setting field 'unauthAttrs' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_unauthAttrs.buffer, backtrack_unauthAttrs.cursor);
            }
        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE AuthenticatedData there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct AuthAttributes
{
    private
    {
        asn1.Asn1SetOf!(.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.Attribute) newValue,
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

    asn1.Asn1SetOf!(.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.Attribute), "toString"))
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

struct UnauthAttributes
{
    private
    {
        asn1.Asn1SetOf!(.Attribute) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.Attribute) newValue,
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

    asn1.Asn1SetOf!(.Attribute) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.Attribute), "toString"))
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

struct MessageAuthenticationCode
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

struct DigestAlgorithmIdentifier
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct SignatureAlgorithmIdentifier
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct KeyEncryptionAlgorithmIdentifier
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct ContentEncryptionAlgorithmIdentifier
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct MessageAuthenticationCodeAlgorithm
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct KeyDerivationAlgorithmIdentifier
{
    private
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier _value;
        bool _isSet;
    }

    jres.Result set(
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier get(
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
        static if(__traits(hasMember, PKIX1Explicit88_1_3_6_1_5_5_7_0_18.AlgorithmIdentifier, "toString"))
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

struct CertificateRevocationLists
{
    private
    {
        asn1.Asn1SetOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateList) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateList) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateList) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateList), "toString"))
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

struct CertificateChoices
{
    enum Choice
    {
        _FAILSAFE,
        certificate,
        extendedCertificate,
    }

    union Value
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Certificate certificate;
        .ExtendedCertificate extendedCertificate;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Certificate), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.ExtendedCertificate), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.certificate)) @nogc nothrow handle_certificate,
        scope jres.Result delegate(typeof(Value.extendedCertificate)) @nogc nothrow handle_extendedCertificate,
    ) @nogc nothrow
    {
        if(_choice == Choice.certificate)
            return handle_certificate(_value.certificate);
        if(_choice == Choice.extendedCertificate)
            return handle_extendedCertificate(_value.extendedCertificate);
        assert(false, "attempted to use an uninitialised CertificateChoices!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.certificate))  handle_certificate,
        scope jres.Result delegate(typeof(Value.extendedCertificate))  handle_extendedCertificate,
    ) 
    {
        if(_choice == Choice.certificate)
            return handle_certificate(_value.certificate);
        if(_choice == Choice.extendedCertificate)
            return handle_extendedCertificate(_value.extendedCertificate);
        assert(false, "attempted to use an uninitialised CertificateChoices!");

    }

    jres.Result setCertificate(
        typeof(Value.certificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.certificate = value;
        _choice = Choice.certificate;
        return jres.Result.noError;
    }

    typeof(Value.certificate) getCertificate(
    ) @nogc nothrow
    {
        assert(_choice == Choice.certificate, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'certificate'");
        return _value.certificate;
    }

    bool isCertificate(
    ) @nogc nothrow const
    {
        return _choice == Choice.certificate;
    }

    jres.Result setExtendedCertificate(
        typeof(Value.extendedCertificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.extendedCertificate = value;
        _choice = Choice.extendedCertificate;
        return jres.Result.noError;
    }

    typeof(Value.extendedCertificate) getExtendedCertificate(
    ) @nogc nothrow
    {
        assert(_choice == Choice.extendedCertificate, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'extendedCertificate'");
        return _value.extendedCertificate;
    }

    bool isExtendedCertificate(
    ) @nogc nothrow const
    {
        return _choice == Choice.extendedCertificate;
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
            /++ FIELD - certificate ++/
            typeof(Value.certificate) temp_certificate;
            result = temp_certificate.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'certificate' in type "~__traits(identifier, typeof(this))~":");
            result = this.setCertificate(temp_certificate);
            if(result.isError)
                return result.wrapError("when setting field 'certificate' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - extendedCertificate ++/
            typeof(Value.extendedCertificate) temp_extendedCertificate;
            result = temp_extendedCertificate.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'extendedCertificate' in type "~__traits(identifier, typeof(this))~":");
            result = this.setExtendedCertificate(temp_extendedCertificate);
            if(result.isError)
                return result.wrapError("when setting field 'extendedCertificate' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type CertificateChoices the identifier tag & class were unable to match any known option");
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
        if(isCertificate)
        {
            depth++;
            putIndent();
            sink("certificate: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getCertificate()), "toString"))
                _value.certificate.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isExtendedCertificate)
        {
            depth++;
            putIndent();
            sink("extendedCertificate: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getExtendedCertificate()), "toString"))
                _value.extendedCertificate.toString(sink, depth+1);
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

struct CertificateSet
{
    private
    {
        asn1.Asn1SetOf!(.CertificateChoices) _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1SetOf!(.CertificateChoices) newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1SetOf!(.CertificateChoices) get(
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
        static if(__traits(hasMember, asn1.Asn1SetOf!(.CertificateChoices), "toString"))
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

struct IssuerAndSerialNumber
{
    private
    {
        bool _isSet_issuer;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Name _issuer;
        bool _isSet_serialNumber;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.CertificateSerialNumber _serialNumber;
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

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_issuer)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type IssuerAndSerialNumber non-optional field 'issuer' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_serialNumber)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type IssuerAndSerialNumber non-optional field 'serialNumber' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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

        
        /+++ TAG FOR FIELD: serialNumber +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'serialNumber' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE IssuerAndSerialNumber when reading top level tag 2 for field 'serialNumber' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE IssuerAndSerialNumber when reading top level tag 2 for field 'serialNumber' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE IssuerAndSerialNumber there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct CMSVersion
{
    enum NamedNumber
    {
        v1 = 1,
        v2 = 2,
        v3 = 3,
        v0 = 0,
        v4 = 4,
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

struct UserKeyingMaterial
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

struct OtherKeyAttribute
{
    private
    {
        bool _isSet_keyAttrId;
        asn1.Asn1ObjectIdentifier _keyAttrId;
        bool _isSet_keyAttr;
        asn1.Asn1Any _keyAttr;
    }

    jres.Result setKeyAttrId(
        typeof(_keyAttrId) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyAttrId = true;
        _keyAttrId = value;
        return jres.Result.noError;
    }

    typeof(_keyAttrId) getKeyAttrId(
    ) @nogc nothrow
    {
        assert(_isSet_keyAttrId, "Non-optional field 'keyAttrId' has not been set yet - please use validate() to check!");
        return _keyAttrId;
    }

    jres.Result setKeyAttr(
        typeof(_keyAttr) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_keyAttr = true;
        _keyAttr = value;
        return jres.Result.noError;
    }

    jres.Result setKeyAttr(
        tcon.Nullable!(asn1.Asn1Any) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setKeyAttr(value.get());
        }
        else
            _isSet_keyAttr = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Any) getKeyAttr(
    ) @nogc nothrow
    {
        if(_isSet_keyAttr)
            return typeof(return)(_keyAttr);
        return typeof(return).init;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_keyAttrId)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type OtherKeyAttribute non-optional field 'keyAttrId' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("keyAttrId: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_keyAttrId), "toString"))
            _keyAttrId.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("keyAttr: ");
        sink("\n");
        if(_isSet_keyAttr)
        {
            static if(__traits(hasMember, typeof(_keyAttr), "toString"))
                _keyAttr.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: keyAttrId +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'keyAttrId' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE OtherKeyAttribute when reading top level tag 6 for field 'keyAttrId' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 6)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE OtherKeyAttribute when reading top level tag 6 for field 'keyAttrId' the tag's value was expected to be 6", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_keyAttrId;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyAttrId);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'keyAttrId' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - keyAttrId ++/
        typeof(_keyAttrId) temp_keyAttrId;
        result = typeof(temp_keyAttrId).fromDecoding!ruleset(memory_keyAttrId, temp_keyAttrId, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'keyAttrId' in type "~__traits(identifier, typeof(this))~":");
        result = this.setKeyAttrId(temp_keyAttrId);
        if(result.isError)
            return result.wrapError("when setting field 'keyAttrId' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: keyAttr +++/
        auto backtrack_keyAttr = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'keyAttr' in type "~__traits(identifier, typeof(this))~":");
            // Field is the intrinsic ANY type - any tag is allowed.
            jbuf.MemoryReader memory_keyAttr;
            result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_keyAttr);
            if(result.isError)
                return result.wrapError("when reading content bytes of field 'keyAttr' in type "~__traits(identifier, typeof(this))~":");
            /++ FIELD - keyAttr ++/
            typeof(_keyAttr) temp_keyAttr;
            result = typeof(temp_keyAttr).fromDecoding!ruleset(memory_keyAttr, temp_keyAttr, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'keyAttr' in type "~__traits(identifier, typeof(this))~":");
            result = this.setKeyAttr(temp_keyAttr);
            if(result.isError)
                return result.wrapError("when setting field 'keyAttr' in type "~__traits(identifier, typeof(this))~":");

        }
        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE OtherKeyAttribute there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct MessageDigest
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

struct SigningTime
{
    private
    {
        .Time _value;
        bool _isSet;
    }

    jres.Result set(
        .Time newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .Time get(
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
        static if(__traits(hasMember, .Time, "toString"))
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

struct Countersignature
{
    private
    {
        .SignerInfo _value;
        bool _isSet;
    }

    jres.Result set(
        .SignerInfo newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    .SignerInfo get(
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
        static if(__traits(hasMember, .SignerInfo, "toString"))
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

asn1.Asn1ObjectIdentifier id_contentType(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_messageDigest(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_signingTime(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 5, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_countersignature(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        /* 840 */ 0x86, 0x48, /* 113549 */ 0x86, 0xF7, 0xD, 1, 9, 6, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 2, mainValue__value);
    return mainValue;

}

struct ExtendedCertificateOrCertificate
{
    enum Choice
    {
        _FAILSAFE,
        certificate,
        extendedCertificate,
    }

    union Value
    {
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Certificate certificate;
        .ExtendedCertificate extendedCertificate;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Certificate), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(.ExtendedCertificate), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result match(
        scope jres.Result delegate(typeof(Value.certificate)) @nogc nothrow handle_certificate,
        scope jres.Result delegate(typeof(Value.extendedCertificate)) @nogc nothrow handle_extendedCertificate,
    ) @nogc nothrow
    {
        if(_choice == Choice.certificate)
            return handle_certificate(_value.certificate);
        if(_choice == Choice.extendedCertificate)
            return handle_extendedCertificate(_value.extendedCertificate);
        assert(false, "attempted to use an uninitialised ExtendedCertificateOrCertificate!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.certificate))  handle_certificate,
        scope jres.Result delegate(typeof(Value.extendedCertificate))  handle_extendedCertificate,
    ) 
    {
        if(_choice == Choice.certificate)
            return handle_certificate(_value.certificate);
        if(_choice == Choice.extendedCertificate)
            return handle_extendedCertificate(_value.extendedCertificate);
        assert(false, "attempted to use an uninitialised ExtendedCertificateOrCertificate!");

    }

    jres.Result setCertificate(
        typeof(Value.certificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.certificate = value;
        _choice = Choice.certificate;
        return jres.Result.noError;
    }

    typeof(Value.certificate) getCertificate(
    ) @nogc nothrow
    {
        assert(_choice == Choice.certificate, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'certificate'");
        return _value.certificate;
    }

    bool isCertificate(
    ) @nogc nothrow const
    {
        return _choice == Choice.certificate;
    }

    jres.Result setExtendedCertificate(
        typeof(Value.extendedCertificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value.extendedCertificate = value;
        _choice = Choice.extendedCertificate;
        return jres.Result.noError;
    }

    typeof(Value.extendedCertificate) getExtendedCertificate(
    ) @nogc nothrow
    {
        assert(_choice == Choice.extendedCertificate, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'extendedCertificate'");
        return _value.extendedCertificate;
    }

    bool isExtendedCertificate(
    ) @nogc nothrow const
    {
        return _choice == Choice.extendedCertificate;
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
            /++ FIELD - certificate ++/
            typeof(Value.certificate) temp_certificate;
            result = temp_certificate.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'certificate' in type "~__traits(identifier, typeof(this))~":");
            result = this.setCertificate(temp_certificate);
            if(result.isError)
                return result.wrapError("when setting field 'certificate' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - extendedCertificate ++/
            typeof(Value.extendedCertificate) temp_extendedCertificate;
            result = temp_extendedCertificate.fromDecoding!ruleset(memory, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'extendedCertificate' in type "~__traits(identifier, typeof(this))~":");
            result = this.setExtendedCertificate(temp_extendedCertificate);
            if(result.isError)
                return result.wrapError("when setting field 'extendedCertificate' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type ExtendedCertificateOrCertificate the identifier tag & class were unable to match any known option");
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
        if(isCertificate)
        {
            depth++;
            putIndent();
            sink("certificate: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getCertificate()), "toString"))
                _value.certificate.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isExtendedCertificate)
        {
            depth++;
            putIndent();
            sink("extendedCertificate: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getExtendedCertificate()), "toString"))
                _value.extendedCertificate.toString(sink, depth+1);
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

struct ExtendedCertificate
{
    private
    {
        bool _isSet_extendedCertificateInfo;
        .ExtendedCertificateInfo _extendedCertificateInfo;
        bool _isSet_signatureAlgorithm;
        .SignatureAlgorithmIdentifier _signatureAlgorithm;
        bool _isSet_signature;
        .Signature _signature;
    }

    jres.Result setExtendedCertificateInfo(
        typeof(_extendedCertificateInfo) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_extendedCertificateInfo = true;
        _extendedCertificateInfo = value;
        return jres.Result.noError;
    }

    typeof(_extendedCertificateInfo) getExtendedCertificateInfo(
    ) @nogc nothrow
    {
        assert(_isSet_extendedCertificateInfo, "Non-optional field 'extendedCertificateInfo' has not been set yet - please use validate() to check!");
        return _extendedCertificateInfo;
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
        if(!_isSet_extendedCertificateInfo)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificate non-optional field 'extendedCertificateInfo' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signatureAlgorithm)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificate non-optional field 'signatureAlgorithm' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_signature)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificate non-optional field 'signature' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("extendedCertificateInfo: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_extendedCertificateInfo), "toString"))
            _extendedCertificateInfo.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: extendedCertificateInfo +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'extendedCertificateInfo' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificate when reading top level tag 16 for field 'extendedCertificateInfo' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificate when reading top level tag 16 for field 'extendedCertificateInfo' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_extendedCertificateInfo;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_extendedCertificateInfo);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'extendedCertificateInfo' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - extendedCertificateInfo ++/
        typeof(_extendedCertificateInfo) temp_extendedCertificateInfo;
        result = temp_extendedCertificateInfo.fromDecoding!ruleset(memory_extendedCertificateInfo, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'extendedCertificateInfo' in type "~__traits(identifier, typeof(this))~":");
        result = this.setExtendedCertificateInfo(temp_extendedCertificateInfo);
        if(result.isError)
            return result.wrapError("when setting field 'extendedCertificateInfo' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: signatureAlgorithm +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'signatureAlgorithm' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificate when reading top level tag 16 for field 'signatureAlgorithm' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificate when reading top level tag 16 for field 'signatureAlgorithm' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
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
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificate when reading top level tag 3 for field 'signature' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 3)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificate when reading top level tag 3 for field 'signature' the tag's value was expected to be 3", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ExtendedCertificate there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct ExtendedCertificateInfo
{
    private
    {
        bool _isSet_version;
        .CMSVersion _version;
        bool _isSet_certificate;
        PKIX1Explicit88_1_3_6_1_5_5_7_0_18.Certificate _certificate;
        bool _isSet_attributes;
        .UnauthAttributes _attributes;
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

    jres.Result setCertificate(
        typeof(_certificate) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_certificate = true;
        _certificate = value;
        return jres.Result.noError;
    }

    typeof(_certificate) getCertificate(
    ) @nogc nothrow
    {
        assert(_isSet_certificate, "Non-optional field 'certificate' has not been set yet - please use validate() to check!");
        return _certificate;
    }

    jres.Result setAttributes(
        typeof(_attributes) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_attributes = true;
        _attributes = value;
        return jres.Result.noError;
    }

    typeof(_attributes) getAttributes(
    ) @nogc nothrow
    {
        assert(_isSet_attributes, "Non-optional field 'attributes' has not been set yet - please use validate() to check!");
        return _attributes;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_version)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificateInfo non-optional field 'version' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_certificate)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificateInfo non-optional field 'certificate' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_attributes)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type ExtendedCertificateInfo non-optional field 'attributes' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
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
        sink("certificate: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_certificate), "toString"))
            _certificate.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("attributes: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_attributes), "toString"))
            _attributes.toString(sink, depth+1);
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

        /+++ TAG FOR FIELD: version +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'version' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 2 for field 'version' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 2 for field 'version' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
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

        
        /+++ TAG FOR FIELD: certificate +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'certificate' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 16 for field 'certificate' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 16)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 16 for field 'certificate' the tag's value was expected to be 16", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_certificate;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_certificate);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'certificate' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - certificate ++/
        typeof(_certificate) temp_certificate;
        result = temp_certificate.fromDecoding!ruleset(memory_certificate, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'certificate' in type "~__traits(identifier, typeof(this))~":");
        result = this.setCertificate(temp_certificate);
        if(result.isError)
            return result.wrapError("when setting field 'certificate' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: attributes +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'attributes' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 17 for field 'attributes' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 17)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE ExtendedCertificateInfo when reading top level tag 17 for field 'attributes' the tag's value was expected to be 17", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_attributes;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_attributes);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'attributes' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - attributes ++/
        typeof(_attributes) temp_attributes;
        result = temp_attributes.fromDecoding!ruleset(memory_attributes, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'attributes' in type "~__traits(identifier, typeof(this))~":");
        result = this.setAttributes(temp_attributes);
        if(result.isError)
            return result.wrapError("when setting field 'attributes' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE ExtendedCertificateInfo there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}

struct Signature
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
