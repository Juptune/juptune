module juptune.data.asn1.generated.raw.AttributeCertificateVersion1_1_2_840_113549_1_9_16_0_15;
static import PKIX1Explicit88_1_3_6_1_5_5_7_0_18 = juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;
static import PKIX1Implicit88_1_3_6_1_5_5_7_0_19 = juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19;

static import tcon = std.typecons;
static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

struct AttCertVersionV1
{
    enum NamedNumber
    {
        v1 = 0,
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
