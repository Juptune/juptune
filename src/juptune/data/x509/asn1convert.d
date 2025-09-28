/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// This module is responsible for converting the ASN.1 model of an x.509 certificate into something
/// a little bit more natural to use, while also performing light amounts of validation.
///
/// The goal of this module is to try and flatten the ASN.1 model where possible (i.e. where allocation isn't required),
/// while providing helper functions for the extra parts that would otherwise require allocation to be handled cleanly.
module juptune.data.x509.asn1convert;

import juptune.core.ds : String2;
import juptune.core.util : Result;

import juptune.data.asn1.decode.bcd.encoding : Asn1ObjectIdentifier, Asn1Integer;

import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 
        : Certificate, AlgorithmIdentifier, AttributeTypeAndValue, Name, Time, Extensions, Extension;
import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19 
        : 
            GeneralNames,
            GeneralSubtrees,
            CRLDistributionPoints,
            Asn1PolicyMappings = PolicyMappings,
            Asn1SubjectDirectoryAttributes = SubjectDirectoryAttributes,
            Asn1AuthorityInfoAccessSyntax = AuthorityInfoAccessSyntax,
            Asn1SubjectInfoAccessSyntax = SubjectInfoAccessSyntax
        ;

// A `Result` error enum.
enum X509Error
{
    none,

    invalidCertVersion, /// The `version` field contains an unknown/invalid version value.
    signatureAlgorithmMismatch, /// The `signatureAlgorithm` and unexposed `signature` fields describe different algorithms.
    invalidTimeType, /// A Time must use UTCTime for years <= 2049, and GeneralizedTime for years >= 2050
    uniqueIdentifiersWrongVersion, /// Unique Identifiers exsit under a certificate that is not v2 or v3.
    extensionsWrongVersion, /// Extensions exist under a certificate that is not v3.
    keyUsageTooManyBits, /// The `keyUsage` extension contains more bits than expected.
    keyUsageNoSetBit, /// The `keyUsage` extension must contain at least 1 set bit when used.
    extendedKeyUsageUnknownUsage, /// The `extendedKeyUsage extension` contains an unknown usage OBJECT IDENTIFIER.

    criticalExtensionNotHandled, /// (Useful for user code) an extension marked as critical was unable to be handled.
}

/// Namespace class used to store all supported signature algorithms.
abstract class X509SignatureAlgorithm
{
    import std.sumtype : SumType;

    /// A SumType of all possible signature algorithms.
    alias SumT = SumType!(Unknown);

    /// An unknown signature was encountered - user code may be able to recognise it though.
    static struct Unknown { AlgorithmIdentifier identifier; }
}

/// Namespace class used to store all recognised extensions.
abstract class X509Extension
{
    import std.typecons : Nullable;
    import std.sumtype : SumType;

    /// A SumType of all recognised extensions.
    alias SumT = SumType!(
        Unknown, 
        AuthorityKeyIdentifier,
        SubjectKeyIdentifier,
        KeyUsage,
        PolicyMappings,
        SubjectAltName,
        IssuerAltName,
        SubjectDirectoryAttributes,
        BasicConstraints,
        NameConstraints,
        PolicyConstraints,
        ExtendedKeyUsage,
        CrlDistributionPoints,
        InhibitAnyPolicy,
        FreshestCrl,
        AuthorityInfoAccessSyntax,
        SubjectInfoAccessSyntax,
    );

    /// An unknown extension was encoutered - user code may be able to recognise it though.
    static struct Unknown { Extension extension; }

    /// The Authority Key Identifier extension from (RFC 5280 4.2.1.1).
    static struct AuthorityKeyIdentifier
    {
        const(ubyte)[] keyIdentifier;
        Nullable!GeneralNames authorityCertIssuer;
        Nullable!Asn1Integer authorityCertSerialNumber;
    }

    /// The Subject Key Identifier extension from (RFC 5280 4.2.1.2).
    static struct SubjectKeyIdentifier
    {
        const(ubyte)[] keyIdentifier;
    }

    /// The Key Usage extension from (RFC 5280 4.2.1.3).
    static struct KeyUsage
    {
        private enum Flag
        {
            digitalSignature        = 1 << 0,
            contentCommitment       = 1 << 1,
            keyEncipherment         = 1 << 2,
            dataEncipherment        = 1 << 3,
            keyAgreement            = 1 << 4,
            keyCertSign             = 1 << 5,
            cRLSign                 = 1 << 6,
            encipherOnly            = 1 << 7,
            decipherOnly            = 1 << 8,

            MAX_BIT_COUNT = 9
        }
        private Flag _flag;

        @nogc nothrow pure const:

        bool digitalSignature() => (this._flag & Flag.digitalSignature) > 0;
        bool contentCommitment() => (this._flag & Flag.contentCommitment) > 0;
        bool keyEncipherment() => (this._flag & Flag.keyEncipherment) > 0;
        bool dataEncipherment() => (this._flag & Flag.dataEncipherment) > 0;
        bool keyAgreement() => (this._flag & Flag.keyAgreement) > 0;
        bool keyCertSign() => (this._flag & Flag.keyCertSign) > 0;
        bool cRLSign() => (this._flag & Flag.cRLSign) > 0;
        bool encipherOnly() => (this._flag & Flag.encipherOnly) > 0;
        bool decipherOnly() => (this._flag & Flag.decipherOnly) > 0;
    }

    /// The Policy Mappings extension from (RFC 5280 4.2.1.5).
    alias PolicyMappings = Asn1PolicyMappings;

    /// The Subject Alt Name extension from (RFC 5280 4.2.1.6).
    static struct SubjectAltName
    {
        GeneralNames names;
    }

    /// The Issuer Alt Name extension from (RFC 5280 4.2.1.7).
    static struct IssuerAltName
    {
        GeneralNames names;
    }

    /// The Subject Directory Attributes extension from (RFC 5280 4.2.1.8).
    alias SubjectDirectoryAttributes = Asn1SubjectDirectoryAttributes;

    /// The Basic Constraints extension from (RFC 5280 4.2.1.9).
    static struct BasicConstraints
    {
        bool ca;
        Nullable!ulong pathLenConstraint;
    }

    /// The Name Constraints extension from (RFC 5280 4.2.1.10).
    static struct NameConstraints
    {
        Nullable!GeneralSubtrees permittedSubtrees;
        Nullable!GeneralSubtrees excludedSubtrees;
    }

    /// The Policy Constraints extension from (RFC 5280 4.2.1.11).
    static struct PolicyConstraints
    {
        Nullable!ulong requireExplicitPolicy;
        Nullable!ulong inhibitPolicyMapping;
    }

    /// The Extended Key Usage extension from (RFC 5280 4.2.1.12).
    static struct ExtendedKeyUsage
    {
        enum Flag
        {
            serverAuth = 1 << 0,
            clientAuth = 1 << 1,
            codeSigning = 1 << 2,
            emailProtection = 1 << 3,
            timeStamping = 1 << 4,
            ocspSigning = 1 << 5,
        }
        private Flag _flag;

        @nogc nothrow pure const:
        
        bool serverAuth() => (this._flag & Flag.serverAuth) > 0;
        bool clientAuth() => (this._flag & Flag.clientAuth) > 0;
        bool codeSigning() => (this._flag & Flag.codeSigning) > 0;
        bool emailProtection() => (this._flag & Flag.emailProtection) > 0;
        bool timeStamping() => (this._flag & Flag.timeStamping) > 0;
        bool ocspSigning() => (this._flag & Flag.ocspSigning) > 0;
    }

    /// The CRL Distribution Points extension from (RFC 5280 4.2.1.13).
    static struct CrlDistributionPoints
    {
        CRLDistributionPoints points;
    }

    /// The Freshest CRL extension from (RFC 5280 4.2.1.15).
    static struct FreshestCrl
    {
        CRLDistributionPoints points;
    }

    /// The Inhibit anyPolicy extension from (RFC 5280 4.2.1.14).
    static struct InhibitAnyPolicy
    {
        ulong skipCerts;
    }

    /// The Authority Information Access extension from (RFC 5280 4.2.2.1).
    alias AuthorityInfoAccessSyntax = Asn1AuthorityInfoAccessSyntax;
    /// The Subject Information Access extension from (RFC 5280 4.2.2.2).
    alias SubjectInfoAccessSyntax = Asn1SubjectInfoAccessSyntax;
}

/++
 + Represents an x.509 certificate, with as much of the ASN.1 jank cut out as possible without
 + the need for allocation.
 +
 + It's advised to read through RFC 5280 to learn what each field is, as there's no point in me copy-pasting
 + the spec into comments.
 + ++/
struct X509Certificate
{
    import std.typecons : Nullable;

    import juptune.core.ds.array : Array;
    import juptune.data.asn1.decode.bcd.encoding : Asn1BitString;

    enum NameComponentKind
    {
        FAILSAFE,

        countryName,
        organizationName,
        organizationalUnitName,
        dnQualifier,
        stateOrProvinceName,
        commonName,
        serialNumber,
        localityName,
        title,
        surname,
        givenName,
        initials,
        pseudonym,
        generationQualifier,
        domainComponent,

        unknown,
    }

    enum Version
    {
        FAILSAFE,
        v1,
        v2,
        v3
    }

    static struct Time // Phobos' stuff needs the GC for some dumb reason lol.
    {
        ushort year;
        ubyte month;
        ubyte day;
        ubyte hour;
        ubyte minute;
        ubyte second;
    }

    // From "Certificate"
    X509SignatureAlgorithm.SumT signatureAlgorithm;
    Asn1BitString signatureValue;

    // From "TBSCertificate"
    Version version_;
    Asn1Integer serialNumber; // Reminder: RFC 5280 dictates that implementations must support this value being 20 bytes long, hence why it's a raw Asn1Integer.
    Time notValidBefore;
    Time notValidAfter;
    Nullable!Asn1BitString issuerUniqueId;
    Nullable!Asn1BitString subjectUniqueId;

    X509SignatureAlgorithm.SumT subjectPublicKeyAlgorithm;
    Asn1BitString subjectPublicKey;

    Name issuer;
    Name subject;
    Nullable!Extensions extensions;

    // Extras
    const(ubyte)[] tbsCertificateRawDerEncoding; // Used for signature validation.
}

/++
 + Flattens the given `asn1Cert` into the more easier to use structure of `cert`, while performing light amounts of validation.
 +
 + Further validation has to be handled outside of this function as it requires additional context on how the certificate is even
 + being used. The rest of the x509 package should handle most of their respective checks for you.
 +
 + Notes:
 +  This function only allocates memory for providing descriptive error messages. If no error is returned then no memory is allocated.
 +
 +  This leads to a slightly awkward design where user code must call auxilary functions such as `x509ForeachNameComponent` to deal
 +  with array types, for the tradeoff of allowing the user code to have maximum flexbility around how to deal with its own memory.
 +
 + Params:
 +  asn1Cert = The ASN.1 model of the x.509 to convert.
 +  cert     = The result.
 +
 + Throws:
 +  Anything that `x509IdentifySignatureAlgorithm` can throw.
 +
 +  Anything that `x509HandleTime` can throw.
 +
 +  `X509Error.signatureAlgorithmMismatch` if there's a mismatch between the `signature` and `signatureAlgorithm` fields.
 +
 +  `X509Error.invalidCertVersion` if the certificate is of an unsupported/invalid version.
 +
 +  `X509Error.uniqueIdentifiersWrongVersion` if the certificate contains an unique identifier with a version that does not suport them.
 +
 +  `X509Error.extensionsWrongVersion` if the certificate contains extensions with a version that does not suport them.
 +
 + Returns:
 +  An errorful `Result` if something went wrong.
 + ++/
Result x509FromAsn1(Certificate asn1Cert, out X509Certificate cert) @nogc nothrow
{
    // Some of these are just so intelisense works
    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18
        : TBSCertificate;

    TBSCertificate tbsCert = asn1Cert.getTbsCertificate();

    /++ Read signature algorithms ++/
    auto result = x509IdentifySignatureAlgorithm(asn1Cert.getSignatureAlgorithm(), cert.signatureAlgorithm);
    if(result.isError)
        return result.wrapError("when identifying signatureAlgorithm:");

    result = x509IdentifySignatureAlgorithm(tbsCert.getSubjectPublicKeyInfo().getAlgorithm(), cert.subjectPublicKeyAlgorithm); // @suppress(dscanner.style.long_line)
    if(result.isError)
        return result.wrapError("when identifying tbsCertificate subjectPublicKeyAlgorithm:");

    X509SignatureAlgorithm.SumT tbsCertSignature;
    result = x509IdentifySignatureAlgorithm(tbsCert.getSignature(), tbsCertSignature);
    if(result.isError)
        return result.wrapError("when identifying tbsCertificate signature algorithm:");

    if(tbsCertSignature != cert.signatureAlgorithm)
    {
        return Result.make(
            X509Error.signatureAlgorithmMismatch, 
            "The ASN.1 `signature` and `signatureAlgorithm` fields are different - this is not allowed as per RFC 5280 4.1.1.2" // @suppress(dscanner.style.long_line)
        );
    }

    /++ Version ++/
    int versionInt;
    result = tbsCert.getVersion().get().asInt(versionInt);
    if(result.isError)
        return result.wrapError("when handling tbsCertificate version:");

    cert.version_ = cast(X509Certificate.Version)(versionInt + 1);
    switch(cert.version_) with(X509Certificate.Version)
    {
        case v1:
        case v2:
        case v3:
            break;

        default:
            return Result.make(
                X509Error.invalidCertVersion, 
                "The `version` field contains an unknown/invalid value",
                String2("version value was ", versionInt)
            );
    }

    /++ Dates ++/
    result = x509HandleTime(tbsCert.getValidity().getNotBefore(), cert.notValidBefore);
    if(result.isError)
        return result.wrapError("when handling notBefore time:");
    result = x509HandleTime(tbsCert.getValidity().getNotAfter(), cert.notValidAfter);
    if(result.isError)
        return result.wrapError("when handling notAfter time:");

    /++ Unique IDs ++/
    auto suid = tbsCert.getSubjectUniqueID();
    auto iuid = tbsCert.getIssuerUniqueID();
    if(!suid.isNull)
    {
        if(cert.version_ == X509Certificate.Version.FAILSAFE || cert.version_ == X509Certificate.Version.v1)
        {
            return Result.make(
                X509Error.uniqueIdentifiersWrongVersion,
                "Certificate contains a subject unique identifier, but the version is not v2 or v3 - forbidden as per RFC 5280 4.1.2.8", // @suppress(dscanner.style.long_line)
                String2("version is ", cert.version_)
            );
        }
        cert.subjectUniqueId = suid.get.get();
    }
    if(!iuid.isNull)
    {
        if(cert.version_ == X509Certificate.Version.FAILSAFE || cert.version_ == X509Certificate.Version.v1)
        {
            return Result.make(
                X509Error.uniqueIdentifiersWrongVersion,
                "Certificate contains an issuer unique identifier, but the version is not v2 or v3 - forbidden as per RFC 5280 4.1.2.8", // @suppress(dscanner.style.long_line)
                String2("version is ", cert.version_)
            );
        }
        cert.issuerUniqueId = iuid.get.get();
    }

    /++ Extensions ++/
    if(!tbsCert.getExtensions().isNull && cert.version_ != X509Certificate.Version.v3)
    {
        return Result.make(
            X509Error.extensionsWrongVersion,
            "Certificate contains extensions, but the version is not v3 - forbidden as per RFC 5280 4.1.2.9",
            String2("version is ", cert.version_)
        );
    }
    cert.extensions = tbsCert.getExtensions();

    /++ Other loose fields with no extra validation ++/
    cert.serialNumber = tbsCert.getSerialNumber().get();
    cert.tbsCertificateRawDerEncoding = tbsCert.getDasn1_RawBytes().get.data;
    cert.subjectPublicKey = tbsCert.getSubjectPublicKeyInfo().getSubjectPublicKey();
    cert.issuer = tbsCert.getIssuer();
    cert.subject = tbsCert.getSubject();

    return Result.noError;
}

// TODO: implement lol
Result x509IdentifySignatureAlgorithm(
    AlgorithmIdentifier asn1Algorithm,
    out X509SignatureAlgorithm.SumT algorithm,
) @nogc nothrow
{
    algorithm = X509SignatureAlgorithm.Unknown(asn1Algorithm);
    return Result.noError;
}

/++
 + Converts the given ASN.1 model `Time` into the easier to use structure of `time`.
 +
 + Params:
 +  asn1Time = The ASN.1 time to convert.
 +  time     = The result.
 +
 + Throws:
 +  `X509Error.invalidTimeType` if the time represents a year <= 2049, but doesn't use the ASN.1 UTCTime type as its representation.
 +
 + Returns:
 +  An errorful `Result` if something went wrong.
 + ++/
Result x509HandleTime(Time asn1Time, out X509Certificate.Time time) @nogc nothrow
{
    auto result = asn1Time.match(
        (utcTime){
            time.day = cast(typeof(time.day))utcTime.day;
            time.month = cast(typeof(time.month))utcTime.month;
            time.year = cast(typeof(time.year))utcTime.year;
            time.hour = cast(typeof(time.hour))utcTime.hour;
            time.minute = cast(typeof(time.minute))utcTime.minute;
            time.second = cast(typeof(time.second))utcTime.second;
            return Result.noError;
        }
    );
    if(result.isError)
        return result;

    if(time.year <= 2049 && !asn1Time.isUtcTime)
        return Result.make(X509Error.invalidTimeType, "A Time has a year <= 2049, but is not using the UTCTime type - this is not allowed as per RFC 5280 4.1.2.5"); // @suppress(dscanner.style.long_line)
    else if(time.year >= 2050)
        assert(false, "TODO: Type check");

    return Result.noError;
}

/++
 + Iterates over the components of the given `name`, passing them into the provided `handler`.
 +
 + Notes:
 +  It's recommended to use `x509HandleNameComponent` on the `component` field passed to the `handler`, as that will detect
 +  most of the common name components.
 +
 +  The ASN.1 model for `name` can very technically change in the future (as its a CHOICE type) so it's recommended to always use this function
 +  for future compatibility purposes.
 +
 + Params:
 +  name    = The name whose components to iterate over.
 +  handler = The handler to call for each component.
 +
 + Throws:
 +  Anything that the provided `handler` throws.
 +
 + Returns:
 +  Any error thrown by `handler`.
 + ++/
Result x509ForeachNameComponent(
    Name name,
    scope Result delegate(AttributeTypeAndValue component) @nogc nothrow handler,
) @nogc nothrow
{
    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : RelativeDistinguishedName;
    assert(name.isRdnSequence(), "bug: unhandled case for Name (or .init Name was passed in)");

    return name.getRdnSequence().get().foreachElementAuto((RelativeDistinguishedName rdn){
        return rdn.get().foreachElementAuto((AttributeTypeAndValue element){
            return handler(element);
        });
    });
}

/// ditto
Result x509ForeachNameComponentGC(
    Name name,
    scope Result delegate(AttributeTypeAndValue component) handler,
)
{
    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : RelativeDistinguishedName;
    assert(name.isRdnSequence(), "bug: unhandled case for Name (or .init Name was passed in)");

    return name.getRdnSequence().get().foreachElementAutoGC((RelativeDistinguishedName rdn){
        return rdn.get().foreachElementAutoGC((AttributeTypeAndValue element){
            return handler(element);
        });
    });
}

/++
 + Attempts to identify the given name component, and provide its textual data.
 +
 + Notes:
 +  Currently you can safely assume that `text` is either an ASCII or UTF8 string.
 +
 +  Currently a null `text` result has no special meaning for identified components, but may change in the future since some
 +  ASN.1 string types will need a converter instead of being able to be used as-is.
 +
 + Params:
 +  component = The name component to identify.
 +  kind      = The identified component, or `X509Certificate.NameComponentKind.unknown` if it wasn't recognised.
 +  text      = The text of an identified component. Will be `null` if the component wasn't recognised.
 +
 + Throws:
 +  Currently, nothing should be thrown.
 +
 + Returns:
 +  An errorful `Result` if something went wrong.
 + ++/
Result x509HandleNameComponent(
    AttributeTypeAndValue component,
    out X509Certificate.NameComponentKind kind,
    out const(char)[] text,
) @nogc nothrow
{
    import std.algorithm : equal;
    import juptune.data.buffer : MemoryReader;

    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18
        :   id_at_countryName,
            id_at_organizationName,
            id_at_organizationalUnitName,
            id_at_dnQualifier,
            id_at_stateOrProvinceName,
            id_at_commonName,
            id_at_serialNumber,
            id_at_localityName,
            id_at_title,
            id_at_surname,
            id_at_givenName,
            id_at_initials,
            id_at_pseudonym,
            id_at_generationQualifier,
            id_domainComponent,
            X520countryName,
            X520OrganizationName,
            X520OrganizationalUnitName,
            X520dnQualifier,
            X520StateOrProvinceName,
            X520CommonName,
            X520SerialNumber,
            X520LocalityName,
            X520Title,
            X520name,
            X520Pseudonym,
            DomainComponent
        ;

    import juptune.data.asn1.decode.bcd.encoding
        : asn1DecodeComponentHeader, Asn1Identifier, Asn1Ruleset, Asn1ComponentHeader, Asn1Utf8String;

    auto primitiveId = Asn1Identifier(Asn1Identifier.Class.universal, Asn1Identifier.Encoding.primitive, 0); // Note: Tag and class have no meaning here
    auto memory = MemoryReader(component.getValue().data);

    auto id = component.getType().get().components;
    if(id.equal(id_at_countryName().get().components))
    {
        X520countryName value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, primitiveId)) return r;
        
        kind = X509Certificate.NameComponentKind.countryName;
        text = value.get().asSlice;
        return Result.noError;
    }
    if(id.equal(id_at_dnQualifier().get().components))
    {
        X520dnQualifier value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, primitiveId)) return r;
        
        kind = X509Certificate.NameComponentKind.dnQualifier;
        text = value.get().asSlice;
        return Result.noError;
    }
    if(id.equal(id_at_serialNumber().get().components))
    {
        X520SerialNumber value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, primitiveId)) return r;
        
        kind = X509Certificate.NameComponentKind.serialNumber;
        text = value.get().asSlice;
        return Result.noError;
    }
    if(id.equal(id_domainComponent().get().components))
    {
        DomainComponent value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, primitiveId)) return r;
        
        kind = X509Certificate.NameComponentKind.domainComponent;
        text = value.get().asSlice;
        return Result.noError;
    }

    import std.meta : AliasSeq;
    static struct AttribInfo(alias id_at_, alias DecodedType_, X509Certificate.NameComponentKind Kind_)
    {
        alias id_at = id_at_;
        alias DecodedType = DecodedType_;
        enum Kind = Kind_;
    }

    alias Kind = X509Certificate.NameComponentKind;
    static foreach(Attrib; AliasSeq!(
        AttribInfo!(id_at_organizationName,         X520OrganizationName,       Kind.organizationName),
        AttribInfo!(id_at_organizationalUnitName,   X520OrganizationalUnitName, Kind.organizationalUnitName),
        AttribInfo!(id_at_stateOrProvinceName,      X520StateOrProvinceName,    Kind.stateOrProvinceName),
        AttribInfo!(id_at_commonName,               X520CommonName,             Kind.commonName),
        AttribInfo!(id_at_localityName,             X520LocalityName,           Kind.localityName),
        AttribInfo!(id_at_title,                    X520Title,                  Kind.title),
        AttribInfo!(id_at_surname,                  X520name,                   Kind.surname),
        AttribInfo!(id_at_givenName,                X520name,                   Kind.givenName),
        AttribInfo!(id_at_initials,                 X520name,                   Kind.initials),
        AttribInfo!(id_at_generationQualifier,      X520name,                   Kind.generationQualifier),
        AttribInfo!(id_at_pseudonym,                X520Pseudonym,              Kind.pseudonym),
    ))
    {
        if(id.equal(Attrib.id_at().get().components))
        {
            // Special case: Dasn1-Any currently doesn't support storing CHOICE properly, but luckily this field
            //               is either a PrintableString or a Utf8String, either of which we can safely just read in as-is.
            // Ponder: ... Does this open up potential exploits? Since technically this can be anything now (that looks like UTF8)?
            Asn1Utf8String utf8;
            if(auto r = Asn1Utf8String.fromDecoding!(Asn1Ruleset.der)(memory, utf8, primitiveId)) return r;
            
            Attrib.DecodedType value;
            if(auto r = value.setUtf8String(utf8)) return r;

            auto result = value.match(
                (str){ text = str.asSlice; return Result.noError; },
                (str){ text = str.asSlice; return Result.noError; },
            );
            if(result.isError)
                return result;

            kind = Attrib.Kind;
            return Result.noError;
        }
    }

    // TODO: Once Dasn1-Any preserves component header info, detect whether we know how to decode the value to aid the user code a bit.
    kind = Kind.unknown;
    return Result.noError;
}

/++
 + Attempts to identify the given extension; flatten it into an easier to work with type, and perform some light validation.
 +
 + Notes:
 +  (Phobos' SumType really sucks so please be aware that `X509Extension.SumT` is a highly unstable part of the API).
 +
 +  A lot of extensions have additional validation requirements that can't be performed by this function due to a lack
 +  of context. This function can only perform validation where the extension is viewed in isolation from any other extension.
 +
 + Params:
 +  asn1Extension = The ASN.1 model to identify and convert.
 +  extension     = The result.
 +
 + Throws:
 +  `X509Error.keyUsageTooManyBits` if a Key Usage extension has more bits than expected.
 +
 +  `X509Error.keyUsageNoSetBit` if a Key Usage extension has no set bits.
 +
 +  `X509Error.extendedKeyUsageUnknownUsage` if an Extended Key Usage extension specifies an unknown usage.
 +
 +  Various errors from `Asn1DecodeError` - mainly around trying to convert Asn1Integer into a native ulong.
 +
 + Returns:
 +  An errorful `Result` if something went wrong.
 + ++/
Result x509HandleExtension(Extension asn1Extension, out X509Extension.SumT extension) @nogc nothrow
{
    import std.algorithm : equal;
    import juptune.data.buffer : MemoryReader;

    import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19
        : 
            id_ce_authorityKeyIdentifier,
            id_ce_subjectKeyIdentifier,
            id_ce_keyUsage,
            id_ce_policyMappings,
            id_ce_subjectAltName,
            id_ce_issuerAltName,
            id_ce_subjectDirectoryAttributes,
            id_ce_basicConstraints,
            id_ce_nameConstraints,
            id_ce_policyConstraints,
            id_ce_extKeyUsage,
            id_ce_cRLDistributionPoints,
            id_ce_inhibitAnyPolicy,
            id_ce_freshestCRL,
            id_pe_authorityInfoAccess,
            id_pe_subjectInfoAccess,
            AuthorityKeyIdentifier,
            SubjectKeyIdentifier,
            KeyUsage,
            SubjectAltName,
            IssuerAltName,
            BasicConstraints,
            NameConstraints,
            PolicyConstraints,
            ExtKeyUsageSyntax,
            InhibitAnyPolicy
        ;

    import juptune.data.asn1.decode.bcd.encoding
        : Asn1Identifier, Asn1Ruleset, asn1DecodeComponentHeader, Asn1ComponentHeader;
    
    auto memory = MemoryReader(asn1Extension.getExtnValue().data);

    Asn1ComponentHeader header;
    if(auto r = asn1DecodeComponentHeader!(Asn1Ruleset.der)(memory, header)) return r;

    // TODO: Slight potential that this could be a slow hotpath, so
    //       either need to write a tree-based switcher, or just hand
    //       roll a gigantic set of switch statements for better speed.
    //
    // Redditors: I'm aware this is trash code, you don't have to inform me thank you.
    auto id = asn1Extension.getExtnID().components;
    if(id_ce_authorityKeyIdentifier().components.equal(id))
    {
        AuthorityKeyIdentifier value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.AuthorityKeyIdentifier ext;
        ext.authorityCertIssuer = value.getAuthorityCertIssuer();
        if(!value.getKeyIdentifier().isNull)
            ext.keyIdentifier = value.getKeyIdentifier().get.get().data;
        if(!value.getAuthorityCertSerialNumber().isNull)
            ext.authorityCertSerialNumber = value.getAuthorityCertSerialNumber().get.get();

        extension = ext;
        return Result.noError;
    }
    if(id_ce_subjectKeyIdentifier().components.equal(id))
    {
        SubjectKeyIdentifier value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.SubjectKeyIdentifier ext;
        ext.keyIdentifier = value.get().get().data;

        extension = ext;
        return Result.noError;
    }
    if(id_ce_keyUsage().components.equal(id))
    {
        KeyUsage value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        alias KeyFlag = X509Extension.KeyUsage.Flag;
        if(value.get().bitCount > KeyFlag.MAX_BIT_COUNT)
        {
            return Result.make(
                X509Error.keyUsageTooManyBits,
                "The `keyUsage` extension has more bits than expected/supported",
                String2("got ", value.get().bitCount, " bits where only ", KeyFlag.MAX_BIT_COUNT, " at most expected")
            );
        }

        bool foundSetBit;
        size_t bitIndex;
        X509Extension.KeyUsage ext;
        foreach(bit; value.get().bits)
        {
            scope(exit) bitIndex++;
            foundSetBit = foundSetBit || bit;

            if(!bit)
                continue;

            final switch(bitIndex)
            {
                case KeyUsage.NamedBit.digitalSignature:    ext._flag |= KeyFlag.digitalSignature; break;
                case 1:                                     ext._flag |= KeyFlag.contentCommitment; break; // TODO: Look into dasn1 bug - why doesn't this field exist in the NamedBit enum?
                case KeyUsage.NamedBit.keyEncipherment:     ext._flag |= KeyFlag.keyEncipherment; break;
                case KeyUsage.NamedBit.dataEncipherment:    ext._flag |= KeyFlag.dataEncipherment; break;
                case KeyUsage.NamedBit.keyAgreement:        ext._flag |= KeyFlag.keyAgreement; break;
                case KeyUsage.NamedBit.keyCertSign:         ext._flag |= KeyFlag.keyCertSign; break;
                case KeyUsage.NamedBit.cRLSign:             ext._flag |= KeyFlag.cRLSign; break;
                case KeyUsage.NamedBit.encipherOnly:        ext._flag |= KeyFlag.encipherOnly; break;
                case KeyUsage.NamedBit.decipherOnly:        ext._flag |= KeyFlag.decipherOnly; break;
            }
        }

        if(!foundSetBit)
        {
            return Result.make(
                X509Error.keyUsageNoSetBit,
                "The `keyUsage` extension was defined, however it has no set bits - this is forbidden as per RFC 5280 4.2.1.3", // @suppress(dscanner.style.long_line)
            );
        }

        extension = ext;
        return Result.noError;
    }
    if(id_ce_policyMappings().components.equal(id))
    {
        Asn1PolicyMappings value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        extension = value;
        return Result.noError;
    }
    if(id_ce_subjectAltName().components.equal(id))
    {
        SubjectAltName value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.SubjectAltName ext;
        ext.names = value.get();

        extension = ext;
        return Result.noError;
    }
    if(id_ce_issuerAltName().components.equal(id))
    {
        IssuerAltName value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.IssuerAltName ext;
        ext.names = value.get();

        extension = ext;
        return Result.noError;
    }
    if(id_ce_subjectDirectoryAttributes().components.equal(id))
    {
        Asn1SubjectDirectoryAttributes value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        extension = value;
        return Result.noError;
    }
    if(id_ce_basicConstraints().components.equal(id))
    {
        BasicConstraints value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.BasicConstraints ext;
        ext.ca = value.getCA().asBool;

        if(!value.getPathLenConstraint().isNull)
        {
            ulong pathLenConstraint;
            if(auto r = value.getPathLenConstraint().get.asInt(pathLenConstraint))
                return r.wrapError("when converting basicConstraint pathLenConstraint into native int:");
            ext.pathLenConstraint = pathLenConstraint;
        }

        extension = ext;
        return Result.noError;
    }
    if(id_ce_nameConstraints().components.equal(id))
    {
        NameConstraints value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.NameConstraints ext;
        ext.permittedSubtrees = value.getPermittedSubtrees();
        ext.excludedSubtrees = value.getExcludedSubtrees();

        extension = ext;
        return Result.noError;
    }
    if(id_ce_policyConstraints().components.equal(id))
    {
        PolicyConstraints value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.PolicyConstraints ext;
        if(!value.getRequireExplicitPolicy().isNull)
        {
            ulong policy;
            if(auto r = value.getRequireExplicitPolicy().get.get().asInt(policy))
                return r.wrapError("when converting policyConstraints requireExplicitPolicy into native int:");
            ext.requireExplicitPolicy = policy;
        }
        if(!value.getInhibitPolicyMapping().isNull)
        {
            ulong policy;
            if(auto r = value.getInhibitPolicyMapping().get.get().asInt(policy))
                return r.wrapError("when converting policyConstraints inhibitPolicyMapping into native int:");
            ext.inhibitPolicyMapping = policy;
        }

        extension = ext;
        return Result.noError;
    }
    if(id_ce_extKeyUsage().components.equal(id))
    {
        ExtKeyUsageSyntax value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.ExtendedKeyUsage ext;
        auto result = value.get().foreachElementAuto((element){
            import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19
                :
                    id_kp_serverAuth,
                    id_kp_clientAuth,
                    id_kp_codeSigning,
                    id_kp_emailProtection,
                    id_kp_timeStamping,
                    id_kp_OCSPSigning
                ;

            alias UseFlag = X509Extension.ExtendedKeyUsage.Flag;
            auto useId = element.get().components;

            if(id_kp_serverAuth().components.equal(useId)) { ext._flag |= UseFlag.serverAuth; return Result.noError; }
            if(id_kp_clientAuth().components.equal(useId)) { ext._flag |= UseFlag.clientAuth; return Result.noError; }
            if(id_kp_codeSigning().components.equal(useId)) { ext._flag |= UseFlag.codeSigning; return Result.noError; }
            if(id_kp_emailProtection().components.equal(useId)) { ext._flag |= UseFlag.emailProtection; return Result.noError; } // @suppress(dscanner.style.long_line)
            if(id_kp_timeStamping().components.equal(useId)) { ext._flag |= UseFlag.timeStamping; return Result.noError; } // @suppress(dscanner.style.long_line)
            if(id_kp_OCSPSigning().components.equal(useId)) { ext._flag |= UseFlag.ocspSigning; return Result.noError; }
            
            import std.algorithm : map;
            return Result.make(
                X509Error.extendedKeyUsageUnknownUsage,
                "The `extKeyUsage` extension contains an unknown usage identifier",
                String2("identifier was ", element.get().components.map!(i => i.isNull ? -1 : i.get))
            );
        });
        if(result.isError)
            return result;

        extension = ext;
        return Result.noError;
    }
    if(id_ce_cRLDistributionPoints().components.equal(id))
    {
        CRLDistributionPoints value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.CrlDistributionPoints ext;
        ext.points = value;

        extension = ext;
        return Result.noError;
    }
    if(id_ce_inhibitAnyPolicy().components.equal(id))
    {
        InhibitAnyPolicy value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.InhibitAnyPolicy ext;
        auto result = value.get().get().asInt(ext.skipCerts);
        if(result.isError)
            return result.wrapError("when converting inhibitAnyPolicy into native ulong");

        extension = ext;
        return Result.noError;
    }
    if(id_ce_freshestCRL().components.equal(id))
    {
        CRLDistributionPoints value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        X509Extension.FreshestCrl ext;
        ext.points = value;

        extension = ext;
        return Result.noError;
    }
    if(id_pe_authorityInfoAccess().components.equal(id))
    {
        Asn1AuthorityInfoAccessSyntax value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        extension = value;
        return Result.noError;
    }
    if(id_pe_subjectInfoAccess().components.equal(id))
    {
        Asn1SubjectInfoAccessSyntax value;
        if(auto r = value.fromDecoding!(Asn1Ruleset.der)(memory, header.identifier)) return r;

        extension = value;
        return Result.noError;
    }

    extension = X509Extension.Unknown(asn1Extension);
    return Result.noError;
}

@("x.509 - general megatest")
unittest
{
    import juptune.core.util : resultAssert;
    import juptune.data.buffer : MemoryReader;

    import juptune.data.asn1.decode.bcd.encoding 
        : asn1DecodeComponentHeader, asn1ReadContentBytes, Asn1ComponentHeader,
            Asn1Identifier, Asn1Ruleset;

    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;

    // Certificate from youtube.com
    const(ubyte[]) asn1 = [
        0x30,  0x82,  0x0e,  0x46,  0x30,  0x82,  0x0d,  0x2e,  0xa0,  0x03,  0x02,  0x01,  0x02,  0x02,  0x10,  0x64,
        0xab,  0xa0,  0x8b,  0xb9,  0x25,  0x2d,  0x64,  0x12,  0xd8,  0xbe,  0x8b,  0x96,  0x7f,  0x38,  0xab,  0x30,
        0x0d,  0x06,  0x09,  0x2a,  0x86,  0x48,  0x86,  0xf7,  0x0d,  0x01,  0x01,  0x0b,  0x05,  0x00,  0x30,  0x3b,
        0x31,  0x0b,  0x30,  0x09,  0x06,  0x03,  0x55,  0x04,  0x06,  0x13,  0x02,  0x55,  0x53,  0x31,  0x1e,  0x30,
        0x1c,  0x06,  0x03,  0x55,  0x04,  0x0a,  0x13,  0x15,  0x47,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x20,  0x54,
        0x72,  0x75,  0x73,  0x74,  0x20,  0x53,  0x65,  0x72,  0x76,  0x69,  0x63,  0x65,  0x73,  0x31,  0x0c,  0x30,
        0x0a,  0x06,  0x03,  0x55,  0x04,  0x03,  0x13,  0x03,  0x57,  0x52,  0x32,  0x30,  0x1e,  0x17,  0x0d,  0x32,
        0x35,  0x30,  0x39,  0x30,  0x38,  0x30,  0x38,  0x33,  0x34,  0x35,  0x33,  0x5a,  0x17,  0x0d,  0x32,  0x35,
        0x31,  0x32,  0x30,  0x31,  0x30,  0x38,  0x33,  0x34,  0x35,  0x32,  0x5a,  0x30,  0x17,  0x31,  0x15,  0x30,
        0x13,  0x06,  0x03,  0x55,  0x04,  0x03,  0x0c,  0x0c,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,
        0x2e,  0x63,  0x6f,  0x6d,  0x30,  0x59,  0x30,  0x13,  0x06,  0x07,  0x2a,  0x86,  0x48,  0xce,  0x3d,  0x02,
        0x01,  0x06,  0x08,  0x2a,  0x86,  0x48,  0xce,  0x3d,  0x03,  0x01,  0x07,  0x03,  0x42,  0x00,  0x04,  0x12,
        0x06,  0x77,  0x77,  0xf6,  0x5c,  0x88,  0xc7,  0x0a,  0xd3,  0x02,  0x70,  0xb0,  0x41,  0x77,  0xe8,  0xa3,
        0xcb,  0x22,  0x75,  0xb1,  0x8b,  0x8f,  0x92,  0xdf,  0x51,  0x13,  0xf3,  0x13,  0x76,  0x17,  0x69,  0xf3,
        0x72,  0xc2,  0xf6,  0xc4,  0xb6,  0x4c,  0xc0,  0x25,  0x23,  0x94,  0x14,  0x1c,  0x18,  0x07,  0xa5,  0x8f,
        0x9b,  0x82,  0xa1,  0xf8,  0xea,  0xdd,  0x9f,  0x69,  0x16,  0x60,  0x16,  0x97,  0x53,  0x64,  0xaa,  0xa3,
        0x82,  0x0c,  0x33,  0x30,  0x82,  0x0c,  0x2f,  0x30,  0x0e,  0x06,  0x03,  0x55,  0x1d,  0x0f,  0x01,  0x01,
        0xff,  0x04,  0x04,  0x03,  0x02,  0x07,  0x80,  0x30,  0x13,  0x06,  0x03,  0x55,  0x1d,  0x25,  0x04,  0x0c,
        0x30,  0x0a,  0x06,  0x08,  0x2b,  0x06,  0x01,  0x05,  0x05,  0x07,  0x03,  0x01,  0x30,  0x0c,  0x06,  0x03,
        0x55,  0x1d,  0x13,  0x01,  0x01,  0xff,  0x04,  0x02,  0x30,  0x00,  0x30,  0x1d,  0x06,  0x03,  0x55,  0x1d,
        0x0e,  0x04,  0x16,  0x04,  0x14,  0x86,  0x54,  0x1e,  0x8e,  0x99,  0xb0,  0x05,  0x78,  0x9e,  0xa7,  0x57,
        0x11,  0x74,  0x6a,  0x9a,  0x63,  0x74,  0x16,  0xa7,  0x53,  0x30,  0x1f,  0x06,  0x03,  0x55,  0x1d,  0x23,
        0x04,  0x18,  0x30,  0x16,  0x80,  0x14,  0xde,  0x1b,  0x1e,  0xed,  0x79,  0x15,  0xd4,  0x3e,  0x37,  0x24,
        0xc3,  0x21,  0xbb,  0xec,  0x34,  0x39,  0x6d,  0x42,  0xb2,  0x30,  0x30,  0x58,  0x06,  0x08,  0x2b,  0x06,
        0x01,  0x05,  0x05,  0x07,  0x01,  0x01,  0x04,  0x4c,  0x30,  0x4a,  0x30,  0x21,  0x06,  0x08,  0x2b,  0x06,
        0x01,  0x05,  0x05,  0x07,  0x30,  0x01,  0x86,  0x15,  0x68,  0x74,  0x74,  0x70,  0x3a,  0x2f,  0x2f,  0x6f,
        0x2e,  0x70,  0x6b,  0x69,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x2f,  0x77,  0x72,  0x32,  0x30,  0x25,  0x06,
        0x08,  0x2b,  0x06,  0x01,  0x05,  0x05,  0x07,  0x30,  0x02,  0x86,  0x19,  0x68,  0x74,  0x74,  0x70,  0x3a,
        0x2f,  0x2f,  0x69,  0x2e,  0x70,  0x6b,  0x69,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x2f,  0x77,  0x72,  0x32,
        0x2e,  0x63,  0x72,  0x74,  0x30,  0x82,  0x0a,  0x0b,  0x06,  0x03,  0x55,  0x1d,  0x11,  0x04,  0x82,  0x0a,
        0x02,  0x30,  0x82,  0x09,  0xfe,  0x82,  0x0c,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,
        0x63,  0x6f,  0x6d,  0x82,  0x16,  0x2a,  0x2e,  0x61,  0x70,  0x70,  0x65,  0x6e,  0x67,  0x69,  0x6e,  0x65,
        0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x09,  0x2a,  0x2e,  0x62,
        0x64,  0x6e,  0x2e,  0x64,  0x65,  0x76,  0x82,  0x15,  0x2a,  0x2e,  0x6f,  0x72,  0x69,  0x67,  0x69,  0x6e,
        0x2d,  0x74,  0x65,  0x73,  0x74,  0x2e,  0x62,  0x64,  0x6e,  0x2e,  0x64,  0x65,  0x76,  0x82,  0x12,  0x2a,
        0x2e,  0x63,  0x6c,  0x6f,  0x75,  0x64,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,
        0x6d,  0x82,  0x18,  0x2a,  0x2e,  0x63,  0x72,  0x6f,  0x77,  0x64,  0x73,  0x6f,  0x75,  0x72,  0x63,  0x65,
        0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x18,  0x2a,  0x2e,  0x64,
        0x61,  0x74,  0x61,  0x63,  0x6f,  0x6d,  0x70,  0x75,  0x74,  0x65,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,
        0x63,  0x61,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6c,  0x82,
        0x0e,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x2e,  0x69,  0x6e,  0x82,
        0x0e,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x2e,  0x6a,  0x70,  0x82,
        0x0e,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x2e,  0x75,  0x6b,  0x82,
        0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x2e,  0x61,  0x72,
        0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x2e,  0x61,
        0x75,  0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x2e,
        0x62,  0x72,  0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,
        0x2e,  0x63,  0x6f,  0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,
        0x6d,  0x2e,  0x6d,  0x78,  0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,
        0x6f,  0x6d,  0x2e,  0x74,  0x72,  0x82,  0x0f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,
        0x63,  0x6f,  0x6d,  0x2e,  0x76,  0x6e,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,
        0x2e,  0x64,  0x65,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x65,  0x73,
        0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x66,  0x72,  0x82,  0x0b,  0x2a,
        0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x68,  0x75,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,
        0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x69,  0x74,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x2e,  0x6e,  0x6c,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x70,
        0x6c,  0x82,  0x0b,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x70,  0x74,  0x82,  0x0f,
        0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x70,  0x69,  0x73,  0x2e,  0x63,  0x6e,  0x82,
        0x11,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x76,  0x69,  0x64,  0x65,  0x6f,  0x2e,  0x63,
        0x6f,  0x6d,  0x82,  0x0c,  0x2a,  0x2e,  0x67,  0x73,  0x74,  0x61,  0x74,  0x69,  0x63,  0x2e,  0x63,  0x6e,
        0x82,  0x10,  0x2a,  0x2e,  0x67,  0x73,  0x74,  0x61,  0x74,  0x69,  0x63,  0x2d,  0x63,  0x6e,  0x2e,  0x63,
        0x6f,  0x6d,  0x82,  0x0f,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x63,  0x6e,  0x61,  0x70,  0x70,  0x73,
        0x2e,  0x63,  0x6e,  0x82,  0x11,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x63,  0x6e,  0x61,
        0x70,  0x70,  0x73,  0x2e,  0x63,  0x6e,  0x82,  0x11,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x70,
        0x70,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,
        0x67,  0x6c,  0x65,  0x61,  0x70,  0x70,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0c,
        0x67,  0x6b,  0x65,  0x63,  0x6e,  0x61,  0x70,  0x70,  0x73,  0x2e,  0x63,  0x6e,  0x82,  0x0e,  0x2a,  0x2e,
        0x67,  0x6b,  0x65,  0x63,  0x6e,  0x61,  0x70,  0x70,  0x73,  0x2e,  0x63,  0x6e,  0x82,  0x12,  0x67,  0x6f,
        0x6f,  0x67,  0x6c,  0x65,  0x64,  0x6f,  0x77,  0x6e,  0x6c,  0x6f,  0x61,  0x64,  0x73,  0x2e,  0x63,  0x6e,
        0x82,  0x14,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x64,  0x6f,  0x77,  0x6e,  0x6c,  0x6f,
        0x61,  0x64,  0x73,  0x2e,  0x63,  0x6e,  0x82,  0x10,  0x72,  0x65,  0x63,  0x61,  0x70,  0x74,  0x63,  0x68,
        0x61,  0x2e,  0x6e,  0x65,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x12,  0x2a,  0x2e,  0x72,  0x65,  0x63,  0x61,
        0x70,  0x74,  0x63,  0x68,  0x61,  0x2e,  0x6e,  0x65,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x10,  0x72,  0x65,
        0x63,  0x61,  0x70,  0x74,  0x63,  0x68,  0x61,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,  0x82,  0x12,
        0x2a,  0x2e,  0x72,  0x65,  0x63,  0x61,  0x70,  0x74,  0x63,  0x68,  0x61,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,
        0x65,  0x74,  0x82,  0x0b,  0x77,  0x69,  0x64,  0x65,  0x76,  0x69,  0x6e,  0x65,  0x2e,  0x63,  0x6e,  0x82,
        0x0d,  0x2a,  0x2e,  0x77,  0x69,  0x64,  0x65,  0x76,  0x69,  0x6e,  0x65,  0x2e,  0x63,  0x6e,  0x82,  0x11,
        0x61,  0x6d,  0x70,  0x70,  0x72,  0x6f,  0x6a,  0x65,  0x63,  0x74,  0x2e,  0x6f,  0x72,  0x67,  0x2e,  0x63,
        0x6e,  0x82,  0x13,  0x2a,  0x2e,  0x61,  0x6d,  0x70,  0x70,  0x72,  0x6f,  0x6a,  0x65,  0x63,  0x74,  0x2e,
        0x6f,  0x72,  0x67,  0x2e,  0x63,  0x6e,  0x82,  0x11,  0x61,  0x6d,  0x70,  0x70,  0x72,  0x6f,  0x6a,  0x65,
        0x63,  0x74,  0x2e,  0x6e,  0x65,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x13,  0x2a,  0x2e,  0x61,  0x6d,  0x70,
        0x70,  0x72,  0x6f,  0x6a,  0x65,  0x63,  0x74,  0x2e,  0x6e,  0x65,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x17,
        0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2d,  0x61,  0x6e,  0x61,  0x6c,  0x79,  0x74,  0x69,  0x63,  0x73,
        0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x19,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x2d,  0x61,  0x6e,  0x61,  0x6c,  0x79,  0x74,  0x69,  0x63,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,
        0x6f,  0x6d,  0x82,  0x17,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x64,  0x73,  0x65,  0x72,  0x76,
        0x69,  0x63,  0x65,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x19,  0x2a,  0x2e,  0x67,
        0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x64,  0x73,  0x65,  0x72,  0x76,  0x69,  0x63,  0x65,  0x73,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x11,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x76,  0x61,
        0x64,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,
        0x67,  0x6c,  0x65,  0x76,  0x61,  0x64,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x11,
        0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x70,  0x69,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,
        0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x61,  0x70,  0x69,  0x73,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x15,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x6f,  0x70,
        0x74,  0x69,  0x6d,  0x69,  0x7a,  0x65,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x17,  0x2a,
        0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x6f,  0x70,  0x74,  0x69,  0x6d,  0x69,  0x7a,  0x65,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x12,  0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,
        0x69,  0x63,  0x6b,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,  0x82,  0x14,  0x2a,  0x2e,  0x64,  0x6f,
        0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,  0x6b,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,
        0x82,  0x18,  0x2a,  0x2e,  0x66,  0x6c,  0x73,  0x2e,  0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,
        0x69,  0x63,  0x6b,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,  0x82,  0x16,  0x2a,  0x2e,  0x67,  0x2e,
        0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,  0x6b,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,
        0x65,  0x74,  0x82,  0x0e,  0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,  0x6b,  0x2e,
        0x63,  0x6e,  0x82,  0x10,  0x2a,  0x2e,  0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,
        0x6b,  0x2e,  0x63,  0x6e,  0x82,  0x14,  0x2a,  0x2e,  0x66,  0x6c,  0x73,  0x2e,  0x64,  0x6f,  0x75,  0x62,
        0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,  0x6b,  0x2e,  0x63,  0x6e,  0x82,  0x12,  0x2a,  0x2e,  0x67,  0x2e,
        0x64,  0x6f,  0x75,  0x62,  0x6c,  0x65,  0x63,  0x6c,  0x69,  0x63,  0x6b,  0x2e,  0x63,  0x6e,  0x82,  0x11,
        0x64,  0x61,  0x72,  0x74,  0x73,  0x65,  0x61,  0x72,  0x63,  0x68,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,
        0x74,  0x82,  0x13,  0x2a,  0x2e,  0x64,  0x61,  0x72,  0x74,  0x73,  0x65,  0x61,  0x72,  0x63,  0x68,  0x2d,
        0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,  0x82,  0x1d,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x74,  0x72,
        0x61,  0x76,  0x65,  0x6c,  0x61,  0x64,  0x73,  0x65,  0x72,  0x76,  0x69,  0x63,  0x65,  0x73,  0x2d,  0x63,
        0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x1f,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x74,
        0x72,  0x61,  0x76,  0x65,  0x6c,  0x61,  0x64,  0x73,  0x65,  0x72,  0x76,  0x69,  0x63,  0x65,  0x73,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x18,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x74,  0x61,
        0x67,  0x73,  0x65,  0x72,  0x76,  0x69,  0x63,  0x65,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,
        0x82,  0x1a,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x74,  0x61,  0x67,  0x73,  0x65,  0x72,
        0x76,  0x69,  0x63,  0x65,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x17,  0x67,  0x6f,
        0x6f,  0x67,  0x6c,  0x65,  0x74,  0x61,  0x67,  0x6d,  0x61,  0x6e,  0x61,  0x67,  0x65,  0x72,  0x2d,  0x63,
        0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x19,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x74,
        0x61,  0x67,  0x6d,  0x61,  0x6e,  0x61,  0x67,  0x65,  0x72,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,
        0x82,  0x18,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x73,  0x79,  0x6e,  0x64,  0x69,  0x63,  0x61,  0x74,
        0x69,  0x6f,  0x6e,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x1a,  0x2a,  0x2e,  0x67,  0x6f,
        0x6f,  0x67,  0x6c,  0x65,  0x73,  0x79,  0x6e,  0x64,  0x69,  0x63,  0x61,  0x74,  0x69,  0x6f,  0x6e,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x24,  0x2a,  0x2e,  0x73,  0x61,  0x66,  0x65,  0x66,  0x72,
        0x61,  0x6d,  0x65,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x73,  0x79,  0x6e,  0x64,  0x69,  0x63,
        0x61,  0x74,  0x69,  0x6f,  0x6e,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x16,  0x61,  0x70,
        0x70,  0x2d,  0x6d,  0x65,  0x61,  0x73,  0x75,  0x72,  0x65,  0x6d,  0x65,  0x6e,  0x74,  0x2d,  0x63,  0x6e,
        0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x18,  0x2a,  0x2e,  0x61,  0x70,  0x70,  0x2d,  0x6d,  0x65,  0x61,  0x73,
        0x75,  0x72,  0x65,  0x6d,  0x65,  0x6e,  0x74,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0b,
        0x67,  0x76,  0x74,  0x31,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0d,  0x2a,  0x2e,  0x67,
        0x76,  0x74,  0x31,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0b,  0x67,  0x76,  0x74,  0x32,
        0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0d,  0x2a,  0x2e,  0x67,  0x76,  0x74,  0x32,  0x2d,
        0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0b,  0x32,  0x6d,  0x64,  0x6e,  0x2d,  0x63,  0x6e,  0x2e,
        0x6e,  0x65,  0x74,  0x82,  0x0d,  0x2a,  0x2e,  0x32,  0x6d,  0x64,  0x6e,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,
        0x65,  0x74,  0x82,  0x14,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x66,  0x6c,  0x69,  0x67,  0x68,  0x74,
        0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,  0x82,  0x16,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,
        0x6c,  0x65,  0x66,  0x6c,  0x69,  0x67,  0x68,  0x74,  0x73,  0x2d,  0x63,  0x6e,  0x2e,  0x6e,  0x65,  0x74,
        0x82,  0x0c,  0x61,  0x64,  0x6d,  0x6f,  0x62,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0e,
        0x2a,  0x2e,  0x61,  0x64,  0x6d,  0x6f,  0x62,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x19,
        0x2a,  0x2e,  0x67,  0x65,  0x6d,  0x69,  0x6e,  0x69,  0x2e,  0x63,  0x6c,  0x6f,  0x75,  0x64,  0x2e,  0x67,
        0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x14,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x73,  0x61,  0x6e,  0x64,  0x62,  0x6f,  0x78,  0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,
        0x16,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x73,  0x61,  0x6e,  0x64,  0x62,  0x6f,  0x78,
        0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x1e,  0x2a,  0x2e,  0x73,  0x61,  0x66,  0x65,  0x6e,
        0x75,  0x70,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x73,  0x61,  0x6e,  0x64,  0x62,  0x6f,  0x78,
        0x2d,  0x63,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0d,  0x2a,  0x2e,  0x67,  0x73,  0x74,  0x61,  0x74,
        0x69,  0x63,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x14,  0x2a,  0x2e,  0x6d,  0x65,  0x74,  0x72,  0x69,  0x63,
        0x2e,  0x67,  0x73,  0x74,  0x61,  0x74,  0x69,  0x63,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0a,  0x2a,  0x2e,
        0x67,  0x76,  0x74,  0x31,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x11,  0x2a,  0x2e,  0x67,  0x63,  0x70,  0x63,
        0x64,  0x6e,  0x2e,  0x67,  0x76,  0x74,  0x31,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0a,  0x2a,  0x2e,  0x67,
        0x76,  0x74,  0x32,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0e,  0x2a,  0x2e,  0x67,  0x63,  0x70,  0x2e,  0x67,
        0x76,  0x74,  0x32,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x10,  0x2a,  0x2e,  0x75,  0x72,  0x6c,  0x2e,  0x67,
        0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x16,  0x2a,  0x2e,  0x79,  0x6f,  0x75,
        0x74,  0x75,  0x62,  0x65,  0x2d,  0x6e,  0x6f,  0x63,  0x6f,  0x6f,  0x6b,  0x69,  0x65,  0x2e,  0x63,  0x6f,
        0x6d,  0x82,  0x0b,  0x2a,  0x2e,  0x79,  0x74,  0x69,  0x6d,  0x67,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0a,
        0x61,  0x69,  0x2e,  0x61,  0x6e,  0x64,  0x72,  0x6f,  0x69,  0x64,  0x82,  0x0b,  0x61,  0x6e,  0x64,  0x72,
        0x6f,  0x69,  0x64,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0d,  0x2a,  0x2e,  0x61,  0x6e,  0x64,  0x72,  0x6f,
        0x69,  0x64,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x66,  0x6c,  0x61,  0x73,  0x68,  0x2e,
        0x61,  0x6e,  0x64,  0x72,  0x6f,  0x69,  0x64,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x04,  0x67,  0x2e,  0x63,
        0x6e,  0x82,  0x06,  0x2a,  0x2e,  0x67,  0x2e,  0x63,  0x6e,  0x82,  0x04,  0x67,  0x2e,  0x63,  0x6f,  0x82,
        0x06,  0x2a,  0x2e,  0x67,  0x2e,  0x63,  0x6f,  0x82,  0x06,  0x67,  0x6f,  0x6f,  0x2e,  0x67,  0x6c,  0x82,
        0x0a,  0x77,  0x77,  0x77,  0x2e,  0x67,  0x6f,  0x6f,  0x2e,  0x67,  0x6c,  0x82,  0x14,  0x67,  0x6f,  0x6f,
        0x67,  0x6c,  0x65,  0x2d,  0x61,  0x6e,  0x61,  0x6c,  0x79,  0x74,  0x69,  0x63,  0x73,  0x2e,  0x63,  0x6f,
        0x6d,  0x82,  0x16,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2d,  0x61,  0x6e,  0x61,  0x6c,
        0x79,  0x74,  0x69,  0x63,  0x73,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0a,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x12,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x63,  0x6f,  0x6d,
        0x6d,  0x65,  0x72,  0x63,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x14,  0x2a,  0x2e,  0x67,  0x6f,  0x6f,
        0x67,  0x6c,  0x65,  0x63,  0x6f,  0x6d,  0x6d,  0x65,  0x72,  0x63,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,
        0x08,  0x67,  0x67,  0x70,  0x68,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x0a,  0x2a,  0x2e,  0x67,  0x67,  0x70,
        0x68,  0x74,  0x2e,  0x63,  0x6e,  0x82,  0x0a,  0x75,  0x72,  0x63,  0x68,  0x69,  0x6e,  0x2e,  0x63,  0x6f,
        0x6d,  0x82,  0x0c,  0x2a,  0x2e,  0x75,  0x72,  0x63,  0x68,  0x69,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,
        0x08,  0x79,  0x6f,  0x75,  0x74,  0x75,  0x2e,  0x62,  0x65,  0x82,  0x0b,  0x79,  0x6f,  0x75,  0x74,  0x75,
        0x62,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0d,  0x2a,  0x2e,  0x79,  0x6f,  0x75,  0x74,  0x75,  0x62,
        0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x11,  0x6d,  0x75,  0x73,  0x69,  0x63,  0x2e,  0x79,  0x6f,  0x75,
        0x74,  0x75,  0x62,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x6d,  0x75,  0x73,  0x69,
        0x63,  0x2e,  0x79,  0x6f,  0x75,  0x74,  0x75,  0x62,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x14,  0x79,
        0x6f,  0x75,  0x74,  0x75,  0x62,  0x65,  0x65,  0x64,  0x75,  0x63,  0x61,  0x74,  0x69,  0x6f,  0x6e,  0x2e,
        0x63,  0x6f,  0x6d,  0x82,  0x16,  0x2a,  0x2e,  0x79,  0x6f,  0x75,  0x74,  0x75,  0x62,  0x65,  0x65,  0x64,
        0x75,  0x63,  0x61,  0x74,  0x69,  0x6f,  0x6e,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x0f,  0x79,  0x6f,  0x75,
        0x74,  0x75,  0x62,  0x65,  0x6b,  0x69,  0x64,  0x73,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x11,  0x2a,  0x2e,
        0x79,  0x6f,  0x75,  0x74,  0x75,  0x62,  0x65,  0x6b,  0x69,  0x64,  0x73,  0x2e,  0x63,  0x6f,  0x6d,  0x82,
        0x05,  0x79,  0x74,  0x2e,  0x62,  0x65,  0x82,  0x07,  0x2a,  0x2e,  0x79,  0x74,  0x2e,  0x62,  0x65,  0x82,
        0x1a,  0x61,  0x6e,  0x64,  0x72,  0x6f,  0x69,  0x64,  0x2e,  0x63,  0x6c,  0x69,  0x65,  0x6e,  0x74,  0x73,
        0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6f,  0x6d,  0x82,  0x13,  0x2a,  0x2e,  0x61,
        0x6e,  0x64,  0x72,  0x6f,  0x69,  0x64,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6e,
        0x82,  0x12,  0x2a,  0x2e,  0x63,  0x68,  0x72,  0x6f,  0x6d,  0x65,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,
        0x65,  0x2e,  0x63,  0x6e,  0x82,  0x16,  0x2a,  0x2e,  0x64,  0x65,  0x76,  0x65,  0x6c,  0x6f,  0x70,  0x65,
        0x72,  0x73,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,  0x63,  0x6e,  0x82,  0x15,  0x2a,  0x2e,
        0x61,  0x69,  0x73,  0x74,  0x75,  0x64,  0x69,  0x6f,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x6c,  0x65,  0x2e,
        0x63,  0x6f,  0x6d,  0x30,  0x13,  0x06,  0x03,  0x55,  0x1d,  0x20,  0x04,  0x0c,  0x30,  0x0a,  0x30,  0x08,
        0x06,  0x06,  0x67,  0x81,  0x0c,  0x01,  0x02,  0x01,  0x30,  0x36,  0x06,  0x03,  0x55,  0x1d,  0x1f,  0x04,
        0x2f,  0x30,  0x2d,  0x30,  0x2b,  0xa0,  0x29,  0xa0,  0x27,  0x86,  0x25,  0x68,  0x74,  0x74,  0x70,  0x3a,
        0x2f,  0x2f,  0x63,  0x2e,  0x70,  0x6b,  0x69,  0x2e,  0x67,  0x6f,  0x6f,  0x67,  0x2f,  0x77,  0x72,  0x32,
        0x2f,  0x6f,  0x42,  0x46,  0x59,  0x59,  0x61,  0x68,  0x7a,  0x67,  0x56,  0x49,  0x2e,  0x63,  0x72,  0x6c,
        0x30,  0x82,  0x01,  0x02,  0x06,  0x0a,  0x2b,  0x06,  0x01,  0x04,  0x01,  0xd6,  0x79,  0x02,  0x04,  0x02,
        0x04,  0x81,  0xf3,  0x04,  0x81,  0xf0,  0x00,  0xee,  0x00,  0x75,  0x00,  0xcc,  0xfb,  0x0f,  0x6a,  0x85,
        0x71,  0x09,  0x65,  0xfe,  0x95,  0x9b,  0x53,  0xce,  0xe9,  0xb2,  0x7c,  0x22,  0xe9,  0x85,  0x5c,  0x0d,
        0x97,  0x8d,  0xb6,  0xa9,  0x7e,  0x54,  0xc0,  0xfe,  0x4c,  0x0d,  0xb0,  0x00,  0x00,  0x01,  0x99,  0x28,
        0xad,  0xbc,  0xb9,  0x00,  0x00,  0x04,  0x03,  0x00,  0x46,  0x30,  0x44,  0x02,  0x20,  0x15,  0xc1,  0x3b,
        0x7d,  0xf1,  0xf3,  0xb7,  0xc8,  0x95,  0xb0,  0xc2,  0x01,  0xed,  0x27,  0xf4,  0x3c,  0x75,  0xe9,  0xad,
        0x5a,  0xb8,  0xb9,  0xa2,  0x3c,  0xdf,  0x4a,  0xfe,  0x9d,  0x79,  0x25,  0xff,  0x58,  0x02,  0x20,  0x09,
        0xe0,  0x9d,  0x52,  0x99,  0x84,  0x4c,  0x52,  0x92,  0x41,  0xcf,  0x32,  0x37,  0x7e,  0xd7,  0xef,  0x05,
        0x5e,  0x42,  0x96,  0xc1,  0x43,  0x33,  0xda,  0x12,  0x76,  0xb5,  0x73,  0x83,  0x77,  0x23,  0xc1,  0x00,
        0x75,  0x00,  0x12,  0xf1,  0x4e,  0x34,  0xbd,  0x53,  0x72,  0x4c,  0x84,  0x06,  0x19,  0xc3,  0x8f,  0x3f,
        0x7a,  0x13,  0xf8,  0xe7,  0xb5,  0x62,  0x87,  0x88,  0x9c,  0x6d,  0x30,  0x05,  0x84,  0xeb,  0xe5,  0x86,
        0x26,  0x3a,  0x00,  0x00,  0x01,  0x99,  0x28,  0xad,  0xbc,  0x4b,  0x00,  0x00,  0x04,  0x03,  0x00,  0x46,
        0x30,  0x44,  0x02,  0x20,  0x2a,  0xeb,  0xbf,  0xba,  0x40,  0x70,  0x1a,  0xb2,  0x94,  0x6d,  0xb2,  0x5c,
        0x05,  0xaa,  0x3c,  0xc2,  0xd4,  0x47,  0x46,  0x41,  0xb7,  0x07,  0x2f,  0x89,  0x5e,  0xc5,  0x0e,  0xd5,
        0x97,  0x6a,  0x46,  0xc9,  0x02,  0x20,  0x3c,  0xa1,  0x02,  0x08,  0xe2,  0x4f,  0xe7,  0x00,  0xb4,  0x42,
        0x5e,  0x58,  0x5d,  0x11,  0xb5,  0xaa,  0x15,  0xa9,  0xf9,  0xab,  0x85,  0x65,  0x55,  0x7b,  0x8c,  0xa6,
        0x22,  0xb7,  0xfb,  0x66,  0x7d,  0x39,  0x30,  0x0d,  0x06,  0x09,  0x2a,  0x86,  0x48,  0x86,  0xf7,  0x0d,
        0x01,  0x01,  0x0b,  0x05,  0x00,  0x03,  0x82,  0x01,  0x01,  0x00,  0x60,  0x56,  0xa7,  0x3d,  0x11,  0xc5,
        0x3c,  0x03,  0xf7,  0x4a,  0x59,  0x35,  0x7d,  0x48,  0x79,  0xbb,  0xf8,  0x58,  0xf0,  0x10,  0x9d,  0x95,
        0x71,  0x3f,  0xf0,  0x29,  0x89,  0xca,  0x8b,  0x01,  0x22,  0x68,  0x19,  0x50,  0x62,  0x99,  0xb3,  0x7b,
        0xd0,  0x77,  0x6a,  0x82,  0xc2,  0x68,  0xf5,  0x3f,  0xdf,  0x90,  0xde,  0x6b,  0x92,  0x1a,  0xed,  0x5a,
        0x82,  0x8b,  0x69,  0x2e,  0x98,  0x10,  0x0c,  0xbe,  0x43,  0xef,  0xfa,  0x75,  0x2d,  0xbc,  0xa3,  0x79,
        0xad,  0x34,  0x99,  0x49,  0x9f,  0x23,  0xdf,  0xeb,  0x35,  0x34,  0xfc,  0xc8,  0x62,  0x28,  0x93,  0xb6,
        0xc5,  0x12,  0x90,  0x7b,  0x94,  0x8f,  0xb6,  0xe6,  0xe0,  0xbe,  0x6a,  0x01,  0xdd,  0xcd,  0xd9,  0x61,
        0xc6,  0x6c,  0xcd,  0x0b,  0x79,  0xca,  0xb8,  0x93,  0x65,  0x4d,  0xb6,  0xa7,  0x55,  0xcb,  0x80,  0xba,
        0xb3,  0x03,  0x4c,  0xda,  0xaf,  0x49,  0xd6,  0xe4,  0x60,  0xab,  0x48,  0x7e,  0x56,  0x59,  0x06,  0x2e,
        0x2b,  0xb0,  0x5f,  0x2d,  0x04,  0x84,  0xeb,  0xed,  0x36,  0xf4,  0x47,  0x9a,  0x3c,  0x1b,  0x79,  0xec,
        0x01,  0xf8,  0x09,  0x59,  0xdc,  0xc3,  0x41,  0xc1,  0xeb,  0x6d,  0x08,  0x08,  0xfd,  0x37,  0x4b,  0x02,
        0xcd,  0xfb,  0xd0,  0x48,  0x76,  0x28,  0x64,  0xbd,  0x88,  0xae,  0x6c,  0xd6,  0xe3,  0x02,  0x13,  0x02,
        0x5e,  0x76,  0xe5,  0x23,  0xe4,  0x95,  0x44,  0x52,  0x54,  0x12,  0x28,  0x86,  0xf5,  0xe5,  0xb4,  0xb2,
        0x91,  0xe7,  0xf3,  0x2a,  0xf7,  0xd4,  0x19,  0xa0,  0x99,  0xdf,  0xc0,  0x9f,  0x8c,  0x34,  0xb9,  0x56,
        0xa3,  0x9f,  0x4e,  0xcb,  0x85,  0x7d,  0x9a,  0x60,  0x25,  0xc0,  0xf5,  0x85,  0x6d,  0x3c,  0xd4,  0x62,
        0x30,  0xdb,  0x9b,  0x60,  0xfb,  0x34,  0xdc,  0x95,  0xbe,  0x53,  0x27,  0x4e,  0x02,  0x65,  0x57,  0xf5,
        0xfa,  0xd8,  0xea,  0xbb,  0x92,  0xe3,  0xe4,  0xa7,  0x12,  0x36 
    ];
    auto memory = MemoryReader(asn1);
    
    Asn1ComponentHeader header;
    MemoryReader content;
    asn1DecodeComponentHeader!(Asn1Ruleset.der)(memory, header).resultAssert;
    asn1ReadContentBytes(memory, header.length, content).resultAssert;

    Certificate asn1Cert;
    asn1Cert.fromDecoding!(Asn1Ruleset.der)(content, header.identifier).resultAssert;

    X509Certificate cert;
    x509FromAsn1(asn1Cert, cert).resultAssert;

    string[X509Certificate.NameComponentKind] issuerComps;
    x509ForeachNameComponentGC(cert.issuer, (element){
        X509Certificate.NameComponentKind kind;
        const(char)[] text;

        x509HandleNameComponent(element, kind, text).resultAssert;
        issuerComps[kind] = text.idup;

        return Result.noError;
    }).resultAssert;

    string[X509Certificate.NameComponentKind] subjectComps;
    x509ForeachNameComponentGC(cert.subject, (element){
        X509Certificate.NameComponentKind kind;
        const(char)[] text;

        x509HandleNameComponent(element, kind, text).resultAssert;
        subjectComps[kind] = text.idup;

        return Result.noError;
    }).resultAssert;

    X509Extension.SumT[TypeInfo] extByTypeInfo;
    cert.extensions.get.get().foreachElementAutoGC((element){
        X509Extension.SumT ext;
        x509HandleExtension(element, ext).resultAssert;

        import std.sumtype : match;
        ext.match!((e) { extByTypeInfo[typeid(e)] = ext; });

        return Result.noError;
    }).resultAssert;
    
    with(X509Certificate.NameComponentKind)
    {
        assert(issuerComps[commonName] == "WR2");
        assert(issuerComps[organizationName] == "Google Trust Services");
        assert(issuerComps[countryName] == "US");

        assert(subjectComps[commonName] == "*.google.com");
    }

    T getSum(T)()
    {
        import std.sumtype : match;
        return extByTypeInfo[typeid(T)].match!((T v) => v, (_) { assert(false, "wrong type?"); return T.init; });
    }

    with(X509Extension)
    {
        import std.format : format;

        BasicConstraints basicConstraint = getSum!BasicConstraints;
        assert(!basicConstraint.ca);
        assert(basicConstraint.pathLenConstraint.isNull);

        AuthorityKeyIdentifier authKeyId = getSum!AuthorityKeyIdentifier;
        assert(authKeyId.keyIdentifier == [
            0xde,  0x1b,  0x1e,  0xed,  0x79,  0x15,  0xd4,  0x3e,  0x37,  0x24,
            0xc3,  0x21,  0xbb,  0xec,  0x34,  0x39,  0x6d,  0x42,  0xb2,  0x30,
        ]);
        assert(authKeyId.authorityCertIssuer.isNull);
        assert(authKeyId.authorityCertSerialNumber.isNull);

        ExtendedKeyUsage extKeyUse = getSum!ExtendedKeyUsage;
        assert(extKeyUse.serverAuth);

        KeyUsage keyUse = getSum!KeyUsage;
        assert(keyUse.digitalSignature);

        SubjectKeyIdentifier subKeyId = getSum!SubjectKeyIdentifier;
        assert(subKeyId.keyIdentifier == [
            0x86,  0x54,  0x1e,  0x8e,  0x99,  0xb0,  0x05,  0x78,  0x9e,  0xa7,  
            0x57,  0x11,  0x74,  0x6a,  0x9a,  0x63,  0x74,  0x16,  0xa7,  0x53,
        ]);

        import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19 : DistributionPoint;
        CrlDistributionPoints dps = getSum!CrlDistributionPoints;
        DistributionPoint dp;
        assert(dps.points.get().elementCount == 1);
        dps.points.get().foreachElementAutoGC((dpElem) { dp = dpElem; return Result.noError; }).resultAssert;
        assert(dp.getReasons().isNull);
        assert(dp.getCRLIssuer().isNull);
        dp.getDistributionPoint().get.getFullName().get().foreachElementAutoGC((generalName){
            assert(generalName.getUniformResourceIdentifier().asSlice == "http://c.pki.goog/wr2/oBFYYahzgVI.crl");
            return Result.noError;
        }).resultAssert;

        import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19 : AccessDescription;
        AuthorityInfoAccessSyntax assSyntax = getSum!AuthorityInfoAccessSyntax;
        size_t assCount;
        assSyntax.get().foreachElementAutoGC((AccessDescription ass){
            import std.algorithm : equal;
            import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 
                : id_ad_ocsp, id_ad_caIssuers;

            final switch(assCount)
            {
                case 0:
                    assert(ass.getAccessMethod().components.equal(id_ad_ocsp().components));
                    assert(ass.getAccessLocation().getUniformResourceIdentifier().asSlice == "http://o.pki.goog/wr2");
                    break;

                case 1:
                    assert(ass.getAccessMethod().components.equal(id_ad_caIssuers().components));
                    assert(ass.getAccessLocation().getUniformResourceIdentifier().asSlice == "http://i.pki.goog/wr2.crt"); // @suppress(dscanner.style.long_line)
                    break;
            }

            assCount++;
            return Result.noError;
        }).resultAssert;

        import juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19 : GeneralName;
        SubjectAltName subAltName = getSum!SubjectAltName;
        string[] altNames;
        subAltName.names.get().foreachElementAutoGC((GeneralName name){
            // Note: I just wanted to test the match function, could've just used getDNSName instead.
            return name.matchGC(
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (dnsName) { altNames ~= dnsName.asSlice; return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
                (_) { assert(false); return Result.noError; },
            );
        }).resultAssert;
        assert(altNames == [ // The world's least bloated certificate
            "*.google.com", "*.appengine.google.com", "*.bdn.dev", "*.origin-test.bdn.dev", 
            "*.cloud.google.com", "*.crowdsource.google.com", "*.datacompute.google.com", 
            "*.google.ca", "*.google.cl", "*.google.co.in", "*.google.co.jp", 
            "*.google.co.uk", "*.google.com.ar", "*.google.com.au", "*.google.com.br", 
            "*.google.com.co", "*.google.com.mx", "*.google.com.tr", "*.google.com.vn", 
            "*.google.de", "*.google.es", "*.google.fr", "*.google.hu", "*.google.it", 
            "*.google.nl", "*.google.pl", "*.google.pt", "*.googleapis.cn", 
            "*.googlevideo.com", "*.gstatic.cn", "*.gstatic-cn.com", "googlecnapps.cn", 
            "*.googlecnapps.cn", "googleapps-cn.com", "*.googleapps-cn.com", "gkecnapps.cn", 
            "*.gkecnapps.cn", "googledownloads.cn", "*.googledownloads.cn", "recaptcha.net.cn", 
            "*.recaptcha.net.cn", "recaptcha-cn.net", "*.recaptcha-cn.net", "widevine.cn", 
            "*.widevine.cn", "ampproject.org.cn", "*.ampproject.org.cn", "ampproject.net.cn", 
            "*.ampproject.net.cn", "google-analytics-cn.com", "*.google-analytics-cn.com", 
            "googleadservices-cn.com", "*.googleadservices-cn.com", "googlevads-cn.com", 
            "*.googlevads-cn.com", "googleapis-cn.com", "*.googleapis-cn.com", "googleoptimize-cn.com", 
            "*.googleoptimize-cn.com", "doubleclick-cn.net", "*.doubleclick-cn.net", 
            "*.fls.doubleclick-cn.net", "*.g.doubleclick-cn.net", "doubleclick.cn", "*.doubleclick.cn", 
            "*.fls.doubleclick.cn", "*.g.doubleclick.cn", "dartsearch-cn.net", "*.dartsearch-cn.net", 
            "googletraveladservices-cn.com", "*.googletraveladservices-cn.com", "googletagservices-cn.com", 
            "*.googletagservices-cn.com", "googletagmanager-cn.com", "*.googletagmanager-cn.com", 
            "googlesyndication-cn.com", "*.googlesyndication-cn.com", "*.safeframe.googlesyndication-cn.com", 
            "app-measurement-cn.com", "*.app-measurement-cn.com", "gvt1-cn.com", "*.gvt1-cn.com", "gvt2-cn.com", 
            "*.gvt2-cn.com", "2mdn-cn.net", "*.2mdn-cn.net", "googleflights-cn.net", "*.googleflights-cn.net", 
            "admob-cn.com", "*.admob-cn.com", "*.gemini.cloud.google.com", "googlesandbox-cn.com", 
            "*.googlesandbox-cn.com", "*.safenup.googlesandbox-cn.com", "*.gstatic.com", "*.metric.gstatic.com", 
            "*.gvt1.com", "*.gcpcdn.gvt1.com", "*.gvt2.com", "*.gcp.gvt2.com", "*.url.google.com", 
            "*.youtube-nocookie.com", "*.ytimg.com", "ai.android", "android.com", "*.android.com", 
            "*.flash.android.com", "g.cn", "*.g.cn", "g.co", "*.g.co", "goo.gl", "www.goo.gl", 
            "google-analytics.com", "*.google-analytics.com", "google.com", "googlecommerce.com", 
            "*.googlecommerce.com", "ggpht.cn", "*.ggpht.cn", "urchin.com", "*.urchin.com", "youtu.be", 
            "youtube.com", "*.youtube.com", "music.youtube.com", "*.music.youtube.com", "youtubeeducation.com", 
            "*.youtubeeducation.com", "youtubekids.com", "*.youtubekids.com", "yt.be", "*.yt.be", 
            "android.clients.google.com", "*.android.google.cn", "*.chrome.google.cn", "*.developers.google.cn", 
            "*.aistudio.google.com"
        ]);
    }
}