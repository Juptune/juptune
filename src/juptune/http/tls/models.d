/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.models;

package:

/++ Constants ++/

enum TLS_VERSION_12 = 0x0303;
enum TLS_VERSION_13 = 0x0304;
enum UINT24_MAX = 16_777_215;

/++ Encoding UDAs ++/

struct ExactLength
{
    size_t length;
}

struct LengthRange(alias OfType_) // NOTE: length is in bytes, as per RFC 8446
{
    alias OfType = OfType_;

    size_t lower;
    size_t upper;
}

struct ExactValue(ValueT)
{
    ValueT value;
}

struct OnlyForHandshakeType
{
    TlsHandshake.Type type;
}

struct RawTlsStruct
{
}

struct Exempt {}

/++ Helper types ++/

template TlsSelectOption(alias EnumValue_, alias ValueT_)
{
    enum EnumValue = EnumValue_;
    alias ValueT = ValueT_;
}

struct TlsSelect(alias EnumT, SelectOptions...)
{
    union Data
    {
        static foreach(i, Option; SelectOptions)
        {
            mixin("Option.ValueT ", tlsSelectIndexString!i, ";");
        }
    }

    private
    {
        Data _data;
        EnumT _tag;
    }

    void set(ValueT)(scope ref const(EnumT) tag, ValueT value) @nogc nothrow // scope ref is to help remind myself that `tag` should be sourced from a variable
    in(this._tag == EnumT.init, "bug: this TlsSelect already has data in it")
    {
        alias Option = OptionByValueType!ValueT;
        assert(tag == Option.Option.EnumValue, "bug: incorrect tag provided for value");

        this._tag = tag;
        mixin("this._data.", tlsSelectIndexString!(Option.Index), " = value;");
    }

    EnumT getTag() @safe @nogc nothrow pure const
    {
        return this._tag;
    }

    ValueT getValue(ValueT)() @nogc nothrow
    in(this._tag != EnumT.init, "bug: this TlsSelect hasn't been initialised yet")
    {
        alias Option = OptionByValueType!ValueT;
        assert(this._tag == Option.Option.EnumValue, "bug: TlsSelect has the wrong tag for the requested value type");

        mixin("return this._data.", tlsSelectIndexString!(Option.Index), ";");
    }

    template OptionByValueType(alias ValueT)
    {
        static foreach(i, Option_; SelectOptions)
        {
            static if(is(Option_.ValueT == ValueT))
            {
                enum Found = true;
                enum Index = i;
                alias Option = Option_;
            }
        }

        static assert(__traits(compiles, Found), "Value of type "~ValueT.stringof~" cannot be used with this TlsSelect"); // @suppress(dscanner.style.long_line)
    }
}

string tlsSelectIndexString(size_t i)() pure
{
    import std.conv : to;
    return "value_"~i.to!string;
}

/++ Raw TLS types ++/

struct TlsHandshake // It's a bit too annoying to use the auto encoder/decoder for this struct, so it's handled manually.
{
    enum HEADER_SIZE = 4;

    enum CipherSuite : ubyte[2]
    {
        FAILSAFE = [0, 0],

        TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03],

        unknown = [255, 255]
    }

    enum Type
    {
        FAILSAFE = 0,
        clientHello = 1,
        serverHello = 2,
        newSessionTicket = 4,
        endOfEarlyData = 5,
        encryptedExtensions = 8,
        certificate = 11,
        certificateRequest = 13,
        certificateVerify = 15,
        finished = 20,
        keyUpdate = 24,
        messageHash = 254,

        MAX = ubyte.max,

        // helloRetryRequest is an edgecase, since it has to be detected halfway through decoding.
        helloRetryRequest = MAX + 1,
    }

    Type messageType;
    @ExactLength(UINT24_MAX) uint length; // NOTE: ExactLength is _only_ here so that CanaryLength can infer encoded byte count. It isn't actually used for validation.
    Message message;

    /++ Messages ++/

    enum SignatureScheme
    {
        FAILSAFE = 0,

        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256 = 0x0401,
        rsa_pkcs1_sha384 = 0x0501,
        rsa_pkcs1_sha512 = 0x0601,

        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256 = 0x0804,
        rsa_pss_rsae_sha384 = 0x0805,
        rsa_pss_rsae_sha512 = 0x0806,

        /* EdDSA algorithms */
        ed25519 = 0x0807,
        ed448 = 0x0808,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256 = 0x0809,
        rsa_pss_pss_sha384 = 0x080a,
        rsa_pss_pss_sha512 = 0x080b,

        /* Legacy algorithms */
        rsa_pkcs1_sha1 = 0x0201,
        ecdsa_sha1 = 0x0203,

        MAX = 0xFFFF,
    }

    static immutable SUPPORTED_SIGNATURE_SCHEMES = [
        // SignatureScheme.rsa_pkcs1_sha256,
        // SignatureScheme.rsa_pkcs1_sha384,
        // SignatureScheme.rsa_pkcs1_sha512,
        SignatureScheme.ecdsa_secp256r1_sha256,
        // SignatureScheme.ecdsa_secp384r1_sha384,
        // SignatureScheme.ecdsa_secp521r1_sha512,
        // SignatureScheme.ed448,
        // SignatureScheme.ed25519,
        // SignatureScheme.rsa_pss_pss_sha256,
        // SignatureScheme.rsa_pss_pss_sha384,
        // SignatureScheme.rsa_pss_pss_sha512,
        SignatureScheme.rsa_pss_rsae_sha256,
        // SignatureScheme.rsa_pss_rsae_sha384,
        // SignatureScheme.rsa_pss_rsae_sha512,
    ];

    static union Message // SumType is heavy, and since TlsHandshake will pretty much never be used by user code, I don't care about it being safer to use.
    {
        ClientHello clientHello;
        ServerHello serverHello;
        NewSessionTicket newSessionTicket;
        EndOfEarlyData endOfEarlyData;
        EncryptedExtensions encryptedExtensions;
        Certificate certificate;
        CertificateRequest certificateRequest;
        CertificateVerify certificateVerify;
        Finished finished;
        KeyUpdate keyUpdate;
        MessageHash messageHash;
    }

    @RawTlsStruct
    static struct ClientHello
    {
        @ExactValue!ushort(TLS_VERSION_12)
        ushort legacyVersion;
        
        @ExactLength(32)
        const(ubyte)[] random;
        
        @LengthRange!ubyte(0, 32)
        const(ubyte)[] legacySessionId;

        @LengthRange!CipherSuite(2, ushort.max - 1)
        const(ubyte)[] cipherSuites;

        @LengthRange!ubyte(1, ubyte.max)
        const(ubyte)[] legacyCompressionMethods;

        @LengthRange!TlsExtension(8, ushort.max)
        const(ubyte)[] extensions;
    }

    @RawTlsStruct
    static struct ServerHello
    {
        static immutable ubyte[] HelloRetryRequestRandom = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];

        static immutable ubyte[] Tls11Random = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];
        static immutable ubyte[] Tls12Random = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

        @ExactValue!ushort(0x0303)
        ushort legacyVersion;
        
        @ExactLength(32)
        const(ubyte)[] random;
        
        @LengthRange!ubyte(0, 32)
        const(ubyte)[] legacySessionIdEcho;

        CipherSuite cipherSuite;

        @ExactValue!ubyte(0)
        ubyte legacyCompressionMethod;

        @LengthRange!TlsExtension(8, ushort.max)
        const(ubyte)[] extensions;
    }

    @RawTlsStruct
    static struct NewSessionTicket
    {
        uint ticketLifetime;
        uint ticketAgeAdd;

        @LengthRange!ubyte(0, ubyte.max)
        const(ubyte)[] ticketNonce;

        @LengthRange!ubyte(1, ushort.max)
        const(ubyte)[] ticket;

        @LengthRange!TlsExtension(0, ushort.max-1)
        const(ubyte)[] extensions;
    }
    
    @RawTlsStruct
    static struct EndOfEarlyData {}

    @RawTlsStruct
    static struct EncryptedExtensions
    {
        @LengthRange!TlsExtension(0, ushort.max)
        const(ubyte)[] extensions;
    }
    
    @RawTlsStruct
    static struct Certificate
    {
        @RawTlsStruct
        static struct Entry
        {
            @LengthRange!ubyte(1, UINT24_MAX) // uint24.max
            const(ubyte)[] data;

            @LengthRange!TlsExtension(0, ushort.max)
            const(ubyte)[] extensions;
        }

        @LengthRange!ubyte(0, ubyte.max)
        const(ubyte)[] certificateRequestContext;

        @LengthRange!Entry(0, UINT24_MAX)
        const(ubyte)[] certificateList;
    }
    
    @RawTlsStruct
    static struct CertificateRequest
    {
        @LengthRange!ubyte(0, ubyte.max)
        const(ubyte)[] certificateRequestContext;

        @LengthRange!TlsExtension(0, ushort.max)
        const(ubyte)[] extensions;
    }
    
    @RawTlsStruct
    static struct CertificateVerify
    {
        SignatureScheme algorithm;
        
        @LengthRange!ubyte(0, ushort.max)
        const(ubyte)[] signature;
    }
    
    // @RawTlsStruct - The expect length is dynamic, so this struct needs a custom decoder.
    static struct Finished
    {
        const(ubyte)[] verifyData;
    }
    
    @RawTlsStruct
    static struct KeyUpdate
    {
        enum Request
        {
            FAILSAFE = ubyte.max,

            update_not_requested = 0,
            updated_requested = 1,

            MAX = ubyte.max,
        }

        Request requestUpdate;
    }
    
    @RawTlsStruct
    static struct MessageHash {}
}

struct TlsExtension // It's a bit too annoying to use the auto encoder/decoder for this struct, so it's handled manually.
{
    enum Type
    {
        FAILSAFE = ushort.max,
        serverName = 0,
        maxFragmentLength = 1,
        statusRequest = 5,
        supportedGroups = 10,
        signatureAlgorithms = 13,
        useSrtp = 14,
        heartbeat = 15,
        applicationLayerProtocolNegotiation = 16,
        signedCertificateTimestampt = 18,
        clientCertificateType = 19,
        serverCertificateType = 20,
        padding = 21,
        RESERVED40 = 40,
        preSharedKey = 41,
        earlyData = 42,
        supportedVersions = 43,
        cookie = 44,
        pskKeyExchangeModes = 45,
        RESERVED46 = 46,
        certificateAuthorities = 47,
        oidFilters = 48,
        postHandshakeAuth = 49,
        signatureAlgorithmsCert = 50,
        keyShare = 51,

        MAX = ushort.max,
    }

    Type type;
    @ExactLength(ushort.max-1) const(ubyte)[] extensionData; // NOTE: ExactLength is _only_ here so that CanaryLength can infer encoded byte count. It isn't actually used for validation.
    Data data; 

    enum NamedGroup : ushort
    {
        FAILSAFE = 0,

        /* Elliptic Curve Groups (ECDHE) */
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519 = 0x001D,
        x448 = 0x001E,

        /* Finite Field Groups (DHE) */
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        ffdhe4096 = 0x0102,
        ffdhe6144 = 0x0103,
        ffdhe8192 = 0x0104,

        MAX = 0xFFFF,
    }

    enum PskKeyExchangeMode
    {
        FAILSAFE = ubyte.max,

        psk_ke = 0,
        psk_dhe_ke = 1,

        MAX = ubyte.max,
    }

    enum CertificateType
    {
        FAILSAFE = ubyte.max,

        x509 = 0,
        rawPublicKey = 2,

        MAX = ubyte.max,
    }

    static union Data
    {
        KeyShare keyShare;
        SupportedVersions supportedVersions;
        Cookie cookie;
        SignatureSchemeList signatureAlgorithms;
        SignatureSchemeList signatureAlgorithmsCert;
        CertificateAuthorities certificateAuthorities;
        OidFilters oidFilters;
        PostHandshakeAuth postHandshakeAuth;
        SupportedGroups supportedGroups;
        PskKeyExchangeModes pskKeyExchangeModes;
        EarlyData earlyData;
        PreSharedKey preSharedKey;
        ServerNameList serverName;
    }

    alias KeyShare = TlsSelect!(
        TlsHandshake.Type,
        TlsSelectOption!(TlsHandshake.Type.clientHello, KeyShareClientHello),
        TlsSelectOption!(TlsHandshake.Type.helloRetryRequest, KeyShareHelloRetryRequest),
        TlsSelectOption!(TlsHandshake.Type.serverHello, KeyShareServerHello),
    );

    @RawTlsStruct
    static struct KeyShareEntry // Not an extension
    {
        NamedGroup group;
        
        @LengthRange!ubyte(1, ushort.max)
        const(ubyte)[] keyExchange;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct KeyShareClientHello
    {
        @LengthRange!KeyShareEntry(0, ushort.max)
        const(ubyte)[] clientShares;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.helloRetryRequest)
    static struct KeyShareHelloRetryRequest
    {
        NamedGroup selectedGroup;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.serverHello)
    static struct KeyShareServerHello
    {
        KeyShareEntry serverShare;
    }

    alias SupportedVersions = TlsSelect!(
        TlsHandshake.Type,
        TlsSelectOption!(TlsHandshake.Type.clientHello, SupportedVersionsClientHello),
        TlsSelectOption!(TlsHandshake.Type.serverHello, SupportedVersionsServerHello),
        TlsSelectOption!(TlsHandshake.Type.helloRetryRequest, SupportedVersionsHelloRetryRequest),
    );

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct SupportedVersionsClientHello
    {
        @LengthRange!ushort(2, 254)
        const(ubyte)[] versions;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.serverHello)
    static struct SupportedVersionsServerHello
    {
        ushort selectedVersion;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.helloRetryRequest)
    static struct SupportedVersionsHelloRetryRequest
    {
        ushort selectedVersion;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    @OnlyForHandshakeType(TlsHandshake.Type.helloRetryRequest)
    static struct Cookie
    {
        @LengthRange!ubyte(1, ushort.max)
        const(ubyte)[] cookie;
    }
    
    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    @OnlyForHandshakeType(TlsHandshake.Type.certificateRequest)
    static struct SignatureSchemeList
    {
        @LengthRange!ushort(2, ushort.max - 1)
        const(ubyte)[] supportedSignatureAlgorithms;
    }

    @RawTlsStruct
    static struct DistinguishedName // Not an extension
    {
        @LengthRange!ubyte(1, ushort.max)
        const(ubyte)[] der;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    @OnlyForHandshakeType(TlsHandshake.Type.certificateRequest)
    static struct CertificateAuthorities
    {
        @LengthRange!DistinguishedName(3, ushort.max)
        const(ubyte)[] authorities;
    }

    @RawTlsStruct
    static struct OidFilter // Not an extension
    {
        @LengthRange!ubyte(1, ubyte.max)
        const(ubyte)[] certificateExtensionOidDer;

        @LengthRange!ubyte(0, ushort.max)
        const(ubyte)[] certificateExtensionValuesDer;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.certificateRequest)
    static struct OidFilters
    {
        @LengthRange!OidFilter(0, ushort.max)
        const(ubyte)[] filters;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct PostHandshakeAuth {}

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    @OnlyForHandshakeType(TlsHandshake.Type.encryptedExtensions)
    static struct SupportedGroups
    {
        @LengthRange!NamedGroup(2, ushort.max)
        const(ubyte)[] namedGroupList;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct PskKeyExchangeModes
    {
        @LengthRange!PskKeyExchangeMode(1, ubyte.max)
        const(ubyte)[] keModes;
    }

    alias EarlyData = TlsSelect!(
        TlsHandshake.Type,
        TlsSelectOption!(TlsHandshake.Type.clientHello, EarlyDataClientHello),
        TlsSelectOption!(TlsHandshake.Type.encryptedExtensions, EarlyDataEncryptedExtensions),
        TlsSelectOption!(TlsHandshake.Type.newSessionTicket, EarlyDataNewSessionTicket),
    );

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct EarlyDataClientHello{}

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.encryptedExtensions)
    static struct EarlyDataEncryptedExtensions{}

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.newSessionTicket)
    static struct EarlyDataNewSessionTicket
    {
        uint maxEarlyDataSize;
    }

    alias PreSharedKey = TlsSelect!(
        TlsHandshake.Type,
        TlsSelectOption!(TlsHandshake.Type.clientHello, OfferedPsks),
        TlsSelectOption!(TlsHandshake.Type.serverHello, ushort),
    );

    @RawTlsStruct
    static struct PskIdentity // Not an extension
    {
        @LengthRange!ubyte(1, ushort.max)
        const(ubyte)[] identity;

        uint obfuscatedTicketAge;
    }

    @RawTlsStruct
    static struct PskBinderEntry // Not an extension
    {
        @LengthRange!ubyte(32, ubyte.max)
        const(ubyte)[] data;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct OfferedPsks
    {
        @LengthRange!PskIdentity(7, ushort.max)
        const(ubyte)[] identities;

        @LengthRange!PskBinderEntry(33, ushort.max)
        const(ubyte)[] binders;
    }

    /++ RFC 6066 ++/

    @RawTlsStruct
    static struct ServerName // Not an extension
    {
        enum NameType
        {
            FAILSAFE = ubyte.max,

            host_name = 0,

            MAX = ubyte.max,
        }

        NameType nameType;
        
        @LengthRange!char(1, ushort.max)
        const(ubyte)[] hostName;
    }

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    static struct ServerNameList
    {
        @LengthRange!ServerName(1, ushort.max)
        const(ubyte)[] severNameList;
    }

    /++ Special ++/

    @RawTlsStruct
    @OnlyForHandshakeType(TlsHandshake.Type.clientHello)
    @OnlyForHandshakeType(TlsHandshake.Type.serverHello)
    static struct EmptyExtensionData
    {
    }
}

struct TlsAlert
{
    enum Level
    {
        FAILSAFE = 0,
        
        warning = 1,
        fatal = 2,

        MAX = 255,
    }

    enum Description
    {
        FAILSAFE = 255,

        close_notify = 0,
        unexpected_message = 10,
        bad_record_mac = 20,
        record_overflow = 22,
        handshake_failure = 40,
        bad_certificate = 42,
        unsupported_certificate = 43,
        certificate_revoked = 44,
        certificate_expired = 45,
        certificate_unknown = 46,
        illegal_parameter = 47,
        unknown_ca = 48,
        access_denied = 49,
        decode_error = 50,
        decrypt_error = 51,
        protocol_version = 70,
        insufficient_security = 71,
        internal_error = 80,
        inappropriate_fallback = 86,
        user_canceled = 90,
        missing_extension = 109,
        unsupported_extension = 110,
        unrecognized_name = 112,
        bad_certificate_status_response = 113,
        unknown_psk_identity = 115,
        certificate_required = 116,
        no_application_protocol = 120,

        MAX = 255,
    }

    Level level;
    Description description;
}

struct TlsPlaintext
{
    enum HEADER_SIZE = 5;
    enum MAX_LENGTH = 16_384;

    enum ContentType
    {
        invalid = 0,
        changeCipherSpec = 20,
        alert = 21,
        handshake = 22,
        applicationData = 23,

        MAX = 255
    }

    ContentType type;
    ushort length;
    const(ubyte)[] fragment;

    size_t sequenceNumber;
}

struct TlsCiphertext
{
    enum MAX_LENGTH = 16_640;
    enum HEADER_SIZE = 5;

    static struct InnerPlaintext
    {
        const(ubyte)[] content;
        TlsPlaintext.ContentType type;
    }

    ushort length;
    const(ubyte)[] encryptedRecord;

    size_t sequenceNumber;
}