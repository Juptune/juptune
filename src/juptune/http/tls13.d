/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls13;

import std.traits : isIntegral;

import juptune.core.util   : Result;
import juptune.data.buffer : MemoryWriter, MemoryReader;

/++ Autodecoder UDAs ++/

private struct ExactLength
{
    size_t length;
}

private struct LengthRange(alias OfType_) // NOTE: length is in bytes, as per RFC 8446
{
    alias OfType = OfType_;

    size_t lower;
    size_t upper;
}

private struct ExactValue(ValueT)
{
    ValueT value;
}

private struct OnlyForHandshakeType
{
    TlsHandshake.Type type;
}

private struct RawTlsStruct
{
}

private struct Exempt {}

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

    private template OptionByValueType(alias ValueT)
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

private string tlsSelectIndexString(size_t i)() pure
{
    import std.conv : to;
    return "value_"~i.to!string;
}

/++ Raw TLS types ++/

struct TlsHandshake // It's a bit too annoying to use the auto encoder/decoder for this struct, so it's handled manually.
{
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
    uint length;
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
    const(ubyte)[] extensionData;
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

private struct TlsPlaintext
{
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

private struct TlsCiphertext
{
    enum MAX_LENGTH = 16_640;

    static struct InnerPlaintext
    {
        const(ubyte)[] content;
        TlsPlaintext.ContentType type;
    }

    ushort length;
    const(ubyte)[] encryptedRecord;

    size_t sequenceNumber;
}

/++ Helpers ++/

private uint bytesRequired(const size_t maxSize) @safe @nogc nothrow pure
{
    if(maxSize <= ubyte.max)
        return 1;
    else if(maxSize <= ushort.max)
        return 2;
    else if(maxSize <= UINT24_MAX)
        return 3;
    else if(maxSize <= uint.max)
        return 4;
    else if(maxSize <= ulong.max)
        return 8;
    assert(false);
}

private size_t enumIndexOf(EnumT)(EnumT value) @safe @nogc nothrow pure
{
    import std.traits : EnumMembers;

    switch(value)
    {
        static foreach(i, Member; EnumMembers!EnumT)
        static if(Member.stringof != "MAX" && Member.stringof != "FAILSAFE")
        {
            case Member: return i;
        }

        default: return -1;
    }
}

/++ Other ++/

enum TLS_MAX_RECORD_SIZE = 17_000; // TODO: bother to spend 5 seconds to figure out the exact number
enum TLS_VERSION_12 = 0x0303;
enum TLS_VERSION_13 = 0x0304;
enum UINT24_MAX = 16_777_215;
private enum CANARY = 0xCC;

static immutable ubyte[] TLS_LEGACY_COMPRESSION_METHODS_RAW = [0x00]; // null

static immutable ubyte[] TLS_CLIENTHELLO_INITIAL_EXTENSION_RAW = [
    // Since ClientHello extensions are written in an imperative way, we need
    // to start off with an initial set of bytes.
    //
    // Since some stuff isn't really configurable by the user, they're embedded here.

    // TlsExtension
    0, 43, // Type of supported_versions
    0x00, 0x03, // Length of 3
        // SupportedVersionsClientHello
        0x02, // Length of 2
        0x03, 0x04, // Version of TLS 1.3

    // TlsExtension
    0, 10, // Type of supported_groups
    0x00, 0x04, // Length of 4
        // SupportedGroups
        0x00, 0x02, // Length of 2
        0x00, 0x1D, // NamedGroup.x25519
];

version(Juptune_LibSodium)
{
    static immutable ubyte[] TLS_SUPPORTED_CIPHER_SUITES_RAW = [
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    ];
}
else static assert(false, "No implementation");

enum TlsError
{
    none,

    dataExceedsBuffer,
    notEnoughBytes,
    tooManyBytes,

    exactValueConstraintFailed,
    exactLengthConstraintFailed,
    lengthRangeConstraintFailed,

    handshakeTooLarge,
    extensionTooLarge,
    invalidRecordType,
    invalidRecordVersion,

    alertRecordOverflow,
    alertUnexpectedMessage,
    alertIllegalParameter,
    alertMissingExtension,
    alertBadRecordMac,

    unknownCipherSuite,
}

struct TlsConfig
{
    import core.time : Duration;

    Duration writeTimeout = Duration.zero; /// The default timeout for writing data
    Duration readTimeout = Duration.zero; /// The default timeout for reading data

    @safe @nogc nothrow pure:

    TlsConfig withReadTimeout(Duration v) return { this.readTimeout = v; return this; }
    TlsConfig withWriteTimeout(Duration v) return { this.writeTimeout = v; return this; }
}

struct TlsEncryptionContext
{
    import std.digest.sha : SHA256;
    import juptune.crypto.keyexchange : X25519PublicKey, X25519PrivateKey;
    
    private:

    bool doneClientHello;
    bool doneServerHello;

    SHA256 clientHello_serverHello_sha256;
    SHA256 transcriptHash_sha256;

    ubyte[32] clientHandshakeTrafficSecret_sha256;
    ubyte[32] serverHandshakeTrafficSecret_sha256;

    ubyte[32] masterSecret;

    TlsExtension.NamedGroup negotiatedGroup;
    TlsHandshake.CipherSuite negotiatedCipher;

    X25519PublicKey theirPublicKey;
    X25519PrivateKey ourPrivateKey;
}

/++ Decoding ++/

struct TlsReader(SocketT)
{
    import std.typecons                 : Nullable;
    import juptune.core.util            : StateMachineTypes;
    import juptune.crypto.keyexchange   : X25519PublicKey, X25519PrivateKey;
    import juptune.data.x509            : X509CertificateStore;

    private alias Machine = StateMachineTypes!(State, StateInfo);
    private alias StateMachine = Machine.Static!([
        Machine.Transition(State.waitingToStart, State.serverHello),
        Machine.Transition(State.serverHello, State.encryptedServerHello),
    ]);

    private enum State
    {
        FAILSAFE,
        waitingToStart,
        
        // Client states
        serverHello,
        encryptedServerHello,

        // Special states
        fatalAlert,
    }

    private static struct StateInfo
    {
        Nullable!TlsAlert alert;
        size_t sequenceNumber;
    }

    private
    {
        StateMachine            _state;
        StateInfo               _stateInfo;
        TlsEncryptionContext*   _encryptContext;
        
        TlsConfig    _config;
        SocketT*     _socket;

        MemoryWriter _stagingWriter;
        
        ubyte[] _recordBuffer;
        MemoryReader _recordReader;
    }

    @disable this(this);

    this(
        SocketT* socket, 
        ubyte[] stagingBuffer, 
        ubyte[] recordBuffer,
        TlsEncryptionContext* encryptContext,
        TlsConfig config
    ) @nogc nothrow
    in(stagingBuffer.length > 0, "stagingBuffer cannot be empty")
    in(recordBuffer.length == TLS_MAX_RECORD_SIZE, "recordBuffer must be TLS_MAX_RECORD_SIZE bytes in size")
    in(socket !is null, "socket cannot be null")
    in(encryptContext !is null, "encryptContext cannot be null")
    {
        this._stagingWriter = MemoryWriter(stagingBuffer);
        this._recordBuffer = recordBuffer;
        this._config = config;
        this._socket = socket;
        this._encryptContext = encryptContext;
        this._state = StateMachine(State.waitingToStart);
    }

    Nullable!TlsAlert raisedAlert() @nogc nothrow => this._stateInfo.alert;

    Result readServerHello(
        scope ref X509CertificateStore certStore,
        const X509CertificateStore.SecurityPolicy certSecurityPolicy,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.waitingToStart))
    in(this._encryptContext.doneClientHello, "bug: encryptContext hasn't had its clientHello info set")
    {
        ubyte[32] sharedSecret_sha256;

        auto result = this.readUnencryptedServerHello(sharedSecret_sha256);
        if(result.isError)
            return result;

        result = this.tryReadChangeCipherSpec();
        if(result.isError)
            return result;

        result = this.readEncryptedServerHello(sharedSecret_sha256, certStore, certSecurityPolicy);
        if(result.isError)
            return result;

        return Result.noError;
    }

    /++ Private readers ++/

    private Result readUnencryptedServerHello(
        scope out ubyte[32] sharedSecret_sha256,
    ) @nogc nothrow
    {
        this._state.transition!(State.waitingToStart, State.serverHello)(this._stateInfo);
        
        TlsPlaintext record;
        TlsHandshake header;
        const(ubyte)[] rawMessage;
        auto result = this.nextStartOfHandshake(record, header, rawMessage);
        if(result.isError)
            return result;
        if(header.messageType != TlsHandshake.Type.serverHello)
            return Result.make(TlsError.none, "TODO");

        this._encryptContext.clientHello_serverHello_sha256.put(record.fragment);
        this._encryptContext.transcriptHash_sha256.put(record.fragment);

        // ASSUMPTION: The unencrypted part of ServerHello is contained in a single record, since otherwise it's such a massive faff to deal with
        auto reader = MemoryReader(rawMessage);
        TlsHandshake.ServerHello hello;
        result = autoDecode!(typeof(hello), "ServerHello")(reader, hello);
        if(result.isError)
            return result;
        if(reader.bytesLeft != 0)
            return Result.make(TlsError.tooManyBytes, "not all bytes were read - malformed ServerHello?");

        // Check random for specific values
        if(hello.random == TlsHandshake.ServerHello.HelloRetryRequestRandom)
            assert(false, "TODO:");
        else if(
            hello.random[$-8..$] == TlsHandshake.ServerHello.Tls11Random
            || hello.random[$-8..$] == TlsHandshake.ServerHello.Tls12Random
        )
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.illegal_parameter));
            return Result.make(TlsError.alertIllegalParameter, "server attempted to negotiate TLS 1.2 or below during handshake"); // @suppress(dscanner.style.long_line)
        }

        // Handle unencrypted extensions
        bool foundKeyShare = false;
        bool foundSupportedVersions = false;
        result = this.handleExtensions(TlsHandshake.Type.serverHello, hello.extensions, (scope TlsExtension ext){
            switch(ext.type)
            {
                case TlsExtension.Type.keyShare:
                    foundKeyShare = true;
                    
                    const data = ext.data.keyShare.getValue!(TlsExtension.KeyShareServerHello).serverShare;
                    if(data.group != TlsExtension.NamedGroup.x25519)
                    {
                        this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.illegal_parameter));
                        return Result.make(TlsError.alertIllegalParameter, "ServerHello's key_share didn't select for x25519 (Juptune Limitation)"); // @suppress(dscanner.style.long_line)
                    }

                    this._encryptContext.negotiatedGroup = data.group;
                    auto result = X25519PublicKey.fromCopyingBytes(
                        data.keyExchange,
                        this._encryptContext.theirPublicKey
                    );
                    if(result.isError)
                        return result;
                    break;

                case TlsExtension.Type.supportedVersions:
                    foundSupportedVersions = true;

                    const data = ext.data.supportedVersions.getValue!(TlsExtension.SupportedVersionsServerHello);
                    if(data.selectedVersion != TLS_VERSION_13)
                    {
                        this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.illegal_parameter));
                        return Result.make(TlsError.alertIllegalParameter, "ServerHello's supported_versions extension is not 0x0304 (TLS 1.3)"); // @suppress(dscanner.style.long_line)
                    }
                    break;

                default: break;
            }
            return Result.noError;
        });
        if(result.isError)
            return result;
        if(!foundKeyShare)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.missing_extension));
            return Result.make(TlsError.alertMissingExtension, "ServerHello is missing the key_share extension");
        }
        if(!foundSupportedVersions)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.missing_extension));
            return Result.make(TlsError.alertMissingExtension, "ServerHello is missing the supported_versions extension"); // @suppress(dscanner.style.long_line)
        }
        this._state.transition!(State.serverHello, State.encryptedServerHello)(this._stateInfo);

        // Derive encryption info
        this._encryptContext.negotiatedCipher = hello.cipherSuite;

        result = this._encryptContext.ourPrivateKey.deriveSharedSecret(
            this._encryptContext.theirPublicKey, 
            sharedSecret_sha256
        );
        if(result.isError)
            return result;

        this._encryptContext.doneServerHello = true;
        this.resetStagingBuffer();

        return Result.noError;
    }

    private Result readEncryptedServerHello(
        scope const ref ubyte[32] sharedSecret_sha256,
        scope ref X509CertificateStore certStore,
        const X509CertificateStore.SecurityPolicy certSecurityPolicy,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.encryptedServerHello))
    {
        import juptune.data.x509 : X509Certificate;

        // Compute keys and decrypt the rest of the handshake
        auto result = hkdfHandshakeSecret(
            *this._encryptContext,
            sharedSecret_sha256,
            this._encryptContext.clientHandshakeTrafficSecret_sha256,
            this._encryptContext.serverHandshakeTrafficSecret_sha256
        );
        if(result.isError)
            return result;

        assert(this._encryptContext.negotiatedCipher == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: support more cipher suites");
        import juptune.crypto.aead : AeadIetfChacha20Poly1305;
        ubyte[32] writerKey;
        ubyte[AeadIetfChacha20Poly1305.NONCE_LENGTH] writerIv;
        result = deriveTrafficKeys(
            this._encryptContext.negotiatedCipher,
            this._encryptContext.serverHandshakeTrafficSecret_sha256,
            writerKey,
            writerIv,
        );
        if(result.isError)
            return result;

        this._stateInfo.sequenceNumber = 0; // Since we've now performed a key change

        TlsCiphertext.InnerPlaintext inner; // TODO: MUST handle when the encrypted ServerHello payload is split across multiple records.
        result = this.nextRecordRaw((ciphertext){
            return this.decryptRecord(ciphertext, writerIv[], writerKey[], inner);
        });
        if(result.isError)
            return result;

        // Handle remaining handshake messages
        auto handshakeReader = MemoryReader(inner.content);
        
        int certificateIndex = -1;
        int certificateVerifyIndex = -1;
        int finishedIndex = -1;
        int currentIndex = 0;

        X509Certificate peerCert;

        while(handshakeReader.bytesLeft > 0)
        {
            scope(exit) currentIndex++;

            TlsHandshake handshake;
            const(ubyte)[] rawMessage;
            const start = handshakeReader.cursor;

            result = this.parseTlsHandshake(handshakeReader, handshake, rawMessage);
            if(result.isError)
                return result;

            switch(handshake.messageType) with(TlsHandshake.Type)
            {
                case encryptedExtensions:
                    // TODO:
                    this._encryptContext.transcriptHash_sha256.put(inner.content[start..handshakeReader.cursor]);
                    break;

                case certificateRequest:
                    // TODO:
                    break;

                case certificate:
                    TlsHandshake.Certificate handshakeCert;
                    auto reader = MemoryReader(rawMessage);
                    result = autoDecode!(typeof(handshakeCert), "Certificate")(reader, handshakeCert);
                    if(result.isError)
                        return result;
                    if(reader.bytesLeft > 0)
                        return Result.make(TlsError.tooManyBytes, "when decoding Certificate message - not all bytes were read"); // @suppress(dscanner.style.long_line)

                    bool isFirst = true;
                    reader = MemoryReader(handshakeCert.certificateList);
                    result = certStore.validateChainFromCopyingDerBytes(
                        (scope out const(ubyte)[] derBytes, scope out bool keepGoing){
                            if(reader.bytesLeft == 0)
                            {
                                keepGoing = false;
                                return Result.noError;
                            }

                            TlsHandshake.Certificate.Entry entry;
                            result = autoDecode!(typeof(entry), "CertificateEntry")(reader, entry);
                            if(result.isError)
                                return result;
                            keepGoing = true;
                            derBytes = entry.data;

                            if(isFirst) // TODO: It's a bit annoying we have to parse the first cert twice - maybe CertificateStore could have a more friendly way of doing this sort of stuff?
                            {
                                import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;
                                import juptune.data.x509.asn1convert : x509FromAsn1;
                                import juptune.data.asn1.decode.bcd.encoding 
                                    : Asn1ComponentHeader, asn1DecodeComponentHeader, asn1ReadContentBytes,
                                    Asn1Ruleset;

                                isFirst = false;

                                auto derMem = MemoryReader(derBytes);
                                
                                Asn1ComponentHeader header;
                                result = asn1DecodeComponentHeader!(Asn1Ruleset.der)(derMem, header);
                                if(result.isError)
                                    return result;

                                Certificate asn1Cert;
                                result = asn1Cert.fromDecoding!(Asn1Ruleset.der)(derMem, header.identifier);
                                if(result.isError)
                                    return result;

                                result = x509FromAsn1(asn1Cert, peerCert);
                                if(result.isError)
                                    return result;
                            }

                            return Result.noError;
                        },
                        certSecurityPolicy,
                        reverseChain: true
                    );
                    if(result.isError)
                        return result;

                    certificateIndex = currentIndex;
                    this._encryptContext.transcriptHash_sha256.put(inner.content[start..handshakeReader.cursor]);
                    break;

                case certificateVerify:
                    auto transcriptHashCopy = this._encryptContext.transcriptHash_sha256;
                    const transcriptHash = transcriptHashCopy.finish();

                    TlsHandshake.CertificateVerify verify;
                    auto reader = MemoryReader(rawMessage);
                    result = autoDecode!(typeof(verify), "CertificateVerify")(reader, verify);
                    if(result.isError)
                        return result;
                    if(reader.bytesLeft > 0)
                        return Result.make(TlsError.tooManyBytes, "when decoding CertificateVerify message - not all bytes were read"); // @suppress(dscanner.style.long_line)

                    assert(false, "THIS IS TODO");

                    certificateVerifyIndex = currentIndex;
                    this._encryptContext.transcriptHash_sha256.put(inner.content[start..handshakeReader.cursor]);
                    break;

                default: break;
            }
        }
        assert(certificateIndex != -1, "TODO: handle gracefully");
        assert(certificateVerifyIndex != -1, "TODO: handle gracefully");
        assert(finishedIndex != -1, "TODO: handle gracefully");

        return Result.noError;
    }

    private Result tryReadChangeCipherSpec() @nogc nothrow
    {
        // TODO: Peek the record first to double check if it's there.

        TlsPlaintext cipherSpec;
        auto result = this.nextRecord(cipherSpec);
        if(result.isError)
            return result;
        assert(cipherSpec.type == TlsPlaintext.ContentType.changeCipherSpec);
        this.resetStagingBuffer();
        return Result.noError;
    }

    /++ Helpers ++/

    private Result handleExtensions(HandlerT)(
        TlsHandshake.Type messageType,
        scope const(ubyte)[] rawExtensions, 
        scope HandlerT handler,
    ) @nogc nothrow
    {
        auto reader = MemoryReader(rawExtensions);
        long typeMask;

        while(reader.bytesLeft > 0)
        {
            ushort type;
            ushort dataLength;

            auto success = reader.readU16BE(type);
            if(!success)
                return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading extension type");
            success = reader.readU16BE(dataLength);
            if(!success)
                return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading extension data length");

            const(ubyte)[] data;
            success = reader.readBytes(dataLength, data);
            if(!success)
                return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading extension data");

            const typeIndex = 1 << enumIndexOf(cast(TlsExtension.Type)type);
            if(typeIndex != -1)
            {
                if((typeMask & typeIndex) != 0)
                {
                    this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.unexpected_message));
                    return Result.make(TlsError.alertUnexpectedMessage, "message contains a duplicate extension - this is not allowed"); // @suppress(dscanner.style.long_line)
                }
                typeMask |= typeIndex;
            }

            TlsExtension tlsExt;
            tlsExt.type = cast(TlsExtension.Type)type;
            tlsExt.extensionData = data;

            auto extResult = Result.noError;
            ExtensionT autoDecodeExt(ExtensionT)()
            {
                import std.traits : getUDAs;

                alias AllowedUdas = getUDAs!(ExtensionT, OnlyForHandshakeType);
                bool allowed = false;
                static foreach(Allowed; AllowedUdas)
                {
                    if(messageType == Allowed.type)
                        allowed = true;
                }
                if(!allowed)
                {
                    extResult = Result.make(TlsError.alertIllegalParameter, "extension "~ExtensionT.stringof~" is not allowed to appear under the current handshake message type"); // @suppress(dscanner.style.long_line)
                    return ExtensionT.init;
                }

                auto dataReader = MemoryReader(data);

                ExtensionT ext;
                auto result = autoDecode!(ExtensionT, ExtensionT.stringof)(dataReader, ext);
                if(result.isError)
                {
                    extResult = result;
                    return ExtensionT.init;
                }

                if(dataReader.bytesLeft != 0)
                {
                    extResult = Result.make(TlsError.tooManyBytes, "not all bytes were read - malformed extension?");
                    return ExtensionT.init;
                }
                return ext;
            }

            switch(type) with(TlsExtension.Type)
            {
                case FAILSAFE: assert(false, "bug: FAILSAFE");
                
                case keyShare:
                    tlsExt.data.keyShare = TlsExtension.KeyShare();
                    if(messageType == TlsHandshake.Type.serverHello)
                        tlsExt.data.keyShare.set(messageType, autoDecodeExt!(TlsExtension.KeyShareServerHello));
                    else
                    {
                        this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.illegal_parameter));
                        return Result.make(TlsError.alertIllegalParameter, "extension key_share is not allowed to appear under the current handshake message type"); // @suppress(dscanner.style.long_line)
                    }
                    break;

                case supportedVersions:
                    tlsExt.data.supportedVersions = TlsExtension.SupportedVersions();
                    if(messageType == TlsHandshake.Type.serverHello)
                        tlsExt.data.supportedVersions.set(messageType, autoDecodeExt!(TlsExtension.SupportedVersionsServerHello)); // @suppress(dscanner.style.long_line)
                    else
                    {
                        this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.illegal_parameter));
                        return Result.make(TlsError.alertIllegalParameter, "extension supported_versions is not allowed to appear under the current handshake message type"); // @suppress(dscanner.style.long_line)
                    }
                    break;
                
                case serverName: assert(false, "TODO: Implement serverName");
                case maxFragmentLength: assert(false, "TODO: Implement maxFragmentLength");
                case statusRequest: assert(false, "TODO: Implement statusRequest");
                case supportedGroups: assert(false, "TODO: Implement supportedGroups");
                case signatureAlgorithms: assert(false, "TODO: Implement signatureAlgorithms");
                case useSrtp: assert(false, "TODO: Implement useSrtp");
                case heartbeat: assert(false, "TODO: Implement heartbeat");
                case applicationLayerProtocolNegotiation: assert(false, "TODO: Implement applicationLayerProtocolNegotiation");
                case signedCertificateTimestampt: assert(false, "TODO: Implement signedCertificateTimestampt");
                case clientCertificateType: assert(false, "TODO: Implement clientCertificateType");
                case serverCertificateType: assert(false, "TODO: Implement serverCertificateType");
                case padding: assert(false, "TODO: Implement padding");
                case RESERVED40: assert(false, "TODO: Implement RESERVED40");
                case preSharedKey: assert(false, "TODO: Implement preSharedKey");
                case earlyData: assert(false, "TODO: Implement earlyData");
                case cookie: assert(false, "TODO: Implement cookie");
                case pskKeyExchangeModes: assert(false, "TODO: Implement pskKeyExchangeModes");
                case RESERVED46: assert(false, "TODO: Implement RESERVED46");
                case certificateAuthorities: assert(false, "TODO: Implement certificateAuthorities");
                case oidFilters: assert(false, "TODO: Implement oidFilters");
                case postHandshakeAuth: assert(false, "TODO: Implement postHandshakeAuth");
                case signatureAlgorithmsCert: assert(false, "TODO: Implement signatureAlgorithmsCert");
                
                default: continue; // TODO: Maybe I should pass unknown extensions through still?
            }

            if(extResult.isError)
                return extResult;

            auto result = handler(tlsExt);
            if(result.isError)
                return result;
        }
        
        assert(reader.bytesLeft == 0, "bug: not all bytes were read, and no error was produced?");
        return Result.noError;
    }

    private Result nextStartOfHandshake(
        out scope TlsPlaintext record,
        out scope TlsHandshake handshake,
        out scope const(ubyte)[] rawMessage,
    ) @nogc nothrow
    {
        import juptune.core.ds : String2;

        this._state.mustBeIn(State.serverHello);

        auto result = this.nextRecord(record);
        if(result.isError)
            return result;

        if(record.type != TlsPlaintext.ContentType.handshake)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.unexpected_message));
            return Result.make(
                TlsError.alertUnexpectedMessage, 
                "when expecting message of type handshake, recieved message of different type instead",
                String2("message was of type ", record.type)
            );
        }

        auto reader = MemoryReader(record.fragment);
        
        result = this.parseTlsHandshake(reader, handshake, rawMessage);
        if(result.isError)
            return result;
        if(reader.bytesLeft > 0)
            return Result.make(TlsError.tooManyBytes, "memory reader still has bytes left - malformed record?");

        return Result.noError;
    }

    private Result parseTlsHandshake(
        scope ref MemoryReader reader,
        out scope TlsHandshake handshake,
        out scope const(ubyte)[] rawMessage,
    ) @nogc nothrow
    {
        import std.traits : EnumMembers;
        
        ubyte type;
        uint length;

        auto success = reader.readU8(type);
        if(!success)
            return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading handshake message type");
        success = reader.readU24BE(length);
        if(!success)
            return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading handshake message length");

        TypeSwitch: switch(type)
        {
            static foreach(Member; EnumMembers!(TlsHandshake.Type))
            static if(
                !is(Member == TlsHandshake.Type.MAX)
                && !is(Member == TlsHandshake.Type.FAILSAFE)
                && !is(Member == TlsHandshake.Type.helloRetryRequest)
            )
            {
                case Member: handshake.messageType = Member; break TypeSwitch;
            }
            
            default:
                return Result.make(TlsError.invalidRecordType, "Handshake message contains an unknown/invalid type"); // @suppress(dscanner.style.long_line)
        }
        handshake.length = length;

        success = reader.readBytes(length, rawMessage);
        if(!success)
            return Result.make(TlsError.notEnoughBytes, "ran out of bytes when reading handshake message value");

        return Result.noError;
    }

    private void enterAlertState(TlsAlert alert) @nogc nothrow
    {
        this._state = StateMachine(State.fatalAlert); // fatalAlert has no valid transitions
        this._stateInfo.alert = alert;
    }

    /++ Record handling ++/

    private Result nextRecord(out scope TlsPlaintext record) @nogc nothrow
    {
        import std.traits : EnumMembers;
        import juptune.core.ds : String2;

        enum PLAINTEXT_HEADER_BYTE_COUNT = 5; // 1 for type; 2 for version; 2 for fragment length

        if(this._recordReader.bytesLeft < PLAINTEXT_HEADER_BYTE_COUNT)
        {
            size_t _;
            auto result = this.fetchRecordData(_);
            if(result.isError)
                return result;
            if(this._recordReader.bytesLeft < PLAINTEXT_HEADER_BYTE_COUNT)
                return Result.make(TlsError.notEnoughBytes, "when fetching data for TlsPlaintext header, expected at least 5 bytes to be available, but got less than that"); // @suppress(dscanner.style.long_line)
        }

        ubyte type;
        ushort version_;
        ushort fragmentLength;

        auto success = this._recordReader.readU8(type);
        assert(success, "bug: success shouldn't be able to be false here?");
        success = this._recordReader.readU16BE(version_);
        assert(success, "bug: success shouldn't be able to be false here?");
        success = this._recordReader.readU16BE(fragmentLength);
        assert(success, "bug: success shouldn't be able to be false here?");

        TypeSwitch: switch(type)
        {
            static foreach(Member; EnumMembers!(TlsPlaintext.ContentType))
            static if(
                !is(Member == TlsPlaintext.ContentType.MAX)
                && !is(Member == TlsPlaintext.ContentType.invalid)
            )
            {
                case Member: record.type = Member; break TypeSwitch;
            }
            
            default:
                return Result.make(TlsError.invalidRecordType, "TlsPlaintext record contains an unknown/invalid content type"); // @suppress(dscanner.style.long_line)
        }
        if(version_ != TLS_VERSION_12)
            return Result.make(TlsError.invalidRecordVersion, "TlsPlaintext record contains an invalid version field - it MUST be 0x0303 when using TLS 1.3"); // @suppress(dscanner.style.long_line)
        if(fragmentLength > TlsPlaintext.MAX_LENGTH)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.record_overflow));
            return Result.make(TlsError.alertRecordOverflow, "TlsPlaintext record contains a payload greater than 2^14 in length"); // @suppress(dscanner.style.long_line)
        }
        record.length = fragmentLength;

        if(this._recordReader.bytesLeft < record.length)
        {
            size_t _;
            auto result = this.fetchRecordData(_);
            if(result.isError)
                return result;
            if(this._recordReader.bytesLeft < record.length)
            {
                return Result.make(
                    TlsError.notEnoughBytes,
                    "when reading TlsPlaintext record fragment, unable to fetch enough bytes to match specified length",
                    String2("specified length is ", record.length, " however only ", this._recordReader.bytesLeft, " bytes are available after reading from socket") // @suppress(dscanner.style.long_line)
                );
            }
        }

        const(ubyte)[] fragment;
        success = this._recordReader.readBytes(record.length, fragment);
        assert(success, "bug: success shouldn't be able to be false here?");

        const start = this._stagingWriter.cursor;
        success = this._stagingWriter.tryBytes(fragment);
        if(!success)
            return Result.make(TlsError.dataExceedsBuffer, "when moving record data into staging buffer - ran out of staging buffer space"); // @suppress(dscanner.style.long_line)
        record.fragment = this._stagingWriter.buffer[start..this._stagingWriter.cursor];

        record.sequenceNumber = this._stateInfo.sequenceNumber++;
        this.compactRecordFrom(this._recordReader.cursor);
        return Result.noError;
    }

    private Result nextRecordRaw(scope Result delegate(TlsCiphertext) @nogc nothrow handle) @nogc nothrow
    {
        import std.traits : EnumMembers;
        import juptune.core.ds : String2;

        enum CIPHERTEXT_HEADER_BYTE_COUNT = 5; // 1 for type; 2 for version; 2 for encrypted length

        if(this._recordReader.bytesLeft < CIPHERTEXT_HEADER_BYTE_COUNT)
        {
            size_t _;
            auto result = this.fetchRecordData(_);
            if(result.isError)
                return result;
            if(this._recordReader.bytesLeft < CIPHERTEXT_HEADER_BYTE_COUNT)
                return Result.make(TlsError.notEnoughBytes, "when fetching data for TlsCiphertext header, expected at least 5 bytes to be available, but got less than that"); // @suppress(dscanner.style.long_line)
        }

        ubyte type;
        ushort version_;
        ushort fragmentLength;

        auto success = this._recordReader.readU8(type);
        assert(success, "bug: success shouldn't be able to be false here?");
        success = this._recordReader.readU16BE(version_);
        assert(success, "bug: success shouldn't be able to be false here?");
        success = this._recordReader.readU16BE(fragmentLength);
        assert(success, "bug: success shouldn't be able to be false here?");

        if(type != TlsPlaintext.ContentType.applicationData)
            return Result.make(TlsError.invalidRecordType, "TlsCiphertext record is not set to applicationData");
        if(version_ != TLS_VERSION_12)
            return Result.make(TlsError.invalidRecordVersion, "TlsCiphertext record contains an invalid version field - it MUST be 0x0303 when using TLS 1.3"); // @suppress(dscanner.style.long_line)
        if(fragmentLength > TlsCiphertext.MAX_LENGTH)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.record_overflow));
            return Result.make(TlsError.alertRecordOverflow, "TlsCiphertext record contains a payload greater than 2^14 + 256 in length"); // @suppress(dscanner.style.long_line)
        }

        TlsCiphertext record;
        record.length = fragmentLength;
        record.sequenceNumber = this._stateInfo.sequenceNumber++;

        if(this._recordReader.bytesLeft < record.length)
        {
            size_t _;
            auto result = this.fetchRecordData(_);
            if(result.isError)
                return result;
            if(this._recordReader.bytesLeft < record.length)
            {
                return Result.make(
                    TlsError.notEnoughBytes,
                    "when reading TlsCiphertext record encrypted_record, unable to fetch enough bytes to match specified length", // @suppress(dscanner.style.long_line)
                    String2("specified length is ", record.length, " however only ", this._recordReader.bytesLeft, " bytes are available after reading from socket") // @suppress(dscanner.style.long_line)
                );
            }
        }

        success = this._recordReader.readBytes(record.length, record.encryptedRecord);
        assert(success, "bug: success shouldn't be able to be false here?");

        auto result = handle(record);
        if(result.isError)
            return result;

        this.compactRecordFrom(this._recordReader.cursor);
        return Result.noError;
    }

    private Result decryptRecord(
        TlsCiphertext text, 
        scope const ubyte[] writerIv, 
        scope const ubyte[] writerKey,
        scope out TlsCiphertext.InnerPlaintext inner,
    ) @nogc nothrow
    {
        import juptune.crypto.aead : AeadIetfChacha20Poly1305, AeadEncryptionContext;

        assert(this._encryptContext.negotiatedCipher == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: support other cipher suites"); // @suppress(dscanner.style.long_line)
        
        // Setup nonce
        ubyte[AeadIetfChacha20Poly1305.NONCE_LENGTH] nonce;
        auto writer = MemoryWriter(nonce[$-8..$]);
        auto success = writer.putU64BE(text.sequenceNumber);
        assert(success);
        foreach(i, ref byte_; nonce)
            byte_ ^= writerIv[i];

        // Setup additional data
        ubyte[1 + 2 + 2] additionalData; // opaque_type + legacy_record_version + length
        additionalData[0] = TlsPlaintext.ContentType.applicationData;
        additionalData[1] = 0x03;
        additionalData[2] = 0x03;
        writer = MemoryWriter(additionalData[3..5]);
        success = writer.putU16BE(text.length);
        assert(success);

        // Decrypt into the record buffer
        // (I'm still not sure if it's a fluke or an intended feature that crypto_aead_chacha20poly1305_ietf_decrypt can decrypt in-place)
        // TODO: I think juptune.crypto.aead needs a refactor, since it tries to take control of the nonce (and uses SecureMemory - which is really annoying to deal with in regards to ulimits).
        //       Generally the attack vector of memory being scanned on the local machine is not considered by Juptune, and I think that's for the best (for my sanity, not for security).
        import juptune.crypto.libsodium 
            : 
                crypto_aead_chacha20poly1305_ietf_decrypt,
                crypto_aead_chacha20poly1305_ietf_keybytes,
                crypto_aead_chacha20poly1305_ietf_npubbytes,
                crypto_aead_chacha20poly1305_ietf_abytes
            ;
        assert(nonce.length == crypto_aead_chacha20poly1305_ietf_npubbytes());
        assert(writerKey.length == crypto_aead_chacha20poly1305_ietf_keybytes());

        // size_t length = this._stagingWriter.bytesLeft;
        size_t length = text.encryptedRecord.length;
        if(length < text.encryptedRecord.length - crypto_aead_chacha20poly1305_ietf_abytes())
            return Result.make(TlsError.dataExceedsBuffer, "when preparing to decrypt TlsCiphertext into staging buffer - not enough bytes left"); // @suppress(dscanner.style.long_line)

        const ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            // &this._stagingWriter.buffer[this._stagingWriter.cursor],
            cast(ubyte*)&text.encryptedRecord[0],
            &length, // NOTE: value gets overwritten
            null,
            &text.encryptedRecord[0],
            text.encryptedRecord.length,
            &additionalData[0],
            additionalData.length,
            &nonce[0],
            &writerKey[0],
        );
        if(ret == -1)
        {
            this.enterAlertState(TlsAlert(TlsAlert.Level.fatal, TlsAlert.Description.bad_record_mac));
            return Result.make(TlsError.alertBadRecordMac, "failed to decrypt TlsCipher text data");
        }
        if(length == 0)
            assert(false, "TODO: handle this");

        // Figure out where the padding is, then move fill out the TlsInnerplaintext struct
        // There's _surely_ a better way to do this, right?
        const innerPlaintext = text.encryptedRecord[0..length];
        ptrdiff_t lastSetByte = cast(ptrdiff_t)innerPlaintext.length - 1;
        for(; lastSetByte > -1; lastSetByte--)
        {
            if(innerPlaintext[lastSetByte] != 0)
                break;
        }
        assert(lastSetByte > 0, "TODO: handle this");

        const start = this._stagingWriter.cursor;
        success = this._stagingWriter.tryBytes(innerPlaintext[0..lastSetByte]);
        if(!success)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of bytes when moving decrypted TlsInnerplaintext into staging buffer"); // @suppress(dscanner.style.long_line)

        inner.type = cast(TlsPlaintext.ContentType)innerPlaintext[lastSetByte];
        inner.content = this._stagingWriter.buffer[start..this._stagingWriter.cursor];

        switch(inner.type) with(TlsPlaintext.ContentType)
        {
            case invalid, MAX:
            default:
                return Result.make(TlsError.invalidRecordType, "TlsInnerplaintext has an invalid content type");

            case changeCipherSpec, alert, handshake, applicationData:
                break;
        }

        return Result.noError;
    }

    /++ I/O handling ++/

    private Result fetchRecordData(out size_t bytesFetched) @nogc nothrow
    {
        const cursor = this._recordReader.buffer.length;
        if(cursor >= this._recordBuffer.length)
            return Result.make(TlsError.dataExceedsBuffer, "attempted to fetch record data while buffer is full - in-process record is too large for the provided buffer"); // @suppress(dscanner.style.long_line)

        void[] got;
        auto result = this._socket.recieve(this._recordBuffer[cursor..$], got, this._config.readTimeout); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        bytesFetched = got.length;
        this._recordReader = MemoryReader(this._recordBuffer[0..cursor + got.length], this._recordReader.cursor);
        return Result.noError;
    }

    private void compactRecordFrom(size_t cursor) @nogc nothrow
    in(cursor <= this._recordReader.cursor, "bug: cursor must be behind the read cursor")
    {
        size_t newLength;
        foreach(i, b; this._recordReader.buffer[cursor..$])
        {
            this._recordBuffer[i] = b;
            newLength++;
        }
        this._recordReader = MemoryReader(this._recordBuffer[0..newLength], this._recordReader.cursor - cursor);
    }

    private void resetStagingBuffer() @nogc nothrow
    {
        this._stagingWriter.cursor = 0;
    }
}

private Result autoDecode(T, string DebugName, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(is(T == struct))
{
    import std.traits : getUDAs;
    static assert(getUDAs!(T, RawTlsStruct).length != 0, "struct of type "~T.stringof~" cannot be autodecoded as it is missing @RawTlsStruct"); // @suppress(dscanner.style.long_line)

    static foreach(i, field; T.tupleof)
    {{
        enum IsExempt = getUDAs!(field, Exempt).length > 0;
        static if(!IsExempt)
        {
            auto result = autoDecode!(
                typeof(field),
                DebugName~"."~__traits(identifier, field),
                __traits(getAttributes, field)
            )(
                reader, 
                mixin("value.", __traits(identifier, field))
            );
            if(result.isError)
                return result;
        }
    }}

    return Result.noError;
}

private Result autoDecode(T, string DebugName, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out const(ubyte)[] value,
)
if(is(T == const(ubyte)[]))
{
    import juptune.core.ds : String2;

    // I may add extra UDAs in the future that aren't the "main UDA" but modify decoding logic in some way.
    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactLength))
        {
            alias MainUda = Uda;
        }
        else static if(is(typeof(Uda) == LengthRange!_, _))
        {
            alias MainUda = Uda;
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    static if(is(typeof(MainUda) == ExactLength))
    {
        auto success = reader.readBytes(MainUda.length, value);
        if(!success)
        {
            return Result.make(
                TlsError.notEnoughBytes,
                "[ExactLength] ran out of bytes while reading value of "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String2("expected length of ", MainUda.length, " but got length of ", reader.bytesLeft)
            );
        }
    }
    else static if(is(typeof(MainUda) == LengthRange!ElementT, ElementT))
    {
        enum lengthByteCount = bytesRequired(MainUda.upper);
        static if(lengthByteCount == 1)
        {
            ubyte length;
            auto success = reader.readU8(length);
        }
        else static if(lengthByteCount == 2)
        {
            ushort length;
            auto success = reader.readU16BE(length);
        }
        else static if(lengthByteCount == 3)
        {
            uint length;
            auto success = reader.readU24BE(length);
        }
        else static if(lengthByteCount == 4)
        {
            ulong length;
            auto success = reader.readU32BE(length);
        }
        else static assert(false, "Invalid value for lengthByteCount");

        if(!success)
            return Result.make(TlsError.notEnoughBytes, "ran out of bytes while reading length for field "~DebugName~" when autodecoding"); // @suppress(dscanner.style.long_line)

        if(length < MainUda.lower)
        {
            return Result.make(
                TlsError.lengthRangeConstraintFailed,
                "expected at least a certain amount of bytes for field "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String2("expected minimum length of ", MainUda.lower, " but got length of ", length)
            );
        }
        if(length > MainUda.upper)
        {
            return Result.make(
                TlsError.lengthRangeConstraintFailed,
                "expected at most a certain amount of bytes for field "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String2("expected maximum length of ", MainUda.lower, " but got length of ", length)
            );
        }

        static if(!is(ElementT == struct) && ElementT.sizeof > 1)
        {
            if(length % ElementT.sizeof != 0)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a size that's a multiple of "~ElementT.stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                    String2("expected length that is a multiple of ", ElementT.sizeof, " but got length of ", length) // @suppress(dscanner.style.long_line)
                );
            }
        }

        success = reader.readBytes(length, value);
        if(!success)
        {
            return Result.make(
                TlsError.exactLengthConstraintFailed,
                "[LengthRange] ran out of bytes while reading value of "~DebugName~" of type "~typeof(value).stringof~" when autodecoding", // @suppress(dscanner.style.long_line)
                String2("expected length of ", length, " but got length of ", reader.bytesLeft)
            );
        }
    }
    else
    {
        pragma(msg, "UNHANDLED: ", MainUda);
        static assert(false, "bug: Unhandled main constraint UDA");
    }

    return Result.noError;
}

private Result autoDecode(T, string DebugName, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(isIntegral!T && !is(T == enum))
{
    import std.bitmanip : Endian;
    import juptune.core.ds : String2;

    auto success = reader.tryIntegral!(T, Endian.bigEndian, true)(value);
    if(!success)
        return Result.make(TlsError.notEnoughBytes, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactValue!ValueT, ValueT))
        {
            static assert(is(ValueT == T));
            if(value != Uda.value)
            {
                return Result.make(
                    TlsError.exactValueConstraintFailed,
                    "expected field "~DebugName~" of type "~T.stringof~" to be a specific value when autodecoding",
                    String2("expected value of ", Uda.value, " but got value of ", value)
                );
            }
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    return Result.noError;
}

private Result autoDecode(T, string DebugName, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(isIntegral!T && is(T == enum))
{
    import std.traits : EnumMembers;

    enum lengthByteCount = bytesRequired(T.MAX);
    static if(lengthByteCount == 1)
    {
        ubyte rawValue;
        auto success = reader.readU8(rawValue);
    }
    else static if(lengthByteCount == 2)
    {
        ushort rawValue;
        auto success = reader.readU16BE(rawValue);
    }
    else static if(lengthByteCount == 3)
    {
        uint rawValue;
        auto success = reader.readU24BE(rawValue);
    }
    else static if(lengthByteCount == 4)
    {
        uint rawValue;
        auto success = reader.readU32BE(rawValue);
    }
    else static assert(false, "Invalid value for lengthByteCount");
    if(!success)
        return Result.make(TlsError.notEnoughBytes, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    Switch:switch(rawValue)
    {
        static foreach(Member; EnumMembers!T)
        static if(!is(Member == T.FAILSAFE) && !is(Member == T.MAX))
        {
            case Member: value = Member; break Switch;
        }

        default:
            return Result.make(
                TlsError.alertIllegalParameter, 
                "unknown/invalid value when reading enum field "~DebugName~" of type "~T.stringof~" when autodecoding"
            );
    }

    return Result.noError;
}

private Result autoDecode(T, string DebugName, FieldUdas...)(
    scope ref MemoryReader reader,
    scope out T value,
)
if(__traits(isStaticArray, T) && is(typeof(T.init[0]) == ubyte))
{
    import std.traits : EnumMembers;
    import juptune.core.ds : String2;

    const(ubyte)[] bytes;
    auto success = reader.readBytes(value.length, bytes);
    if(!success)
        return Result.make(TlsError.notEnoughBytes, "ran out of bytes while reading field "~DebugName~" of type "~T.stringof~" when autodecoding"); // @suppress(dscanner.style.long_line)

    static foreach(Uda; FieldUdas)
    {
        pragma(msg, "UNHANDLED: ", Uda);
        static assert(false, "bug: Unhandled constraint UDA");
    }

    static if(is(T == enum))
    {
        value = T.unknown;

        static foreach(Member; EnumMembers!T)
        static if(!is(Member == T.FAILSAFE))
        {{
            static immutable StaticInstanceOfMember = Member;
            if(bytes == StaticInstanceOfMember)
                value = StaticInstanceOfMember;
        }}
    }
    else
        value = bytes;
    return Result.noError;
}

/++ Encoding ++/

struct TlsWriter(SocketT)
{
    import juptune.core.util : StateMachineTypes;
    import juptune.crypto.keyexchange : X25519PrivateKey;

    private alias Machine = StateMachineTypes!(State, StateInfo);
    private alias StateMachine = Machine.Static!([
        Machine.Transition(State.waitingToStart, State.clientHello),
        Machine.Transition(State.clientHello, State.waitingForServerHelloInfo),
    ]);

    private enum State
    {
        FAILSAFE,
        waitingToStart,

        // Client states
        clientHello,
        waitingForServerHelloInfo,
    }

    private static struct StateInfo
    {
        size_t sequenceNumber;

        size_t recordLengthPointer = size_t.max;
        size_t handshakeLengthPointer = size_t.max;
        size_t extensionLengthPointer = size_t.max;
        size_t subExtensionLengthPointer = size_t.max; // Some extensions also support their own extensions!
    }

    private
    {
        StateMachine            _state;
        StateInfo               _stateInfo;
        TlsEncryptionContext*   _encryptContext;
        
        TlsConfig    _config;
        SocketT*     _socket;

        MemoryWriter _stagingWriter;
        MemoryWriter _recordWriter;
    }

    @disable this(this);

    this(
        SocketT* socket, 
        ubyte[] stagingBuffer, 
        ubyte[] recordBuffer, 
        TlsEncryptionContext* encryptContext,
        TlsConfig config
    ) @nogc nothrow
    in(stagingBuffer.length > 0, "stagingBuffer cannot be empty")
    in(recordBuffer.length == TLS_MAX_RECORD_SIZE, "recordBuffer must be TLS_MAX_RECORD_SIZE bytes in size")
    in(socket !is null, "socket cannot be null")
    in(encryptContext !is null, "encryptContext cannot be null")
    {
        this._stagingWriter = MemoryWriter(stagingBuffer);
        this._recordWriter = MemoryWriter(recordBuffer);
        this._config = config;
        this._socket = socket;
        this._encryptContext = encryptContext;
        this._state = StateMachine(State.waitingToStart);
    }

    Result startClientHello() @nogc nothrow
    in(this._state.mustBeIn(State.waitingToStart))
    in(this._stagingWriter.cursor == 0, "bug: the staging writer hasn't been reset?")
    in(!this._encryptContext.doneClientHello, "bug: encryption context already has clientHello information?")
    {
        import juptune.crypto.rng : cryptoFillBuffer;
        this._state.mustTransition!(State.waitingToStart, State.clientHello)(this._stateInfo);

        with(this._stagingWriter)
        {
            auto success = putU8(TlsHandshake.Type.clientHello);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing TlsHandshake type"); // @suppress(dscanner.style.long_line)

            this._stateInfo.handshakeLengthPointer = this._stagingWriter.cursor;
            success = putU24BE((CANARY << 16) | (CANARY << 8) | CANARY);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing TlsHandshake length"); // @suppress(dscanner.style.long_line)

            ubyte[32] handshakeRandom;
            cryptoFillBuffer(handshakeRandom);

            TlsHandshake.ClientHello clientHello;
            clientHello.legacyVersion = TLS_VERSION_12;
            clientHello.random = handshakeRandom;
            clientHello.cipherSuites = TLS_SUPPORTED_CIPHER_SUITES_RAW;
            clientHello.legacyCompressionMethods = TLS_LEGACY_COMPRESSION_METHODS_RAW;
            clientHello.extensions = TLS_CLIENTHELLO_INITIAL_EXTENSION_RAW;

            auto result = autoEncode!(typeof(clientHello), "ClientHello")(this._stagingWriter, clientHello);
            if(result.isError)
                return result;

            this._stateInfo.extensionLengthPointer = this._stagingWriter.cursor - clientHello.extensions.length - 2; // - 2 since this length uses 2 bytes.

            result = this.putKeyShareClientHello();
            if(result.isError)
                return result;

            result = this.putSignatureAlgorithmsClientHello();
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    Result putServerName(scope const(char)[] sni) @nogc nothrow
    in(this._state.mustBeIn(State.clientHello))
    {
        return this.putTlsExtension(TlsExtension.Type.serverName, (){
            return this.putVector!(ushort.max-1, "ServerNameList.server_name_list")((){
                TlsExtension.ServerName sniEntry;
                sniEntry.nameType = TlsExtension.ServerName.NameType.host_name;
                sniEntry.hostName = cast(const(ubyte)[])sni;
                return autoEncode!(typeof(sniEntry), "ServerName")(this._stagingWriter, sniEntry);
            });
        });
    }

    Result finishClientHello() @nogc nothrow
    in(this._state.mustBeIn(State.clientHello))
    {
        this._state.mustTransition!(State.clientHello, State.waitingForServerHelloInfo)(this._stateInfo);

        auto result = this.updateLengthInStagingBuffer!(
            UINT24_MAX,
            "updating TlsHandshake length",
            TlsError.handshakeTooLarge, "ClientHello's payload is larger than uint24.max",
        )(
            this._stateInfo.handshakeLengthPointer,
            from: this._stateInfo.handshakeLengthPointer + 3, // + 3 to skip the length bytes
            to: this._stagingWriter.cursor,
        );
        if(result.isError)
            return result;

        result = this.updateLengthInStagingBuffer!(
            ushort.max-1,
            "updating ClientHello's extension length",
            TlsError.handshakeTooLarge, "ClientHello's extension payload is larger than ushort.max-1",
        )(
            this._stateInfo.extensionLengthPointer,
            from: this._stateInfo.extensionLengthPointer + 2, // + 2 to skip the length bytes
            to: this._stagingWriter.cursor,
        );
        if(result.isError)
            return result;

        this._encryptContext.clientHello_serverHello_sha256.put(this._stagingWriter.usedBuffer);
        this._encryptContext.transcriptHash_sha256.put(this._stagingWriter.usedBuffer);
        this._encryptContext.doneClientHello = true;

        result = this.putFragmentedPlaintextRecords(
            TlsPlaintext.ContentType.handshake, 
            this._stagingWriter.usedBuffer
        );
        if(result.isError)
            return result;

        this._stagingWriter.cursor = 0;
        return Result.noError;
    }

    Result withEcdheServerHelloInfo() @nogc nothrow
    in(this._state.mustBeIn(State.waitingForServerHelloInfo))
    {
        assert(false, "TODO: Implement");
    }

    /++ Private putters ++/

    private Result putTlsExtension(
        TlsExtension.Type type,
        scope Result delegate() @nogc nothrow putBody
    ) @nogc nothrow
    {
        with(this._stagingWriter)
        {
            auto success = putU16BE(cast(ushort)type);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing TlsExtention type"); // @suppress(dscanner.style.long_line)

            const pointer = cursor;
            success = putU16BE(0xCCCC);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing TlsExtention dummy length"); // @suppress(dscanner.style.long_line)

            auto result = putBody();
            if(result.isError)
                return result;

            result = this.updateLengthInStagingBuffer!(
                ushort.max-1,
                "updating TlsExtension length",
                TlsError.extensionTooLarge, "TlsExtension's payload is larger than ushort.max-1"
            )(
                pointer,
                from: pointer + 2, // + 2 to skip the length bytes
                to: cursor
            );
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    private Result putVector(
        size_t maxLength,
        string debugContext,
    )(
        scope Result delegate() @nogc nothrow putBody
    )
    {
        with(this._stagingWriter)
        {
            const pointer = cursor;

            enum lengthByteCount = bytesRequired(maxLength);
            static if(lengthByteCount == 1)
                auto success = putU8(cast(ubyte)0xCC);
            else static if(lengthByteCount == 2)
                auto success = putU16BE(cast(ushort)0xCCCC);
            else static if(lengthByteCount == 3)
                auto success = putU24BE(cast(uint)0xCCCCCC);
            else static if(lengthByteCount == 4)
                auto success = putU32BE(cast(uint)0xCCCCCCCC);
            else static assert(false, "Invalid value for lengthByteCount");
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing vector "~debugContext~" dummy length"); // @suppress(dscanner.style.long_line)

            auto result = putBody();
            if(result.isError)
                return result;

            result = this.updateLengthInStagingBuffer!(
                maxLength,
                "updating vector "~debugContext~" length",
                TlsError.extensionTooLarge, "vector "~debugContext~"'s payload is larger than TODO"
            )(
                pointer,
                from: pointer + lengthByteCount,
                to: cursor
            );
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    private Result putKeyShareClientHello() @nogc nothrow
    {
        auto result = X25519PrivateKey.generate(this._encryptContext.ourPrivateKey);
        if(result.isError)
            return result;

        ubyte[32] x25519PublicKey;
        result = this._encryptContext.ourPrivateKey.getPublicKey(x25519PublicKey[]);
        if(result.isError)
            return result;

        TlsExtension.KeyShareEntry x25519Entry;
        x25519Entry.group = TlsExtension.NamedGroup.x25519;
        x25519Entry.keyExchange = x25519PublicKey[];

        return this.putTlsExtension(TlsExtension.Type.keyShare, (){
            return this.putVector!(ushort.max-1, "KeyShareClientHello.client_shares")((){
                return autoEncode!(typeof(x25519Entry), "KeyShareEntry")(this._stagingWriter, x25519Entry);
            });
        });
    }

    private Result putSignatureAlgorithmsClientHello() @nogc nothrow
    {
        return this.putTlsExtension(TlsExtension.Type.signatureAlgorithms, (){
            return this.putVector!(ushort.max-2, "SignatureSchemeList.supported_signature_algorithms")((){
                static foreach(algorithm; [
                    TlsHandshake.SignatureScheme.rsa_pkcs1_sha256,
                    TlsHandshake.SignatureScheme.rsa_pkcs1_sha384,
                    TlsHandshake.SignatureScheme.rsa_pkcs1_sha512,
                    TlsHandshake.SignatureScheme.ecdsa_secp256r1_sha256,
                    TlsHandshake.SignatureScheme.ecdsa_secp384r1_sha384,
                    TlsHandshake.SignatureScheme.ecdsa_secp521r1_sha512,
                    TlsHandshake.SignatureScheme.ed448,
                    TlsHandshake.SignatureScheme.ed25519,
                    TlsHandshake.SignatureScheme.rsa_pss_pss_sha256,
                    TlsHandshake.SignatureScheme.rsa_pss_pss_sha384,
                    TlsHandshake.SignatureScheme.rsa_pss_pss_sha512,
                    TlsHandshake.SignatureScheme.rsa_pss_rsae_sha256,
                    TlsHandshake.SignatureScheme.rsa_pss_rsae_sha384,
                    TlsHandshake.SignatureScheme.rsa_pss_rsae_sha512,
                ])
                {{
                    auto success = this._stagingWriter.putU16BE(algorithm);
                    if(!success)
                        return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing SignatureSchemeList entry"); // @suppress(dscanner.style.long_line)
                }}

                return Result.noError;
            });
        });
    }
    
    /++ Helpers ++/

    private Result updateLengthInStagingBuffer(
        size_t maxLength,
        string dataExceededContext,
        TlsError tooLargeError,
        string tooLargeMessage,
    )(
        size_t pointer, 
        size_t from, 
        size_t to
    )
    in(from <= to, "from is greater than to")
    {
        const length = to - from;
        if(length > maxLength)
            return Result.make(tooLargeError, tooLargeMessage);
        
        enum lengthByteCount = bytesRequired(maxLength);
        auto lengthWriter = MemoryWriter(this._stagingWriter.usedBuffer[pointer..pointer + lengthByteCount]); // @suppress(dscanner.style.long_line)
        
        static if(lengthByteCount == 1)
            auto success = lengthWriter.putU8(cast(ubyte)length);
        else static if(lengthByteCount == 2)
            auto success = lengthWriter.putU16BE(cast(ushort)length);
        else static if(lengthByteCount == 3)
            auto success = lengthWriter.putU24BE(cast(uint)length);
        else static if(lengthByteCount == 4)
            auto success = lengthWriter.putU32BE(cast(uint)length);
        else static assert(false, "Invalid value for lengthByteCount");

        if(!success)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when "~dataExceededContext); // @suppress(dscanner.style.long_line)

        return Result.noError;
    }

    /++ Record handling ++/

    private Result putFragmentedPlaintextRecords(TlsPlaintext.ContentType type, scope const(ubyte)[] data) @nogc nothrow
    in(data.length > 0, "bug: data.length is 0")
    {
        import std.algorithm : min;

        while(data.length > 0)
        {
            const length = min(data.length, TlsPlaintext.MAX_LENGTH);

            TlsPlaintext record;
            record.type = type;
            record.length = cast(ushort)length;
            record.fragment = data[0..length];

            auto result = this.putRecord(record);
            if(result.isError)
                return result;

            data = data[length..$];
        }

        return Result.noError;
    }

    private Result putRecord(const TlsPlaintext record) @nogc nothrow
    in(this._recordWriter.cursor == 0, "bug: the recordWriter hasn't been reset?")
    in(record.length <= TlsPlaintext.MAX_LENGTH, "bug: record.length is too large")
    in(record.length == record.fragment.length)
    {
        with(this._recordWriter)
        {
            auto success = putU8(cast(ubyte)record.type);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of record buffer space when writing TlsPlaintext type"); // @suppress(dscanner.style.long_line)

            success = putU16BE(TLS_VERSION_12);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of record buffer space when writing TlsPlaintext legacy version"); // @suppress(dscanner.style.long_line)

            success = putU16BE(record.length);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of record buffer space when writing TlsPlaintext length"); // @suppress(dscanner.style.long_line)

            success = tryBytes(record.fragment);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of record buffer space when writing TlsPlaintext fragment"); // @suppress(dscanner.style.long_line)

            auto result = this._socket.put(this._recordWriter.usedBuffer, this._config.writeTimeout);
            if(result.isError)
                return result;
            
            this._recordWriter.cursor = 0;
        }

        this._stateInfo.sequenceNumber++;
        return Result.noError;
    }
}

private Result autoEncode(T, string DebugName, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const ref T value,
)
if(is(T == struct))
{
    import std.traits : getUDAs;
    static assert(getUDAs!(T, RawTlsStruct).length != 0, "struct of type "~T.stringof~" cannot be autoencoded as it is missing @RawTlsStruct"); // @suppress(dscanner.style.long_line)

    static foreach(i, field; T.tupleof)
    {{
        enum IsExempt = getUDAs!(field, Exempt).length > 0;
        static if(!IsExempt)
        {
            auto result = autoEncode!(
                typeof(field),
                DebugName~"."~__traits(identifier, field),
                __traits(getAttributes, field)
            )(
                writer, 
                mixin("value.", __traits(identifier, field))
            );
            if(result.isError)
                return result;
        }
    }}

    return Result.noError;
}

private Result autoEncode(T, string DebugName, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const ubyte[] value,
)
if(is(T == const(ubyte)[]))
{
    import juptune.core.ds : String2;

    static foreach(Uda; FieldUdas)
    {
        static if(is(typeof(Uda) == ExactLength))
        {
            if(value.length != Uda.length)
            {
                return Result.make(
                    TlsError.exactLengthConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a specific length",
                    String2("expected length of ", Uda.length, " but got length of ", value.length)
                );
            }
        }
        else static if(is(typeof(Uda) == LengthRange!ElementT, ElementT))
        {{
            if(value.length < Uda.lower)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be at least a certain size",
                    String2("expected minimum length of ", Uda.lower, " but got length of ", value.length)
                );
            }
            if(value.length > Uda.upper)
            {
                return Result.make(
                    TlsError.lengthRangeConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be at most a certain size",
                    String2("expected maximum length of ", Uda.lower, " but got length of ", value.length)
                );
            }

            static if(!is(ElementT == struct) && ElementT.sizeof > 1)
            {
                if(value.length % ElementT.sizeof != 0)
                {
                    return Result.make(
                        TlsError.lengthRangeConstraintFailed,
                        "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a size that's a multiple of "~ElementT.stringof, // @suppress(dscanner.style.long_line)
                        String2("expected length that is a multiple of ", ElementT.sizeof, " but got length of ", value.length) // @suppress(dscanner.style.long_line)
                    );
                }
            }

            enum BytesForLength = bytesRequired(Uda.upper);
            static if(BytesForLength == 1)
                auto success = writer.putU8(cast(ubyte)value.length);
            else static if(BytesForLength == 2)
                auto success = writer.putU16BE(cast(ushort)value.length);
            else static if(BytesForLength == 4)
                auto success = writer.putU32BE(cast(uint)value.length);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing "~DebugName~" length"); // @suppress(dscanner.style.long_line)
        }}
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }

    if(value.length > 0)
    {
        auto success = writer.tryBytes(value);
        if(!success)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing "~DebugName~" content"); // @suppress(dscanner.style.long_line)
    }

    return Result.noError;
}

private Result autoEncode(T, string DebugName, FieldUdas...)(
    scope ref MemoryWriter writer,
    scope const T value,
)
if(isIntegral!T)
{
    import juptune.core.ds     : String2;
    import juptune.data.buffer : Endian;

    static foreach(Uda; FieldUdas)
    {{
        static if(is(typeof(Uda) == ExactValue!_, _))
        {
            if(value != Uda.value)
            {
                return Result.make(
                    TlsError.exactValueConstraintFailed,
                    "expected field "~DebugName~" of type "~typeof(value).stringof~" to be a specific value",
                    String2("expected value of ", Uda.value, " but got value of ", value)
                );
            }
        }
        else
        {
            pragma(msg, "UNHANDLED: ", Uda);
            static assert(false, "bug: Unhandled constraint UDA");
        }
    }}

    const success = writer.tryIntegral!(T, Endian.bigEndian)(value);
    if(!success)
        return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing "~DebugName); // @suppress(dscanner.style.long_line)

    return Result.noError;
}

/++ HKDF ++/

private immutable HKDF_EXPAND_LABEL_PREFIX = "tls13 ";

private Result hkdfExpandLabel(
    TlsHandshake.CipherSuite cipherSuite,
    scope ubyte[] outKey,
    scope const(char)[] label,
    scope const(ubyte)[] context,
    scope const(ubyte)[] masterKey,
) @nogc nothrow
in(outKey.length <= ushort.max, "outKey is too large")
in(label.length >= 1, "label must not be empty")
in(label.length <= (255 - HKDF_EXPAND_LABEL_PREFIX.length), "label is too large")
in(context.length <= 255, "context is too large")
{
    import juptune.crypto.hkdf : hkdfExpandSha256;

    ubyte[514] buffer;
    auto writer = MemoryWriter(buffer[]);

    bool success;
    success = writer.putU16BE(cast(ushort)outKey.length);
    success = writer.putU8(cast(ubyte)(HKDF_EXPAND_LABEL_PREFIX.length + label.length)) && success;
    success = writer.tryBytes(cast(const(ubyte)[])HKDF_EXPAND_LABEL_PREFIX) && success;
    success = writer.tryBytes(cast(const(ubyte)[])label) && success;
    success = writer.putU8(cast(ubyte)context.length) && success;
    if(context.length > 0)
        success = writer.tryBytes(context) && success;
    assert(success, "bug: success shouldn't be able to be false here?");

    auto hkdfLabel = writer.usedBuffer;
    if(cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
    {
        assert(masterKey.length == 32, "masterKey must be 32 bytes long when using a SHA256 cipher suite");
        return hkdfExpandSha256(outKey, hkdfLabel, masterKey[0..32]);
    }
    else
        return Result.make(TlsError.unknownCipherSuite, "cannot perform HKDF using unknown cipher suite");
}

private Result hkdfHandshakeSecret(
    scope ref TlsEncryptionContext encryptContext,
    scope ref const(ubyte)[32] sharedSecret,
    scope out ubyte[32] clientHandshakeTrafficSecret,
    scope out ubyte[32] serverHandshakeTrafficSecret,
) @nogc nothrow
in(encryptContext.doneClientHello, "doneClientHello must be true")
in(encryptContext.doneServerHello, "doneServerHello must be true")
in(encryptContext.clientHello_serverHello_sha256 != typeof(encryptContext.clientHello_serverHello_sha256).init)
{
    import std.digest.sha : SHA256;
    import juptune.crypto.hkdf : hkdfExtractSha256;

    const cipherSuite = encryptContext.negotiatedCipher;
    assert(cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: Support non-SHA256 cipher suites"); // @suppress(dscanner.style.long_line)

    ubyte[32] salt;
    ubyte[32] psk;

    //              0
    //              |
    //              v
    //    PSK ->  HKDF-Extract = Early Secret
    ubyte[32] earlySecret;
    auto result = hkdfExtractSha256(earlySecret, salt, psk);
    if(result.isError)
        return result;

    //         Early Secret
    //              |
    //              v
    // Derive-Secret(., "derived", "")
    const emptySha = SHA256().finish();
    result = hkdfExpandLabel(cipherSuite, salt, "derived", emptySha, earlySecret);
    if(result.isError)
        return result;
    earlySecret[] = 0;

    //                ^^ Derived ^^
    //                      |
    //                      v
    // (EC)DHE -> HKDF-Extract = Handshake Secret
    ubyte[32] handshakeSecret;
    result = hkdfExtractSha256(handshakeSecret, salt, sharedSecret);
    if(result.isError)
        return result;

    psk = encryptContext.clientHello_serverHello_sha256.finish();
    // --> Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello) = client_handshake_traffic_secret
        result = hkdfExpandLabel(
            cipherSuite, 
            clientHandshakeTrafficSecret, 
            "c hs traffic", 
            psk, 
            handshakeSecret
        );
        if(result.isError)
            return result;

    // --> Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello) = server_handshake_traffic_secret
        result = hkdfExpandLabel(
            cipherSuite, 
            serverHandshakeTrafficSecret, 
            "s hs traffic", 
            psk, 
            handshakeSecret
        );
        if(result.isError)
            return result;

    //       Handshake Secret
    //              |
    //              v
    // Derive-Secret(., "derived", "")
    result = hkdfExpandLabel(cipherSuite, earlySecret, "derived", emptySha, handshakeSecret); // NOTE: reusing the earlySecret buffer
    if(result.isError)
        return result;
    handshakeSecret[] = 0;

    //            ^^ Derived ^^
    //                  |
    //                  v
    // 0 -> HKDF-Extract = Master Secret
    result = hkdfExtractSha256(encryptContext.masterSecret, earlySecret, emptySha);
    if(result.isError)
        return result;

    return Result.noError;
}

private Result deriveTrafficKeys(
    TlsHandshake.CipherSuite cipherSuite,
    scope const(ubyte)[] secret,
    scope ubyte[] outKey,
    scope ubyte[] outIv,
) @nogc nothrow
{
    auto result = hkdfExpandLabel(cipherSuite, outKey, "key", null, secret);
    if(result.isError)
        return result;

    return hkdfExpandLabel(cipherSuite, outIv, "iv", null, secret);
}

debug unittest
{
    import juptune.event.io : TcpSocket;
    alias Reader = TlsReader!TcpSocket;
    alias Writer = TlsWriter!TcpSocket;

    import juptune.core.util : resultAssert;
    import juptune.event;
    import juptune.data.x509;

    import std.exception;
    import std.file : readText;

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread((){
        // TcpSocket client;
        // client.open().resultAssert;

        // bool _;
        // client.connect("142.250.129.138", _, 443).resultAssert;

        // TlsEncryptionContext encryptContext;

        // X509CertificateStore certStore;
        // certStore.loadBundleFromPem(
        //     readText("/etc/ssl/ca-bundle.pem").assumeWontThrow,
        //     ignoreAsn1DecodingErrors: true,
        //     hasImplicitTrust: true
        // ).resultAssert;

        // auto policy = X509CertificateStore.SecurityPolicy().withAllowSelfSignedChain(false);

        // auto writer = Writer(&client, new ubyte[1024 * 32], new ubyte[TLS_MAX_RECORD_SIZE], &encryptContext, TlsConfig());
        // writer.startClientHello().resultAssert;
        // writer.putServerName("www.google.com").resultAssert;
        // writer.finishClientHello().resultAssert;

        // auto reader = Reader(&client, new ubyte[1024 * 32], new ubyte[TLS_MAX_RECORD_SIZE], &encryptContext, TlsConfig());
        // reader.readServerHello(certStore, policy).resultAssert;
    });
    loop.join();
    // assert(false);
}