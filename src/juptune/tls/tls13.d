/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.tls.tls13;

/**** TLS Protocol Descriptors ****/

private struct TLS13Vector // uda: T[]
{
    size_t floor;
    size_t ceiling; // inclusive
}

private struct TLS13Enum // uda: enum
{
}

private template TLS13Constant(alias Value_) // uda: struct member
{
    enum Value = Value_;
}

private struct TLS13Is24Bit // uda: uint
{
}

private struct TLS13Struct // uda: struct
{
}

private template TLS13LengthRef(alias LengthMember_) // uda: struct member
{
    alias LengthMember = LengthMember_;
}

private template TLS13SelectRef(alias SelectMember_) // uda: struct member
{
    alias SelectMember = SelectMember_;
}

private struct TLS13Variant(alias VariantSelectEnumT_, alias VariantUnionT_)
{
    // Forward template params for ease of access
    alias VariantSelectEnumT = VariantSelectEnumT_;
    alias VariantUnionT = VariantUnionT_;

    private template EnumValueFor(alias UnionMember)
    {
        alias EnumValueFor = noreturn;
        static foreach(uda; __traits(getAttributes, UnionMember))
            static if(is(typeof(uda)) && is(typeof(uda) == VariantSelectEnumT))
                EnumValueFor = uda;
        static assert(!is(EnumValueFor == noreturn), "Could not correlate union member to enum value");
    }

    private template UnionMemberFor(alias ValueT)
    {
        alias UnionMemberFor = noreturn;
        static foreach(memberName; __traits(allMembers, VariantUnionT))
            static if(is(typeof(__traits(getMember, VariantUnionT, memberName)) == ValueT))
                UnionMemberFor = __traits(getMember, VariantUnionT, memberName);
        static assert(!is(UnionMemberFor == noreturn), "Could not correlate value to union member");
    }

    private
    {
        VariantSelectEnumT _select;
        VariantUnionT _value;
        bool _isSet;
    }

    @safe @nogc nothrow:

    void select(VariantSelectEnumT select)
    in(!this._isSet, "Variant type already selected")
    {
        this._select = select;
        this._isSet = true;
    }

    VariantSelectEnumT selectedType() const
    in(this._isSet, "Variant type not selected")
    {
        return this._select;
    }

    bool selected(VariantSelectEnumT select) const
    {
        return this._isSet && this._select == select;
    }

    bool selected(alias ValueT)() const
    {
        return this._isSet && this._select == EnumValueFor!(UnionMemberFor!ValueT);
    }

    ref ValueT get(alias ValueT)() @trusted
    in(selectedType() == EnumValueFor!(UnionMemberFor!ValueT), "The selected variant type does not match the requested type") // @suppress(dscanner.style.long_line)
    {
        return mixin("this._value."~__traits(identifier, UnionMemberFor!ValueT));
    }
}

/**** TLS Protocol Helpers ****/

private template TLS13BytesNeeded(MaxDecimalValue)
{
    enum BytesNeeded = 
        MaxDecimalValue <= 0xFF              ? 1 : 
        MaxDecimalValue <= 0xFFFF            ? 2 :
        MaxDecimalValue <= 0xFFFFFF          ? 3 :
        MaxDecimalValue <= 0xFFFFFFFF        ? 4 :
        MaxDecimalValue <= 0xFFFFFFFFFF      ? 5 :
        MaxDecimalValue <= 0xFFFFFFFFFFFF    ? 6 :
        MaxDecimalValue <= 0xFFFFFFFFFFFFFF  ? 7 :
        8;
}

/**** TLS Common Types ****/

private alias TLS13ProtocolVersion = ushort;
private alias TLS13Random = ubyte[32];
private struct TLS13Opaque { ubyte value; alias value this; }
private struct TLS13Empty {}
private enum TLS13_LEGACY_VERSION = 0x0303; // TLS 1.2

private enum TLS13CipherSuite : ubyte[2]
{
    TLS_AES_128_GCM_SHA256 = [0x13, 0x01],
    TLS_AES_256_GCM_SHA384 = [0x13, 0x02],
    TLS_CHACHA20_POLY1305_SHA256 = [0x13, 0x03],
    TLS_AES_128_CCM_SHA256 = [0x13, 0x04],
    TLS_AES_128_CCM_8_SHA256 = [0x13, 0x05],
}

/**** TLS Record Layer Types (https://datatracker.ietf.org/doc/html/rfc8446#autoid-91) ****/

@TLS13Enum
private enum TLS13ContentType : ubyte
{
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24, /* RFC 6520 */
    _MAX = 255
}

@TLS13Struct
private struct TLS13Plaintext
{
    TLS13ContentType type;
    TLS13ProtocolVersion legacyRecordVersion;
    ushort length;

    @TLS13LengthRef!(TLS13Plaintext.length)
    TLS13Opaque[] fragment;
}

@TLS13Struct
private struct TLS13InnerPlaintext
{
    @TLS13LengthRef!(TLS13Plaintext.length)
    TLS13Opaque[] content;

    TLS13ContentType type;

    @TLS13LengthRef!noreturn // "length_of_padding"
    ubyte[] zeros;
}

@TLS13Struct
private struct TLS13Ciphertext
{
    @TLS13Constant!(TLS13ContentType.application_data)
    TLS13ContentType opaqueType = TLS13ContentType.application_data;
    
    @TLS13Constant!(TLS13_LEGACY_VERSION)
    TLS13ProtocolVersion legacyRecordVersion = TLS13_LEGACY_VERSION;

    ushort length;

    @TLS13LengthRef!(TLS13Ciphertext.length)
    TLS13Opaque[] encryptedRecord;
}

/**** TLS Alert Message Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2) ****/

@TLS13Enum
private enum TLS13AlertLevel : ubyte
{
    warning = 1,
    fatal = 2,
    _MAX = 255
}

@TLS13Enum
private enum TLS13AlertDescription : ubyte
{
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation_RESERVED = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable_RESERVED = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value_RESERVED = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _MAX = 255
}

@TLS13Struct
private struct TLS13Alert
{
    TLS13AlertLevel level;
    TLS13AlertDescription description;
}

/**** TLS Handshake Protocol Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3) ****/

@TLS13Enum
private enum TLS13HandshakeType : ubyte
{
    hello_request_RESERVED = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request_RESERVED = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request_RESERVED = 6,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange_RESERVED = 12,
    certificate_request = 13,
    server_hello_done_RESERVED = 14,
    certificate_verify = 15,
    client_key_exchange_RESERVED = 16,
    finished = 20,
    certificate_url_RESERVED = 21,
    certificate_status_RESERVED = 22,
    supplemental_data_RESERVED = 23,
    key_update = 24,
    message_hash = 254,
    _MAX = 255
}

@TLS13Struct
private struct TLS13Handshake
{
    TLS13HandshakeType msgType;

    @TLS13Is24Bit
    uint length;

    private union U
    {
        @(TLS13HandshakeType.client_hello)
        TLS13ClientHello clientHello;

        @(TLS13HandshakeType.server_hello)
        TLS13ServerHello serverHello;

        @(TLS13HandshakeType.end_of_early_data)
        TLS13EndOfEarlyData endOfEarlyData;

        @(TLS13HandshakeType.encrypted_extensions)
        TLS13EncryptedExtensions encryptedExtensions;

        @(TLS13HandshakeType.certificate_request)
        TLS13CertificateRequest certificateRequest;

        @(TLS13HandshakeType.certificate)
        TLS13Certificate certificate;

        @(TLS13HandshakeType.certificate_verify)
        TLS13CertificateVerify certificateVerify;

        @(TLS13HandshakeType.finished)
        TLS13Finished finished;

        @(TLS13HandshakeType.new_session_ticket)
        TLS13NewSessionTicket newSessionTicket;

        @(TLS13HandshakeType.key_update)
        TLS13KeyUpdate keyUpdate;
    }
    @TLS13SelectRef!(TLS13Handshake.msgType)
    TLS13Variant!(TLS13HandshakeType, U) msg;
}

/**** TLS Key Exchange Messages (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1) ****/

@TLS13Enum
private enum TLS13PskKeyExchangeMode : ubyte
{
    psk_ke = 0,
    psk_dhe_ke = 1,
    _MAX = 255
}

@TLS13Enum
private enum TLS13ExtensionType : ushort
{
    server_name = 0,                             /* RFC 6066 */
    max_fragment_length = 1,                     /* RFC 6066 */
    status_request = 5,                          /* RFC 6066 */
    supported_groups = 10,                       /* RFC 8422, 7919 */
    signature_algorithms = 13,                   /* RFC 8446 */
    use_srtp = 14,                               /* RFC 5764 */
    heartbeat = 15,                              /* RFC 6520 */
    application_layer_protocol_negotiation = 16, /* RFC 7301 */
    signed_certificate_timestamp = 18,           /* RFC 6962 */
    client_certificate_type = 19,                /* RFC 7250 */
    server_certificate_type = 20,                /* RFC 7250 */
    padding = 21,                                /* RFC 7685 */
    RESERVED = 40,                               /* Used but never assigned */
    pre_shared_key = 41,                         /* RFC 8446 */
    early_data = 42,                             /* RFC 8446 */
    supported_versions = 43,                     /* RFC 8446 */
    cookie = 44,                                 /* RFC 8446 */
    psk_key_exchange_modes = 45,                 /* RFC 8446 */
    RESERVED2 = 46,                               /* Used but never assigned */
    certificate_authorities = 47,                /* RFC 8446 */
    oid_filters = 48,                            /* RFC 8446 */
    post_handshake_auth = 49,                    /* RFC 8446 */
    signature_algorithms_cert = 50,              /* RFC 8446 */
    key_share = 51,                              /* RFC 8446 */
    _MAX = 65_535
}

@TLS13Struct
private struct TLS13Extension
{
    TLS13ExtensionType extensionType;

    @TLS13Vector(2, (1 << 16) - 1)
    TLS13Opaque[] extensionData;
}

@TLS13Struct
private struct TLS13ClientHello
{
    @TLS13Constant!TLS13_LEGACY_VERSION
    TLS13ProtocolVersion legacyVersion = TLS13_LEGACY_VERSION;

    TLS13Random random;

    @TLS13Vector(0, 32)
    TLS13Opaque[] legacySessionId;

    @TLS13Vector(2, (1 << 16) - 2)
    TLS13CipherSuite[] cipherSuites;

    @TLS13Vector(1, (1 << 8) - 1)
    TLS13Opaque[] legacyCompressionMethods;

    @TLS13Vector(2, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

@TLS13Struct
private struct TLS13ServerHello
{
    @TLS13Constant!TLS13_LEGACY_VERSION
    TLS13ProtocolVersion legacyVersion = TLS13_LEGACY_VERSION;

    TLS13Random random;

    @TLS13Vector(0, 32)
    TLS13Opaque[] legacySessionId;

    TLS13CipherSuite cipherSuite;

    ubyte legacyCompressionMethod;

    @TLS13Vector(6, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

@TLS13Struct
private struct TLS13KeyShareEntry
{
    TLS13NamedGroup group;

    @TLS13Vector(1, (1 << 16) - 1)
    TLS13Opaque[] key_exchange;
}

@TLS13Struct
private struct TLS13KeyShareClientHello
{
    @TLS13Vector(0, (1 << 16) - 1)
    TLS13KeyShareEntry[] clientShares;
}

@TLS13Struct
private struct TLS13KeyShareHelloRetryRequest
{
    TLS13NamedGroup selectedGroup;
}

@TLS13Struct
private struct TLS13KeyShareServerHello
{
    TLS13KeyShareEntry serverShare;
}

@TLS13Struct
private struct TLS13UncompressedPointRepresentation
{
    @TLS13Constant!4
    uint legacyForm = 4;

    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8.2

    @TLS13LengthRef!noreturn
    TLS13Opaque[] X;

    @TLS13LengthRef!noreturn
    TLS13Opaque[] Y;
}

@TLS13Struct
private struct TLS13PskKeyExchangeModes
{
    @TLS13Vector(1, 255)
    TLS13PskKeyExchangeMode[] keModes;
}

@TLS13Struct
private struct TLS13EarlyDataIndication
{
    private union U
    {
        @(TLS13HandshakeType.new_session_ticket)
        uint maxEarlyDataSize;

        @(TLS13HandshakeType.client_hello)
        TLS13Empty empty1;

        @(TLS13HandshakeType.encrypted_extensions)
        TLS13Empty empty2;
    }
    @TLS13SelectRef!(TLS13Handshake.msgType)
    TLS13Variant!(TLS13HandshakeType, U) value;
}

@TLS13Struct
private struct TLS13PskIdentity
{
    @TLS13Vector(1, (1 << 16) - 1)
    TLS13Opaque[] identity;

    uint obfuscatedTicketAge;
}

@TLS13Struct
private struct TLS13PskBinderEntry
{
    @TLS13Vector(32, 255)
    TLS13Opaque[] binder;
}

@TLS13Struct
private struct TLS13OfferedPsks
{
    @TLS13Vector(7, (1 << 16) - 1)
    TLS13PskIdentity[] identities;

    @TLS13Vector(33, (1 << 16) - 1)
    TLS13PskBinderEntry[] binders;
}

@TLS13Struct
private struct TLS13PreSharedKeyExtension
{
    private union U
    {
        @(TLS13HandshakeType.client_hello)
        TLS13OfferedPsks offeredPsks;

        @(TLS13HandshakeType.server_hello)
        uint selectedIdentity;
    }
    @TLS13SelectRef!(TLS13Handshake.msgType)
    TLS13Variant!(TLS13HandshakeType, U) value;
}

/**** TLS Version Extension Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.1) ****/

@TLS13Struct
private struct TLS13SupportedVersions
{
    private union U
    {
        @(TLS13HandshakeType.client_hello)
        @TLS13Vector(2, 254)
        TLS13ProtocolVersion[] versions;

        @(TLS13HandshakeType.server_hello)
        TLS13ProtocolVersion selectedVersion;
    }
    @TLS13SelectRef!(TLS13Handshake.msgType)
    TLS13Variant!(TLS13HandshakeType, U) value;
}

/**** TLS Cookie Extension Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.2) ****/

@TLS13Struct
private struct TLS13Cookie
{
    @TLS13Vector(1, (1 << 16) - 1)
    TLS13Opaque[] cookie;
}

/**** TLS Signature Algorithms Extension Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3) ****/

@TLS13Enum
private enum TLS13SignatureScheme : ushort
{
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    ed25519 = 0x0807,
    ed448 = 0x0808,

    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,

    _MAX = 0xffff,
}

@TLS13Struct
private struct TLS13SignatureSchemeList
{
    @TLS13Vector(2, (1 << 16) - 2)
    TLS13SignatureScheme[] supportedSignatureAlgorithms;
}

/**** TLS Supported Groups Extension Types (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.4) ****/

@TLS13Enum
private enum TLS13NamedGroup : ushort
{
    unallocated_RESERVED = 0x0000,

    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,

    x25519 = 0x001d,
    x448 = 0x001e,

    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    _MAX = 0xffff,
}

@TLS13Struct
private struct TLS13NamedGroupList
{
    @TLS13Vector(2, (1 << 16) - 1)
    TLS13NamedGroup[] namedGroupList;
}

/**** Server Parameters Messages (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.2) ****/

private struct PostHandshakeAuth {}

@TLS13Struct
private struct TLS13DistinguishedName
{
    @TLS13Vector(1, (1 << 16) - 1)
    TLS13Opaque[] value;
}

@TLS13Struct
private struct TLS13OIDFilter
{
    @TLS13Vector(1, (1 << 8) - 1)
    TLS13Opaque[] certificateExtensionOID;

    @TLS13Vector(0, (1 << 16) - 1)
    TLS13Opaque[] certificateExtensionValues;
}

@TLS13Struct
private struct TLS13OIDFilterExtension
{
    @TLS13Vector(0, (1 << 16) - 1)
    TLS13OIDFilter[] filters;
}

@TLS13Struct
private struct TLS13EncryptedExtensions
{
    @TLS13Vector(0, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

@TLS13Struct
private struct TLS13CertificateRequest
{
    @TLS13Vector(0, (1 << 8) - 1)
    TLS13Opaque[] certificateRequestContext;

    @TLS13Vector(2, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

/**** Authentication Messages (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.3) ****/

@TLS13Enum
private enum TLS13CertificateType
{
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
    _MAX = 255,
}

@TLS13Struct
private struct TLS13CertificateEntry
{
    private union U
    {
        @(TLS13CertificateType.RawPublicKey)
        @TLS13Vector(1, (1 << 24) - 1)
        TLS13Opaque[] ASN1_subjectPublicKeyInfo; /* From RFC 7250 ASN.1_subjectPublicKeyInfo */ // @suppress(dscanner.style.phobos_naming_convention)

        @(TLS13CertificateType.X509)
        @TLS13Vector(1, (1 << 24) - 1)
        TLS13Opaque[] certData;
    }
    @TLS13SelectRef!noreturn // "certificate_type"
    TLS13Variant!(TLS13CertificateType, U) data;

    @TLS13Vector(0, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

@TLS13Struct
private struct TLS13Certificate
{
    @TLS13Vector(0, (1 << 8) - 1)
    TLS13Opaque[] certificateRequestContext;

    @TLS13Vector(0, (1 << 24) - 1)
    TLS13CertificateEntry[] certificateList;
}

@TLS13Struct
private struct TLS13CertificateVerify
{
    TLS13SignatureScheme algorithm;

    @TLS13Vector(0, (1 << 16) - 1)
    TLS13Opaque[] signature;
}

@TLS13Struct
private struct TLS13Finished
{
    @TLS13LengthRef!noreturn // "Hash.length"
    TLS13Opaque[] verifyData;
}

/**** Ticket Establishment (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.4) ****/

@TLS13Struct
private struct TLS13NewSessionTicket
{
    uint ticketLifetime;
    uint ticketAgeAdd;

    @TLS13Vector(0, 255)
    TLS13Opaque[] ticketNonce;

    @TLS13Vector(1, (1 << 16) - 1)
    TLS13Opaque[] ticket;

    @TLS13Vector(0, (1 << 16) - 1)
    TLS13Extension[] extensions;
}

/**** Updating Keys (https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.5) ****/

enum KeyUpdateRequest : ubyte
{
    update_not_requested = 0,
    update_requested = 1,
    _MAX = 255
}

@TLS13Struct
private struct TLS13EndOfEarlyData {}

@TLS13Struct
private struct TLS13KeyUpdate
{
    KeyUpdateRequest requestUpdate;
}

/**** Unittests ****/

version(unittest)
{
    private enum TestEnum
    {
        FAILSAFE,
        anInt,
        aString,
    }

    private union TestUnion
    {
        @(TestEnum.anInt)
        int anInt;

        @(TestEnum.aString)
        string aString;
    }

    private alias TestVariant = TLS13Variant!(TestEnum, TestUnion);
}

@("TLS13Variant - Unselected")
unittest
{
    import std.exception : assertThrown;

    TestVariant v;
    assertThrown!Error(v.get!int);
    assert(!v.selected(TestEnum.anInt));
}

@("TLS13Variant - Selected Get Mismatch Errors")
unittest
{
    import std.exception : assertThrown;

    TestVariant v;
    v.select(TestEnum.anInt);
    assertThrown!Error(v.get!string);
    assert(!v.selected(TestEnum.aString) && !v.selected!(string));
    assert(v.selected(TestEnum.anInt) && v.selected!(int));
}

@("TLS13Variant - Selected")
unittest
{
    TestVariant v;
    v.select(TestEnum.anInt);
    v.get!int = 42;
    assert(v.get!int == 42);
    assert(v.selected(TestEnum.anInt) && v.selected!(int));
}