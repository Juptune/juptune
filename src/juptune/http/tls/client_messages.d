/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.client_messages;

import juptune.core.util : Result;
import juptune.data.buffer : MemoryWriter, MemoryReader;
import juptune.data.x509 : X509CertificateStore, X509Certificate;

import juptune.http.tls.common, juptune.http.tls.models, juptune.http.tls.encode, juptune.http.tls.decode; // Intentionally everything

package:

/++ ClientHello + Extensions ++/

static immutable ubyte[] TLS_LEGACY_COMPRESSION_METHODS_RAW = [0x00]; // null

static immutable ubyte[] TLS_CLIENTHELLO_INITIAL_EXTENSION_RAW = [
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

Result putClientHello(
    scope ref MemoryWriter buffer,
    scope ref TlsStateMachine state,
    scope Result delegate() @nogc nothrow putExtensions,
) @nogc nothrow
in(state.mustBeIn(State.waitingToStart))
{
    import juptune.crypto.rng : cryptoFillBuffer;

    state.mustTransition!(State.waitingToStart, State.startClientHello);

    // Setup TlsHandshake header
    
    auto success = buffer.putU8(TlsHandshake.Type.clientHello);
    if(!success)
        return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing TlsHandshake.messageType");

    CanaryLength!(TlsHandshake.length) handshakeLength;
    auto result = handshakeLength.putTemporaryLength(buffer);
    if(result.isError)
        return result;

    // Encode the main body of ClientHello + some static extention bytes
    
    ubyte[32] handshakeRandom;
    cryptoFillBuffer(handshakeRandom);

    TlsHandshake.ClientHello clientHello;
    clientHello.legacyVersion = TLS_VERSION_12;
    clientHello.random = handshakeRandom;
    clientHello.cipherSuites = TLS_SUPPORTED_CIPHER_SUITES_RAW;
    clientHello.legacyCompressionMethods = TLS_LEGACY_COMPRESSION_METHODS_RAW;
    clientHello.extensions = TLS_CLIENTHELLO_INITIAL_EXTENSION_RAW;

    result = autoEncode!"ClientHello"(buffer, clientHello);
    if(result.isError)
        return result;

    // Take more explicit control over the extensions field's length, and let the caller place any extra extensions
    
    auto writerForExtensionsLength = MemoryWriter(
        buffer.buffer, 
        buffer.cursor 
            - TLS_CLIENTHELLO_INITIAL_EXTENSION_RAW.length 
            - bytesRequiredForLength(ushort.max)
    ); // CanaryLength works off of the current cursor for a MemoryWriter, so we have to create a temporary MemoryWriter with its cursor in the right position.

    CanaryLength!(TlsHandshake.ClientHello.extensions) extensionsLength;
    result = extensionsLength.putTemporaryLength(writerForExtensionsLength);
    if(result.isError)
        return result;

    state.mustTransition!(State.startClientHello, State.writeClientHelloExtensions);
    result = putExtensions();
    if(result.isError)
        return result;
    state.mustTransition!(State.writeClientHelloExtensions, State.readServerHello);

    // Resolve lengths

    extensionsLength.putActualLength(buffer);
    handshakeLength.putActualLength(buffer);

    return Result.noError;
}

Result putServerNameIndicatorExtension(
    scope ref MemoryWriter buffer,
    scope ref TlsStateMachine state,
    scope const(char)[] serverName,
) @nogc nothrow
in(state.mustBeIn(State.writeClientHelloExtensions))
{
    return putExtension(buffer, TlsExtension.Type.serverName, (){
        CanaryLength!(TlsExtension.ServerNameList.severNameList) length;
        auto result = length.putTemporaryLength(buffer);
        if(result.isError)
            return result;

        TlsExtension.ServerName name;
        name.nameType = TlsExtension.ServerName.NameType.host_name;
        name.hostName = cast(ubyte[])serverName;
        
        result = autoEncode!"TlsExtension.ServerName"(buffer, name);
        if(result.isError)
            return result;

        length.putActualLength(buffer);
        return Result.noError;
    });
}

Result putKeyShareExtension(
    scope ref MemoryWriter buffer,
    scope ref TlsStateMachine state,
    scope ref EncryptionContext encryption,
) @nogc nothrow
in(state.mustBeIn(State.writeClientHelloExtensions))
{
    import juptune.crypto.keyexchange : X25519PrivateKey;

    auto result = X25519PrivateKey.generate(encryption.ourPrivateKey);
    if(result.isError)
        return result;

    ubyte[32] x25519PublicKey;
    result = encryption.ourPrivateKey.getPublicKey(x25519PublicKey[]);
    if(result.isError)
        return result;

    return putExtension(buffer, TlsExtension.Type.keyShare, (){
        CanaryLength!(TlsExtension.KeyShareClientHello.clientShares) length;
        auto result = length.putTemporaryLength(buffer);
        if(result.isError)
            return result;

        TlsExtension.KeyShareEntry x25519Entry;
        x25519Entry.group = TlsExtension.NamedGroup.x25519;
        x25519Entry.keyExchange = x25519PublicKey[];
        
        result = autoEncode!"TlsExtension.KeyShareEntry"(buffer, x25519Entry);
        if(result.isError)
            return result;

        length.putActualLength(buffer);
        return Result.noError;
    });
}

Result putSignatureAlgorithmsExtension(
    scope ref MemoryWriter buffer,
    scope ref TlsStateMachine state,
) @nogc nothrow
in(state.mustBeIn(State.writeClientHelloExtensions))
{
    return putExtension(buffer, TlsExtension.Type.signatureAlgorithms, (){
        CanaryLength!(TlsExtension.SignatureSchemeList.supportedSignatureAlgorithms) length;
        auto result = length.putTemporaryLength(buffer);
        if(result.isError)
            return result;

        static foreach(scheme; TlsHandshake.SUPPORTED_SIGNATURE_SCHEMES)
        {{
            auto success = buffer.putU16BE(scheme);
            if(!success)
                return Result.make(TlsError.dataExceedsBuffer, "ran out of staging buffer space when writing SignatureSchemeList entry"); // @suppress(dscanner.style.long_line)
        }}

        length.putActualLength(buffer);
        return Result.noError;
    });
}

private Result putExtension(
    scope ref MemoryWriter buffer,
    TlsExtension.Type type,
    scope Result delegate() @nogc nothrow putBody,
) @nogc nothrow
{
    auto success = buffer.putU16BE(type);
    if(!success)
        return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when writing TlsExtension.type");

    CanaryLength!(TlsExtension.extensionData) dataLength;
    auto result = dataLength.putTemporaryLength(buffer);
    if(result.isError)
        return result;

    result = putBody();
    if(result.isError)
        return result;

    dataLength.putActualLength(buffer);
    return Result.noError;
}

/++ ServerHello & extensions ++/

Result readServerHello(
    scope ref MemoryReader reader,
    scope ref TlsStateMachine state,
    scope ref EncryptionContext encryptContext,
) @nogc nothrow
in(state.mustBeIn(State.readServerHello))
{
    import juptune.crypto.keyexchange : X25519PublicKey;

    // NOTE: fetchPlaintextHandshakeRecordIntoStaging should have read the entire unencrypted ServerHello into memory,
    //       so if we run out of bytes then that's a peer issue, not a "we haven't read a fragmented record" issue.

    TlsHandshake.ServerHello hello;
    auto result = autoDecode!"ServerHello"(reader, hello);
    if(result.isError)
        return result;

    // Check random for specific values
    if(hello.random == TlsHandshake.ServerHello.HelloRetryRequestRandom)
        assert(false, "TODO:");
    else if(
        hello.random[$-8..$] == TlsHandshake.ServerHello.Tls11Random
        || hello.random[$-8..$] == TlsHandshake.ServerHello.Tls12Random
    )
    {
        return Result.make(TlsError.alertIllegalParameter, "server attempted to negotiate TLS 1.2 or below during handshake"); // @suppress(dscanner.style.long_line)
    }

    // Handle extensions
    bool foundKeyShare = false;
    bool foundSupportedVersions = false;
    result = readExtensions(TlsHandshake.Type.serverHello, hello.extensions, (TlsExtension ext){
        switch(ext.type) with(TlsExtension.Type)
        {
            case keyShare:
                foundKeyShare = true;

                const data = ext.data.keyShare.getValue!(TlsExtension.KeyShareServerHello).serverShare;
                if(data.group != TlsExtension.NamedGroup.x25519)
                    return Result.make(TlsError.alertIllegalParameter, "ServerHello's key_share didn't select for x25519 (Juptune Limitation)"); // @suppress(dscanner.style.long_line)

                encryptContext.namedGroup = data.group;

                auto result = X25519PublicKey.fromCopyingBytes(
                    data.keyExchange,
                    encryptContext.theirPublicKey
                );
                if(result.isError)
                    return result;
                break;

            case supportedVersions:
                foundSupportedVersions = true;

                const data = ext.data.supportedVersions.getValue!(TlsExtension.SupportedVersionsServerHello);
                if(data.selectedVersion != TLS_VERSION_13)
                    return Result.make(TlsError.alertIllegalParameter, "ServerHello's supported_versions extension is not 0x0304 (TLS 1.3)"); // @suppress(dscanner.style.long_line)
                break;

            default: break;
        }
        return Result.noError;
    }).wrapError("when reading ServerHello extensions:");

    if(result.isError)
        return result;
    if(!foundKeyShare)
        return Result.make(TlsError.alertMissingExtension, "ServerHello is missing the key_share extension");
    if(!foundSupportedVersions)
        return Result.make(TlsError.alertMissingExtension, "ServerHello is missing the supported_versions extension"); // @suppress(dscanner.style.long_line)

    // Setup encryption context
    encryptContext.cipherSuite = hello.cipherSuite;

    state.mustTransition!(State.readServerHello, State.readEncryptedServerHello);
    return Result.noError;
}

private Result readExtensions(
    TlsHandshake.Type messageType,
    scope const(ubyte)[] rawExtensions, 
    scope Result delegate(TlsExtension) @nogc nothrow handler,
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
            return Result.make(TlsError.eof, "ran out of bytes when reading extension type");
        success = reader.readU16BE(dataLength);
        if(!success)
            return Result.make(TlsError.eof, "ran out of bytes when reading extension data length");

        const(ubyte)[] data;
        success = reader.readBytes(dataLength, data);
        if(!success)
            return Result.make(TlsError.eof, "ran out of bytes when reading extension data");

        const typeIndex = 1 << enumIndexOf(cast(TlsExtension.Type)type);
        if(typeIndex != -1)
        {
            if((typeMask & typeIndex) != 0)
                return Result.make(TlsError.alertUnexpectedMessage, "message contains a duplicate extension - this is not allowed"); // @suppress(dscanner.style.long_line)
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
            auto result = autoDecode!(ExtensionT.stringof)(dataReader, ext);
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
                tlsExt.data.keyShare.set(messageType, autoDecodeExt!(TlsExtension.KeyShareServerHello));
                break;

            case supportedVersions:
                tlsExt.data.supportedVersions = TlsExtension.SupportedVersions();
                tlsExt.data.supportedVersions.set(messageType, autoDecodeExt!(TlsExtension.SupportedVersionsServerHello)); // @suppress(dscanner.style.long_line)
                break;
            
            case serverName:
                autoDecodeExt!(TlsExtension.EmptyExtensionData);
                break;

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

/++ Encrypted ServerHello ++/

Result handleEncryptedExtensions(
    scope const(ubyte)[] rawExtensionArray,
    scope ref TlsStateMachine state,
) @nogc nothrow
in(state.mustBeIn(State.readEncryptedServerHello))
{
    auto reader = MemoryReader(rawExtensionArray);

    TlsHandshake.EncryptedExtensions extArray;
    auto result = autoDecode!"TlsHandshake.EncryptedExtensions"(reader, extArray);
    if(result.isError)
        return result;

    return readExtensions(
        TlsHandshake.Type.serverHello,
        extArray.extensions,
        (ext){
            return Result.noError;
        }
    );
}

Result handleServerHelloCertificate(
    scope ref MemoryReader reader,
    scope ref TlsStateMachine state,
    scope out X509Certificate peerCert,
    scope X509CertificateStore* certStore,
    X509CertificateStore.SecurityPolicy certPolicy,
) @nogc nothrow
in(state.mustBeIn(State.readEncryptedServerHello))
{
    TlsHandshake.Certificate handshakeCert;
    auto result = autoDecode!"TlsHandshake.Certificate"(reader, handshakeCert);
    if(result.isError)
        return result;
    if(reader.bytesLeft > 0)
        return Result.make(TlsError.tooManyBytes, "when decoding Certificate message - not all bytes were read"); // @suppress(dscanner.style.long_line)

    bool isFirst = true;
    auto entryReader = MemoryReader(handshakeCert.certificateList);
    return certStore.validateChainFromCopyingDerBytes(
        (scope out const(ubyte)[] derBytes, scope out bool keepGoing){
            if(entryReader.bytesLeft == 0)
            {
                keepGoing = false;
                return Result.noError;
            }

            TlsHandshake.Certificate.Entry entry;
            result = autoDecode!"CertificateEntry"(entryReader, entry);
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
        certPolicy,
        reverseChain: true
    );
}

Result handleServerHelloCertificateVerify(
    scope ref MemoryReader reader,
    scope ref TlsStateMachine state,
    scope ref X509Certificate peerCert,
    scope const(ubyte)[] transcriptHash,
) @nogc nothrow
in(state.mustBeIn(State.readEncryptedServerHello))
{
    import std.digest.sha : sha256Of;
    import juptune.crypto.ecdsa : EcdsaGroupName, EcdsaPublicKey, EcdsaSignatureAlgorithm;
    import juptune.crypto.rsa : RsaPadding, RsaPublicKey, RsaSignatureAlgorithm;

    TlsHandshake.CertificateVerify verify;
    auto result = autoDecode!"TlsHandshake.CertificateVerify"(reader, verify);
    if(result.isError)
        return result;
    if(reader.bytesLeft > 0)
        return Result.make(TlsError.tooManyBytes, "when decoding CertificateVerify message - not all bytes were read"); // @suppress(dscanner.style.long_line)

    static immutable ubyte[64] SPACES = 0x20;
    static immutable CONTEXT_STRING = "TLS 1.3, server CertificateVerify";
    static immutable ubyte[1] SEPARATOR = 0;

    Result handleEcdsa(EcdsaGroupName NamedCurve)()
    {
        // TODO: verify subjectPublicKeyAlgorithm

        EcdsaPublicKey pubKey;
        auto result = EcdsaPublicKey.fromBytes(NamedCurve, peerCert.subjectPublicKey.bytes, pubKey);
        if(result.isError)
            return result;

        static if(NamedCurve == EcdsaGroupName.secp256r1)
        {
            enum HASH_LENGTH = 32;
            enum ALGORITHM = EcdsaSignatureAlgorithm.sha256;
            alias Hasher = sha256Of;
        }
        else static assert(false, "TODO: handle this particular curve");

        assert(transcriptHash.length == HASH_LENGTH);

        ubyte[SPACES.length + CONTEXT_STRING.length + SEPARATOR.length + HASH_LENGTH] rawSignature;
        rawSignature[0..SPACES.length] = 0x20;
        rawSignature[SPACES.length..SPACES.length + CONTEXT_STRING.length] = cast(const(ubyte)[])CONTEXT_STRING[0..$];
        rawSignature[SPACES.length + CONTEXT_STRING.length] = SEPARATOR[0];
        rawSignature[SPACES.length + CONTEXT_STRING.length + SEPARATOR.length..$] = transcriptHash[0..$];

        const rawSignatureHash = Hasher(rawSignature);

        bool success;
        result = pubKey.verifySignature(
            verify.signature,
            rawSignatureHash,
            ALGORITHM,
            success
        );
        if(result.isError)
            return result;

        if(!success)
            return Result.make(TlsError.verificationFailed, "failed to verify ECDSA signature in CertificateVerify");

        return Result.noError;
    }

    Result handleRsa(RsaPadding Padding, RsaSignatureAlgorithm SigAlgorithm)()
    {
        // TODO: verify subjectPublicKeyAlgorithm

        RsaPublicKey pubKey;
        auto result = RsaPublicKey.fromAsn1RsaPublicKeyBytes(peerCert.subjectPublicKey.bytes, pubKey);
        if(result.isError)
            return result;

        static if(SigAlgorithm == RsaSignatureAlgorithm.sha256)
        {
            enum HASH_LENGTH = 32;
            alias Hasher = sha256Of;
        }
        else static assert(false, "TODO: handle this particular curve");

        assert(transcriptHash.length == HASH_LENGTH);

        ubyte[SPACES.length + CONTEXT_STRING.length + SEPARATOR.length + HASH_LENGTH] rawSignature;
        rawSignature[0..SPACES.length] = 0x20;
        rawSignature[SPACES.length..SPACES.length + CONTEXT_STRING.length] = cast(const(ubyte)[])CONTEXT_STRING[0..$];
        rawSignature[SPACES.length + CONTEXT_STRING.length] = SEPARATOR[0];
        rawSignature[SPACES.length + CONTEXT_STRING.length + SEPARATOR.length..$] = transcriptHash[0..$];

        const rawSignatureHash = Hasher(rawSignature);

        bool success;
        result = pubKey.verifySignature(
            verify.signature,
            rawSignatureHash,
            Padding,
            SigAlgorithm,
            success
        );
        if(result.isError)
            return result;

        if(!success)
            return Result.make(TlsError.verificationFailed, "failed to verify ECDSA signature in CertificateVerify");

        return Result.noError;
    }

    switch(verify.algorithm) with(TlsHandshake.SignatureScheme)
    {
        case ecdsa_secp256r1_sha256:
            return handleEcdsa!(EcdsaGroupName.secp256r1);

        case rsa_pss_rsae_sha256:
            return handleRsa!(RsaPadding.pkcs1Pss, RsaSignatureAlgorithm.sha256);

        default:
            return Result.make(TlsError.unsupportedAlgorithm, "server selected for an unsupported algorithm");
    }

    return Result.noError;
}

Result handleServerHelloFinished(
    scope ref MemoryReader reader,
    scope ref TlsStateMachine state,
    scope ref EncryptionContext encryption,
) @nogc nothrow
in(state.mustBeIn(State.readEncryptedServerHello))
{
    import std.digest.hmac : HMAC;
    import std.digest.sha : SHA256;

    auto transcriptCopy = encryption.transcript;
    const transcriptHash = transcriptCopy.finish();

    const expectedHash = reader.buffer;

    ubyte[32] finishedKey;
    auto result = encryption.hkdfExpandLabel(finishedKey, "finished", null, encryption.serverTrafficSecret_sha256); // @suppress(dscanner.style.long_line)
    if(result.isError)
        return result;

    auto h = HMAC!SHA256(finishedKey);
    h.put(transcriptHash);
    const gotHash = h.finish();

    if(expectedHash != gotHash)
        return Result.make(TlsError.alertDecryptError, "HMAC mismatch when processing ServerHello's Finished");

    state.mustTransition!(State.readEncryptedServerHello, State.writeClientChangeCipherSpec);
    return Result.noError;
}

/++ Outgoing Finished ++/

static immutable ubyte[] CHANGE_CIPHER_SPEC = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

Result writeClientFinished(
    scope ref TlsStateMachine state,
    scope ref EncryptionContext encryption,
    scope Result delegate(TlsPlaintext.ContentType type, scope const(ubyte)[] bytes) @nogc nothrow sendAsCiphertextRecords, // @suppress(dscanner.style.long_line)
) @nogc nothrow
in(state.mustBeIn(State.writeClientChangeCipherSpec))
{
    import std.digest.hmac : HMAC;
    import std.digest.sha : SHA256;

    auto transcriptCopy = encryption.transcript;
    const transcriptHash = transcriptCopy.finish();

    ubyte[32] finishedKey;
    auto result = encryption.hkdfExpandLabel(finishedKey, "finished", null, encryption.clientTrafficSecret_sha256); // @suppress(dscanner.style.long_line)
    if(result.isError)
        return result;

    auto h = HMAC!SHA256(finishedKey);
    h.put(transcriptHash);
    const gotHash = h.finish();

    ubyte[TlsHandshake.HEADER_SIZE + typeof(gotHash).length] payload;
    payload[$-gotHash.length..$] = gotHash;
    payload[0] = cast(ubyte)TlsHandshake.Type.finished;
    
    auto lengthWriter = MemoryWriter(payload[1..4]);
    const success = lengthWriter.putU24BE(gotHash.length);
    assert(success);

    state.mustTransition!(State.writeClientChangeCipherSpec, State.applicationData);
    return sendAsCiphertextRecords(TlsPlaintext.ContentType.handshake, payload);
}