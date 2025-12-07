/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.common;

import juptune.core.util : StateMachineTypes;

enum TlsError
{
    none,

    /++ General I/O errors ++/
    dataExceedsBuffer,
    peerTooSlow,
    eof,
    tooManyBytes,

    /++ Protocol constraint errors ++/
    exactValueConstraintFailed,
    exactLengthConstraintFailed,
    lengthRangeConstraintFailed,

    /++ Encryption related errors ++/
    unknownCipherSuite,
    unsupportedAlgorithm,
    verificationFailed,

    /++ Protocol alerts ++/
    alertRecordOverflow,
    alertUnexpectedMessage,
    alertIllegalParameter,
    alertMissingExtension,
    alertBadRecordMac,
    alertDecryptError,
}

struct TlsConfig
{
    import core.time : Duration;

    Duration writeTimeout = Duration.zero; /// The default timeout for writing data
    Duration readTimeout = Duration.zero; /// The default timeout for reading data

    ubyte maxFragmentReadAttempts = ubyte.max; /// How many attempts are made to fully read in a record's fragment data before an error is thrown

    @safe @nogc nothrow pure:

    TlsConfig withReadTimeout(Duration v) { this.readTimeout = v; return this; }
    TlsConfig withWriteTimeout(Duration v) { this.writeTimeout = v; return this; }
    TlsConfig withMaxFragmentReadAttempts(ubyte v) { this.maxFragmentReadAttempts = v; return this; }
}

package:

private alias Machine = StateMachineTypes!(State, void*);
alias TlsStateMachine = Machine.Static!([
    Machine.Transition(State.waitingToStart,                State.startClientHello),
    Machine.Transition(State.startClientHello,              State.writeClientHelloExtensions),
    Machine.Transition(State.writeClientHelloExtensions,    State.readServerHello),
    Machine.Transition(State.readServerHello,               State.readEncryptedServerHello),
]);

enum State
{
    FAILSAFE,
    waitingToStart,
    
    // Client states
    startClientHello,
    writeClientHelloExtensions,
    readServerHello,
    readEncryptedServerHello,

    // Special states
    fatalAlert,
}

struct EncryptionContext
{
    import std.digest.sha : SHA256;

    import juptune.core.util : Result;
    import juptune.crypto.aead : AeadIetfChacha20Poly1305;
    import juptune.crypto.keyexchange : X25519PublicKey, X25519PrivateKey;
    import juptune.http.tls.models : TlsHandshake, TlsExtension, TlsCiphertext, TlsPlaintext;

    static immutable HKDF_EXPAND_LABEL_PREFIX = "tls13 ";

    SHA256 transcript;
    X25519PublicKey theirPublicKey;
    X25519PrivateKey ourPrivateKey;

    TlsHandshake.CipherSuite cipherSuite;
    TlsExtension.NamedGroup namedGroup;

    ubyte[32] clientHello_serverHello_transcriptHash;

    size_t sequenceNumber;

    union
    {
        struct {
            ubyte[32] sharedSecret_sha256; 
            ubyte[32] clientTrafficSecret_sha256;
            ubyte[32] serverTrafficSecret_sha256;
            ubyte[32] masterSecret_sha256;

            ubyte[32] serverKey_sha256;
            ubyte[AeadIetfChacha20Poly1305.NONCE_LENGTH] serverIv_sha256;

            ubyte[32] clientKey_sha256;
            ubyte[AeadIetfChacha20Poly1305.NONCE_LENGTH] clientIv_sha256;
        } // For: TLS_CHACHA20_POLY1305_SHA256
    }

    @nogc nothrow:

    Result deriveSharedSecret()
    {
        assert(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        return this.ourPrivateKey.deriveSharedSecret(this.theirPublicKey, this.sharedSecret_sha256[]);
    }

    Result deriveTrafficKeys() @nogc nothrow
    {
        assert(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: Support non-SHA256 cipher suites"); // @suppress(dscanner.style.long_line)
        
        auto result = hkdfExpandLabel(this.serverKey_sha256, "key", null, this.serverTrafficSecret_sha256);
        if(result.isError)
            return result;

        result = hkdfExpandLabel(this.serverIv_sha256, "iv", null, this.serverTrafficSecret_sha256);
        if(result.isError)
            return result;
        
        result = hkdfExpandLabel(this.clientKey_sha256, "key", null, this.clientTrafficSecret_sha256);
        if(result.isError)
            return result;

        result = hkdfExpandLabel(this.clientIv_sha256, "iv", null, this.clientTrafficSecret_sha256);
        if(result.isError)
            return result;

        this.sequenceNumber = 0;
        return Result.noError;
    }

    Result deriveHandshakeSecrets() @nogc nothrow
    {
        import std.digest.sha : SHA256;
        import juptune.crypto.hkdf : hkdfExtractSha256;

        assert(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: Support non-SHA256 cipher suites"); // @suppress(dscanner.style.long_line)

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
        result = this.hkdfExpandLabel(salt, "derived", emptySha, earlySecret);
        if(result.isError)
            return result;
        earlySecret[] = 0;

        //                ^^ Derived ^^
        //                      |
        //                      v
        // (EC)DHE -> HKDF-Extract = Handshake Secret
        ubyte[32] handshakeSecret;
        result = hkdfExtractSha256(handshakeSecret, salt, this.sharedSecret_sha256);
        if(result.isError)
            return result;

        psk = this.clientHello_serverHello_transcriptHash;
        // --> Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello) = client_handshake_traffic_secret
            result = this.hkdfExpandLabel(
                this.clientTrafficSecret_sha256, 
                "c hs traffic", 
                psk, 
                handshakeSecret
            );
            if(result.isError)
                return result;

        // --> Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello) = server_handshake_traffic_secret
            result = this.hkdfExpandLabel(
                this.serverTrafficSecret_sha256, 
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
        result = this.hkdfExpandLabel(earlySecret, "derived", emptySha, handshakeSecret); // NOTE: reusing the earlySecret buffer
        if(result.isError)
            return result;
        handshakeSecret[] = 0;

        //            ^^ Derived ^^
        //                  |
        //                  v
        // 0 -> HKDF-Extract = Master Secret
        result = hkdfExtractSha256(this.masterSecret_sha256, earlySecret, emptySha);
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result deriveApplicationSecrets() @nogc nothrow
    {
        import juptune.crypto.hkdf : hkdfExtractSha256;

        assert(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: Support non-SHA256 cipher suites"); // @suppress(dscanner.style.long_line)

        auto finalHash = this.transcript.finish();

        //                            Master Secret
        //                                  |
        //                                  v
        // Derive-Secret(., "c ap traffic", ClientHello...server Finished)
        auto result = this.hkdfExpandLabel(this.clientTrafficSecret_sha256, "c ap traffic", finalHash, this.masterSecret_sha256); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        //                            Master Secret
        //                                  |
        //                                  v
        // Derive-Secret(., "s ap traffic", ClientHello...server Finished)
        result = this.hkdfExpandLabel(this.serverTrafficSecret_sha256, "c ap traffic", finalHash, this.masterSecret_sha256); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result hkdfExpandLabel(
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
        import juptune.data.buffer : MemoryWriter;

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
        if(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
        {
            assert(masterKey.length == 32, "masterKey must be 32 bytes long when using a SHA256 cipher suite");
            return hkdfExpandSha256(outKey, hkdfLabel, masterKey[0..32]);
        }
        else
            return Result.make(TlsError.unknownCipherSuite, "cannot perform HKDF using unknown cipher suite");
    }

    Result decryptRecordInPlace(
        scope const ubyte[] encryptedRecord, 
        scope const ubyte[] writerIv, 
        scope const ubyte[] writerKey,
        scope out TlsCiphertext.InnerPlaintext inner,
    ) @nogc nothrow
    {
        import juptune.crypto.aead : AeadIetfChacha20Poly1305, AeadEncryptionContext;
        import juptune.data.buffer : MemoryWriter;

        assert(this.cipherSuite == TlsHandshake.CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "TODO: support other cipher suites"); // @suppress(dscanner.style.long_line)
        
        // Setup nonce
        ubyte[AeadIetfChacha20Poly1305.NONCE_LENGTH] nonce;
        auto writer = MemoryWriter(nonce[$-8..$]);
        auto success = writer.putU64BE(this.sequenceNumber++);
        assert(success);
        foreach(i, ref byte_; nonce)
            byte_ ^= writerIv[i];

        // Setup additional data
        ubyte[1 + 2 + 2] additionalData; // opaque_type + legacy_record_version + length
        additionalData[0] = TlsPlaintext.ContentType.applicationData;
        additionalData[1] = 0x03;
        additionalData[2] = 0x03;
        writer = MemoryWriter(additionalData[3..5]);
        success = writer.putU16BE(cast(ushort)encryptedRecord.length);
        assert(success);

        // Decrypt in place
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
        size_t length = encryptedRecord.length;
        if(length < encryptedRecord.length - crypto_aead_chacha20poly1305_ietf_abytes())
            return Result.make(TlsError.dataExceedsBuffer, "when preparing to decrypt TlsCiphertext into staging buffer - not enough bytes left"); // @suppress(dscanner.style.long_line)

        const ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            // &this._stagingWriter.buffer[this._stagingWriter.cursor],
            cast(ubyte*)&encryptedRecord[0],
            &length, // NOTE: value gets overwritten
            null,
            &encryptedRecord[0],
            encryptedRecord.length,
            &additionalData[0],
            additionalData.length,
            &nonce[0],
            &writerKey[0],
        );
        if(ret == -1)
            return Result.make(TlsError.alertBadRecordMac, "failed to decrypt TlsCipher text data");
        if(length == 0)
            assert(false, "TODO: handle this");

        // Figure out where the padding is, then move fill out the TlsInnerplaintext struct
        // There's _surely_ a better way to do this, right?
        const innerPlaintext = encryptedRecord[0..length];
        ptrdiff_t lastSetByte = cast(ptrdiff_t)innerPlaintext.length - 1;
        for(; lastSetByte > -1; lastSetByte--)
        {
            if(innerPlaintext[lastSetByte] != 0)
                break;
        }
        assert(lastSetByte > 0, "TODO: handle this");

        inner.type = cast(TlsPlaintext.ContentType)innerPlaintext[lastSetByte];
        inner.content = innerPlaintext[0..lastSetByte];

        switch(inner.type) with(TlsPlaintext.ContentType)
        {
            case invalid, MAX:
            default:
                return Result.make(TlsError.alertIllegalParameter, "TlsInnerplaintext has an invalid content type");

            case changeCipherSpec, alert, handshake, applicationData:
                break;
        }

        return Result.noError;
    }
}

uint bytesRequiredForLength(const size_t maxSize) @safe @nogc nothrow pure
{
    import juptune.http.tls.models : UINT24_MAX;
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

size_t enumIndexOf(EnumT)(EnumT value) @safe @nogc nothrow pure
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