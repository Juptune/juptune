/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.tls.tls13;

import core.time : Duration;

import std.typecons : Nullable;

import juptune.core.util : Result;
import juptune.data.x509 : X509CertificateStore, X509Certificate;
import juptune.http.tls.common, juptune.http.tls.models; // Intentionally everything

struct TlsClientHelloOutSettings
{
    const(char)[] serverNameIndicator;
}

struct TlsServerHelloInSettings
{
    X509CertificateStore* certStore;
    X509CertificateStore.SecurityPolicy certPolicy;
}

struct TlsSocket(UnderlyingSocketT)
{
    import juptune.core.ds     : Array;
    import juptune.data.buffer : MemoryReader, MemoryWriter;

    private
    {
        UnderlyingSocketT* _socket;

        TlsStateMachine     _state;
        EncryptionContext   _encryptContext;
        TlsConfig           _config;

        ubyte[]      _readBuffer;
        MemoryReader _recordReader;
        MemoryWriter _recordWriter;
        MemoryWriter _stagingBuffer;

        MemoryReader _leftoverReader; // If non-empty, then receive wasn't able to pass all the data back to the user, so this reader holds the remaining leftovers (subreader of _readBuffer)

        Array!ubyte     _peerCertBytes; // NOTE: Currently the max size is indirectly controlled by the size of _readBuffer
        X509Certificate _peerCert;
    }

    this(
        UnderlyingSocketT* socket, 
        ubyte[] readBuffer,
        ubyte[] writeBuffer,
        ubyte[] stagingBuffer,
        TlsConfig config,
    ) @nogc nothrow
    in(socket !is null, "socket is null")
    in(readBuffer.length > 0, "readBuffer is empty")
    in(writeBuffer.length > 0, "writeBuffer is empty")
    in(stagingBuffer.length > 0, "stagingBuffer is empty")
    {
        this._socket = socket;
        this._readBuffer = readBuffer;
        this._recordWriter = MemoryWriter(writeBuffer);
        this._stagingBuffer = MemoryWriter(stagingBuffer);
        this._config = config;
        this._state = TlsStateMachine(State.waitingToStart);
    }

    Result handshakeAsClient(
        scope const ref TlsClientHelloOutSettings chSettings,
        scope ref TlsServerHelloInSettings shSettings,
    ) @nogc nothrow
    {
        import juptune.http.tls.client_messages : 
            putClientHello, 
            putServerNameIndicatorExtension,
            putKeyShareExtension,
            putSignatureAlgorithmsExtension,
            readServerHello,
            handleEncryptedExtensions,
            handleServerHelloCertificate,
            handleServerHelloCertificateVerify,
            handleServerHelloFinished,
            writeClientFinished
        ;

        // Send ClientHello (and add it into the transcript)

        auto result = putClientHello(this._stagingBuffer, this._state,
            putExtensions: (){
                auto result = putKeyShareExtension(this._stagingBuffer, this._state, this._encryptContext);
                if(result.isError)
                    return result;

                result = putSignatureAlgorithmsExtension(this._stagingBuffer, this._state);
                if(result.isError)
                    return result;

                if(chSettings.serverNameIndicator.length > 0)
                {
                    result = putServerNameIndicatorExtension(
                        this._stagingBuffer, 
                        this._state, 
                        chSettings.serverNameIndicator
                    );
                    if(result.isError)
                        return result;
                }

                return Result.noError;
            }
        );
        if(result.isError)
            return result.wrapError("when putting ClientHello into staging buffer:");

        result = this.sendAsPlaintextRecords(TlsPlaintext.ContentType.handshake, this._stagingBuffer.usedBuffer);
        if(result.isError)
            return result.wrapError("when sending ClientHello over socket:");
        this._encryptContext.transcript.put(this._stagingBuffer.usedBuffer);
        this._stagingBuffer.cursor = 0;

        // Read unencrypted ServerHello

        TlsHandshake serverHello;
        MemoryReader serverHelloReader; // NOTE: Subset of _stagingBuffer
        result = this.fetchPlaintextHandshakeRecordsIntoStaging(serverHello, serverHelloReader, allowCompaction: true);
        if(result.isError)
            return result.wrapError("when fetching unencrypted ServerHello over socket:");
        if(serverHello.messageType != TlsHandshake.Type.serverHello)
            return Result.make(TlsError.alertUnexpectedMessage, "expected incoming ServerHello following outgoing ClientHello"); // @suppress(dscanner.style.long_line)

        result = readServerHello(serverHelloReader, this._state, this._encryptContext);
        if(result.isError)
            return result.wrapError("when parsing unencrypted serverHello:");
        if(serverHelloReader.bytesLeft != 0)
            return Result.make(TlsError.tooManyBytes, "when reading ServerHello, not all bytes needed to be read?");
        this._stagingBuffer.cursor = 0;

        // Setup encryption state

        ubyte[4] reconstructedHeader; // fetchPlaintextHandshakeRecordsIntoStaging doesn't include a few header bytes, so we have to reconstruct the header and feed it into the transcript
        auto reconstructedWriter = MemoryWriter(reconstructedHeader);
        with(reconstructedWriter)
        {
            putU8(TlsHandshake.Type.serverHello);
            putU24BE(cast(uint)serverHelloReader.buffer.length);
        }
        this._encryptContext.transcript.put(reconstructedHeader[]);
        this._encryptContext.transcript.put(serverHelloReader.buffer);
        
        auto tempTranscript = this._encryptContext.transcript;
        this._encryptContext.clientHello_serverHello_transcriptHash = tempTranscript.finish();

        result = this._encryptContext.deriveSharedSecret();
        if(result.isError)
            return result.wrapError("when deriving handshake secrets:");

        result = this._encryptContext.deriveHandshakeSecrets();
        if(result.isError)
            return result.wrapError("when deriving handshake secrets:");

        result = this._encryptContext.deriveTrafficKeys();
        if(result.isError)
            return result.wrapError("when deriving handshake secrets:");

        // Check for and ignore changeCipherSpec

        result = this.ignoreChangeCipherSpec(allowCompaction: true);
        if(result.isError)
            return result.wrapError("when attempting to ignore changeCipherSpec:");

        // Read encrypted ServerHello
        
        ulong messageMask;

        while((messageMask & (1 << enumIndexOf(TlsHandshake.Type.finished))) == 0) // Keep reading until we've hit the finished message
        {
            result = this.fetchEncryptedHandshakeMessagesUntilFinished( // NOTE: This also adds each message to the transcript AFTER the callback is called
                (TlsHandshake message, scope ref MemoryReader messageReader){
                    const typeIndex = 1 << enumIndexOf(message.messageType);
                    if(typeIndex != -1)
                    {
                        if((messageMask & typeIndex) != 0)
                            return Result.make(TlsError.alertUnexpectedMessage, "duplicate encrypted handshake messages found"); // @suppress(dscanner.style.long_line)
                        messageMask |= typeIndex;
                    }

                    if((typeIndex & enumIndexOf(TlsHandshake.messageType.finished)) != 0)
                        return Result.make(TlsError.alertUnexpectedMessage, "no messages after Finished should appear");

                    switch(message.messageType) with(TlsHandshake.Type)
                    {
                        case encryptedExtensions:
                            return handleEncryptedExtensions(messageReader.buffer, this._state).wrapError("when reading encryptedExtensions:"); // @suppress(dscanner.style.long_line)

                        case certificate:
                            return handleServerHelloCertificate(
                                messageReader, 
                                this._state,
                                this._peerCertBytes,
                                this._peerCert,
                                shSettings.certStore,
                                shSettings.certPolicy,
                                this._config.dumpCerts,
                                chSettings.serverNameIndicator,
                            ).wrapError("when reading certificate:");

                        case certificateVerify:
                            auto verifyTranscript = this._encryptContext.transcript;
                            auto verifyHash = verifyTranscript.finish();
                            return handleServerHelloCertificateVerify(
                                messageReader,
                                this._state,
                                this._peerCert,
                                verifyHash
                            ).wrapError("when reading certificateVerify");

                        case finished:
                            return handleServerHelloFinished(
                                messageReader,
                                this._state,
                                this._encryptContext
                            ).wrapError("when reading finished");

                        default: break;
                    }
                    return Result.noError;
                }, 
                allowCompaction: true
            );
            if(result.isError)
                return result.wrapError("when parsing encrypted ServerHello:");
        }

        // Finish the client side of the handshake

        result = writeClientFinished(
            this._state, 
            this._encryptContext, 
            &this.sendAsCiphertextRecords!true
        );
        if(result.isError)
            return result.wrapError("when writing client-side Finished:");

        // Finalise encryption state, then we're ready to write!
        
        result = this._encryptContext.deriveApplicationSecrets();
        if(result.isError)
            return result;

        result = this._encryptContext.deriveTrafficKeys();
        if(result.isError)
            return result;

        this._stagingBuffer = MemoryWriter.init; // No longer needed ^_^
        return Result.noError;
    }

    /++ Driver interface ++/

    bool isOpen() @nogc nothrow => (this._socket is null ? false : this._socket.isOpen);

    Result close() @nogc nothrow => this._socket.close();

    Result send(scope const(void)[] buffer, scope out size_t bytesSent, Duration timeout = Duration.zero) @nogc nothrow
    in(this._state.mustBeIn(State.applicationData))
    {
        if(timeout == Duration.zero && this._config.alwaysTimeout)
            timeout = this._config.writeTimeout;

        bytesSent = buffer.length;
        return this.sendAsCiphertextRecords!true(TlsPlaintext.ContentType.applicationData, cast(const(ubyte)[])buffer);
    }

    Result receive(void[] buffer, out void[] sliceWithData, Duration timeout = Duration.zero) @nogc nothrow
    in(this._state.mustBeIn(State.applicationData))
    {
        import std.algorithm : min;

        // Fetch from previous socket read if there's anything left over.
        if(this._leftoverReader.bytesLeft > 0)
        {            
            const length = min(buffer.length, this._leftoverReader.bytesLeft);
            buffer[0..length] = cast(void[])this._leftoverReader.buffer[
                this._leftoverReader.cursor
                ..
                this._leftoverReader.cursor+length
            ];
            this._leftoverReader.goForward(length);
            sliceWithData = buffer[0..length];
            return Result.noError;
        }

        // Otherwise fetch and decrypt the latest ciphertext record.
        this.compactReadBuffer();

        if(timeout == Duration.zero && this._config.alwaysTimeout)
            timeout = this._config.readTimeout;

        TlsCiphertext.InnerPlaintext plaintext;
        MemoryReader reader;
        auto result = this.fetchAndDecryptSingleCiphertextRecordIntoReadBuffer(plaintext, reader, allowCompaction: true); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result.wrapError("when fetching application data from socket:");
        
        // Handle special record types.
        if(plaintext.type == TlsPlaintext.ContentType.alert)
            return this.convertAlertToResult(reader);
        else if(plaintext.type == TlsPlaintext.ContentType.handshake)
        {
            // This will _usually_ be the server sending us a session ticket after the initial handshake.
            // Handling this is honestly really annoying, so _for now_ I'll just blindly ignore handshake messages, even though
            // that's not completely correct behaviour.
            return receive(buffer, sliceWithData, timeout); // I really hope this triggers tail call optimisation lol.
        }
        else if(plaintext.type != TlsPlaintext.ContentType.applicationData)
            return Result.make(TlsError.alertUnexpectedMessage, "when receiving ciphertext record, record has unexpected message type"); // @suppress(dscanner.style.long_line)

        // Either give the entire buffer to the user, or give a partial buffer back and mess with internal state to signal there's leftover data.
        const length = min(buffer.length, reader.bytesLeft);
        if(length != reader.bytesLeft)
        {
            buffer[0..$] = cast(void[])reader.buffer[reader.cursor..reader.cursor+length];
            reader.goForward(length);
            this._leftoverReader = MemoryReader(reader.buffer, reader.cursor);

            sliceWithData = buffer[0..$];
        }
        else
        {
            buffer[0..length] = cast(void[])reader.buffer[0..$];
            sliceWithData = buffer[0..length];
        }

        return Result.noError;
    }

    Result put(const(void)[] buffer, Duration timeout = Duration.zero) @nogc nothrow
    {
        while(buffer.length > 0)
        {
            size_t bytesSent;
            auto result = this.send(buffer, bytesSent, timeout);
            if(result.isError)
                return result;
            buffer = buffer[bytesSent..$];
        }

        return Result.noError;
    }

    /++ Helpers ++/

    private Result ignoreChangeCipherSpec(bool allowCompaction) @nogc nothrow
    {
        if(this._recordReader.bytesLeft < TlsPlaintext.HEADER_SIZE)
        {
            if(allowCompaction)
                this.compactReadBuffer();

            size_t _;
            auto result = this.fetchIntoReadBuffer(_);
            if(result.isError)
                return result.wrapError("when peeking changeCipherSpec record:");
            if(this._recordReader.bytesLeft < TlsPlaintext.HEADER_SIZE)
                return Result.make(TlsError.peerTooSlow, "when peeking changeCipherSpec record, peer is sending data way too slowly to comfortably process"); // @suppress(dscanner.style.long_line)
        }

        ubyte contentTypeByte;
        auto success = this._recordReader.peekU8(contentTypeByte);
        assert(success, "bug: how did success fail?");

        if(contentTypeByte != TlsPlaintext.ContentType.changeCipherSpec)
            return Result.noError;

        // Move past it without going into the staging buffer first.
        ushort recordVersion;
        ushort length;
        const(ubyte)[] fragment;
        
        with(this._recordReader)
        {
            success = readU8(contentTypeByte);
            assert(success, "bug: how did success fail?");
            success = readU16BE(recordVersion);
            assert(success, "bug: how did success fail?");
            success = readU16BE(length);
            assert(success, "bug: how did success fail?");
        }

        if(recordVersion != TLS_VERSION_12)
            return Result.make(TlsError.alertIllegalParameter, "expected changeCipherSpec version to be set to TLS 1.2 (0x0303)"); // @suppress(dscanner.style.long_line)
        if(length > 1)
            return Result.make(TlsError.alertRecordOverflow, "changeCipherSpec record fragment length is too large");

        success = this._recordReader.readBytes(length, fragment);
        if(!success)
            return Result.make(TlsError.eof, "peer is trolling");

        return Result.noError;
    }

    private Result convertAlertToResult(scope ref MemoryReader memory)
    {
        enum Level
        {
            FAILSAFE,
            warning = 1,
            fatal = 2,
        }

        ubyte levelByte;
        ubyte descriptionByte;
        
        auto success = memory.readU8(levelByte);
        if(!success)
            return Result.make(TlsError.eof, "ran out of bytes when reading alert level");
        success = memory.readU8(descriptionByte);
        if(!success)
            return Result.make(TlsError.eof, "ran out of bytes when reading alert description");
        
        if(memory.bytesLeft != 0)
            return Result.make(TlsError.tooManyBytes, "left over bytes after reading alert");

        if(levelByte != Level.warning && levelByte != Level.fatal)
            return Result.make(TlsError.invalidAlert, "alert is malformed - unknown level byte");

        this._state.mustTransition!(State.applicationData, State.alertOrClosed);
        switch(descriptionByte)
        {
            case 0: /* close_notify */ return Result.make(TlsError.alertCloseNotify, "[close_notify] peer has closed their end of the connection"); // @suppress(dscanner.style.long_line)
            case 10: /* unexpected_message */ return Result.make(TlsError.alertUnexpectedMessage, "[unexpected_message] peer received an unexpected message from our end"); // @suppress(dscanner.style.long_line)
            case 20: /* bad_record_mac */ return Result.make(TlsError.alertBadRecordMac, "[bad_record_mac] peer was unable to decrypt or verify a message from our end"); // @suppress(dscanner.style.long_line)
            case 22: /* record_overflow */ return Result.make(TlsError.alertRecordOverflow, "[record_overflow] peer received a mesage that was too large"); // @suppress(dscanner.style.long_line)
            case 40: /* handshake_failure */ return Result.make(TlsError.alertHandshakeFailure, "[handshake_failure] peer was not able to agree with our available security parameters"); // @suppress(dscanner.style.long_line)
            case 42: /* bad_certificate */ return Result.make(TlsError.alertBadCertificate, "[bad_certificate] peer was unable to to verify or parse a certificate we sent"); // @suppress(dscanner.style.long_line)
            case 43: /* unsupported_certificate */ return Result.make(TlsError.alertUnsupportedCertificate, "[unsupported_certificate] peer was unable to support a certificate we sent"); // @suppress(dscanner.style.long_line)
            case 44: /* certificate_revoked */ return Result.make(TlsError.alertCertificateRevoked, "[certificate_revoked] peer received a certificate from us that was revoked"); // @suppress(dscanner.style.long_line)
            case 45: /* certificate_expired */ return Result.make(TlsError.alertCertificateExpired, "[certificate_expired] peer received a certificate from us that has expired"); // @suppress(dscanner.style.long_line)
            case 46: /* certificate_unknown */ return Result.make(TlsError.alertCertificateUnknown, "[certificate_unknown] peer had an unspecified error when handling a certificate we sent"); // @suppress(dscanner.style.long_line)
            case 47: /* illegal_parameter */ return Result.make(TlsError.alertIllegalParameter, "[illegal_parameter] peer received a handshake message that it determined to be invalid or inconsistent"); // @suppress(dscanner.style.long_line)
            case 48: /* unknown_ca */ return Result.make(TlsError.alertUnknownCa, "[unknown_ca] peer could not locate the CA for a certificate chain we sent"); // @suppress(dscanner.style.long_line)
            case 49: /* access_denied */ return Result.make(TlsError.alertAccessDenied, "[access_denied] peer decided our certificate is not allowed to access it"); // @suppress(dscanner.style.long_line)
            case 50: /* decode_error */ return Result.make(TlsError.alertDecodeError, "[decode_error] peer received a message that was corrupted or does not follow a constraint defined in RFC8446"); // @suppress(dscanner.style.long_line)
            case 51: /* decrypt_error */ return Result.make(TlsError.alertDecryptError, "[decrypt_error] peer failed to decrypt or verify a handshake-specific message from our end"); // @suppress(dscanner.style.long_line)
            case 70: /* protocol_version */ return Result.make(TlsError.alertProtocolVersion, "[protocol_version] peer was unable to negotiate a mutually supported version of TLS"); // @suppress(dscanner.style.long_line)
            case 71: /* insufficient_security */ return Result.make(TlsError.alertInsufficientSecurity, "[insufficient_security] peer desires security parameters that are stricter than the ones we support"); // @suppress(dscanner.style.long_line)
            case 80: /* internal_error */ return Result.make(TlsError.alertInternalError, "[internal_error] peer ran into an unspecified error"); // @suppress(dscanner.style.long_line)
            case 86: /* inappropriate_fallback */ return Result.make(TlsError.alertInappropriateFallback, "[inappropriate_fallback] peer failed to accept our reconnection attempt"); // @suppress(dscanner.style.long_line)
            case 90: /* user_canceled */ return Result.make(TlsError.alertUserCanceled, "[user_canceled] peer's user has requested to cancel the connection"); // @suppress(dscanner.style.long_line)
            case 109: /* missing_extension */ return Result.make(TlsError.alertMissingExtension, "[missing_extension] peer did not receive a mandatory or negotiated extension from us"); // @suppress(dscanner.style.long_line)
            case 110: /* unsupported_extension */ return Result.make(TlsError.alertUnsupportedExtension, "[unsupported_extension] peer received an extension from us that is prohibited or was not negotiated for"); // @suppress(dscanner.style.long_line)
            case 112: /* unrecognized_name */ return Result.make(TlsError.alertUnrecognizedName, "[unrecognized_name] peer does not provide support for the specified SNI"); // @suppress(dscanner.style.long_line)
            case 113: /* bad_certificate_status_response */ return Result.make(TlsError.alertBadCertificateStatusResponse, "[bad_certificate_status_response] peer was provided an invalid OCSP response"); // @suppress(dscanner.style.long_line)
            case 115: /* unknown_psk_identity */ return Result.make(TlsError.alertUnknownPskIdentity, "[unknown_psk_identity] peer did not receive an acceptable PSK identity from us"); // @suppress(dscanner.style.long_line)
            case 116: /* certificate_required */ return Result.make(TlsError.alertCertificateRequired, "[certificate_required] peer did not receive a certificate from us"); // @suppress(dscanner.style.long_line)
            case 120: /* no_application_protocol */ return Result.make(TlsError.alertNoApplicationProtocol, "[no_application_protocol] peer does not support any protocols we listed via ALPN"); // @suppress(dscanner.style.long_line)
            default: return Result.make(TlsError.alertGeneric, "Alert contains an unrecognised description");
        }
    }

    /++ Socket I/O ++/

    private Result sendAsPlaintextRecords(TlsPlaintext.ContentType type, scope const(ubyte)[] bytes) @nogc nothrow
    {
        import std.algorithm : min;

        while(bytes.length > 0)
        {
            const length = min(bytes.length, TlsPlaintext.MAX_LENGTH);

            ubyte[TlsPlaintext.HEADER_SIZE] header;
            header[0] = cast(ubyte)type;
            header[1] = 0x03;
            header[2] = 0x03;
            
            auto lengthWriter = MemoryWriter(header[3..$]);
            const success = lengthWriter.putU16BE(cast(ushort)length);
            assert(success);

            auto result = this._socket.putScattered([header[], bytes[0..length]], this._config.writeTimeout);
            if(result.isError)
                return result.wrapError("when sending plaintext records:");

            bytes = bytes[length..$];
        }

        return Result.noError;
    }

    private Result sendAsCiphertextRecords(bool asClient)(
        TlsPlaintext.ContentType type, 
        scope const(ubyte)[] bytes
    ) @nogc nothrow
    {
        import std.algorithm : min;
        import juptune.crypto.libsodium : crypto_aead_chacha20poly1305_ietf_abytes;

        // Check whether we have enough buffer space left.
        const startCursor = this._recordWriter.cursor;
        const overhead = TlsCiphertext.HEADER_SIZE + crypto_aead_chacha20poly1305_ietf_abytes() + 1; // + 1 for the content type byte we have to append.
        const bytesPerRecord = this._recordReader.bytesLeft - overhead;

        if(overhead >= this._recordWriter.bytesLeft)
            return Result.make(TlsError.dataExceedsBuffer, "ran out of buffer space when fragmenting data into TlsCiphertext records"); // @suppress(dscanner.style.long_line)

        while(bytes.length > 0)
        {
            // Write either a partial amount, or the rest of the remaining bytes, with the type byte suffixed.
            const toSend = min(bytesPerRecord, bytes.length);

            auto success = this._recordWriter.tryBytes(bytes[0..toSend]);
            assert(success, "bug: this shouldn't happen?");
            success = this._recordWriter.putU8(cast(ubyte)type);
            assert(success, "bug: this shouldn't happen?");
            bytes = bytes[toSend..$];

            const plaintext = this._recordWriter.buffer[startCursor..this._recordWriter.cursor];
            auto inPlaceWriter = MemoryWriter(this._recordWriter.buffer[startCursor..$]);

            // Encrypted the inner plaintext payload
            auto result = this._encryptContext.encryptRecord(
                inPlaceWriter,
                plaintext,
                (asClient) ? this._encryptContext.clientIv_sha256 : this._encryptContext.serverIv_sha256,
                (asClient) ? this._encryptContext.clientKey_sha256 : this._encryptContext.serverKey_sha256,
                writerIsInPlace: true
            );
            if(result.isError)
                return result.wrapError("when attempting to encrypt plaintext for transport:");

            const ciphertext = inPlaceWriter.usedBuffer;

            // Setup unencrypted ciphertext header
            ubyte[TlsCiphertext.HEADER_SIZE] header;
            header[0] = cast(ubyte)TlsPlaintext.ContentType.applicationData;
            header[1] = 0x03;
            header[2] = 0x03;
            
            auto lengthWriter = MemoryWriter(header[3..$]);
            success = lengthWriter.putU16BE(cast(ushort)ciphertext.length);
            assert(success);
            
            // Write the unencrypted header + encrypted inner payload
            result = this._socket.putScattered([header[], ciphertext], this._config.writeTimeout);
            if(result.isError)
                return result.wrapError("when sending ciphertext records:");
        }

        return Result.noError;
    }

    private Result fetchEncryptedHandshakeMessagesUntilFinished(
        scope Result delegate(TlsHandshake, scope ref MemoryReader) @nogc nothrow onMessage,
        bool allowCompaction = false,
    ) @nogc nothrow
    {
        // NOTE: This function currently assumes that messages are not split between record boundaries.
        // TODO: Something more robust.

        // Fetch the next encrypted record
        TlsCiphertext.InnerPlaintext plain;
        MemoryReader plainReader;

        auto result = this.fetchAndDecryptSingleCiphertextRecordIntoReadBuffer(
            plain,
            plainReader,
            allowCompaction
        );
        if(result.isError)
            return result.wrapError("when fetching encrypted handshake messages from socket:");

        // The record can hold multiple messages, so keep reading until we run out of bytes.
        while(plainReader.bytesLeft > 0)
        {
            const startCursor = plainReader.cursor;

            ubyte contentTypeByte;
            uint length;
            const(ubyte)[] data;

            auto success = plainReader.readU8(contentTypeByte);
            assert(success, "bug: how did success fail?");

            success = plainReader.readU24BE(length);
            if(!success)
                return Result.make(TlsError.eof, "ran out of bytes when reading length of encrypted handshake message");

            success = plainReader.readBytes(length, data);
            if(!success)
                return Result.make(TlsError.eof, "ran out of bytes when reading body of encrypted handshake message");

            TlsHandshake handshake;
            handshake.messageType = cast(TlsHandshake.Type)contentTypeByte;
            auto dataReader = MemoryReader(data);

            result = onMessage(handshake, dataReader);
            if(result.isError)
                return result;
            this._encryptContext.transcript.put(plainReader.buffer[startCursor..plainReader.cursor]);
        }

        return Result.noError;
    }

    private Result fetchPlaintextHandshakeRecordsIntoStaging(
        scope out TlsHandshake record,
        scope out MemoryReader reader,
        bool allowCompaction = false,
    ) @nogc nothrow
    {
        bool isFirst = true;
        const stagingCursorStart = this._stagingBuffer.cursor;
        while(true) // Handshake records can still get fragmented, so we'll have to keep reading in records until we're done
        {
            // Ensure we have enough bytes for the header.
            if(this._recordReader.bytesLeft < TlsPlaintext.HEADER_SIZE)
            {
                if(allowCompaction)
                    this.compactReadBuffer();

                size_t _;
                auto result = this.fetchIntoReadBuffer(_);
                if(result.isError)
                    return result.wrapError("when reading plaintext handshake record:");
                if(this._recordReader.bytesLeft < TlsPlaintext.HEADER_SIZE)
                    return Result.make(TlsError.peerTooSlow, "when reading plaintext handshake record, peer is sending data way too slowly to comfortably process"); // @suppress(dscanner.style.long_line)
            }

            // Parse the header, and perform some sanity/spec-related checks.
            ubyte contentTypeByte;
            ushort recordVersion;
            ushort length;
            const(ubyte)[] fragment;
            
            with(this._recordReader)
            {
                auto success = readU8(contentTypeByte);
                assert(success, "bug: how did success fail?");
                success = readU16BE(recordVersion);
                assert(success, "bug: how did success fail?");
                success = readU16BE(length);
                assert(success, "bug: how did success fail?");
            }

            if(cast(TlsPlaintext.ContentType)contentTypeByte != TlsPlaintext.ContentType.handshake)
                return Result.make(TlsError.alertUnexpectedMessage, "expected handshake record when fetching plaintext handshake"); // @suppress(dscanner.style.long_line)
            if(recordVersion != TLS_VERSION_12)
                return Result.make(TlsError.alertIllegalParameter, "expected plaintext record version to be set to TLS 1.2 (0x0303)"); // @suppress(dscanner.style.long_line)
            if(length > TlsPlaintext.MAX_LENGTH)
                return Result.make(TlsError.alertRecordOverflow, "plaintext record fragment length is too large");

            // Figure out if we have enough space left to store the payload, and perform any additional socket reads until we have enough bytes.
            const maxBytesLeft = this._readBuffer.length - this._recordReader.cursor;
            if(maxBytesLeft < length)
                return Result.make(TlsError.dataExceedsBuffer, "not enough space in read buffer to store record fragment"); // @suppress(dscanner.style.long_line)

            uint attempts;
            while(this._recordReader.bytesLeft < length)
            {
                scope(exit) attempts++;

                if(attempts > this._config.maxFragmentReadAttempts)
                    return Result.make(TlsError.peerTooSlow, "when reading plaintext handshake fragment, peer took too many read attempts to send the full fragment body"); // @suppress(dscanner.style.long_line)

                size_t _;
                auto result = this.fetchIntoReadBuffer(_);
                if(result.isError)
                    return result.wrapError("when fetching plaintext record into read buffer:");
            }

            auto success = this._recordReader.readBytes(length, fragment);
            assert(success, "bug: how did success fail?");

            // The first read attempt should also contain some extra header information, every other read attempt is just for body data.
            if(isFirst)
            {
                if(fragment.length < TlsHandshake.HEADER_SIZE)
                    return Result.make(TlsError.alertUnexpectedMessage, "expected plaintext record length to be at least 4 for plaintext handshake initial fragment"); // @suppress(dscanner.style.long_line)

                record.messageType = cast(TlsHandshake.Type)fragment[0];
                success = MemoryReader(fragment[1..4]).readU24BE(record.length);
                assert(success, "bug: how did success fail?");

                success = this._stagingBuffer.tryBytes(fragment[4..$]);
                if(!success)
                    return Result.make(TlsError.dataExceedsBuffer, "not enough space in staging buffer to store record fragment"); // @suppress(dscanner.style.long_line)

                isFirst = false;
            }
            else
            {
                success = this._stagingBuffer.tryBytes(fragment);
                if(!success)
                    return Result.make(TlsError.dataExceedsBuffer, "not enough space in staging buffer to store record fragment"); // @suppress(dscanner.style.long_line)
            }
            
            // Once we've read in enough bytes, pass everything back to the caller.
            const bytesInStaging = this._stagingBuffer.cursor - stagingCursorStart;
            if(bytesInStaging == record.length)
            {
                reader = MemoryReader(this._stagingBuffer.usedBuffer[stagingCursorStart..$]);
                return Result.noError;
            }
        }
    }

    private Result fetchAndDecryptSingleCiphertextRecordIntoReadBuffer(
        scope out TlsCiphertext.InnerPlaintext record,
        scope out MemoryReader reader,
        bool allowCompaction = false,
    ) @nogc nothrow
    {
        import std.traits : EnumMembers;
        import juptune.core.ds : String;

        // Ensure we have enough header bytes.
        if(this._recordReader.bytesLeft < TlsCiphertext.HEADER_SIZE)
        {
            if(allowCompaction)
                this.compactReadBuffer();

            size_t _;
            auto result = this.fetchIntoReadBuffer(_);
            if(result.isError)
                return result.wrapError("when reading ciphertext record:");
            if(this._recordReader.bytesLeft < TlsPlaintext.HEADER_SIZE)
                return Result.make(TlsError.peerTooSlow, "when reading ciphertext, peer is sending data way too slowly to comfortably process"); // @suppress(dscanner.style.long_line)
        }

        // Parse the header and perform some checks.
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
            return Result.make(TlsError.alertIllegalParameter, "TlsCiphertext record is not set to applicationData");
        if(version_ != TLS_VERSION_12)
            return Result.make(TlsError.alertIllegalParameter, "TlsCiphertext record contains an invalid version field - it MUST be 0x0303 when using TLS 1.3"); // @suppress(dscanner.style.long_line)
        if(fragmentLength > TlsCiphertext.MAX_LENGTH)
            return Result.make(TlsError.alertRecordOverflow, "TlsCiphertext record contains a payload greater than 2^14 + 256 in length"); // @suppress(dscanner.style.long_line)

        // Make a best-effort attempt to read in enough bytes from the socket to match the record's length field.
        uint attempts;
        while(this._recordReader.bytesLeft < fragmentLength)
        {
            scope(exit) attempts++;

            if(attempts > this._config.maxFragmentReadAttempts)
                return Result.make(TlsError.peerTooSlow, "when reading ciphertext fragment, peer took too many read attempts to send the full fragment body"); // @suppress(dscanner.style.long_line)

            size_t _;
            auto result = this.fetchIntoReadBuffer(_);
            if(result.isError)
                return result.wrapError("when fetching ciphertext record into read buffer");
        }

        // Decrypt the ciphertext body in-place.
        const(ubyte)[] encryptedRecord;
        success = this._recordReader.readBytes(fragmentLength, encryptedRecord);
        assert(success, "bug: success shouldn't be able to be false here?");

        auto result = this._encryptContext.decryptRecordInPlace(
            encryptedRecord,
            this._encryptContext.serverIv_sha256,
            this._encryptContext.serverKey_sha256,
            record
        );
        if(result.isError)
            return result.wrapError("when decrypting ciphertext record:");
        
        reader = MemoryReader(record.content); // now unencrypted
        return Result.noError;
    }

    // Socket -> Read Buffer
    private Result fetchIntoReadBuffer(out size_t bytesFetched) @nogc nothrow
    {
        const cursor = this._recordReader.buffer.length;
        if(cursor >= this._readBuffer.length)
            return Result.make(TlsError.dataExceedsBuffer, "attempted to fetch record data while buffer is full - in-process record is too large for the provided buffer"); // @suppress(dscanner.style.long_line)

        void[] got;
        auto result = this._socket.receive(this._readBuffer[cursor..$], got, this._config.readTimeout);
        if(result.isError)
            return result.wrapError("when fetching data from socket into read buffer:");

        bytesFetched = got.length;
        this._recordReader = MemoryReader(this._readBuffer[0..cursor + got.length], this._recordReader.cursor);
        return Result.noError;
    }

    private void compactReadBuffer() @nogc nothrow
    {
        if(this._recordReader.cursor == 0)
            return;

        const newLength = this._recordReader.buffer.length - this._recordReader.cursor;
        foreach(i, b; this._recordReader.buffer[this._recordReader.cursor..$])
            this._readBuffer[i] = b;
        this._recordReader = MemoryReader(this._readBuffer[0..newLength]);
    }
}

import juptune.event.io : TcpSocket;
alias TlsTcpSocket = TlsSocket!TcpSocket;

debug unittest
{
    import core.time : seconds;

    import juptune.event.io : TcpSocket;
    import juptune.core.util : resultAssert;
    import juptune.event;

    import std.exception;
    import std.file : readText;

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread((){
        // import juptune.http;

        // IpAddress ip;
        // IpAddress.parse(ip, "45.84.74.9", 443).resultAssert;

        // auto client = HttpClient(HttpClientConfig().withTlsConfig(
        //     TlsConfig().withReadTimeout(2.seconds).withDumpCerts(true)
        // ));
        // client.connectTls(ip, "man7.org").resultAssert;

        // HttpRequest req;
        // req.withMethod("GET");
        // req.withPath("/");
        // req.setHeader("User-Agent", "curl/8.16.0");
        // req.setHeader("Accept", "*/*");
        
        // HttpResponse resp;
        // client.request(req, resp).resultAssert;

        // import std.file : write;
        // debug write("test.html", cast(string)resp.body.slice);
    });
    loop.join();
}

