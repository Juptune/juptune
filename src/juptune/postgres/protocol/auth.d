/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.auth;

import std.sumtype : SumType, match;

import juptune.core.ds : Array;
import juptune.core.util : Result;
import juptune.data : MemoryReader;
import juptune.postgres.protocol.connection : PostgresProtocol, PostgresMessageType, PostgresProtocolError;

package alias AuthScheme = SumType!(
    AuthenticationSasl, 
    AuthenticationSaslContinue,
    AuthenticationSuccess,
    AuthenticationSaslComplete,
);

package struct AuthenticationSasl
{
    enum Algorithm
    {
        FAILSAFE,
        scram_sha_256 = 1 << 0,
    }

    Algorithm algorithmBitmask;
}

package struct AuthenticationSaslContinue
{
    const(ubyte)[] serverFirstMessage;
}

package struct AuthenticationSaslComplete
{
    const(ubyte)[] serverLastMessage;
}

package struct AuthenticationSuccess {}

package Result authenticate(
    scope ref PostgresProtocol psql,
    AuthScheme scheme, 
    scope const(char)[] username, 
    scope const(char)[] password,
    scope PostgresProtocol.MessageHandlerT handleExtraMessage,
) @nogc nothrow
in(psql.bufferIsEmpty, "bug: buffer was expected to be empty")
{
    return scheme.match!(
        (AuthenticationSasl sasl) => authSasl(sasl, psql, username, password, handleExtraMessage),
        (AuthenticationSaslContinue _) => Result.make(PostgresProtocolError.unexpectedMessage, "when authenticating, AuthenticationSaslContinue isn't a possible initial response from the server?"), // @suppress(dscanner.style.long_line)
        (AuthenticationSuccess _) => Result.make(PostgresProtocolError.unexpectedMessage, "when authenticating, AuthenticationSuccess isn't a possible initial response from the server?"), // @suppress(dscanner.style.long_line)
        (AuthenticationSaslComplete _) => Result.make(PostgresProtocolError.unexpectedMessage, "when authenticating, AuthenticationSaslComplete isn't a possible initial response from the server?"), // @suppress(dscanner.style.long_line)
    );
}

private Result authSasl(
    AuthenticationSasl sasl, 
    scope ref PostgresProtocol psql,
    scope const(char)[] username, 
    scope const(char)[] password,
    scope PostgresProtocol.MessageHandlerT handleExtraMessage,
) @nogc nothrow
{
    import juptune.crypto.rng : cryptoFillBuffer, cryptoFillBufferFromAlphabet;
    import juptune.postgres.protocol.decode : decodeSaslContinue, decodeAuthentication, decodeSaslComplete;
    import juptune.postgres.protocol.encode : sendSaslInitialResponse, sendSaslResponse;

    assert((sasl.algorithmBitmask & sasl.Algorithm.scram_sha_256) != 0, "only SCRAM-SHA-256 is supported right now, so it NEEDS to be set"); // @suppress(dscanner.style.long_line)

    /++ Generate some initial data & specify other overarching vars ++/
    Array!ubyte authMessageTranscript;

    ubyte[32] serverSignature;
    ubyte[32] serverNonce;
    size_t serverNonceLength;
    const(ubyte)[] serverSalt; // This is a slice of the input buffer, where these specific bytes have overwritten parts of the base64 input.
    uint iterationCount;

    // Generate a nonce of printable chars
    static immutable string PRINTABLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-!$%^&*()[];:'@{}#<.>"; // @suppress(dscanner.style.long_line)
    ubyte[32] nonce;
    cryptoFillBufferFromAlphabet(nonce, cast(const(ubyte)[])PRINTABLE_CHARS);

    /++ First, send a SASLInitialResponse message with the client-first-message ++/
    auto result = sendSaslInitialResponse(psql, nonce, username, authMessageTranscript);
    if(result.isError)
        return result;

    /++ Second, handle the AuthenticationSASLContinue message and parse its data into our vars ++/
    bool foundSaslContinue;

    result = psql.nextMessagesImpl((PostgresMessageType type, scope ref MemoryReader reader){
        switch(type) with(PostgresMessageType)
        {
            case authentication:
                foundSaslContinue = true;
                return decodeSaslContinue(reader, nonce, serverNonce, serverNonceLength, serverSalt, iterationCount, authMessageTranscript); // @suppress(dscanner.style.long_line)

            default:
                import juptune.core.ds : String;
                return Result.make(
                    PostgresProtocolError.unexpectedMessage,
                    "encountered unexpected message when reading reply to SASLInitialResponse",
                    String("got message of type ", type)
                );
        }
    }, () => !foundSaslContinue);
    if(result.isError)
        return result;
    psql.resetBuffer();

    /++ Third, compute the ClientProof value and send it to the server as a SASLResponse message ++/
    result = sendSaslResponse(
        psql,
        password,
        serverSalt,
        authMessageTranscript,
        serverSignature,
        iterationCount,
        nonce,
        serverNonce[0..serverNonceLength],
    );
    if(result.isError)
        return result;
    
    /++ Finally, listen out for the response, passing any unknown messages to the caller instead ++/
    bool success;
    bool ready;
    return psql.nextMessagesImpl((PostgresMessageType type, scope ref MemoryReader reader){
        switch(type) with(PostgresMessageType)
        {
            case authentication:
                AuthScheme scheme;
                auto result = decodeAuthentication(reader, scheme);
                if(result.isError)
                    return result;

                result = scheme.match!(
                    (AuthenticationSaslComplete _) => decodeSaslComplete(scheme, serverSignature),
                    (AuthenticationSuccess _) { success = true; return Result.noError; },
                    (_) => Result.make(PostgresProtocolError.unexpectedMessage, "when reading reply to SASLResponse, expected AuthenticationSuccess or AuthenticationSASLComplete"), // @suppress(dscanner.style.long_line)
                );
                if(result.isError)
                    return result;
                return Result.noError;

            case readyForQuery:
                ready = true;
                return Result.noError;

            default: return handleExtraMessage(type, reader);
        }
    }, () => !success || !ready);
}