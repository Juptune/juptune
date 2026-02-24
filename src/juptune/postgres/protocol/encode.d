/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.encode;

import juptune.core.ds : Array;
import juptune.core.util : Result;
import juptune.postgres.protocol.connection 
    : 
        PostgresProtocol, 
        PostgresProtocolVersion, 
        PostgresProtocolError, 
        PostgresColumnDescription
    ;
import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

package Result sendStartupMessage(
    scope ref PostgresProtocol psql,
    scope const(char)[] user, 
    scope const(char)[] databaseOrNull,
) @nogc nothrow
in(psql.bufferIsEmpty, "bug: buffer was expected to be empty")
{
    Result putParam(scope const(char)[] paramName, scope const(char)[] paramValue)
    {
        auto result = psql.putStringz(paramName);
        if(result.isError)
            return result;
        return psql.putStringz(paramValue);
    }

    auto result = psql.putLengthPrefixedBytes((){
        auto result = psql.putInt(PostgresProtocolVersion.v3_0);
        if(result.isError)
            return result;

        result = putParam("user", user);
        if(result.isError)
            return result;
        
        if(databaseOrNull.length > 0)
        {
            result = putParam("database", databaseOrNull);
            if(result.isError)
                return result;
        }

        return psql.putBytes([0]); // null indicates "end of parameters"
    });
    if(result.isError)
        return result;

    return psql.sendEntireBuffer();
}

package Result sendSaslInitialResponse(
    scope ref PostgresProtocol psql,
    scope const(ubyte)[] nonce,
    scope const(char)[] username,
    scope ref Array!ubyte authMessageTranscript,
) @nogc nothrow
in(psql.bufferIsEmpty, "bug: buffer was expected to be empty")
{
    auto result = psql.putBytes(['p']); // type byte of SASLInitialResponse
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putStringz("SCRAM-SHA-256"); // the selected algorithm
        if(result.isError)
            return result;

        return psql.putLengthPrefixedBytes((){
            auto result = psql.putString("n,,n="); // GS2 header: "n" = does not support channel binding, ",," = no SASL auth identity, "n=" = prefix for below
            if(result.isError)
                return result;

            const start = psql.bufferCursor - 2; // - 2 to include the "n="

            result = psql.putString(username); // SCRAM username, Postgres doesn't actually use this but I'm putting it here anyway.
            if(result.isError)
                return result;

            result = psql.putString(",r=");
            if(result.isError)
                return result;

            result = psql.putBytes(nonce);
            if(result.isError)
                return result;

            authMessageTranscript.put(psql.rawBuffer[start..psql.bufferCursor], ',');
            return Result.noError;
        }, includeLengthBytes: false);
    });
    if(result.isError)
        return result;

    return psql.sendEntireBuffer();
}

package Result sendSaslResponse(
    scope ref PostgresProtocol psql,
    scope const(char)[] password,
    scope const(ubyte)[] salt,
    scope ref Array!ubyte authMessageTranscript,
    scope out ubyte[32] serverSignature,
    uint iterationCount,
    scope const(ubyte)[] clientNonce,
    scope const(ubyte)[] serverNonce,
) @nogc nothrow
in(psql.bufferIsEmpty, "bug: buffer was expected to be empty")
{
    import std.digest.hmac : HMAC;
    import std.digest.sha : SHA256, sha256Of;

    import juptune.data.base : Base64Encoder, Base64Rfc4648Alphabet;

    auto result = psql.putBytes(['p']); // type byte of SASLResponse
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        /++ Calculate initial signature data ++/
        
        static immutable ubyte[] saltPrefix = [0, 0, 0, 1];

        // SaltedPassword  := Hi(Normalize(password), salt, i)
        auto hmac = HMAC!SHA256(cast(const(ubyte)[])password);
        auto u1 = hmac.put(salt).put(saltPrefix).finish();
        auto uPrev = u1;
        foreach(i; 1..iterationCount)
        {
            uPrev = hmac.put(uPrev).finish();
            u1[] ^= uPrev[];
        }
        auto saltedPassword = u1;

        // ClientKey       := HMAC(SaltedPassword, "Client Key")
        auto clientKey = HMAC!SHA256(saltedPassword).put(cast(const(ubyte)[])"Client Key").finish();

        // StoredKey       := H(ClientKey)
        auto storedKey = sha256Of(clientKey);

        /++ Setup the client_final_response without proof ++/
        
        const start = psql.bufferCursor;
        auto result = psql.putString("c=biws,r="); // "c=biws" = No channel stuff, "r=" prefix for below
        if(result.isError)
            return result;
        result = psql.putBytes(clientNonce);
        if(result.isError)
            return result;
        result = psql.putBytes(serverNonce);
        if(result.isError)
            return result;
        authMessageTranscript.put(psql.rawBuffer[start..psql.bufferCursor]);
        result = psql.putString(",");
        if(result.isError)
            return result;

        /++ Calculate the remaining signature data ++/
        
        /*
            AuthMessage     := client-first-message-bare + "," +
                            server-first-message + "," +
                            client-final-message-without-proof
        */
        auto authMessage = authMessageTranscript.slice;

        // ClientSignature := HMAC(StoredKey, AuthMessage)
        auto clientSignature = HMAC!SHA256(storedKey).put(authMessage).finish();

        // ClientProof     := ClientKey XOR ClientSignature
        auto clientProof = clientKey;
        clientProof[] ^= clientSignature[];

        // ServerKey       := HMAC(SaltedPassword, "Server Key")
        auto serverKey = HMAC!SHA256(saltedPassword).put(cast(const(ubyte)[])"Server Key").finish();

        // ServerSignature := HMAC(ServerKey, AuthMessage)
        serverSignature = HMAC!SHA256(serverKey).put(authMessage).finish();

        /++ Attach proof, and send the message ++/

        char[64] baseBuffer;
        size_t baseLength;

        scope putBase = (scope const(char)[] data)
        {
            baseBuffer[baseLength..baseLength+data.length] = data;
            baseLength += data.length;
            return Result.noError;
        };

        auto encoder = Base64Encoder!Base64Rfc4648Alphabet();
        result = encoder.encode(clientProof, putBase);
        if(result.isError)
            return result;
        result = encoder.finish(putBase);
        if(result.isError)
            return result;

        result = psql.putString("p=");
        if(result.isError)
            return result;
        result = psql.putString(baseBuffer[0..baseLength]);
        if(result.isError)
            return result;

        return Result.noError;
    });
    if(result.isError)
        return result;

    return psql.sendEntireBuffer();
}

package Result sendQueryMessage(
    scope ref PostgresProtocol psql,
    scope const(char)[] query, 
) @nogc nothrow
in(psql.bufferIsEmpty, "bug: buffer was expected to be empty")
{
    auto result = psql.putBytes(['Q']); // type byte of Query
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes(() => psql.putStringz(query));
    if(result.isError)
        return result;

    return psql.sendEntireBuffer();
}

package Result preparePrepareMessage(
    scope ref PostgresProtocol psql,
    scope const(char)[] name,
    scope const(char)[] query,
    scope const(PostgresDataTypeOid)[] paramTypes,
) @nogc nothrow
{
    auto result = psql.putBytes(['P']); // type byte of Prepare
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putStringz(name);
        if(result.isError)
            return result;

        result = psql.putStringz(query);
        if(result.isError)
            return result;

        result = psql.putInt!short(cast(short)paramTypes.length); // TODO: Bounds check
        if(result.isError)
            return result;

        foreach(type; paramTypes)
        {
            result = psql.putInt!int(type);
            if(result.isError)
                return result;
        }

        return Result.noError;
    });
    if(result.isError)
        return result;

    return Result.noError;
}

package Result prepareBindMessage(BindParameterT)(
    scope ref PostgresProtocol                      psql,
    scope const(char)[]                             portalName,
    scope const(char)[]                             statementName,
    scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
    scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
    scope BindParameterT                            bindParameterOrNull,
)
{
    auto result = psql.putBytes(['B']); // type byte of Bind
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putStringz(portalName);
        if(result.isError)
            return result;

        result = psql.putStringz(statementName);
        if(result.isError)
            return result;

        result = psql.putInt!short(cast(short)paramFormatCodes.length); // TODO: Bounds check
        if(result.isError)
            return result;
        foreach(type; paramFormatCodes)
        {
            result = psql.putInt!short(type);
            if(result.isError)
                return result;
        }

        const paramLengthCursor = psql.bufferCursor;
        result = psql.putInt!short(0);
        if(result.isError)
            return result;

        int paramCount;
        bool moreParamsToBind = (bindParameterOrNull !is null);
        while(moreParamsToBind)
        {
            result = psql.putLengthPrefixedBytes(
                () => bindParameterOrNull(paramCount++, psql, moreParamsToBind),
                includeLengthBytes: false,
            );
            if(result.isError)
                return result;
        }

        psql.putIntAt!short(cast(short)paramCount, paramLengthCursor); // TODO: Bounds check

        result = psql.putInt!short(cast(short)resultFormatCodes.length); // TODO: Bounds check
        if(result.isError)
            return result;
        foreach(type; resultFormatCodes)
        {
            result = psql.putInt!short(type);
            if(result.isError)
                return result;
        }

        return Result.noError;
    });
    if(result.isError)
        return result;

    return Result.noError;
}

package Result prepareDescribeMessage(
    scope ref PostgresProtocol psql,
    char type,
    scope const(char)[] name,
) @nogc nothrow
{
    auto result = psql.putBytes(['D']); // type byte of Describe
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putBytes([cast(ubyte)type]);
        if(result.isError)
            return result;

        result = psql.putStringz(name);
        if(result.isError)
            return result;

        return Result.noError;
    });
    if(result.isError)
        return result;

    return Result.noError;
}

package Result prepareExecuteMessage(
    scope ref PostgresProtocol psql,
    scope const(char)[] portalName,
    int maxRows,
) @nogc nothrow
{
    auto result = psql.putBytes(['E']); // type byte of Execute
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putStringz(portalName);
        if(result.isError)
            return result;

        result = psql.putInt!int(maxRows);
        if(result.isError)
            return result;

        return Result.noError;
    });
    if(result.isError)
        return result;

    return Result.noError;
}

package Result prepareCloseMessage(
    scope ref PostgresProtocol psql,
    char type,
    scope const(char)[] name,
) @nogc nothrow
{
    auto result = psql.putBytes(['C']); // type byte of Execute
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        auto result = psql.putBytes([cast(ubyte)type]);
        if(result.isError)
            return result;

        result = psql.putStringz(name);
        if(result.isError)
            return result;

        return Result.noError;
    });
    if(result.isError)
        return result;

    return Result.noError;
}

package Result sendSyncMessage(scope ref PostgresProtocol psql) @nogc nothrow
{
    auto result = psql.putBytes(['S']); // type byte of Sync
    if(result.isError)
        return result;

    result = psql.putLengthPrefixedBytes((){
        return Result.noError;
    });
    if(result.isError)
        return result;

    return psql.sendEntireBuffer();
}