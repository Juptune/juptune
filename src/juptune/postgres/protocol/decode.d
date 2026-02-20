/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.decode;

import std.sumtype : match;

import juptune.core.ds : Array;
import juptune.core.util : Result;
import juptune.data : MemoryReader;
import juptune.postgres.protocol.auth 
    : 
        AuthScheme, 
        AuthenticationSasl, 
        AuthenticationSaslContinue, 
        AuthenticationSuccess, 
        AuthenticationSaslComplete
    ;
import juptune.postgres.protocol.connection 
    : 
        PostgresProtocolError, 
        PostgresColumnDescription, 
        PostgresProtocol, 
        PostgresParameters
    ;

package Result decodeAuthentication(scope ref MemoryReader reader, scope out AuthScheme scheme) @nogc nothrow
{
    import juptune.core.ds : String;

    uint kind;
    auto success = reader.readU32BE(kind);
    if(!success)
        return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading authentication scheme of Authentication message"); // @suppress(dscanner.style.long_line)

    switch(kind)
    {
        case 0: // AuthenticationSuccess
            scheme = AuthenticationSuccess();
            return Result.noError;

        case 10: // AuthenticationSASL
            AuthenticationSasl sasl;
            while(reader.bytesLeft > 0)
            {
                const(char)[] mechanism;
                success = reader.readNullTerminatedString(mechanism);
                if(!success)
                    return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading mechanism of AuthenticationSASL message"); // @suppress(dscanner.style.long_line)

                switch(mechanism)
                {
                    case "SCRAM-SHA-256":
                        sasl.algorithmBitmask |= AuthenticationSasl.Algorithm.scram_sha_256;
                        break;

                    default: break;
                }
            }

            if(sasl.algorithmBitmask == AuthenticationSasl.Algorithm.FAILSAFE)
                return Result.make(PostgresProtocolError.noValidSaslAlgorithm, "server only provides SASL algorithms that are not supported by Juptune"); // @suppress(dscanner.style.long_line)
            scheme = sasl;
            return Result.noError;

        case 11: // AuthenticationSASLContinue
            AuthenticationSaslContinue cont;
            cont.serverFirstMessage = reader.buffer[reader.cursor..$];
            scheme = cont;
            return Result.noError;

        case 12: // AuthenticationSASLFinal
            AuthenticationSaslComplete comp;
            comp.serverLastMessage = reader.buffer[reader.cursor..$];
            scheme = comp;
            return Result.noError;

        default:
            return Result.make(
                PostgresProtocolError.unsupportedAuthScheme, 
                "when determining auth scheme of Authentication message, encountered unsupported scheme",
                String("got auth scheme of kind ", kind)
            );
    }
}

package Result decodeSaslContinue(
    scope ref MemoryReader reader,
    scope const(ubyte)[32] clientNonce,
    scope ref ubyte[32] serverNonce,
    scope ref size_t serverNonceLength,
    scope ref const(ubyte)[] serverSalt,
    scope ref uint iterationCount,
    scope ref Array!ubyte authMessageTranscript,
) @nogc nothrow
{
    import std.algorithm : splitter;

    import juptune.core.util : fromBase10;
    import juptune.data.base : Base64Decoder, Base64Rfc4648Alphabet;
    import juptune.postgres.protocol.decode : decodeAuthentication;

    AuthScheme scheme;
    auto result = decodeAuthentication(reader, scheme);
    if(result.isError)
        return result;

    AuthenticationSaslContinue cont;
    result = scheme.match!(
        (AuthenticationSaslContinue c) { cont = c; return Result.noError; },
        (_) => Result.make(PostgresProtocolError.unexpectedMessage, "when reading reply to SASLInitialResponse, expected AuthenticationSASLContinue"), // @suppress(dscanner.style.long_line)
    );
    if(result.isError)
        return result;

    authMessageTranscript.put(cont.serverFirstMessage, ',');

    foreach(segment; cont.serverFirstMessage.splitter(cast(ubyte)','))
    {
        if(segment.length < 2)
            return Result.make(PostgresProtocolError.invalidMessage, "when handling AuthenticationSASLContinue, one of its non-empty SCRAM arguments has less than 2 chars which is unexpected"); // @suppress(dscanner.style.long_line)

        switch(cast(const(char)[])segment[0..2])
        {
            case "r=":
                if(segment.length < (clientNonce.length + 2) || segment[2..clientNonce.length+2] != clientNonce) // + 2 to account for header bytes
                    return Result.make(PostgresProtocolError.invalidMessage, "when handling AuthenticationSASLContinue, 'r' attribute doesn't start with our client nonce"); // @suppress(dscanner.style.long_line)

                serverNonceLength = segment.length - (clientNonce.length + 2);
                serverNonce[0..serverNonceLength] = segment[$-serverNonceLength..$];
                break;

            case "s=":
                // We're reusing the buffer for decoding the base64 into - this is technically really bad practice buuuuut that's future Brad's problem.
                auto decoder = Base64Decoder!Base64Rfc4648Alphabet();
                
                size_t overwriteCursor;
                scope onChunk = (scope const ubyte[] bytes){
                    (cast(ubyte[])segment)[overwriteCursor..overwriteCursor+bytes.length] = bytes;
                    overwriteCursor += bytes.length;
                    return Result.noError;
                };

                result = decoder.decode(cast(const(char)[])segment[2..$], onChunk);
                if(result.isError)
                    return result;
                result = decoder.finish(onChunk);
                if(result.isError)
                    return result;

                serverSalt = (cast(ubyte[])segment)[0..overwriteCursor];
                break;

            case "i=":
                string error;
                iterationCount = fromBase10!uint(cast(const(char)[])segment[2..$], error);
                if(error.length > 0)
                    return Result.make(PostgresProtocolError.invalidMessage, "when handling AuthenticationSASLContinue, 'i' attribute contains an invalid number"); // @suppress(dscanner.style.long_line)
                break;

            default:
                import juptune.core.ds : String;
                return Result.make(
                    PostgresProtocolError.invalidMessage, 
                    "when handling AuthenticationSASLContinue, one of its SCRAM arguments is not recognised/supported",
                    String("got segment ", cast(const(char)[])segment)
                );
        }
    }

    return Result.noError;
}

package Result decodeSaslComplete(
    AuthScheme scheme,
    scope const(ubyte)[] ourServerSignature,
) @nogc nothrow
{
    import std.algorithm : splitter;

    import juptune.data.base : Base64Decoder, Base64Rfc4648Alphabet;

    AuthenticationSaslComplete comp;
    auto result = scheme.match!(
        (AuthenticationSaslComplete c) { comp = c; return Result.noError; },
        (_) => Result.make(PostgresProtocolError.unexpectedMessage, "when reading reply to SASLResponse, expected AuthenticationSaslComplete"), // @suppress(dscanner.style.long_line)
    );
    if(result.isError)
        return result;

    foreach(segment; comp.serverLastMessage.splitter(cast(ubyte)','))
    {
        if(segment.length < 2)
            return Result.make(PostgresProtocolError.invalidMessage, "when handling AuthenticationSaslComplete, one of its SCRAM arguments has less than 2 chars which is unexpected"); // @suppress(dscanner.style.long_line)

        switch(cast(const(char)[])segment[0..2])
        {
            case "v=":
                // We're reusing the buffer for decoding the base64 into - this is technically really bad practice buuuuut that's future Brad's problem.
                auto decoder = Base64Decoder!Base64Rfc4648Alphabet();
                
                size_t overwriteCursor;
                scope onChunk = (scope const ubyte[] bytes){
                    (cast(ubyte[])segment)[overwriteCursor..overwriteCursor+bytes.length] = bytes;
                    overwriteCursor += bytes.length;
                    return Result.noError;
                };

                result = decoder.decode(cast(const(char)[])segment[2..$], onChunk);
                if(result.isError)
                    return result;
                result = decoder.finish(onChunk);
                if(result.isError)
                    return result;

                const theirServerSignature = (cast(ubyte[])segment)[0..overwriteCursor];
                if(theirServerSignature != ourServerSignature)
                    return Result.make(PostgresProtocolError.invalidMessage, "when handling AuthenticationSaslComplete, server's 'v' attribute contains a server signature that differs from our one"); // @suppress(dscanner.style.long_line)
                break;

            default:
                import juptune.core.ds : String;
                return Result.make(
                    PostgresProtocolError.invalidMessage, 
                    "when handling AuthenticationSaslComplete, one of its SCRAM arguments is not recognised/supported",
                    String("got segment ", cast(const(char)[])segment)
                );
        }
    }

    return Result.noError;
}

package Result decodeErrorResponse(
    scope ref MemoryReader reader,
) @nogc nothrow
{
    import std.algorithm : min;

    import juptune.core.ds : Array, String;

    static struct Response
    {
        enum Severity : string
        {
            unknown = "UNKNOWN",
            error = "ERROR",
            fatal = "FATAL",
            panic = "PANIC",
            warning = "WARNING",
            notice = "NOTICE",
            debug_ = "DEBUG",
            info = "INFO",
            log = "LOG",
        }

        Severity severity;
        char[5] sqlstateCode;
        const(char)[] message; // Will be subslice of PostgresProtocol's read buffer
        const(char)[] detail; // Will be subslice of PostgresProtocol's read buffer
        const(char)[] hint; // Will be subslice of PostgresProtocol's read buffer
        const(char)[] position;
        const(char)[] where;
        const(char)[] schema;
        const(char)[] table;
        const(char)[] column;
        const(char)[] dataType;
        const(char)[] constraint;
    }

    /++ Read in the actual response ++/
    Response resp;
    while(reader.bytesLeft > 0)
    {
        ubyte type;
        const(char)[] data;

        auto success = reader.readU8(type);
        assert(success, "bug: success can't be false here?");

        if(type == 0 && reader.bytesLeft == 0) // Null sentinel value.
            break;

        success = reader.readNullTerminatedString(data);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "when reading ErrorResponse, ran out of bytes when reading null terminated string"); // @suppress(dscanner.style.long_line)

        switch(cast(char)type)
        {
            case 'V':
                switch(data)
                {
                    case "ERROR": resp.severity = Response.Severity.error; break;
                    case "FATAL": resp.severity = Response.Severity.fatal; break;
                    case "PANIC": resp.severity = Response.Severity.panic; break;
                    case "WARNING": resp.severity = Response.Severity.warning; break;
                    case "NOTICE": resp.severity = Response.Severity.notice; break;
                    case "DEBUG": resp.severity = Response.Severity.debug_; break;
                    case "INFO": resp.severity = Response.Severity.info; break;
                    case "LOG": resp.severity = Response.Severity.log; break;

                    default: resp.severity = Response.Severity.unknown; break;
                }
                break;

            case 'C':
                const len = min(data.length, resp.sqlstateCode.length);
                resp.sqlstateCode[0..len] = data[0..len];
                break;

            case 'M':
                resp.message = data;
                break;

            case 'D':
                resp.detail = data;
                break;

            case 'H':
                resp.hint = data;
                break;

            case 'P':
                resp.position = data;
                break;

            case 'W':
                resp.where = data;
                break;

            case 's':
                resp.schema = data;
                break;

            case 't':
                resp.table = data;
                break;

            case 'c':
                resp.column = data;
                break;

            case 'd':
                resp.dataType = data;
                break;
            
            case 'n':
                resp.constraint = data;
                break;

            default: break; // Ignore unknown attributes
        }
    }

    /++ Then decide on how to format it as an error ++/
    Array!char msg;

    // Generic formatting case
    msg.put('[');
    msg.put(resp.severity);
    if(resp.sqlstateCode[0] != char.init)
        msg.put(" | SQLSTATE ", resp.sqlstateCode);
    if(resp.schema.length > 0)
        msg.put(" | SCHEMA ", resp.schema);
    if(resp.table.length > 0)
        msg.put(" | TABLE ", resp.table);
    if(resp.column.length > 0)
        msg.put(" | COLUMN ", resp.column);
    if(resp.dataType.length > 0)
        msg.put(" | DATATYPE ", resp.dataType);
    if(resp.constraint.length > 0)
        msg.put(" | CONSTRAINT ", resp.constraint);
    if(resp.position.length > 0)
        msg.put(" | POSITION ", resp.position);
    msg.put("] ", resp.message);

    if(resp.detail.length > 0)
        msg.put('\n', resp.detail);
    if(resp.hint.length > 0)
        msg.put("\nHINT: ", resp.hint);

    return Result.make(PostgresProtocolError.errorResponse, "operation generated an ErrorResponse", String.fromDestroyingArray(msg)); // @suppress(dscanner.style.long_line)
}

package Result decodeRowDescription(HandlerT)(
    scope ref MemoryReader reader,
    scope HandlerT onRowDescription,
)
{
    ushort columnCount;

    auto success = reader.readU16BE(columnCount);
    if(!success)
        return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription row count"); // @suppress(dscanner.style.long_line)

    return onRowDescription(columnCount, (scope out PostgresColumnDescription desc){
        success = reader.readNullTerminatedString(desc.nameDoNotCopy);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription column name"); // @suppress(dscanner.style.long_line)
        
        success = reader.readI32BE(desc.tableObjectId);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription table OID"); // @suppress(dscanner.style.long_line)

        success = reader.readU16BE(desc.columnAttributeNumber);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription column attribute number"); // @suppress(dscanner.style.long_line)

        int dataType;
        success = reader.readI32BE(dataType);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription data type"); // @suppress(dscanner.style.long_line)
        desc.dataType = cast(typeof(desc.dataType))dataType;

        success = reader.readI16BE(desc.dataTypeSize);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription data type size"); // @suppress(dscanner.style.long_line)

        success = reader.readI32BE(desc.dataTypeModifier);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription data type modifier"); // @suppress(dscanner.style.long_line)

        ushort format;
        success = reader.readU16BE(format);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowDescription format"); // @suppress(dscanner.style.long_line)
        desc.format = cast(typeof(desc.format))format;

        return Result.noError;
    });
}

package Result decodeRowData(HandlerT)(
    scope ref MemoryReader reader,
    scope HandlerT onDataRow,
)
{
    ushort columnCount;

    auto success = reader.readU16BE(columnCount);
    if(!success)
        return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowData row count"); // @suppress(dscanner.style.long_line)

    return onDataRow(columnCount, (scope out MemoryReader columnReader, scope out bool isNull){
        int length;
        success = reader.readI32BE(length);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowData column data length"); // @suppress(dscanner.style.long_line)

        if(length == -1)
        {
            isNull = true;
            return Result.noError;
        }

        const(ubyte)[] subslice;
        success = reader.readBytes(length, subslice);
        if(!success)
            return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading RowData column data bytes"); // @suppress(dscanner.style.long_line)

        columnReader = MemoryReader(subslice);
        return Result.noError;
    });
}

/++ Parameters ++/

package Result decodeParameterStatus(
    scope ref MemoryReader reader,
    scope ref PostgresParameters params,
) @nogc nothrow
{
    const(char)[] name;
    const(char)[] value;

    auto success = reader.readNullTerminatedString(name);
    if(!success)
        return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading ParameterStatus name");

    success = reader.readNullTerminatedString(value);
    if(!success)
        return Result.make(PostgresProtocolError.notEnoughBytes, "ran out of bytes when reading ParameterStatus value");

    switch(name)
    {
        case "DateStyle":
            return onDateStyleParam(value, params);

        default:
            return Result.noError;
    }
}

private Result onDateStyleParam(scope const(char)[] value, scope ref PostgresParameters params) @nogc nothrow
{
    import std.algorithm : splitter;

    import juptune.core.ds : String;

    auto range = value.splitter(", ");
    foreach(component; range)
    {
        switch(component)
        {
            case "ISO":
                params.dateStyle = PostgresParameters.DateStyle.iso;
                break;

            case "MDY":
                params.dateOrder = PostgresParameters.DateOrder.mdy;
                break;

            default:
                return Result.make(PostgresProtocolError.limitation, "unrecognised/unsupported DateStyle parameter component", String(component)); // @suppress(dscanner.style.long_line)
        }
    }

    return Result.noError;
}