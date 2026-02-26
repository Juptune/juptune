/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.connection;

import core.time : Duration;

import juptune.core.util : Result;

/// `Result` error enum
enum PostgresProtocolError
{
    none,
    bufferTooSmall,
    unexpectedMessage,
    missingMessage,
    notEnoughBytes,
    unsupportedAuthScheme,
    noValidSaslAlgorithm,
    invalidMessage,
    limitation,
    errorResponse,
    emptyQuery,
}

/// Enum of recognised versions for the Postgres Protocol
enum PostgresProtocolVersion
{
    FAILSAFE,
    v3_0 = (3 << 16) | (0),
    v3_2 = (3 << 16) | (2),
}

/// Supported modes for negotiating a TLS.
enum PostgresTlsMode
{
    FAILSAFE,

    /// Never attempt to negotiate TLS.
    never,

    /// Attempt to negotiate TLS, but fallback to plaintext if the server doesn't want to use it.
    ifPossible,

    /// Attempt to negotiate TLS, but fail the connection if the server doesn't want to use it.
    always,
}

/// Information for connecting to a Postgres instance.
struct PostgresConnectInfo
{
    import juptune.data.x509 : X509CertificateStore;

    // Connection info
    const(char)[] user; /// The username to connect as.
    const(char)[] databaseOrNull; /// The database to connect to. If `null` then the value of `user` is used as the database name.
    const(char)[] plaintextPassword; /// The plaintext password to use if password authentication is required.

    // TLS info
    PostgresTlsMode tlsMode; /// TLS negotiation mode.
    X509CertificateStore* customStore; /// If not `null`, then this store is used to validate the cluster's server certificate. If `null` then the host platform's default store is used instead.
    X509CertificateStore.SecurityPolicy x509Policy; /// Policy for authenticating the server's certificate.
}

/// General configuration for the low-level `PostresProtocol` struct.
struct PostgresProtocolConfig
{
    /// The minimum amount of buffer space (for reading and writing) to keep allocated at all times.
    size_t minBufferSpace = 1024 * 8;

    /++
     + The maximum amount of buffer space (for reading an writing) that's allowed to be dynamically allocated
     + when sending/reading messages.
     +
     + If this limit is exceeded then `PostgresProtocolError.bufferTooSmall` will be thrown by most `PostgresProtocol` functions.
     +
     + The buffer's length gets reset to `minBufferSpace` after every flush to the network. (Note: Due to how `Array`'s default capacity
     + mechanism works, once the buffer has grown it will likely always be slightly larger than `minBufferSpace` in reality).
     + ++/
    size_t maxBufferSpace = size_t.max;

    /// Timeout for any socket write operations.
    Duration writeTimeout = Duration.zero;

    /// Timeout for any socket read operations.
    Duration readTimeout = Duration.zero;

    @safe @nogc nothrow:

    PostgresProtocolConfig withMinBufferSize(size_t value) { this.minBufferSpace = value; return this; }
    PostgresProtocolConfig withMaxBufferSize(size_t value) { this.maxBufferSpace = value; return this; }
    PostgresProtocolConfig withWriteTimeout(Duration value) { this.writeTimeout = value; return this; }
    PostgresProtocolConfig withReadTimeout(Duration value) { this.readTimeout = value; return this; }
}

/++
 + A collection of parameters that are meaningful to Juptune in some way.
 + ++/
struct PostgresParameters
{
    /// What format textual dates use (but only if they're not already in ISO YMD format, e.g. the first 4 characters aren't the year).
    enum DateStyle
    {
        FAILSAFE,
        iso,
    }

    /// What format textual dates order the year-month-day triple (but only if they're not already in ISO YMD format).
    enum DateOrder
    {
        FAILSAFE,
        ymd,
        dmy,
        mdy,
    }

    DateStyle dateStyle = DateStyle.iso;
    DateOrder dateOrder = DateOrder.mdy;
}

/++
 + Contains information about a particular column. This represents either a column in a table, or
 + a column within a query's return result.
 + ++/
struct PostgresColumnDescription
{
    import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

    /// What wire format the value will be in.
    enum Format : byte
    {
        FAILSAFE = -1,
        text = 0,
        binary = 1,
    }

    /++
     + The name of the column. This will almost always be provided as an internal slice into `PostgresProtocol`'s buffer,
     + so **please perform a full copy of the memory within the slice** rather than a by-value copy of just the slice itself,
     + if the name needs to be persisted.
     + ++/
    const(char)[] nameDoNotCopy;

    /// If applicable, the object ID of the table this column belongs to. Otherwise 0.
    int tableObjectId;

    /// If applicable, the attribute number of this column from within a table. Otherwise 0.
    ushort columnAttributeNumber;

    /// The data type stored by this column.
    PostgresDataTypeOid dataType;

    /// The exact amount of bytes taken up by this data type (I _believe_ when in its binary format).
    /// A value < 0 indicates a variable length type.
    short dataTypeSize;

    /// Some data types have additional modifiers which are expressed via this field on a per-datatype basis.
    int dataTypeModifier;

    /// How the value of this column is transferred over the wire.
    Format format;
}

package enum PostgresMessageType : char
{
    FAILSAFE,
    authentication = 'R',
    backendKeyData = 'K',
    bind = 'B',
    bindComplete = '2',
    close = 'C', // client -> server only
    closeComplete = '3',
    commandComplete = 'C', // server -> client only
    copyData = 'd',
    copyDone = 'c',
    copyFail = 'f',
    copyInResponse = 'G',
    copyOutResponse = 'H', // server -> client only
    copyBothResponse = 'W',
    dataRow = 'D', // server -> client only
    describe = 'D', // client -> server only
    emptyQueryResponse = 'I',
    errorResponse = 'E', // server -> client only
    execute = 'E', // client -> server only
    flush = 'H', // client -> server only
    functionCall = 'F',
    functionCallResponse = 'V',
    negotiateProtocolVersion = 'v',
    noData = 'n',
    noticeResponse = 'N',
    notificationResponse = 'A',
    parameterDescription = 't',
    parameterStatus = 'S', // server -> client only
    parse = 'P',
    parseComplete = '1',
    passwordMessage = 'p',
    portalSuspended = 's',
    query = 'Q',
    readyForQuery = 'Z',
    rowDescription = 'T',
    sync = 'S', // client -> server only
    terminate = 'X',
}

/++
 + A lowish-level client providing functionality for connecting and communicating to a server using the Postgres protocol.
 +
 + The idea of this particular struct is to be a very raw, straightforward-yet-clunky way of accessing the actual
 + Postgres protocol with as little overhead as possible, and that other higher-level abstractions can be built on 
 + top of it for more comfortable use cases.
 +
 + Memory:
 +  Unlike a lot of other protocol implementations within Juptune, this struct will dynamically manage its own memory rather
 +  than using preallocated user-provided buffers.
 +
 +  This is because the easiest way (by far) to deal with Postgres protocol messages is to read them entirely into memory first before
 +  processing them, rather than trying to piece a bunch of network reads together using a single smaller buffer.
 +
 +  Due to the natural variability of payload sizes when using a database like Postgres, it's inevitable that said buffer would either
 +  need to be _very_ large to handle the occasional large payload, or _dynamic_ so that it can handle general workloads without wasting
 +  as much memory all the time.
 +
 +  This is of course a tradeoff, however it is exceedingly more likely that Postgres itself will be the bottleneck rather than the ultimately
 +  minimal performance costs of constantly (in the worst case) resizing an internal buffer.
 +
 + Usage:
 +  Internally a state machine is used to ensure correct usage of this struct.
 +
 +  First call `.connect` to connect and authenticate to a Postgres instance.
 +
 +  For simple querying (where you don't need any external parameters being passed in), use `.simpleQuery`.
 +
 +  For advanced/prepared querying, first call `.prepare` to prepare the query; then call `bindDescribeExecute` to actually
 +  execute the query, and optionally call `.close` so that the server can release resources associated with the prepared statement.
 +
 + Limitations:
 +  Currently only SCRAM-SHA-256 is supported as the authentication method.
 +
 +  Unix sockets as a transport medium are not supported.
 +
 +  Not all parts of the protocol are implemented, e.g. replication streaming, COPY support, query cancellation.
 + ++/
struct PostgresProtocol
{
    import juptune.core.ds : Array;
    import juptune.core.util : StateMachineTypes;
    import juptune.data : MemoryReader;
    import juptune.event.io : TcpSocket, IpAddress;
    import juptune.http.tls : TlsTcpSocket;
    import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

    /// Delegate for handling a raw incoming Postgres message - currently not used by the public API.
    alias MessageHandlerT = Result delegate(PostgresMessageType type, scope ref MemoryReader reader) @nogc nothrow;

    /// A callback provided by `PostgresProtocol` which will fetch the next `PostgresColumnDescription` from a protocol message.
    alias NextColumnDescriptionT = Result delegate(scope out PostgresColumnDescription desc) @nogc nothrow;
    /// A callback provided by `PostgresProtocol` which will fetch the next raw bytes of a column value from a protocol message.
    alias NextColumnDataT = Result delegate(scope out MemoryReader valueReader, scope out bool isNull) @nogc nothrow;

    /// A callback provided by the user which gives them a chance to inspect all `PostgresColumnDescription` for a query/table.
    /// The `nextDescription` callback can only be called up to `columnCount` amount of times.
    alias ColumnDescriptionHandlerT = Result delegate(ushort columnCount, scope NextColumnDescriptionT nextDescription) @nogc nothrow; // @suppress(dscanner.style.long_line)
    /// A callback provided by the user which gives them a chance to retrieve all data for a query.
    /// The `nextData` callback can only be called up to `columnCount` amount of times.
    alias DataRowHandlerT = Result delegate(ushort columnCount, scope NextColumnDataT nextData) @nogc nothrow;
    /// A callback provided by the user which gives them a chance to bind as many parameters as they desire to a prepared statement.
    alias BindParameterHandlerT = Result delegate(const int paramIndex, scope ref PostgresProtocol psql, scope out bool moreParamsLeftToBind) @nogc nothrow; // @suppress(dscanner.style.long_line)

    alias ColumnDescriptionHandlerGcT = Result delegate(ushort columnCount, scope NextColumnDescriptionT nextDescription); // @suppress(dscanner.style.long_line)
    alias DataRowHandlerGcT = Result delegate(ushort columnCount, scope NextColumnDataT nextData);
    alias BindParameterHandlerGcT = Result delegate(const int paramIndex, scope ref PostgresProtocol psql, scope out bool moreParamsLeftToBind); // @suppress(dscanner.style.long_line)

    private
    {
        alias Machine = StateMachineTypes!(State, void*);
        alias StateMachine = Machine.Static!([
            Machine.Transition(State.notConnected, State.readyForQuery),
            Machine.Transition(State.readyForQuery, State.handlingQuery),
            Machine.Transition(State.handlingQuery, State.readyForQuery),
            Machine.Transition(State.handlingQuery, State.bindingParams),
            Machine.Transition(State.bindingParams, State.handlingQuery),
        ]);

        enum State
        {
            FAILSAFE,
            notConnected,
            readyForQuery,
            handlingQuery,
            bindingParams,
        }

        StateMachine _state;
        PostgresProtocolConfig _config;
        PostgresParameters _parameters;

        TcpSocket _plaintextSocket;
        TlsTcpSocket _encryptedSocket;
        bool _useEncryptedSocket;

        Array!ubyte _buffer;
        size_t _cursor;
    }

    @disable this(this);

    /++ 
     + Initialises a new `PostgresProtocol` instance. You should call `.connect` after this.
     +
     + Params:
     +   config = Configuration on how to handle certain aspects of the protocol/networking.
     + ++/
    this(PostgresProtocolConfig config) @nogc nothrow pure
    {
        this._config = config;
        this._state = StateMachine(State.notConnected);
    }

    /++ Public API (connecting) ++/

    /++
     + Attempts to connect to the server at the given IP address. 
     +
     + The client will attempt to negotiate whether to use a TLS socket, or a TCP socket as per `connectInfo.tlsMode`.
     +
     + The client will automatically attempt to use `connectInfo.password` for authentication if challenged by the server.
     + It will also automatically handle any supported authentication schemes.
     +
     + Assertions:
     +  You can only call this function once per `PostgresProtocol` instance, please reconstruct the instance if you'd like
     +  to attempt another connection.
     +
     + Params:
     +  address     = The IP address & port of the server to connect to.
     +  connectInfo = Information on how to attempt the connection.
     +
     + Throws:
     +  `PostgresProtocolError.noValidSaslAlgorithm` if a SASL-based authentication scheme was chosen, however none of the available
     +  schemes are supported by `PostgresProcotol`.
     +
     +  `PostgresProtocolError.unsupportedAuthScheme` if no supported auth schemes are available.
     +
     +  `PostgresProtocolError.missingMessage` if the server didn't send an Authentication message when expected.
     +
     +  `PostgresProtocolError.bufferTooSmall` if the buffer would exceed `PostgresProtocolConfig.maxBufferSize` when reading or writing.
     +
     +  `PostgresProtocolError.unexpectedMessage` if an unexpected message was returned by the server.
     +
     +  `PostgresProtocolError.invalidMessage` if a message returned by the server is in some way malformed.
     +
     +  `PostgresProtocolError.notEnoughBytes` if the server didn't send enough bytes than expected (more likely a Juptune parsing bug).
     +
     +  `PostgresProtocolError.errorResponse` if the server returned an ErrorResponse message.
     +
     +  Anything that `TcpSocket` and `TlsSocket` can throw.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result connect(IpAddress address, scope PostgresConnectInfo connectInfo) @nogc nothrow
    in(this._state.mustBeIn(State.notConnected))
    {
        import std.typecons : Nullable;

        import juptune.postgres.protocol.auth : AuthScheme, authenticate;
        import juptune.postgres.protocol.decode : decodeAuthentication, decodeParameterStatus;
        import juptune.postgres.protocol.encode : sendStartupMessage;

        // Connect and negotiate TLS
        auto result = this._plaintextSocket.open();
        if(result.isError)
            return result.wrapError("when opening socket for postgres server:");

        result = this._plaintextSocket.connect(address);
        if(result.isError)
            return result.wrapError("when connecting to postgres server:");

        final switch(connectInfo.tlsMode) with(PostgresTlsMode)
        {
            case never: break;
            
            case ifPossible:
            case always:
                this._useEncryptedSocket = true;
                assert(false, "TODO: Implement negotiation message");

            case FAILSAFE: assert(false, "FAILSAFE");
        }
        this._buffer.length = this._config.minBufferSpace;

        // Send startup message and handle any responses
        result = sendStartupMessage(this, connectInfo.user, connectInfo.databaseOrNull);
        if(result.isError)
            return result;

        Nullable!AuthScheme authScheme;

        result = this.nextMessagesImpl((PostgresMessageType type, scope ref MemoryReader reader){
            switch(type) with(PostgresMessageType)
            {
                case authentication:
                    AuthScheme scheme;
                    result = decodeAuthentication(reader, scheme);
                    if(result.isError)
                        return result;
                    authScheme = scheme;
                    break;

                default:
                    import juptune.core.ds : String;
                    return Result.make(
                        PostgresProtocolError.unexpectedMessage,
                        "encountered unexpected message when reading reply to StartupMessage",
                        String("got message of type ", type)
                    );
            }
            return Result.noError;
        }, (){
            return false;
        });
        if(result.isError)
            return result;

        if(authScheme.isNull)
            return Result.make(PostgresProtocolError.missingMessage, "expected Authentication message in response to StartupMessage"); // @suppress(dscanner.style.long_line)

        // Authenticate and handle any responses
        this.resetBuffer();
        result = authenticate(
            this, 
            authScheme.get, 
            connectInfo.user, 
            connectInfo.plaintextPassword,
            (PostgresMessageType type, scope ref MemoryReader reader){
                switch(type) with(PostgresMessageType)
                {
                    case backendKeyData: break; // We don't implement any features used by this right now, so discard it.

                    case parameterStatus:
                        return decodeParameterStatus(reader, this._parameters);

                    default:
                        import juptune.core.ds : String;
                        return Result.make(
                            PostgresProtocolError.unexpectedMessage,
                            "encountered unexpected message when reading reply to authentication",
                            String("got message of type ", type)
                        );
                }
                return Result.noError;
            }
        );
        if(result.isError)
            return result;

        this.resetBuffer();
        this._state.mustTransition!(State.notConnected, State.readyForQuery);
        return Result.noError;
    }

    /// The current set of parameters the client & server are operation under.
    ref const(PostgresParameters) params() @nogc nothrow const
    {
        return this._parameters;
    }

    /++
     + Whether or not this instance is "safe" to use/ready to issues query-related messages.
     +
     + The primary usage of this function is to check if the connection is still viable after handling
     + an errorful `Result` from a query-related function.
     +
     + If this function returns `false` after an errorful `Result` is produced, cease using this instance immediately
     + as you'll otherwise trigger an assert to fail (hopefully).
     + ++/
    bool isReadyToQuery() @nogc nothrow
    {
        return this._state.isIn(State.readyForQuery);
    }

    /++ Public API (querying) ++/

    /++
     + Sends a simple Query message and calls the user-provided callbacks to handle any results.
     +
     + Simple querying is useful for queries that have more than 1 statement and/or don't require the use of placeholders
     + for their parameters.
     +
     + Notes: 
     +  All slices that are passed to `onRowDescriptionOrNull` and `onDataRowNull` are slices to the internal buffer of this struct,
     +  you must perform a **full memory copy of these slices** if you wish to persist any of the data returned to you.
     +
     +  Failure to do this will lead to values being changed under your nose, and in the worst case memory corruption/security exploits.
     +
     +  Under most circumstances, when an error is produced it is safe to continue using an instance of this struct as it
     +  will attempt to self-correct. User code should use `.isReadyToQuery` to double check whether continued use is safe.
     +
     + Assertions:
     +  This function can only be called once `.connect` succesfully executes.
     +
     +  If either `onRowDescriptionOrNull` or `onDataRowOrNull` are `null`, then they _both_ must be `null`. You're either handling the results,
     +  or you're not.
     +
     + Params:
     +  query                   = The SQL query to execute.
     +  onRowDescriptionOrNull  = If not null, then this function is called a single time once the colmun descriptions 
     +                            for the query's return results are available.
     +  onDataRowOrNull         = If not null, then this function is called multiple times - once for each row
     +                            returned by the query - when the raw bytes for the row's values are available.
     +                            This function should call into the decode functions within `juptune.postgres.protocol.datatype`.
     +
     + Throws:
     +  Anything that `onRowDescriptionOrNull` and `onDataRowOrNull` can throw.
     +
     +  `PostgresProtocolError.emptyQuery` if the server returned an EmptyQuery response.
     +
     +  `PostgresProtocolError.bufferTooSmall` if the buffer would exceed `PostgresProtocolConfig.maxBufferSize` when reading or writing.
     +
     +  `PostgresProtocolError.unexpectedMessage` if an unexpected message was returned by the server.
     +
     +  `PostgresProtocolError.invalidMessage` if a message returned by the server is in some way malformed.
     +
     +  `PostgresProtocolError.notEnoughBytes` if the server didn't send enough bytes than expected (more likely a Juptune parsing bug).
     +
     +  `PostgresProtocolError.errorResponse` if the server returned an ErrorResponse message.
     +
     +  Anything that `.put` and `.recieve` for `TcpSocket` and `TlsSocket` can throw.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result simpleQuery(
        scope const(char)[] query,
        scope ColumnDescriptionHandlerT onRowDescriptionOrNull,
        scope DataRowHandlerT onDataRowOrNull,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    {
        return this.simpleQueryImpl(query, onRowDescriptionOrNull, onDataRowOrNull);
    }

    // ditto.
    Result simpleQueryGc(
        scope const(char)[] query,
        scope ColumnDescriptionHandlerGcT onRowDescriptionOrNull,
        scope DataRowHandlerGcT onDataRowOrNull,
    )
    in(this._state.mustBeIn(State.readyForQuery))
    {
        return this.simpleQueryImpl(query, onRowDescriptionOrNull, onDataRowOrNull);
    }

    /++
     + Sends a Prepare message (followed by a Sync message), which generates a prepared query that can then be used with `bindDescribeExecute`.
     +
     + Notes: 
     +  Under most circumstances, when an error is produced it is safe to continue using an instance of this struct as it
     +  will attempt to self-correct. User code should use `.isReadyToQuery` to double check whether continued use is safe.
     +
     + Assertions:
     +  This function can only be called once `.connect` succesfully executes.
     +
     + Params:
     +  statementName   = The name to give the prepared statement, can be null/empty.
     +  query           = The prepared statment, reminder that the placeholder syntax is `$1`, `$2`, etc. 
     +  paramTypes      = Pre-specifies the data types of placeholders within the query, e.g. paramTypes[0] is the type of `$1` and so on.
     +                    This can be any length, extras are ignored, and if a placeholder isn't given an explcit type then Postgres
     +                    will try to infer it. You can also define placeholders like `$1::time` within the query itself.
     +
     + Throws:
     +  `PostgresProtocolError.bufferTooSmall` if the buffer would exceed `PostgresProtocolConfig.maxBufferSize` when reading or writing.
     +
     +  `PostgresProtocolError.unexpectedMessage` if an unexpected message was returned by the server.
     +
     +  `PostgresProtocolError.invalidMessage` if a message returned by the server is in some way malformed.
     +
     +  `PostgresProtocolError.notEnoughBytes` if the server didn't send enough bytes than expected (more likely a Juptune parsing bug).
     +
     +  `PostgresProtocolError.errorResponse` if the server returned an ErrorResponse message.
     +
     +  Anything that `.put` and `.recieve` for `TcpSocket` and `TlsSocket` can throw.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result prepare(
        scope const(char)[] statementName,
        scope const(char)[] query,
        scope const(PostgresDataTypeOid)[] paramTypes,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        import juptune.postgres.protocol.encode : preparePrepareMessage, sendSyncMessage;

        this._state.mustTransition!(State.readyForQuery, State.handlingQuery);

        auto result = preparePrepareMessage(this, statementName, query, paramTypes);
        if(result.isError)
            return result;

        result = sendSyncMessage(this);
        if(result.isError)
            return result;

        result = this.nextMessagesReadyForQueryCase(
            (PostgresMessageType type, scope ref MemoryReader reader)
            {
                switch(type) with(PostgresMessageType)
                {
                    case parseComplete:
                        // Just ignore it.
                        return Result.noError;

                    default:
                        import juptune.core.ds : String;
                        return Result.make(
                            PostgresProtocolError.unexpectedMessage,
                            "encountered unexpected message when reading reply to Prepare",
                            String("got message of type ", type)
                        );
                }
            },
        );
        if(result.isError)
            return result;
        
        this.resetBuffer();
        return Result.noError;
    }

    /++
     + Sends a Bind, Describe, and Execute message (followed by a Sync message) simultaneously, which effectively
     + binds parameters onto a prepared statement; describes what the return results are, and then executes the query
     + which provides the actual return results.
     +
     + Notes: 
     +  Under most circumstances, when an error is produced it is safe to continue using an instance of this struct as it
     +  will attempt to self-correct. User code should use `.isReadyToQuery` to double check whether continued use is safe.
     +
     + Assertions:
     +  This function can only be called once `.connect` succesfully executes.
     +
     + Params:
     +  statementName           = The name of a prepared statement previously prepared by `.prepare`. This may be null/empty.
     +  paramFormatCodes        = Describes the wire format for all parameters. `null` means "everything is text", a single
     +                            value means "everything is what I specify", otherwise it must match the number of parameters
     +                            bound by `bindParameterOrNull` where each value corresponds to a single parameter.
     +  resultFormatCodes       = Describes the wire format for all return values. Follows the same logic as `paramFormatCodes`
     +                            except for the count of returned columns per row, rather than the count of bound parameters.
     +  bindParameterOrNull     = If not null, this callback is repeatedly called until the `moreParamsLeftToBind` passed into it
     +                            becomes `false`. Each time this function is called, it should call into one of the encode functions
     +                            within `juptune.postgres.protocol.datatypes` to encode a single parameter.
     +  onRowDescriptionOrNull  = If not null, then this function is called a single time once the colmun descriptions 
     +                            for the query's return results are available. 
     +  onDataRowOrNull         = If not null, then this function is called multiple times - once for each row
     +                            returned by the query - when the raw bytes for the row's values are available.
     +                            This function should call into the decode functions within `juptune.postgres.protocol.datatype`.
     +
     + Throws:
     +  Anything that `bindParameterOrNull`, `onRowDescriptionOrNull`, and `onDataRowOrNull` can throw.
     +
     +  `PostgresProtocolError.bufferTooSmall` if the buffer would exceed `PostgresProtocolConfig.maxBufferSize` when reading or writing.
     +
     +  `PostgresProtocolError.unexpectedMessage` if an unexpected message was returned by the server.
     +
     +  `PostgresProtocolError.invalidMessage` if a message returned by the server is in some way malformed.
     +
     +  `PostgresProtocolError.notEnoughBytes` if the server didn't send enough bytes than expected (more likely a Juptune parsing bug).
     +
     +  `PostgresProtocolError.errorResponse` if the server returned an ErrorResponse message.
     +
     +  Anything that `.put` and `.recieve` for `TcpSocket` and `TlsSocket` can throw.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result bindDescribeExecute(
        scope const(char)[]                             statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterHandlerT                     bindParameterOrNull,
        scope ColumnDescriptionHandlerT                 onRowDescriptionOrNull,
        scope DataRowHandlerT                           onDataRowOrNull,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        return this.bindDescribeExecuteImpl("", statementName, paramFormatCodes, resultFormatCodes, bindParameterOrNull, onRowDescriptionOrNull, onDataRowOrNull); // @suppress(dscanner.style.long_line)
    }

    /// ditto.
    Result bindDescribeExecuteGc(
        scope const(char)[]                             statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterHandlerGcT                   bindParameterOrNull,
        scope ColumnDescriptionHandlerGcT               onRowDescriptionOrNull,
        scope DataRowHandlerGcT                         onDataRowOrNull,
    )
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        return this.bindDescribeExecuteImpl("", statementName, paramFormatCodes, resultFormatCodes, bindParameterOrNull, onRowDescriptionOrNull, onDataRowOrNull); // @suppress(dscanner.style.long_line)
    }

    /// ditto.
    Result bindDescribeExecuteInfer(BindParameterT, ColumnHandlerT, DataHandlerT)(
        scope const(char)[]                             statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterT                            bindParameterOrNull,
        scope ColumnHandlerT                            onRowDescriptionOrNull,
        scope DataHandlerT                              onDataRowOrNull,
    )
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        return this.bindDescribeExecuteImpl("", statementName, paramFormatCodes, resultFormatCodes, bindParameterOrNull, onRowDescriptionOrNull, onDataRowOrNull); // @suppress(dscanner.style.long_line)
    }

    /++
     + Sends a Close message (followed by a Sync message) simultaneously, which tells the backend to close a prepared
     + statement by its name. If no prepared statement for the given name exists, then nothing happens.
     +
     + Notes: 
     +  Under most circumstances, when an error is produced it is safe to continue using an instance of this struct as it
     +  will attempt to self-correct. User code should use `.isReadyToQuery` to double check whether continued use is safe.
     +
     + Assertions:
     +  This function can only be called once `.connect` succesfully executes.
     +
     + Params:
     +  statementName = The name of a prepared statement previously prepared by `.prepare`. This may be null/empty.
     +
     + Throws:
     +  `PostgresProtocolError.bufferTooSmall` if the buffer would exceed `PostgresProtocolConfig.maxBufferSize` when reading or writing.
     +
     +  `PostgresProtocolError.unexpectedMessage` if an unexpected message was returned by the server.
     +
     +  `PostgresProtocolError.invalidMessage` if a message returned by the server is in some way malformed.
     +
     +  `PostgresProtocolError.notEnoughBytes` if the server didn't send enough bytes than expected (more likely a Juptune parsing bug).
     +
     +  `PostgresProtocolError.errorResponse` if the server returned an ErrorResponse message.
     +
     +  Anything that `.put` and `.recieve` for `TcpSocket` and `TlsSocket` can throw.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result closeStatement(scope const(char)[] statementName) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    {
        import juptune.postgres.protocol.encode : prepareCloseMessage, sendSyncMessage;

        this._state.mustTransition!(State.readyForQuery, State.handlingQuery);

        auto result = prepareCloseMessage(this, 'S', statementName);
        if(result.isError)
            return result;

        result = sendSyncMessage(this);
        if(result.isError)
            return result;

        return this.nextMessagesReadyForQueryCase((PostgresMessageType type, scope ref MemoryReader reader) {
            switch(type) with(PostgresMessageType)
            {
                case closeComplete:
                    // Just ignore it.
                    return Result.noError;

                default:
                    import juptune.core.ds : String;
                    return Result.make(
                        PostgresProtocolError.unexpectedMessage,
                        "encountered unexpected message when reading reply to Close",
                        String("got message of type ", type)
                    );
            }
        });
    }

    private Result bindDescribeExecuteImpl(BindParameterT, ColumnHandlerT, DataHandlerT)(
        scope const(char)[]                             portalName,
        scope const(char)[]                             statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterT                            bindParameterOrNull,
        scope ColumnHandlerT                            onRowDescriptionOrNull,
        scope DataHandlerT                              onDataRowOrNull,
    )
    {
        import juptune.postgres.protocol.decode : decodeRowDescription;
        import juptune.postgres.protocol.encode : prepareBindMessage, prepareDescribeMessage, prepareExecuteMessage, sendSyncMessage; // @suppress(dscanner.style.long_line)

        this._state.mustTransition!(State.readyForQuery, State.handlingQuery);

        this._state.mustTransition!(State.handlingQuery, State.bindingParams);
        auto result = prepareBindMessage(
            this,
            portalName,
            statementName,
            paramFormatCodes,
            resultFormatCodes,
            bindParameterOrNull
        );
        if(result.isError)
        {
            // Since we haven't actually sent any data, it's safe to error correct.
            this._state.mustTransition!(State.bindingParams, State.handlingQuery);
            this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
            this.resetBuffer();
            return result;
        }
        this._state.mustTransition!(State.bindingParams, State.handlingQuery);

        result = prepareDescribeMessage(this, 'P', portalName);
        if(result.isError)
        {
            this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
            this.resetBuffer();
            return result;
        }

        result = prepareExecuteMessage(this, portalName, 0);
        if(result.isError)
        {
            this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
            this.resetBuffer();
            return result;
        }

        result = sendSyncMessage(this);
        if(result.isError)
        {
            // We wouldn't have sent any data in this case, so it's safe to error correct.
            if(result.isError(PostgresProtocolError.bufferTooSmall))
            {
                this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
                this.resetBuffer();
            }

            return result;
        }

        result = this.handleQueryMessages(onRowDescriptionOrNull, onDataRowOrNull);
        if(result.isError)
            return result;

        this.resetBuffer();
        return Result.noError;
    }

    private Result executeImpl(DataHandlerT)(
        scope const(char)[] portalName,
        int maxRowsToReturn,
        scope DataHandlerT onDataRowOrNull,
    )
    {
        import juptune.postgres.protocol.encode : prepareExecuteMessage, sendSyncMessage;

        this._state.mustTransition!(State.readyForQuery, State.handlingQuery);
        
        auto result = prepareExecuteMessage(this, portalName, maxRowsToReturn);
        if(result.isError)
            return result;

        result = sendSyncMessage(this);
        if(result.isError)
            return result;

        return this.handleQueryMessages(null, onDataRowOrNull);
    }

    private Result simpleQueryImpl(ColumnHandlerT, DataHandlerT)(
        scope const(char)[] query,
        scope ColumnHandlerT onRowDescriptionOrNull,
        scope DataHandlerT onDataRowOrNull,
    )
    {
        import juptune.postgres.protocol.encode : sendQueryMessage;

        if(onRowDescriptionOrNull is null || onDataRowOrNull is null)
        {
            assert(
                onRowDescriptionOrNull is null && onDataRowOrNull is null,
                "when either onRowDescriptionOrNull or onDataRowOrNull is null, then BOTH must be null"
            );
        }

        this._state.mustTransition!(State.readyForQuery, State.handlingQuery);

        // Send a Query message
        auto result = sendQueryMessage(this, query);
        if(result.isError)
            return result;

        // Handle the response
        return this.handleQueryMessages(onRowDescriptionOrNull, onDataRowOrNull);
    }

    private Result handleQueryMessages(ColumnHandlerT, DataHandlerT)(
        scope ColumnHandlerT onRowDescriptionOrNull,
        scope DataHandlerT onDataRowOrNull,
    )
    {
        import juptune.postgres.protocol.decode : decodeRowDescription, decodeRowData;

        auto result = this.nextMessagesReadyForQueryCase(
            (PostgresMessageType type, scope ref MemoryReader reader)
            {
                switch(type) with(PostgresMessageType)
                {
                    static if(!is(ColumnHandlerT == typeof(null)))
                    {
                        case rowDescription:
                            if(onRowDescriptionOrNull is null)
                                return Result.noError;
                            return decodeRowDescription(reader, onRowDescriptionOrNull);
                    }

                    case dataRow:
                        if(onDataRowOrNull is null)
                            return Result.noError;
                        return decodeRowData(reader, onDataRowOrNull);

                    case emptyQueryResponse:
                        return Result.make(PostgresProtocolError.emptyQuery, "query was empty");

                    case noData:
                    case bindComplete:
                    case commandComplete:
                        // Just ignore it.
                        return Result.noError;

                    default:
                        import juptune.core.ds : String;
                        return Result.make(
                            PostgresProtocolError.unexpectedMessage,
                            "encountered unexpected message when reading reply to simple Query/Execute",
                            String("got message of type ", type)
                        );
                }
            },
        );

        this.resetBuffer();
        return result;
    }

    /++ Decode messages ++/

    package Result nextMessagesReadyForQueryCase(HandlerT)(
        scope HandlerT handler,
    )
    {
        import juptune.postgres.protocol.decode : decodeErrorResponse;

        auto errorResponseResult = Result.noError;

        bool ready = false;
        auto result = this.nextMessagesImpl(
            (PostgresMessageType type, scope ref MemoryReader reader)
            {
                // If we ran into an error, keep eating messages until we find ReadyForQuery
                if(errorResponseResult.isError)
                {
                    if(type != PostgresMessageType.readyForQuery)
                        return Result.noError;

                    ready = true;
                    this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
                    return Result.noError;
                }

                // Otherwise process the wider range of available messages
                switch(type) with(PostgresMessageType)
                {
                    case readyForQuery:
                        ready = true;
                        this._state.mustTransition!(State.handlingQuery, State.readyForQuery);
                        return Result.noError;

                    case errorResponse:
                        errorResponseResult = decodeErrorResponse(reader);
                        return Result.noError;

                    default:
                        auto result = handler(type, reader);
                        if(result.isError)
                            errorResponseResult = result;
                        return Result.noError;
                }

            },
            () => !ready,
            handleErrorResponse: false,
        );

        return (errorResponseResult.isError) ? errorResponseResult : result;
    }
    
    package Result nextMessagesImpl(HandlerT, MoreDataT)(
        scope /*MessageHandlerT*/ HandlerT handler,
        scope /*bool delegate() @nogc nothrow*/ MoreDataT expectingMoreData,
        bool handleErrorResponse = true,
    )
    in(this._cursor == 0, "bug: buffer was expected to be empty")
    {
        import std.meta : NoDuplicates;
        import std.traits : EnumMembers;
        
        import juptune.postgres.protocol.decode : decodeErrorResponse;

        // Read enough bytes for the header.
        while(this._cursor < 5) // 1 for type byte, 4 for length bytes
        {
            auto result = this.fetchIntoBuffer();
            if(result.isError)
                return result;
        }

        // Keep reading until there's nothing left over
        auto reader = MemoryReader(this._buffer[0..this._cursor]);
        while(reader.bytesLeft > 0)
        {
            // Read in the message header.
            ubyte type;
            uint length;

            auto success = reader.readU8(type);
            assert(success, "bug: this shouldn't be possible");
            success = reader.readU32BE(length);
            assert(success, "bug: this shouldn't be possible");

            // Ensure we have enough space in the buffer, and then keep reading until all of the data has come through.
            const start = reader.cursor;

            auto result = this.ensureBufferFreeSpace(length);
            if(result.isError)
                return result;

            const lengthMinus4 = length - 4; // - 4 since we need to not include the length bytes

            while(this._cursor - start < lengthMinus4)
            {
                result = this.fetchIntoBuffer();
                if(result.isError)
                    return result;
            }
            reader = MemoryReader(this._buffer[0..this._cursor], reader.cursor);
            
            const(ubyte)[] data;
            success = reader.readBytes(lengthMinus4, data);
            assert(success, "bug: this shouldn't be possible");

            auto subreader = MemoryReader(data);

            // Ensure the message type matches one that we know.
            PostgresMessageType messageType = cast(PostgresMessageType)type;
            Switch: switch(messageType)
            {
                static foreach(Member; NoDuplicates!(EnumMembers!PostgresMessageType))
                {
                    case Member: break Switch;
                }

                default:
                    return Result.make(PostgresProtocolError.invalidMessage, "message with unknown type was encountered"); // @suppress(dscanner.style.long_line)
            }

            // Handle certain message types automatically
            switch(messageType) with(PostgresMessageType)
            {
                case errorResponse:
                    if(handleErrorResponse)
                        return decodeErrorResponse(subreader);
                    break;

                case noticeResponse:
                    // Just ignore it
                    continue;
                
                default: break;
            }

            // Then let the handler... handle, the rest of the parsing.
            result = handler(messageType, subreader);
            if(result.isError)
                return result;
        }

        // If the caller still wants data, call this function again.
        if(expectingMoreData())
        {
            this.resetBuffer();
            return this.nextMessagesImpl(handler, expectingMoreData);
        }

        return Result.noError;
    }

    /++ General I/O operations ++/

    package Result sendEntireBuffer() @nogc nothrow
    {
        scope(exit) this.resetBuffer();

        if(this._useEncryptedSocket)
            return this._encryptedSocket.put(this._buffer[0..this._cursor], this._config.writeTimeout).wrapError("when writing to postgres socket:"); // @suppress(dscanner.style.long_line)
        else
            return this._plaintextSocket.put(this._buffer[0..this._cursor], this._config.writeTimeout).wrapError("when writing to postgres socket:"); // @suppress(dscanner.style.long_line)
    }

    private Result fetchIntoBuffer() @nogc nothrow
    in(this._cursor < this._buffer.length, "bug: cannot fetch when buffer is full")
    {
        auto result = Result.noError;
        void[] got;
        if(this._useEncryptedSocket)
            result = this._encryptedSocket.recieve(this._buffer[0..$], got, this._config.readTimeout);
        else
            result = this._plaintextSocket.recieve(this._buffer[0..$], got, this._config.readTimeout);

        if(result.isError)
            return result.wrapError("when fetching from postgres network socket:");

        this._cursor += got.length;
        return Result.noError;
    }

    /++ Buffer operations ++/

    package bool bufferIsEmpty() @nogc nothrow pure const => this._cursor == 0;

    package Result putLengthPrefixedBytes(PutterT)(
        scope /*Result delegate() @nogc nothrow*/ PutterT putter, 
        bool includeLengthBytes = true,
    )
    {
        const start = this._cursor;
        auto result = this.putBytes([0, 0, 0, 0]);
        if(result.isError)
            return result;

        result = putter();
        if(result.isError)
            return result;

        const end = (includeLengthBytes) ? this._cursor : this._cursor - 4;
        this.putIntAt(cast(uint)(end - start), start);
        return Result.noError;
    }

    package Result putString(scope const(char)[] str) @nogc nothrow
    {
        return this.putBytes(cast(const(ubyte)[])str);
    }

    package Result putStringz(scope const(char)[] str) @nogc nothrow
    {
        auto result = this.ensureBufferFreeSpace(str.length + 1); // + 1 for null terminator.
        if(result.isError)
            return result;

        this._buffer[this._cursor..this._cursor+str.length] = cast(const(ubyte)[])str;
        this._buffer[this._cursor + str.length] = cast(ubyte)0;
        this._cursor += str.length + 1;
        return Result.noError;
    }

    package Result putBytes(scope const(ubyte)[] bytes) @nogc nothrow
    {
        auto result = this.ensureBufferFreeSpace(bytes.length);
        if(result.isError)
            return result;

        this._buffer[this._cursor..this._cursor+bytes.length] = bytes;
        this._cursor += bytes.length;
        return Result.noError;
    }
    
    package Result putInt(IntT)(IntT value) @nogc nothrow
    {
        import juptune.data : MemoryWriter, Endian;

        auto result = this.ensureBufferFreeSpace(IntT.sizeof);
        if(result.isError)
            return result;
        
        auto writer = MemoryWriter(this._buffer[this._cursor..this._cursor+IntT.sizeof]);
        auto success = writer.tryIntegral!(IntT, Endian.bigEndian)(value);
        assert(success, "this shouldn't be able to fail?");
        this._cursor += IntT.sizeof;

        return Result.noError;
    }
    
    package void putIntAt(IntT)(IntT value, size_t cursor) @nogc nothrow
    in(cursor <= this._cursor - IntT.sizeof)
    {
        import juptune.data : MemoryWriter, Endian;
        
        auto writer = MemoryWriter(this._buffer[cursor..cursor+IntT.sizeof]);
        auto success = writer.tryIntegral!(IntT, Endian.bigEndian)(value);
        assert(success, "this shouldn't be able to fail?");
    }

    private Result ensureBufferFreeSpace(size_t amount) @nogc nothrow
    in(this._cursor <= this._buffer.length)
    {
        const left = this._buffer.length - this._cursor;
        if(left >= amount)
            return Result.noError;

        return this.ensureBufferLength(this._buffer.length + amount);
    }

    private Result ensureBufferLength(size_t length) @nogc nothrow
    {
        if(this._buffer.length >= length)
            return Result.noError;

        if(length > this._config.maxBufferSpace)
            return Result.make(PostgresProtocolError.bufferTooSmall, "buffer is too small to handle incoming message");

        this._buffer.length = length;
        return Result.noError;
    }

    package void resetBuffer() @nogc nothrow
    {
        this._cursor = 0;
        this._buffer.length = this._config.minBufferSpace;
    }

    package const(ubyte[]) rawBuffer() @nogc nothrow
    {
        return this._buffer.slice;
    }

    package size_t bufferCursor() @nogc nothrow
    {
        return this._cursor;
    }

    package bool mustBeBindingParams() @nogc nothrow
    {
        return this._state.mustBeIn(State.bindingParams);
    }
}