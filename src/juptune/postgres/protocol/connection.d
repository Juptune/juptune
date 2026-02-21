/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.connection;

import core.time : Duration;

import juptune.core.util : Result;

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

enum PostgresProtocolVersion
{
    FAILSAFE,
    v3_0 = (3 << 16) | (0),
    v3_2 = (3 << 16) | (2),
}

enum PostgresTlsMode
{
    FAILSAFE,
    never,
    ifPossible,
    always,
}

struct PostgresConnectInfo
{
    import juptune.data.x509 : X509CertificateStore;

    // Connection info
    const(char)[] user;
    const(char)[] databaseOrNull;
    const(char)[] plaintextPassword;

    // TLS info
    PostgresTlsMode tlsMode;
    X509CertificateStore* customStore;
    X509CertificateStore.SecurityPolicy x509Policy;
}

enum PostgresMessageType : char
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

struct PostgresProtocolConfig
{
    size_t minBufferSpace = 1024 * 8;
    size_t maxBufferSpace = size_t.max;
    Duration writeTimeout = Duration.zero;
    Duration readTimeout = Duration.zero;

    @safe @nogc nothrow:

    PostgresProtocolConfig withMinBufferSize(size_t value) { this.minBufferSpace = value; return this; }
    PostgresProtocolConfig withMaxBufferSize(size_t value) { this.maxBufferSpace = value; return this; }
    PostgresProtocolConfig withWriteTimeout(Duration value) { this.writeTimeout = value; return this; }
    PostgresProtocolConfig withReadTimeout(Duration value) { this.readTimeout = value; return this; }
}

struct PostgresParameters
{
    enum DateStyle
    {
        FAILSAFE,
        iso,
    }

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

struct PostgresColumnDescription
{
    import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

    enum Format : byte
    {
        FAILSAFE = -1,
        text = 0,
        binary = 1,
    }

    const(char)[] nameDoNotCopy;
    int tableObjectId;
    ushort columnAttributeNumber;
    PostgresDataTypeOid dataType; // NOTE: Not all OIDs are defined in the enum (yet)
    short dataTypeSize;
    int dataTypeModifier;
    Format format;
}

struct PostgresProtocol
{
    import juptune.core.ds : Array;
    import juptune.core.util : StateMachineTypes;
    import juptune.data : MemoryReader;
    import juptune.event.io : TcpSocket, IpAddress;
    import juptune.http.tls : TlsTcpSocket;
    import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

    alias MessageHandlerT = Result delegate(PostgresMessageType type, scope ref MemoryReader reader) @nogc nothrow;

    alias NextColumnDescriptionT = Result delegate(scope out PostgresColumnDescription desc) @nogc nothrow;
    alias NextColumnDataT = Result delegate(scope out MemoryReader valueReader, scope out bool isNull) @nogc nothrow;

    alias ColumnDescriptionHandlerT = Result delegate(ushort columnCount, scope NextColumnDescriptionT nextDescription) @nogc nothrow; // @suppress(dscanner.style.long_line)
    alias DataRowHandlerT = Result delegate(ushort columnCount, scope NextColumnDataT nextData) @nogc nothrow;

    alias ColumnDescriptionHandlerGcT = Result delegate(ushort columnCount, scope NextColumnDescriptionT nextDescription); // @suppress(dscanner.style.long_line)
    alias DataRowHandlerGcT = Result delegate(ushort columnCount, scope NextColumnDataT nextData);

    alias BindParameterHandlerT = Result delegate(const int paramIndex, scope ref PostgresProtocol psql, scope out bool moreParamsLeftToBind) @nogc nothrow; // @suppress(dscanner.style.long_line)
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

    this(PostgresProtocolConfig config) @nogc nothrow pure
    {
        this._config = config;
        this._state = StateMachine(State.notConnected);
    }

    /++ Public API (connecting) ++/

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

    ref const(PostgresParameters) params() @nogc nothrow pure const
    {
        return this._parameters;
    }

    /++ Public API (querying) ++/

    Result simpleQuery(
        scope const(char)[] query,
        scope ColumnDescriptionHandlerT onRowDescriptionOrNull,
        scope DataRowHandlerT onDataRowOrNull,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    {
        return this.simpleQueryImpl(query, onRowDescriptionOrNull, onDataRowOrNull);
    }

    Result simpleQueryGc(
        scope const(char)[] query,
        scope ColumnDescriptionHandlerGcT onRowDescriptionOrNull,
        scope DataRowHandlerGcT onDataRowOrNull,
    )
    in(this._state.mustBeIn(State.readyForQuery))
    {
        return this.simpleQueryImpl(query, onRowDescriptionOrNull, onDataRowOrNull);
    }

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

    Result bindDescribeExecute(
        scope const(char)[] portalName,
        scope const(char)[] statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterHandlerT bindParameterOrNull,
        scope ColumnDescriptionHandlerT onRowDescriptionOrNull,
        scope DataRowHandlerT onDataRowOrNull,
    ) @nogc nothrow
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        return this.bindDescribeExecuteImpl(portalName, statementName, paramFormatCodes, resultFormatCodes, bindParameterOrNull, onRowDescriptionOrNull, onDataRowOrNull); // @suppress(dscanner.style.long_line)
    }

    Result bindDescribeExecuteGc(
        scope const(char)[] portalName,
        scope const(char)[] statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterHandlerGcT bindParameterOrNull,
        scope ColumnDescriptionHandlerGcT onRowDescriptionOrNull,
        scope DataRowHandlerGcT onDataRowOrNull,
    )
    in(this._state.mustBeIn(State.readyForQuery))
    in(this.bufferIsEmpty, "bug: buffer was expected to be empty")
    {
        return this.bindDescribeExecuteImpl(portalName, statementName, paramFormatCodes, resultFormatCodes, bindParameterOrNull, onRowDescriptionOrNull, onDataRowOrNull); // @suppress(dscanner.style.long_line)
    }

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
        scope const(char)[] portalName,
        scope const(char)[] statementName,
        scope const(PostgresColumnDescription.Format)[] paramFormatCodes,
        scope const(PostgresColumnDescription.Format)[] resultFormatCodes,
        scope BindParameterT bindParameterOrNull,
        scope ColumnHandlerT onRowDescriptionOrNull,
        scope DataHandlerT onDataRowOrNull,
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
            return result;
        this._state.mustTransition!(State.bindingParams, State.handlingQuery);

        result = prepareDescribeMessage(this, 'P', portalName);
        if(result.isError)
            return result;

        result = prepareExecuteMessage(this, portalName, 0);
        if(result.isError)
            return result;

        result = sendSyncMessage(this);
        if(result.isError)
            return result;

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

@("DEBUG")
debug unittest
{
    import std.exception : assumeWontThrow;

    import juptune.core.util : resultAssert;
    import juptune.event;
    import juptune.postgres.protocol.datatypes : PostgresDataTypeOid;

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread((){
        IpAddress local;
        IpAddress.parse(local, "127.0.0.1", 5432).resultAssert;

        auto psql = PostgresProtocol(PostgresProtocolConfig());
        psql.connect(local, PostgresConnectInfo(
            tlsMode: PostgresTlsMode.never,
            user: "postgres",
            plaintextPassword: "password",
        )).resultAssert;

        PostgresColumnDescription[] descs, resultDescs;

        import std;
        psql.simpleQueryGc(`
            DROP TABLE IF EXISTS test;
            CREATE TABLE test(
                id SERIAL PRIMARY KEY NOT NULL,

                b BOOLEAN,
                cn CHARACTER (10),
                cnv CHARACTER VARYING (10),
                d DATE,
                dp DOUBLE PRECISION,
                i INTEGER,
                r REAL,
                si SMALLINT,
                t TEXT,
                ti TIME,
                tiz TIME WITH TIME ZONE,
                ts TIMESTAMP,
                tsz TIMESTAMP WITH TIME ZONE,
                u UUID
            );

            INSERT INTO test(
                b,
                cn,
                cnv,
                d,
                dp,
                i,
                r,
                si,
                t,
                ti,
                tiz,
                ts,
                tsz,
                u
            ) VALUES 
                (TRUE, '123', '1234', '1234-01-02', 123.456, 123, 123.456, 123, '123', '01:02:03.456', '01:02:03.456+7', '1234-01-02 01:02:03', '1234-01-02 01:02:03.456+7', 'dfc17952-6eaa-4aca-a455-0b7f5eed2b46'),
                (FALSE, '321', '4321', '4321-10-20', 654.321, 321, 654.321, 321, '321', '06:05:04.321', '07:06:05.432+1', '4321-10-20 03:02:01', '4321-10-20 07:06:05.432+1', 'dfc17952-6eaa-4aca-a455-0b7f5eed2b46')
            ;

            SELECT * FROM test;
        `,
        (ushort columnCount, scope PostgresProtocol.NextColumnDescriptionT nextColumnDescription) {
            descs.length = columnCount;

            foreach(i; 0..columnCount)
            {
                nextColumnDescription(descs[i]).resultAssert;
                descs[i].nameDoNotCopy = descs[i].nameDoNotCopy.dup;
            }
            return Result.noError;
        },
        (ushort columnCount, scope PostgresProtocol.NextColumnDataT nextData){
            import juptune.data.buffer : MemoryReader;
            import juptune.postgres.protocol.datatypes;

            writeln("======================");
            writeln("        NEW ROW       ");
            writeln("======================");
            foreach(i; 0..columnCount)
            {
                MemoryReader columnReader;
                bool isNull;
                nextData(columnReader, isNull).resultAssert;

                write("col ", descs[i].nameDoNotCopy, ": <", descs[i].dataType, "> ");
                if(isNull)
                {
                    writeln("NULL");
                    continue;
                }

                switch(descs[i].dataType) with(PostgresDataTypeOid)
                {
                    case int4:
                        int value;
                        decodeInt4Text(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case int2:
                        short value;
                        decodeInt2Text(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case boolean:
                        bool value;
                        decodeBooleanText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case uuid:
                    case bpchar:
                    case varchar:
                    case text:
                        const(char)[] value;
                        decodeTextText(columnReader, value, psql.params).resultAssert;
                        writeln('"', value, '"');
                        break;

                    case date:
                        PostgresDate value;
                        decodeDateText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case time:
                        Duration value;
                        decodeTimeText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case timetz:
                        PostgresTimetz value;
                        decodeTimetzText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case timestamp:
                        PostgresTimestamp value;
                        decodeTimestampText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    case timestamptz:
                        PostgresTimestamptz value;
                        decodeTimestamptzText(columnReader, value, psql.params).resultAssert;
                        writeln(value);
                        break;

                    default:
                        writeln("<UNHANDLED> ", descs[i].dataType);
                        break;
                }
            }
            return Result.noError;
        }).assumeWontThrow.resultAssert;

        psql.prepare(
            "",
            "SELECT * FROM test WHERE b = $1",
            [PostgresDataTypeOid.boolean]
        ).resultAssert;
        
        psql.bindDescribeExecuteGc(
            "",
            "",
            [PostgresColumnDescription.Format.binary],
            [],
            (const index, scope ref psql, scope out moreToBind){
                assert(index == 0);

                psql.putBytes([1]).resultAssert;
                moreToBind = false;

                return Result.noError;
            },
            null,
            (ushort columnCount, scope PostgresProtocol.NextColumnDataT nextData){
                import juptune.data.buffer : MemoryReader;
                import juptune.postgres.protocol.datatypes;

                writeln("======================");
                writeln("        NEW ROW       ");
                writeln("======================");
                foreach(i; 0..columnCount)
                {
                    MemoryReader columnReader;
                    bool isNull;
                    nextData(columnReader, isNull).resultAssert;

                    writeln(columnReader.buffer);
                }
                return Result.noError;
            }
        ).assumeWontThrow.resultAssert;

        psql.closeStatement("").resultAssert;

        stdout.flush().assumeWontThrow;
        assert(false);
    });
    loop.join();
}