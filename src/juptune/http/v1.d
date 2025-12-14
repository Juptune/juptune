/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.v1;

import juptune.core.ds   : MemoryBlockPoolAllocator, MemoryBlockAllocation;
import juptune.core.util : Result, StateMachineTypes;
import juptune.event.io  : TcpSocket, IoError;
import juptune.http.uri  : Uri, uriParseNoCopy, UriParseHints, UriParseRules;

private 
{
    enum INVALID_HEADER_CHAR = 0xFF;
    
    enum Rfc9110CharType
    {
        VCHAR                   = 1 << 0,
        TCHAR                   = 1 << 1,
        MIDDLE_OF_HEADER_VALUE  = 1 << 2,
        HTAB                    = 1 << 3,
        SP                      = 1 << 4,

        MIDDLE_OF_HEADER_MASK   = VCHAR | MIDDLE_OF_HEADER_VALUE,
        REASON_MASK             = VCHAR | HTAB | SP,
    }
    
    immutable g_headerNormaliseTable = (){
        ubyte[256] table;
        table[] = INVALID_HEADER_CHAR;

        foreach(ch; 'A'..'Z'+1)
            table[ch] = cast(ubyte)((ch - 'A') + 'a');

        foreach(ch; 'a'..'z'+1)
            table[ch] = cast(ubyte)ch;

        foreach(ch; '0'..'9'+1)
            table[ch] = cast(ubyte)ch;

        table['-'] = '-';
        return table;
    }();

    immutable g_rfc9110CharType = (){
        Rfc9110CharType[256] table;

        with(Rfc9110CharType)
        {
            foreach(ch; 'a'..'z'+1)
                table[ch] = VCHAR | TCHAR;
            foreach(ch; 'A'..'Z'+1)
                table[ch] = VCHAR | TCHAR;
            foreach(ch; '0'..'9'+1)
                table[ch] = VCHAR | TCHAR;
            foreach(ch; ['!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'])
                table[ch] = VCHAR | TCHAR;
            
            // VCHAR only
            foreach(ch; ['"', '(', ')', '[', ']', '{', '}', ',', '/', ':', ';', '<', '=', '>', '?', '@', '\\'])
                table[ch] = VCHAR;

            // MIDDLE_OF_HEADER_VALUE
            foreach(ch; [' ', '\t'])
                table[ch] = MIDDLE_OF_HEADER_VALUE;
            table[' '] |= SP;
            table['\t'] |= HTAB;
        }

        return table;
    }();
}

private enum response(string status, string msg) = "HTTP/1.1 "~status~" "~msg~"\r\n\r\n";

/// An enumeration of supported Http1 versions
enum Http1Version
{
    FAILSAFE,
    http10,
    http11,
}

/// `Result` error enum
enum Http1Error
{
    none,
    dataExceedsBuffer,  /// Not enough room in provided buffer to process request
    badTransport,       /// Transport layer error

    badRequestMethod,   /// Issue with request method
    badRequestPath,     /// Issue with request path
    badRequestVersion,  /// Issue with request version

    badResponseVersion, /// Issue with response version
    badResponseCode,    /// Issue with response code
    badResponseReason,  /// Issue with response reason

    badHeaderName,      /// Issue with header name
    badHeaderValue,     /// Issue with header value
    badLengthHeader,    /// Issue with content-length and transfer-encoding headers

    badBodyChunk,       /// Issue with a chunk in a chunked body
    badBodyChunkSize,   /// Issue with a chunk size in a chunked body
}

/++
 + A RAII struct that represents a slice of the Http1Reader's buffer
 + that is pinned for user processing.
 +
 + Any active instance of this struct will prevent the Http1Reader from
 + fetching more data into the buffer, and will prevent the Http1Reader
 + from moving the buffer's contents around.
 +
 + This is to ensure that the user code can safely access the buffer without
 + sudden changes to the buffer's contents.
 + ++/
struct Http1PinnedSlice
{
    private uint* _pinned;

    @nogc nothrow:

    this(uint* pinned)
    in(pinned !is null, "pinned cannot be null")
    in(*pinned == false, "pinned cannot be true")
    {
        this._pinned = pinned;
        *pinned += 1;
    }

    /// Releases the pinned slice.
    ~this()
    {
        if(this._pinned !is null)
        {
            *this._pinned -= 1;
            this._pinned = null;
        }
    }
}

/++ 
 + Contains the contents of a request line.
 +
 + Notes:
 +  This struct contains a pinned slice of the Http1Reader's buffer, so after
 +  processing the request line, the user code must release the slice by destroying
 +  the struct (e.g. setting it to `.init`, letting it go out of scope, etc.)
 +
 +  In order to make it as clear as possible that data from this struct must **not** be escaped,
 +  the `access` method is provided which enforces via the type system that string data is not
 +  escaped.
 + ++/
struct Http1RequestLine
{
    private Http1PinnedSlice entireLine;
    Http1Version httpVersion; /// The http version of the request line
    private const(char)[] method;
    private Uri path;

    /// Accesses the request line data.
    void access(scope void delegate(scope const char[] method, scope Uri path) @safe nothrow func) @safe nothrow
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
    }

    /// ditto.
    void access(scope void delegate(scope const char[] method, scope Uri path) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
    }
}

/++ 
 + Contains the contents of a response line.
 +
 + Notes:
 +  This struct contains a pinned slice of the Http1Reader's buffer, so after
 +  processing the response line, the user code must release the slice by destroying
 +  the struct (e.g. setting it to `.init`, letting it go out of scope, etc.)
 +
 +  In order to make it as clear as possible that data from this struct must **not** be escaped,
 +  the `access` method is provided which enforces via the type system that string data is not
 +  escaped.
 + ++/
struct Http1ResponseLine
{
    private Http1PinnedSlice entireLine;
    Http1Version httpVersion; /// The http version of the response line
    uint statusCode; /// The status code of the response
    private const(char)[] reasonPhrase;

    /// Accesses the response line data.
    void access(scope void delegate(scope const char[] reasonPhrase) @safe nothrow func) @safe nothrow
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.reasonPhrase);
    }

    /// ditto.
    void access(scope void delegate(scope const char[] reasonPhrase) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.reasonPhrase);
    }
}

/++ 
 + Contains the contents of a body chunk.
 +
 + Notes:
 +  This struct contains a pinned slice of the Http1Reader's buffer, so after
 +  processing the body chunk, the user code must release the slice by destroying
 +  the struct (e.g. setting it to `.init`, letting it go out of scope, etc.)
 +
 +  In order to make it as clear as possible that data from this struct must **not** be escaped,
 +  the `access` method is provided which enforces via the type system that string data is not
 +  escaped.
 +
 +  You are not provided an entire chunk at once, but rather a slice of the chunk which is 
 +  determined by either the size of the buffer, the size of the chunk, or the size of the
 +  data recieved by the incoming TCP packet.
 + ++/
struct Http1BodyChunk
{
    Http1PinnedSlice entireChunk;
    private ubyte[] data;
    private bool dataLeft;
    private const(char)[] extensionLine;

    /// Accesses the body chunk data.
    void access(scope void delegate(scope ubyte[] data) @safe nothrow func) @safe nothrow
    in(this.entireChunk._pinned !is null, "entireChunk must be pinned")
    {
        func(this.data);
    }

    /// ditto.
    void access(scope void delegate(scope ubyte[] data) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireChunk._pinned !is null, "entireChunk must be pinned")
    {
        func(this.data);
    }

    /++
     + Determines if there's more data left to read from the body.
     +
     + Notes:
     +  Due to how the reader is implemented, if the body uses chunked transfer-encoding
     +  this will return `true` and an empty data slice will be provided which marks the end of the chunked data body,
     +  and only the next read will produce a `false` result.
     +
     + Returns:
     +  `true` if there's more data left to read, `false` otherwise.
     + ++/
    bool hasDataLeft() @safe @nogc nothrow const
    {
        return this.dataLeft;
    }
}

/++ 
 + Contains the contents of a header.
 +
 + Notes:
 +  This struct contains a pinned slice of the Http1Reader's buffer, so after
 +  processing the header, the user code must release the slice by destroying
 +  the struct (e.g. setting it to `.init`, letting it go out of scope, etc.)
 +
 +  In order to make it as clear as possible that data from this struct must **not** be escaped,
 +  the `access` method is provided which enforces via the type system that string data is not
 +  escaped.
 + ++/
struct Http1Header
{
    Http1PinnedSlice entireLine;
    private const(char)[] name;
    private const(char)[] value;

    /// Accesses the header data.
    void access(scope void delegate(scope const char[] name, scope const char[] value) @safe nothrow func) @safe nothrow
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.name, this.value);
    }

    /// ditto.
    void access(scope void delegate(scope const char[] name, scope const char[] value) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.name, this.value);
    }
}

/++
 + Provides the overall summary of a request/response.
 + ++/
struct Http1MessageSummary
{
    /++
     + Represents the HTTP-level connection status. This is either determined by the
     + version of the request, or by the `connection` header if one exists.
     + 
     + If set to `true`, and the reader is reading a request, the socket should be closed
     + after a response is sent.
     +
     + If set to `true`, and the reader is reading a response, the socket should be closed
     + immediately.
     +
     + If set to `false`, then assume that further requests are/will be available on the underlying socket.
     + ++/
    bool connectionClosed;
}

/++
 + Configuration for the Http1Reader and Http1Writer.
 +
 + The main reason the config is combined is for simplicity, as the reader and writer
 + are intended to be used together, and thus it makes sense to have a single config struct.
 +
 + This is especially apparent for higher level APIs that may not display the distinction between
 + the reader and writer, and thus would benefit from a unified configuration object.
 + ++/
struct Http1Config
{
    import core.time : Duration;

    /++
     + The maximum number of times the reader will attempt to read data from the socket
     + before giving up and returning an error (in certain circumstances).
     +
     + Imagine this situtation: There is a bad actor trying to exhuast the server's resources
     + by opening a bunch of connections, sending just enough data at just enough of a rate
     + to keep the connection alive, but not enough to actually send a request.
     +
     + The reader in this case could be trying to just parse a request line, so is looking for a `\r\n`
     + that never ends up coming. If after `maxReadAttempts` the reader still hasn't found the `\r\n`,
     + it will return an error as it assumes the client is acting in bad faith.
     +
     + Body data is not included in this check currently, as a better method/heuristic is needed for
     + large bodies.
     +
     + This also does not apply to transport layer errors, such as the socket being closed by the client
     + and I/O timeouts.
     + ++/
    size_t maxReadAttempts = 5;

    Duration writeTimeout = Duration.zero; /// The default timeout for writing data
    Duration readTimeout = Duration.zero; /// The default timeout for reading data

    @safe @nogc nothrow pure:

    Http1Config withMaxReadAttempts(size_t v) return { this.maxReadAttempts = v; return this; }
    Http1Config withReadTimeout(Duration v) return { this.readTimeout = v; return this; }
    Http1Config withWriteTimeout(Duration v) return { this.writeTimeout = v; return this; }
}

/++
 + Configuration for reading a response.
 +
 + This is neccessary as the reader does not have context of the overall state of the request/response pipeline,
 + so certain things must be configured by the user code.
 + ++/
struct Http1ReadResponseConfig
{
    /++
     + If set to true, then the response will be forced to be interpreted as a bodyless response,
     + regardless of what the headers say.
     +
     + This is defined in RFC 9112 section 6.3.1. to apply to HEAD requests; 1xx, 204, and 304 responses.
     +
     + As the reader lacks context of the overall state of the request/response pipeline, it is up to the
     + user code to determine if the response is a HEAD response, and to set this flag accordingly.
     + ++/
    bool isBodyless = false;

    @safe @nogc nothrow pure:

    Http1ReadResponseConfig withIsBodyless(bool v) return { this.isBodyless = v; return this; }
}

/++ 
 + A low-level reader for the HTTP/1.0 and HTTP/1.1 protocols, operating
 + directly on a socket.
 +
 + Performance:
 +  No explicit effort has been made to optimise this reader for performance, but
 +  it should be reasonably fast. No benchmarks have been done yet.
 +
 +  Correctness, safety, and readability have been the main priorities. This is not to say
 +  that optimisations will not be made in the future, but they are not a priority at the moment.
 +
 +  Memory wise the reader does not directly allocate heap memory as it uses user-provided buffers,
 +  however the kernal syscalls used for I/O can of course do whatever they want.
 +
 + Buffer:
 +  The reader operates directly on a buffer provided by the user and does
 +  not directly allocate any memory.
 +
 +  For status lines, the buffer must be able to hold the entire status line.
 +
 +  For headers, the buffer must be able to hold the entire line for each singular header, however
 +  it does not need to be large enough to store the entire set of headers.
 +
 +  For bodies using chunked transfer-encoding, the buffer must be able to hold the entire chunk size
 +  and extension line. For the actual body data the buffer is used to determine the maximum amount of bytes
 +  that can be stored before the user is forced to process the data, to make way for the rest of the chunk.
 +
 +  For bodies using content-length, the buffer is used to determine the maximum amount of bytes that can be
 +  stored before the user is forced to process the data, to make way for the rest of the body.
 +
 +  Due to the general reuse of this buffer, returned data structures will often be "pinned", which means
 +  that the user code must process the data and then release the pin by destroying the returned data structure,
 +  prior to this reader fetching any more data from the socket.
 +
 + Flow:
 +  This reader is a low-level, state-machine API, and thus requires quite a lot involvement from the user code,
 +  as well as a magical incantation of calls to properly parse requests and responses.
 +
 +  Any read function that returns a result will contain a valid HTTP response message that can be sent to the client
 +  as-is, if the result is an error. This is to allow the user code to quickly send an error response to the client
 +  without having to do any extra work.
 +
 +  This struct contains plenty of checks to ensure that the user code is not doing any illegal state transitions,
 +  and will also try its best to protect the user from themself in terms of memory safety.
 +
 + RequestFlow:
 +  1. Call `readRequestLine` to read the request line.
 +      1.1. Process the request line and destroy the returned `Http1RequestLine` struct before continuing.
 +  2. While `checkEndOfHeaders` returns `false`:
 +      2.1. Call `readHeader` to read a header.
 +      2.2. Process the header and destroy the returned `Http1Header` struct before continuing.
 +  3. While `readBody`'s return value's `hasDataLeft` is `true`:
 +      3.1. Process the body chunk and destroy the returned `Http1BodyChunk` struct before continuing.
 +  4. Call `finishMessage` to finish the request, and if the `Http1MessageSummary.connectionClosed` is `false`,
 +     loop back to step 1 (if applicable), otherwise cease using this reader and socket for communication.
 +
 + ResponseFlow:
 +  Responses are slightly different as in some cases it requires external context from a previous request/response
 +  as well as the fact responses can contain trailers for chunked bodies, thus requiring an extra processing stage.
 +
 +  1. Call `readResponseLine` to read the response line.
 +      1.1. If the response is for a HEAD request, please ensure you set `config.isBodyless` to `true` for
 +           correct handling.
 +      1.2. Process the response line and destroy the returned `Http1ResponseLine` struct before continuing.
 +  2. While `checkEndOfHeaders` returns `false`:
 +      2.1. Call `readHeader` to read a header.
 +      2.2. Process the header and destroy the returned `Http1Header` struct before continuing.
 +  3. While `readBody`'s return value's `hasDataLeft` is `true`:
 +      3.1. Process the body chunk and destroy the returned `Http1BodyChunk` struct before continuing.
 +  4. While `checkEndOfTrailers` returns `false`:
 +      4.1. Call `readTrailer` to read a trailer.
 +      4.2. Process the trailer and destroy the returned `Http1Header` struct before continuing.
 +  5. Call `finishMessage` to finish the response, and if the `Http1MessageSummary.connectionClosed` is `false`,
 +     loop back to step 1 (if applicable), otherwise cease using this reader and socket for communication.
 +
 + Notes:
 +  Currently reading body data requires the use of the provided user buffer, but in the future
 +  a separate set of functions will be provided that will allow the user to provide a separate buffer specifically
 +  for body data.
 +
 +  Currently the reader does not provide a way to use gather/scatter I/O, but this is planned for the future,
 +  at least for body data.
 +
 +  This reader will never close the socket as it does not "own" the socket resource, it is up to the
 +  user to handle this. No side effects beyond reading data from the socket will occur.
 +
 +  You should ensure that messages are read in their entirety before responding to the client, as application
 +  errors are not the same as protocol errors, so the rest of the messages within the HTTP pipeline may be
 +  valid and should still be processed.
 +
 + Security:
 +  The reader internally makes use of a type-system-based state machine to help ensure that
 +  bad state transitions can't occur.
 +
 +  See `Http1Config.maxReadAttempts` for a description of a potential DoS vector.
 +
 + Issues:
 +  The reader is currently in a very early state, and is not yet ready for production use.
 +
 +  The current API is especially volatile and has no stability guarantees, as quite a lot of functionality
 +  is still missing or not yet exposed.
 +
 +  The reader currently does not support any form of compression.
 +
 +  The reader is not very extenstively tested.
 +
 +  Specific security concerns haven't been investigated or addressed yet.
 +
 +  The reader's currently priority is to handle the most common cases, and not to be a fully compliant
 +  for a while.
 +
 +  Specific differences between HTTP/1.0 and HTTP/1.1 are not fully implemented yet. HTTP/1.1 has been
 +  the main focus so far.
 +
 +  And of course there's all the other stuff I haven't thought of yet, such as more esoteric features and use cases.
 + ++/
struct Http1ReaderBase(SocketT)
{
    private alias Machine = StateMachineTypes!(State, MessageState);
    private alias StateMachine = Machine.Static!([
        Machine.Transition(State.startLine,          State.maybeEndOfHeaders),
        Machine.Transition(State.headers,            State.maybeEndOfHeaders),
        Machine.Transition(State.maybeEndOfHeaders,  State.headers),
        Machine.Transition(State.maybeEndOfHeaders,  State.body),
        Machine.Transition(State.body,               State.maybeEndOfTrailers, (ref state) => !state.isRequest),
        Machine.Transition(State.body,               State.finalise, (ref state) => state.isRequest),
        Machine.Transition(State.trailers,           State.maybeEndOfTrailers),
        Machine.Transition(State.maybeEndOfTrailers, State.trailers),
        Machine.Transition(State.maybeEndOfTrailers, State.finalise),
        Machine.Transition(State.finalise,           State.startLine),
    ]);

    private enum State
    {
        FAILSAFE,
        startLine,
        headers,
        maybeEndOfHeaders,
        body,
        trailers,
        maybeEndOfTrailers,
        finalise,
    }

    private enum BodyEncoding
    {
        FAILSAFE,
        hasContentLength    = 1 << 0,
        isChunked           = 1 << 1,
        hasTransferEncoding = 1 << 2,
    }

    private static struct MessageState
    {
        Http1Version httpVersion;
        BodyEncoding bodyEncoding;
        Http1MessageSummary summary;
        bool isRequest;
        bool hasReadFirstChunk;
        bool isBodyless; // RFC 9112 section 6.3.1
        size_t contentLength;
        size_t contentLengthRead;
    }

    private
    {
        // General state
        Http1Config _config;
        SocketT* _socket;
        ubyte[] _buffer;

        // Current state
        MessageState _message;
        StateMachine _state;

        // I/O state
        size_t _writeCursor;
        size_t _readCursor;
        size_t _pinCursor;
        uint   _pinnedSliceIsAlive;

        invariant(_writeCursor <= _buffer.length);
        invariant(_readCursor <= _writeCursor);
        invariant(_pinCursor <= _readCursor);
    }

    @disable this(this);

    @nogc nothrow:

    /++
     + Constructs a new Http1Reader.
     +
     + State:
     +  The reader will be put into the `startLine` state.
     +
     + Notes:
     +  The reader does not take ownership of the socket, and thus will not close it.
     +
     +  The reader takes ownership of `buffer`'s data, but not its lifetime.
     +
     +  `socket` and `buffer` must outlive the reader.
     +
     + Params:
     +  socket = The socket to read from.
     +  buffer = The buffer to read into.
     +  config = The configuration for the reader.
     + ++/
    this(SocketT* socket, ubyte[] buffer, Http1Config config)
    in(socket !is null, "socket cannot be null")
    in(buffer !is null, "buffer cannot be null")
    in(buffer.length > 0, "buffer cannot be empty")
    {
        this._socket = socket;
        this._buffer = buffer;
        this._config = config;
        this._state  = StateMachine(State.startLine);
    }

    /// Enforces that all pinned slices have been released.
    ~this()
    {
        assert(this._pinnedSliceIsAlive == 0, "pinned slice was not freed before dtor of Http1Reader");
    }
    
    /++ 
     + Reads the entire request line. This will configure the reader to be a request parser for the
     + remainder of this message, until `finishMessage` is called.
     +
     + State:
     +  This function must be called when the reader is in the `startLine` state.
     +
     +  After this function is called, the reader will be in the `maybeEndOfHeaders` state.
     +
     + Params:
     +  requestLine = Stores the request line data.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.dataExceedsBuffer` if the request line is larger than the provided buffer.
     +
     +  `Http1Error.badRequestMethod` if the request method is missing or invalid.
     +
     +  `Http1Error.badRequestPath` if the request path is missing or invalid.
     +
     +  `Http1Error.badRequestVersion` if the request version is missing, invalid, or specifies an unsupported version.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    Result readRequestLine(out scope Http1RequestLine requestLine)
    in(this._state.mustBeIn(State.startLine))
    {
        ubyte[] slice;
        this._message = MessageState.init;
        this._message.isRequest = true;

        // Method
        auto result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badRequestMethod, response!("400", "Empty method in request line"));
        requestLine.method = cast(char[])slice[0..$];

        if(!requestLine.method.isHttp1Token())
            return Result.make(Http1Error.badRequestMethod, response!("400", "Invalid method in request line"));

        // Path
        result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badRequestPath, response!("400", "Empty path in request line. A minimum of / is required")); // @suppress(dscanner.style.long_line)
        
        result = uriParseNoCopy(cast(char[])slice, requestLine.path);
        if(result.isError)
            return result;
        else if(
            (requestLine.path.hints & (UriParseHints.isAbsolute | UriParseHints.isNetworkReference))
            || !(requestLine.path.hints & UriParseHints.pathIsAbsolute)
        )
            return Result.make(Http1Error.badRequestPath, response!("400", "Invalid path in request line. Must be an absolute, relative-reference path.")); // @suppress(dscanner.style.long_line)

        // Version
        result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;
        else if(slice.length != 8)
            return Result.make(Http1Error.badRequestVersion, response!("400", "Invalid/unsupported http version in request line")); // @suppress(dscanner.style.long_line)
        else if(slice[0..8] == "HTTP/1.0")
        {
            this._message.httpVersion = Http1Version.http10;
            this._message.summary.connectionClosed = true; // HTTP/1.0 defaults to connection: close
        }
        else if(slice[0..8] == "HTTP/1.1")
            this._message.httpVersion = Http1Version.http11;
        else
            return Result.make(Http1Error.badRequestVersion, response!("400", "Unsupported http version in request line")); // @suppress(dscanner.style.long_line)

        requestLine.httpVersion = this._message.httpVersion;
        requestLine.entireLine = Http1PinnedSlice(&this._pinnedSliceIsAlive);
        this._state.mustTransition!(State.startLine, State.maybeEndOfHeaders)(this._message);
        this._pinCursor = this._readCursor;
        return Result.noError;
    }
    
    /++
     + Reads the entire response line. This will configure the reader to be a response parser for the
     + remainder of this message, until `finishMessage` is called.
     +
     + State:
     +  This function must be called when the reader is in the `startLine` state.
     +
     +  After this function is called, the reader will be in the `maybeEndOfHeaders` state.
     +
     + Notes:
     +  Under certain circumstances (such as `config.isBodyless` being `true`) the reader will act as if
     +  the response has no body, regardless of whatever the headers may suggest. You must still
     +  call `readBody` to follow the correct state transitions.
     +
     + Params:
     +  responseLine = Stores the response line data.
     +  config       = The configuration for reading in this response.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.dataExceedsBuffer` if the response line is larger than the provided buffer.
     +
     +  `Http1Error.badResponseVersion` if the response version is missing, invalid, or specifies an unsupported version.
     +
     +  `Http1Error.badResponseCode` if the response code is missing or invalid.
     +
     +  `Http1Error.badResponseReason` if the response reason phrase is invalid.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     + ++/
    Result readResponseLine(
        out scope Http1ResponseLine responseLine, 
        Http1ReadResponseConfig responseConfig = Http1ReadResponseConfig.init
    )
    {
        ubyte[] slice;
        this._message = MessageState.init;
        this._message.isRequest = false;

        // Version
        auto result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length != 8)
            return Result.make(Http1Error.badResponseVersion, response!("400", "Invalid/unsupported http version in response line")); // @suppress(dscanner.style.long_line)
        else if(slice[0..8] == "HTTP/1.0")
        {
            this._message.httpVersion = Http1Version.http10;
            this._message.summary.connectionClosed = true; // HTTP/1.0 defaults to connection: close
        }
        else if(slice[0..8] == "HTTP/1.1")
            this._message.httpVersion = Http1Version.http11;
        else
            return Result.make(Http1Error.badResponseVersion, response!("400", "Unsupported http version in response line")); // @suppress(dscanner.style.long_line)
        responseLine.httpVersion = this._message.httpVersion;
        responseLine.entireLine = Http1PinnedSlice(&this._pinnedSliceIsAlive);

        // Status code
        result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badResponseCode, response!("400", "Invalid status code in response line"));

        import juptune.core.util.conv : to;
        responseLine.statusCode = to!uint(cast(char[])slice, result);
        if(result.isError)
            return Result.make(Http1Error.badResponseCode, response!("400", "Invalid status code in response line")); // @suppress(dscanner.style.long_line)

        if(
            (responseLine.statusCode >= 100 && responseLine.statusCode <= 199)
            || responseLine.statusCode == 204
            || responseLine.statusCode == 304
            || responseConfig.isBodyless
        )
        {
            this._message.isBodyless = true;
        }

        // Reason phrase
        result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;
        else if(!(cast(char[])slice[0..$]).isHttp1Reason())
            return Result.make(Http1Error.badResponseReason, response!("400", "Invalid reason phrase in response line")); // @suppress(dscanner.style.long_line)
        responseLine.reasonPhrase = cast(char[])slice[0..$];

        this._state.mustTransition!(State.startLine, State.maybeEndOfHeaders)(this._message);
        this._pinCursor = this._readCursor;
        return Result.noError;
    }

    /++
     + Reads a single header.
     +
     + State:
     +  This function must be called when the reader is in the `headers` state.
     +
     +  After this function is called, the reader will be in the `maybeEndOfHeaders` state.
     +
     +  If the header is "content-length" then the reader will enter an internal state that allows
     +  it to keep track of how much data has been read from the body when using `readBody`.
     +
     +  If the header is "transfer-encoding" with a value of "chunked" then the reader will enter an internal
     +  state that allows it to parse the chunked body when using `readBody`.
     +
     + Notes:
     +  Certain headers that are critical to the reader's operation will be processed automatically,
     +  but will still be returned to the user code for custom processing.
     +
     +  In defiance of the RFC, and is relatively common practice nowadays, the reader
     +  will force all header names into lowercase. This is to simplify the user code's processing,
     +  and to ensure the user code does not have to deal with case-insensitive comparisons.
     +
     +  This is especially important for user code that can use HTTP/2 and HTTP/3, as those protocols
     +  are case-insensitive with header names. (if/whenever these protocols are supported). Case-sensitive
     +  header names are a relic of the past, and should not be used nor encouraged.
     +
     +  In case it's not clear, headers are always returned in the order they were sent by the client.
     +
     + Params:
     +  header = Stores the header data.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.dataExceedsBuffer` if the entire header line is larger than the provided buffer.
     +
     +  `Http1Error.badHeaderName` if the header name is missing or invalid.
     +
     +  `Http1Error.badHeaderValue` if the header value is missing or invalid.
     +
     +  `Http1Error.badLengthHeader` if the header is a content-length or transfer-encoding header when another
     +  header of the same type has already been read.
     +
     +  `Http1Error.badLengthHeader` if the header is a content-length header and the value is not a valid size_t.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    alias readHeader = readHeaderImpl!false;

    /// Ditto.
    alias readTrailer = readHeaderImpl!true;

    private Result readHeaderImpl(bool trailers)(out scope Http1Header header)
    in((!trailers && this._state.mustBeIn(State.headers)) || (trailers && this._state.mustBeIn(State.trailers)))
    {
        ubyte[] slice;

        // Name
        auto result = this.readUntil!':'(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badHeaderName, response!("400", "Empty header name"));
        else if(slice[$-1] == ' ')
            return Result.make(Http1Error.badHeaderName, response!("400", "RFC 7230 3.2.4 - No whitespace is allowed between the header field-name and colon")); // @suppress(dscanner.style.long_line)
        else if(!http1CanonicalHeaderNameInPlace(slice))
            return Result.make(Http1Error.badHeaderName, response!("400", "Invalid header name"));
        header.name = cast(char[])slice[0..$];

        // Value
        result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;

        size_t start;
        size_t end = slice.length;
        while(start < end && slice[start] == ' ')
            start++;
        while(end > start && slice[end-1] == ' ')
            end--;
        header.value = cast(char[])slice[start..end];

        if(!header.value.isHttp1HeaderValue())
            return Result.make(Http1Error.badHeaderValue, response!("400", "Invalid header value"));
        
        // Handle special headers
        static if(!trailers) // TODO: Should really do some special trailers-only validation here, but I cba right now.
        {
            result = this.processHeader(header);
            if(result.isError)
                return result;
        }

        header.entireLine = Http1PinnedSlice(&this._pinnedSliceIsAlive);
        this._pinCursor = this._readCursor;

        static if(trailers)
            this._state.mustTransition!(State.trailers, State.maybeEndOfTrailers)(this._message);
        else
            this._state.mustTransition!(State.headers, State.maybeEndOfHeaders)(this._message);
        
        return Result.noError;
    }

    /++
     + Checks if the headers have ended.
     +
     + State:
     +  This function must be called when the reader is in the `maybeEndOfHeaders` state.
     +
     +  After this function is called, the reader will be in the `body` state if the headers have ended,
     +  or the `headers` state if the headers have not ended.
     +
     + Params:
     +  isEnd = Set to `true` if the headers have ended, `false` otherwise.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    alias checkEndOfHeaders = checkEndOfHeadersImpl!(false, false);

    /// ditto.
    alias checkEndOfTrailers = checkEndOfHeadersImpl!(false, true);

    private Result checkEndOfHeadersImpl(bool internal, bool trailers)(out scope bool isEnd)
    in(this._pinCursor == this._readCursor, "pin cursor must be at the read cursor")
    in(internal || (!trailers && this._state.mustBeIn(State.maybeEndOfHeaders)) || (trailers && this._state.mustBeIn(State.maybeEndOfTrailers))) // @suppress(dscanner.style.long_line)
    {
        static if(trailers)
        {
            enum FROM     = State.maybeEndOfTrailers;
            enum TO       = State.finalise;
            enum CONTINUE = State.trailers;
        }
        else
        {
            enum FROM     = State.maybeEndOfHeaders;
            enum TO       = State.body;
            enum CONTINUE = State.headers;
        }

        static if(!internal)
        {
            static if(!trailers) scope(exit)
            {
                // RFC 9112 section 6.3.1
                if(this._state.isIn(State.body) && this._message.isBodyless)
                {
                    this._message.bodyEncoding = BodyEncoding.hasContentLength;
                    this._message.contentLength = 0;
                }
            }
            else
            {
                // Since we always transition into this state for responses, even when it's not
                // a chunked response, we need to check if we're actually in a chunked response otherwise emulate things.
                if(!(this._message.bodyEncoding & BodyEncoding.isChunked))
                {
                    isEnd = true;
                    this._state.mustTransition!(FROM, TO)(this._message);
                    return Result.noError;
                }
            }
        }

        // Fast path: if we already have enough data in the buffer we can
        //            skip the readUntil call.
        // TODO: readUntil could be completely avoided by using fetchData directly
        if(this._writeCursor - this._readCursor >= 2
        && this._buffer[this._readCursor] == '\r' 
        && this._buffer[this._readCursor+1] == '\n')
        {
            this._readCursor += 2;
            this._pinCursor = this._readCursor;
            static if(!internal) this._state.mustTransition!(FROM, TO)(this._message);
            isEnd = true;
            return Result.noError;
        }

        ubyte[] slice;
        auto result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;

        if(slice.length == 0) // Reminder: readUntil auto trims \r\n
        {
            this._pinCursor = this._readCursor;
            static if(!internal) this._state.mustTransition!(FROM, TO)(this._message);
            isEnd = true;
        }
        else
        {
            static if(!internal) this._state.mustTransition!(FROM, CONTINUE)(this._message);
            this._readCursor = this._pinCursor;
        }

        return Result.noError;
    }

    /++
     + Reads a single chunk of body data.
     +
     + State:
     +  This function must be called when the reader is in the `body` state.
     +
     +  [Requests Only]
     +  After this function is called, the reader will be in the `body` state if there's more data to read,
     +  or the `finalise` state if there's no more data to read.
     +
     +  [Responses Only]
     +  After this function is called, the reader will be in the `body` state if there's more data to read,
     +  or the `maybeEndOfTrailers` state if there's no more data to read.
     +
     + Notes:
     +  This is intended to be a helper function used to read body data in a unified way, 
     +  regardless of the body encoding for those that do not need nor care about having encoding-specific
     +  logic.
     +
     +  Currently lower-level access to the body data is not provided, but will be in the future.
     +
     +  This function makes use of the user buffer to determine the maximum amount of bytes that can be
     +  stored at once. In the future an overload that allows the user to provide a separate buffer
     +  will be provided.
     +
     +  If the body is chunked, then the reader will automatically handle the chunking.
     +
     +  If the body is chunked, a small quirk is that the reader will return an empty data slice
     +  when the "empty marker" chunk is reached, and only the next read will return `false` for `hasDataLeft`.
     +
     +  In order to simplify the user code, the reader will always transition responses to the `maybeEndOfTrailers`
     +  state, even if the response is not using chunked transfer-encoding.
     +
     + Params:
     +  bodyChunk = Stores the body chunk data.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badBodyChunk` if the body is chunked and the client sent an invalid chunk.
     +
     +  `Http1Error.badBodyChunkSize` if the body is chunked and the client sent an invalid chunk size.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    Result readBody(out scope Http1BodyChunk bodyChunk)
    in(this._state.mustBeIn(State.body))
    in(this._pinCursor == this._readCursor, "pin cursor must be at the read cursor")
    {
        if((this._message.bodyEncoding & BodyEncoding.hasContentLength) && this._message.contentLength > 0)
            return this.readBodyContentLength(bodyChunk);
        else if(this._message.bodyEncoding & BodyEncoding.isChunked)
            return this.readBodyChunked(bodyChunk);
        else
        {
            bodyChunk.dataLeft = false;
            bodyChunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);
            if(this._message.isRequest)
                this._state.mustTransition!(State.body, State.finalise)(this._message);
            else
                this._state.mustTransition!(State.body, State.maybeEndOfTrailers)(this._message);
            return Result.noError;
        }
    }

    /++
     + Acknowledges that the message has been fully read, and returns the summary of the message.
     +
     + State:
     +  This function must be called when the reader is in the `finalise` state.
     +
     +  After this function is called, the reader will be in the `startLine` state.
     +
     + Params:
     +  summary = Stores the message summary.
     +
     + Throws:
     +  Currently, nothing. This may change in the future if finishing a message requires I/O operations.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    Result finishMessage(out scope Http1MessageSummary summary)
    in(this._state.mustBeIn(State.finalise))
    {
        summary = this._message.summary;
        this._state.mustTransition!(State.finalise, State.startLine)(this._message);
        return Result.noError;
    }

    private Result readBodyContentLength(out scope Http1BodyChunk chunk)
    {
        auto result = this.readBodyBytes(chunk);
        if(result.isError)
            return result;
        else if(!chunk.hasDataLeft)
        {
            if(this._message.isRequest)
                this._state.mustTransition!(State.body, State.finalise)(this._message);
            else
                this._state.mustTransition!(State.body, State.maybeEndOfTrailers)(this._message);
        }
        
        return Result.noError;
    }

    private Result readBodyChunked(out scope Http1BodyChunk chunk)
    {
        if(this._message.contentLength == 0)
        {
            // This check cannot be done after the body has been read, as the
            // CRLF may not be inside the buffer, requiring a fetchData call,
            // which we can't do until the user code has released the buffer reference.
            if(this._message.hasReadFirstChunk)
            {
                bool isEnd;
                auto result = this.checkEndOfHeadersImpl!(true, false)(isEnd);
                if(result.isError)
                    return result;
                else if(!isEnd)
                    return Result.make(Http1Error.badBodyChunk, response!("400", "Client sent an invalid chunk - expected CRLF to terminate chunk data")); // @suppress(dscanner.style.long_line)
            }

            auto result = this.readChunkSize(this._message.contentLength, chunk.extensionLine);
            if(result.isError)
                return result;

            if(this._message.contentLength == 0)
            {
                if(this._message.isRequest)
                {
                    // Requests can't have trailers, so we can just look for the final CRLF here.
                    bool isEnd;
                    result = this.checkEndOfHeadersImpl!(true, false)(isEnd);
                    if(result.isError)
                        return result;
                    else if(!isEnd)
                        return Result.make(Http1Error.badBodyChunk, response!("400", "Client sent an invalid terminator chunk - expected additional CRLF due to lack of trailers")); // @suppress(dscanner.style.long_line)
                    
                    this._state.mustTransition!(State.body, State.finalise)(this._message);
                }
                else
                {
                    this._state.mustTransition!(State.body, State.maybeEndOfTrailers)(this._message);
                }
                chunk.dataLeft = false;
                chunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);
                this._pinCursor = this._readCursor;
                return Result.noError;
            }
        }

        auto result = this.readBodyBytes(chunk);
        if(result.isError)
            return result;
        else if(!chunk.hasDataLeft)
        {
            this._message.contentLength = 0;
            this._message.contentLengthRead = 0;
            this._message.hasReadFirstChunk = true;
            chunk.dataLeft = true; // Since we still have more chunks to read, simplifies user code
        }

        return Result.noError;
    }

    private Result readChunkSize(out size_t chunkSize, out const(char)[] chunkExtension)
    {
        ubyte[] slice;
        auto result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;

        import std.algorithm : countUntil;
        const firstSemiIndex = slice.countUntil(';');
        if(firstSemiIndex > 0)
        {
            chunkExtension = cast(const(char)[])slice[firstSemiIndex+1..$];
            slice = slice[0..firstSemiIndex];
        }

        import juptune.core.util.conv : to;
        result = to!size_t(cast(char[])slice, chunkSize, 16);
        if(result.isError)
            return Result.make(Http1Error.badBodyChunkSize, response!("400", "Client sent an invalid chunk size - could not convert to a size_t")); // @suppress(dscanner.style.long_line)

        this._pinCursor = this._readCursor;
        return Result.noError;
    }

    private Result readBodyBytes(ref scope Http1BodyChunk chunk)
    in(this._message.contentLength >= this._message.contentLengthRead, "bug: content-length read is greater than content-length") // @suppress(dscanner.style.long_line)
    {
        if(this._readCursor == this._writeCursor)
        {
            size_t bytesFetched;
            size_t _ = this._pinCursor;
            auto result = this.fetchData(bytesFetched, _);
            if(result.isError)
                return result;
            if(bytesFetched == 0)
                return Result.make(Http1Error.dataExceedsBuffer, response!("500", "when reading next body chunk, 0 bytes were read?")); // @suppress(dscanner.style.long_line)
        }

        import std.algorithm : min;
        const bytesLeft = this._message.contentLength - this._message.contentLengthRead;
        const toCopy = min(bytesLeft, this._writeCursor - this._readCursor);

        chunk.data = this._buffer[this._readCursor..this._readCursor + toCopy];
        this._readCursor += toCopy;
        this._message.contentLengthRead += toCopy;
        this._pinCursor = this._readCursor;
        chunk.dataLeft = (this._message.contentLengthRead < this._message.contentLength);
        chunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);

        return Result.noError;
    }

    private Result fetchData(out size_t bytesFetched, ref size_t savedCursor)
    in(this._pinnedSliceIsAlive == 0, "part of the buffer is pinned. possible memory corruption could occur")
    in(savedCursor >= this._pinCursor, "savedCursor cannot be less than the pin cursor")
    in(savedCursor <= this._readCursor, "savedCursor cannot be greater than the read cursor")
    {
        if(this._pinCursor > 0)
        {
            // Move the pinned slice to the front of the buffer
            for(size_t i = 0; i < this._writeCursor - this._pinCursor; i++)
                this._buffer[i] = this._buffer[this._pinCursor + i];
            this._readCursor -= this._pinCursor;
            this._writeCursor -= this._pinCursor;
            savedCursor -= this._pinCursor;
            this._pinCursor = 0;
        }

        if(this._writeCursor == this._buffer.length)
            return Result.make(Http1Error.dataExceedsBuffer, response!("422", "when fetching next set of data, the buffer was full")); // @suppress(dscanner.style.long_line)

        void[] got;
        auto result = this._socket.recieve(this._buffer[this._writeCursor..$], got, this._config.readTimeout);
        if(result.isError)
            return result;

        bytesFetched = got.length;
        this._writeCursor += got.length;
        assert(this._writeCursor <= this._buffer.length);

        return Result.noError;
    }

    private Result readUntil(ubyte delimiter)(out scope ubyte[] slice)
    {
        int attempts = 0;
        size_t startCursor = this._readCursor;

        Tail:
        attempts++;
        if(attempts >= this._config.maxReadAttempts)
            return Result.make(Http1Error.badTransport, response!("400", "Took too many read calls during a readUntil, client may be malicious")); // @suppress(dscanner.style.long_line)

        while(this._readCursor < this._writeCursor && this._buffer[this._readCursor] != delimiter)
        {
            static if(delimiter != '\n')
            if(this._buffer[this._readCursor] == '\n')
                return Result.make(Http1Error.badTransport, response!("400", "Client sent an unexpected new line character while reading until a delimiter")); // @suppress(dscanner.style.long_line)
            this._readCursor++;
        }

        if(this._readCursor == this._writeCursor)
        {
            // We didn't find the delimiter, so we need to fetch more data
            size_t bytesFetched;
            auto result = this.fetchData(bytesFetched, startCursor);
            if(result.isError)
                return result;
            if(bytesFetched == 0)
                return Result.make(Http1Error.dataExceedsBuffer, response!("500", "when reading until a delimiter, 0 bytes were read?")); // @suppress(dscanner.style.long_line)

            goto Tail;
        }

        slice = this._buffer[startCursor..this._readCursor];
        ++this._readCursor; // Skip the delimiter

        static if(delimiter == '\n')
        if(slice.length > 0 && slice[$-1] == '\r')
            slice = slice[0..$-1];

        return Result.noError;
    }

    private Result processHeader(ref scope Http1Header header)
    {
        switch(header.name)
        {
            case "content-length":
                if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
                    return Result.make(Http1Error.badLengthHeader, response!("400", "Client sent multiple content-length headers")); // @suppress(dscanner.style.long_line)
                else if(this._message.bodyEncoding & BodyEncoding.hasTransferEncoding)
                    return Result.make(Http1Error.badLengthHeader, response!("400", "Client sent a content-length header alongside a transfer-encoding header")); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasContentLength;

                import juptune.core.util.conv : to;
                auto result = to!size_t(header.value, this._message.contentLength);
                if(result.isError)
                    return Result.make(Http1Error.badLengthHeader, response!("400", "Client sent an invalid content-length header - could not convert to a size_t")); // @suppress(dscanner.style.long_line)
                return Result.noError;

            case "transfer-encoding":
                if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
                    return Result.make(Http1Error.badLengthHeader, response!("400", "Client sent a transfer-encoding header when the body has a content-length")); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasTransferEncoding;

                import std.algorithm : endsWith;
                if(header.value.endsWith("chunked"))
                    this._message.bodyEncoding |= BodyEncoding.isChunked;
                return Result.noError;

            case "connection":
                if(header.value == "close")
                    this._message.summary.connectionClosed = true;
                else if(header.value == "keep-alive")
                    this._message.summary.connectionClosed = false;
                return Result.noError;

            default:
                return Result.noError;
        }
    }
}
/// Http1 over an insecure TCP socket.
alias Http1Reader = Http1ReaderBase!TcpSocket;

/++
 + A low-level writer for the HTTP/1.0 and HTTP/1.1 protocols.
 +
 + Performance:
 +  No explicit effort has been made to optimise this writer for performance, but
 +  it should be reasonably fast.
 +
 +  Memory wise the writer does not directly allocate heap memory as it uses the user-provided buffer,
 +  however the I/O calls can of course do whatever they want.
 +
 +  If the writer would have to perform more than 1 flush due to the data
 +  being larger than the buffer, then the writer will perform two flushes
 +  at most - one for the currently buffered data, and one for the entire remaining data 
 +  (without needing to buffer the remaining data directly).
 +
 + Buffer:
 +  The writer operates directly on a buffer provided by the user.
 +
 +  The size of the buffer dictates how many bytes can be stored before a flush
 +  is forced. Certain actions, such as calling `finishMessage`, will also force a flush.
 +
 +  Generally the idea of the buffer is to reduce the amount of I/O calls, more
 +  than anything else.
 +
 + Flow:
 +  The writer is a low-level, state-machine API, and thus requires quite a lot of involvement from the user
 +  as well as a magical incantation of calls to create fully valid HTTP messages.
 +
 +  Similar to the `Http1Reader` any `HttpError` result will contain a valid HTTP response,
 +  however it's not really useful due to the fact these errors will almost always occur mid-message,
 +  making it impossible to relay the information to the client.
 +
 +  Generally, if a protocol error is encountered simply close the connection.
 +
 + RequestFlow:
 +  1. Call `putRequestLine` to write the request line.
 +  2. Call `putHeader` to write any headers.
 +      2.1 If you plan to write a body, you must either write a `content-length` header,
 +          or write a `transfer-encoding: chunked` header.
 +  3. Call `finishHeaders` to finish the headers.
 +  4. Call `putBody` to write any body data, if any.
 +  5. Call `finishBody` to finish the body.
 +  6. Call `finishMessage` to finish the message.
 +
 + ResponseFlow:
 +  The response flow is very similar to the request flow except we need
 +  to account for being able to write trailer headers.
 +
 +  1. Call `putResponseLine` to write the response line.
 +  2. Call `putHeader` to write any headers.
 +    2.1 If you plan to write a body, you must either write a `content-length` header,
 +        or write a `transfer-encoding: chunked` header.
 +  3. Call `finishHeaders` to finish the headers.
 +  4. Call `putBody` to write any body data, if any.
 +  5. Call `finishBody` to finish the body.
 +  6. If the `transfer-encoding: chunked` header was written:
 +      6.1 Call `putTrailer` to write any trailer headers, if any.
 +  7. Call `finishTrailer` to finish the trailer headers. You must do this regardless of if you wrote/can use trailers.
 +  8. Call `finishMessage` to finish the message.
 +
 + Notes:
 +  The writer currently does not support scattered writes.
 +
 +  The writer will never close the socket as it does not have ownership of it.
 +
 + Security:
 +  The writer internally makes use of a type-system-based state machine to make it more difficult
 +  to perform a bad state transition.
 +
 +  No other specific security issues are addressed beyond ensuring that the data
 +  written is valid according to RFC 9110 & 9112
 +
 + Issues:
 +  The writer is currently in an early state, and is not yet ready for production.
 +
 +  The current API is not stable, and may change in the future.
 +
 +  The writer does not natively perform compression.
 +
 +  The writer is not very extensively tested yet.
 +
 +  Specific differences between HTTP/1.0 and HTTP/1.1 are not fully implemented,
 +  as HTTP/1.1 has been the main focus.
 + ++/
struct Http1WriterBase(SocketT)
{
    private alias Machine = StateMachineTypes!(State, MessageState);
    private alias StateMachine = Machine.Static!([
        Machine.Transition(State.startLine, State.headers),
        Machine.Transition(State.headers,   State.body),
        Machine.Transition(State.body,      State.finalise, (ref state) => state.isRequest),
        Machine.Transition(State.body,      State.trailers, (ref state) => !state.isRequest),
        Machine.Transition(State.trailers,  State.finalise),
        Machine.Transition(State.finalise,  State.startLine),
    ]);

    private enum State
    {
        FAILSAFE,
        startLine,
        headers,
        body,
        trailers,
        finalise,
    }

    private enum BodyEncoding
    {
        FAILSAFE,
        hasContentLength    = 1 << 0,
        isChunked           = 1 << 1,
        hasTransferEncoding = 1 << 2,
    }

    private static struct MessageState
    {
        Http1Version httpVersion;
        Http1MessageSummary summary;
        BodyEncoding bodyEncoding;
        bool isRequest;
        size_t contentLength;
    }

    private @nogc nothrow
    {
        // General state
        Http1Config _config;
        SocketT* _socket;
        ubyte[] _buffer;

        // Current state
        MessageState _message;
        StateMachine _state;

        // I/O state
        size_t _writeCursor;

        invariant(_writeCursor <= _buffer.length);
    }
    
    @disable this(this);

    @nogc nothrow:

    /++
     + Creates a new HTTP/1 writer.
     +
     + State:
     +  The writer will be in the `startLine` state.
     +
     + Notes:
     +  The writer does not take ownership of the socket.
     +
     +  The writer takes ownership of the data inside of `buffer`, but not it's overall lifetime.
     +
     +  `socket` and `buffer` must outlive the writer.
     +
     + Params:
     +  socket = The socket to write to.
     +  buffer = The buffer to use for writing.
     +  config = The configuration to use.
     + ++/
    this(SocketT* socket, ubyte[] buffer, Http1Config config)
    in(socket !is null, "socket cannot be null")
    {
        this._socket = socket;
        this._buffer = buffer;
        this._config = config;
        this._state  = StateMachine(State.startLine);
    }

    /++
     + Writes the HTTP message stored within the provided `result`
     + to the socket.
     +
     + State:
     +  The writer must be in the `startLine` state. It will still be in the `startLine` 
     +  state after this function is called.
     +
     + Assertions:
     +  The provided `result` must be an `Http1Error` result.
     +
     + Notes:
     +  This function assumes that the result was created by a `Http1Reader` or
     +  a `Http1Writer`, as these types ensure that the error response is a valid HTTP message.
     +
     +  Technically there is nothing stopping the user from homebrewing their own `Http1Error` result,
     +  but this is not recommended.
     +
     + Params:
     +  result = The result to write.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    Result putResultResponse(Result result)
    in(this._state.mustBeIn(State.startLine))
    in(result.isErrorType!Http1Error, "Only Http1Error results are supported as they contain a premade HTTP response")
    in(this._writeCursor == 0, "bug: Unflushed data? Messages must be flushed upon completion, so this shouldnt happen")
    {
        return this._socket.put(result.error);
    }

    /++
     + Writes an entire request line. This will configure this writer to be a request writer
     + for the remainder of the message, until `finishMessage` is called.
     +
     + State:
     +  The writer must be in the `startLine` state.
     +
     +  The writer will be in the `headers` state after this function is called.
     +
     + Params:
     +  method      = The method to use.
     +  path        = The path to use.
     +  httpVersion = The HTTP version to use.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badRequestMethod` if the method is invalid.
     +
     +  `Http1Error.badRequestPath` if the path is invalid. See `http1IsPathValidForMethod`.
     +
     +  `Http1Error.badRequestVersion` if the HTTP version is invalid.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    Result putRequestLine(scope const char[] method, scope const char[] path, Http1Version httpVersion)
    in(this._state.mustBeIn(State.startLine))
    in(this._writeCursor == 0, "bug: Unflushed data? Messages must be flushed upon completion, so this shouldnt happen")
    {
        this._message = MessageState.init;
        this._message.isRequest = true;
        this._message.httpVersion = httpVersion;

        if(!method.isHttp1Token())
            return Result.make(Http1Error.badRequestMethod, response!("500", "Invalid method provided when writing request line")); // @suppress(dscanner.style.long_line)
        if(!http1IsPathValidForMethod(method, path))
            return Result.make(Http1Error.badRequestPath, response!("500", "Path is either invalid or not supported for selected method when writing request line")); // @suppress(dscanner.style.long_line // @suppress(dscanner.style.long_line)

        auto result = this.bufferedWrite(method);
        if(result.isError)
            return result;

        result = this.bufferedWrite(" ");
        if(result.isError)
            return result;

        result = this.bufferedWrite(path);
        if(result.isError)
            return result;

        result = this.bufferedWrite(" ");
        if(result.isError)
            return result;

        switch(httpVersion)
        {
            case Http1Version.http10:
                result = this.bufferedWrite("HTTP/1.0\r\n");
                break;
            case Http1Version.http11:
                result = this.bufferedWrite("HTTP/1.1\r\n");
                break;
            default:
                return Result.make(Http1Error.badRequestVersion, response!("500", "Unsupported http version provided when writing request line")); // @suppress(dscanner.style.long_line)
        }
        if(result.isError)
            return result;

        this._state.mustTransition!(State.startLine, State.headers)(this._message);
        return Result.noError;
    }

    /++
     + Writes an entire response line. This will configure this writer to be a response writer
     + for the remainder of the message, until `finishMessage` is called.
     +
     + State:
     +  The writer must be in the `startLine` state.
     +
     +  The writer will be in the `headers` state after this function is called.
     +
     + Params:
     +  httpVersion = The HTTP version to use.
     +  statusCode  = The status code to use.
     +  reason      = The reason to use.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badRequestVersion` if the HTTP version is invalid.
     +
     +  `Http1Error.badRequestReason` if the reason is empty or invalid.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    Result putResponseLine(Http1Version httpVersion, uint statusCode, scope const char[] reason)
    in(this._state.mustBeIn(State.startLine))
    in(this._writeCursor == 0, "bug: Unflushed data? Messages must be flushed upon completion, so this shouldnt happen")
    {
        this._message = MessageState.init;
        this._message.httpVersion = httpVersion;

        if(!reason.isHttp1Reason())
            return Result.make(Http1Error.badResponseReason, response!("500", "Invalid reason provided when writing response line")); // @suppress(dscanner.style.long_line)

        Result result = Result.noError;

        switch(httpVersion)
        {
            case Http1Version.http10:
                result = this.bufferedWrite("HTTP/1.0 ");
                break;
            case Http1Version.http11:
                result = this.bufferedWrite("HTTP/1.1 ");
                break;
            default:
                return Result.make(Http1Error.badRequestVersion, response!("500", "Unsupported http version provided when writing response line")); // @suppress(dscanner.style.long_line)
        }
        if(result.isError)
            return result;

        import juptune.core.util.conv : IntToCharBuffer, toBase10;
        IntToCharBuffer buffer;
        auto statusCodeStr = toBase10(statusCode, buffer);
        result = this.bufferedWrite(statusCodeStr);
        if(result.isError)
            return result;

        result = this.bufferedWrite(" ");
        if(result.isError)
            return result;

        result = this.bufferedWrite(reason);
        if(result.isError)
            return result;

        result = this.bufferedWrite("\r\n");
        if(result.isError)
            return result;

        this._state.mustTransition!(State.startLine, State.headers)(this._message);
        return Result.noError;
    }

    /++
     + Writes a single header.
     +
     + State:
     +  The writer must be in the `headers` state.
     +
     +  The writer will be in the `headers` state after this function is called.
     +
     +  If the header is "content-length" then the writer will enter an internal
     +  state that allows it to keep track of how much data has been written with `putBody`.
     +
     +  If the header is "transfer-encoding" with a value of "chunked" then the writer
     +  will enter an internal state that allows it to create chunked bodies when using `putBody`.
     +
     + Notes:
     +  The writer will automatically keep track of any critical headers it requires
     +  in order to function correctly, such as "content-length" and "transfer-encoding".
     +
     +  In defiance of the RFC, and is relatively common practice nowadays, the writer
     +  will force all header names into lowercase. This is to simplify the user code's processing,
     +  and to ensure the user code does not have to deal with case-insensitive comparisons.
     +
     +  This is especially important for user code that can use HTTP/2 and HTTP/3, as those protocols
     +  are case-insensitive with header names. (if/whenever these protocols are supported). Case-sensitive
     +  header names are a relic of the past, and should not be used nor encouraged.
     +
     +  Headers are written in the order they are provided.
     +
     + Params:
     +  name  = The name of the header.
     +  value = The value of the header.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badHeaderName` if the header name is invalid.
     +
     +  `Http1Error.badHeaderValue` if the header value is invalid.
     +
     +  `Http1Error.badTransport` if `putTrailer` is being used when not using chunked encoding.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    alias putHeader = putHeaderImpl!false;

    /// Ditto.
    alias putTrailer = putHeaderImpl!true;

    private Result putHeaderImpl(bool trailers)(scope const char[] name, scope const char[] value)
    in((!trailers && this._state.mustBeIn(State.headers)) || (trailers && this._state.mustBeIn(State.trailers)))
    {
        static if(trailers)
        if(!(this._message.bodyEncoding & BodyEncoding.isChunked))
            return Result.make(Http1Error.badTransport, response!("500", "Attempted to write a trailer header when not using chunked encoding")); // @suppress(dscanner.style.long_line)

        if(!value.isHttp1HeaderValue())
            return Result.make(Http1Error.badHeaderValue, response!("500", "Invalid header value provided when writing header")); // @suppress(dscanner.style.long_line)

        const(char)[] bufferedName;
        auto result = this.bufferHeaderName(name, bufferedName);
        if(result.isError)
            return result;

        result = this.processHeader(bufferedName, value);
        if(result.isError)
            return result;

        result = this.bufferedWrite(": ");
        if(result.isError)
            return result;

        result = this.bufferedWrite(value);
        if(result.isError)
            return result;

        result = this.bufferedWrite("\r\n");
        if(result.isError)
            return result;

        return Result.noError;
    }

    /++
     + Finishes the headers.
     +
     + State:
     +  The writer must be in the `headers` state.
     +
     +  The writer will be in the `body` state after this function is called.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    alias finishHeaders = finishHeadersImpl!false;

    /// Ditto.
    alias finishTrailers = finishHeadersImpl!true;

    private Result finishHeadersImpl(bool trailers)()
    in((!trailers && this._state.mustBeIn(State.headers)) || (trailers && this._state.mustBeIn(State.trailers)))
    {
        static if(trailers)
        if(!(this._message.bodyEncoding & BodyEncoding.isChunked)) // If we're not using chunked encoding, we don't need to write a final \r\n
        {
            this._state.mustTransition!(State.trailers, State.finalise)(this._message);
            return Result.noError;
        }

        auto result = this.bufferedWrite("\r\n");
        if(result.isError)
            return result;
        
        static if(!trailers)
            this._state.mustTransition!(State.headers, State.body)(this._message);
        else
            this._state.mustTransition!(State.trailers, State.finalise)(this._message);

        return Result.noError;
    }

    /++
     + Writes body data.
     +
     + State:
     +  The writer must be in the `body` state.
     +
     +  The writer will be in the `body` state after this function is called.
     +
     + Notes:
     +  If the body encoding is `BodyEncoding.hasContentLength` then the writer will
     +  automatically keep track of how much data has been written, and will return an error
     +  if the user attempts to write more data than the `content-length` header specified.
     +
     +  If the body encoding is `BodyEncoding.isChunked` then the writer will instead
     +  use a chunked encoded body, allowing the user to write as much data as they want.
     +
     +  Currently the ability to write chunk extensions is not supported.
     +
     + Params:
     +  data = The data to write.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badTransport` if the writer is using "content-length" for this message
     +   and the length of `data` will exceed the amount of data allowed by "conent-length".
     +
     +  `Http1Error.badTransport` if the writer cannot determine how to encode the body.
     + ++/
    Result putBody(scope const void[] data)
    in(this._state.mustBeIn(State.body))
    {
        if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
            return this.putBodyContentLength(data);
        else if(this._message.bodyEncoding & BodyEncoding.isChunked)
            return this.putBodyChunked(data);
        else
            return Result.make(Http1Error.badTransport, response!("500", "Attempted to write body data when encoding style hasn't been selected")); // @suppress(dscanner.style.long_line)
    }

    /++
     + Finishes the body.
     +
     + State:
     +  The writer must be in the `body` state.
     +
     +  [Requests Only]
     +  The writer will be in the `finalise` state after this function is called.
     +
     +  [Responses Only]
     +  The writer will be in the `trailers` state after this function is called.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     +  `Http1Error.badTransport` if the writer is using "content-length" for this message
     +  and the amount of data sent in the body is not equal to the amount of data specified by "content-length".
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    Result finishBody()
    in(this._state.mustBeIn(State.body))
    {
        if((this._message.bodyEncoding & BodyEncoding.hasContentLength) && this._message.contentLength > 0)
            return Result.make(Http1Error.badTransport, response!("500", "Attempted to finish body when content-length bytes has not been fully written to body")); // @suppress(dscanner.style.long_line)
        
        if(this._message.isRequest)
        {
            if(this._message.bodyEncoding & BodyEncoding.isChunked)
            {
                auto result = this.bufferedWrite("0\r\n\r\n");
                if(result.isError)
                    return result;
            }
            this._state.mustTransition!(State.body, State.finalise)(this._message);
        }
        else
        {
            if(this._message.bodyEncoding & BodyEncoding.isChunked)
            {
                auto result = this.bufferedWrite("0\r\n");
                if(result.isError)
                    return result;
            }
            this._state.mustTransition!(State.body, State.trailers)(this._message);
        }

        return Result.noError;  
    }

    /++
     + Acknowledges that the entire HTTP message has been written, and returns a summary
     +
     + State:
     +  The writer must be in the `finalise` state.
     +
     +  The writer will be in the `startLine` state after this function is called.
     +
     +  The writer will no longer be in request/response mode after this function is called.
     +
     + Notes:
     +  This will always perform a flush.
     +
     + Params:
     +  summary = The summary of the message.
     +
     + Throws:
     +  If an error occurs, the writer will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. See `juptune.event.io.IoError`.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response.
     + ++/
    Result finishMessage(scope out Http1MessageSummary summary)
    in(this._state.mustBeIn(State.finalise))
    {
        auto result = this.flush();
        if(result.isError)
            return result;

        summary = this._message.summary;
        this._state.mustTransition!(State.finalise, State.startLine)(this._message);
        return Result.noError;
    }

    private Result putBodyContentLength(scope const void[] data)
    {
        if(data.length > this._message.contentLength)
            return Result.make(Http1Error.badTransport, response!("500", "Attempted to write more body data than the content-length header specified")); // @suppress(dscanner.style.long_line)

        auto result = this.bufferedWrite(data);
        if(result.isError)
            return result;

        this._message.contentLength -= data.length;
        return Result.noError;
    }

    private Result putBodyChunked(scope const void[] data)
    {
        if(data.length == 0)
            return Result.noError;

        import juptune.core.util.conv : toBase16, IntToHexCharBuffer;
        IntToHexCharBuffer buffer;
        auto hex = toBase16(data.length, buffer);
        // HACK: toBase16 is purely designed to create a human readable string
        //       in the form `0x00001234`, but we need to remove the `0x0000` prefix
        //
        //       A proper solution is to implement a better toBase16 function, but
        //       this will do for now.
        hex = hex[2..$]; // Remove the `0x` prefix
        while(hex.length > 0 && hex[0] == '0')
            hex = hex[1..$];

        auto result = this.bufferedWrite(hex);
        if(result.isError)
            return result;

        result = this.bufferedWrite("\r\n");
        if(result.isError)
            return result;

        result = this.bufferedWrite(data);
        if(result.isError)
            return result;

        result = this.bufferedWrite("\r\n");
        if(result.isError)
            return result;

        return Result.noError;
    }

    private Result flush()
    {
        if(this._writeCursor == 0)
            return Result.noError;

        auto result = this._socket.put(this._buffer[0..this._writeCursor], this._config.writeTimeout);
        if(result.isError)
            return result;

        this._writeCursor = 0;
        return Result.noError;
    }

    private Result bufferedWrite(scope const void[] data)
    {
        if(this._writeCursor + data.length >= this._buffer.length)
        {
            auto result = this.flush();
            if(result.isError)
                return result;

            if(data.length >= this._buffer.length) // If we would need to perform more than 1 flush, just send it all directly
                return this._socket.put(data, this._config.writeTimeout);
            
            // Otherwise we can just buffer it for the time being
            this._buffer[0..data.length] = cast(ubyte[])data[0..$];
            this._writeCursor = data.length;
            return Result.noError;
        }

        this._buffer[this._writeCursor..this._writeCursor + data.length] = cast(ubyte[])data[0..$];
        this._writeCursor += data.length;
        return Result.noError;
    }

    private Result bufferHeaderName(scope const char[] name, out scope const(char)[] buffered)
    {
        auto end = this._writeCursor + name.length;
        if(end > this._buffer.length && this._writeCursor > 0)
        {
            auto result = this.flush();
            if(result.isError)
                return result;
            end = name.length;
        }

        if(end > this._buffer.length)
            return Result.make(Http1Error.dataExceedsBuffer, response!("500", "when buffering header name, the buffer was full")); // @suppress(dscanner.style.long_line)

        ubyte[] slice = this._buffer[this._writeCursor..end];
        slice[0..$] = cast(ubyte[])name[0..$];
        this._writeCursor = end;
        
        if(!http1CanonicalHeaderNameInPlace(cast(ubyte[])slice))
            return Result.make(Http1Error.badHeaderName, response!("500", "when buffering header name, the header name was invalid")); // @suppress(dscanner.style.long_line)
        
        buffered = cast(const(char)[])slice[0..$];
        return Result.noError;
    }

    private Result processHeader(scope const char[] name, scope const char[] value)
    {
        switch(name)
        {
            case "content-length":
                if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
                    return Result.make(Http1Error.badLengthHeader, response!("500", "when processing header, attempted to send a content-length header when the body has a content-length")); // @suppress(dscanner.style.long_line)
                else if(this._message.bodyEncoding & BodyEncoding.hasTransferEncoding)
                    return Result.make(Http1Error.badLengthHeader, response!("500", "when processing header, attempted to send a content-length header when the body has a transfer-encoding")); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasContentLength;

                import juptune.core.util.conv : to;
                auto result = to!size_t(value, this._message.contentLength);
                if(result.isError)
                    return Result.make(Http1Error.badLengthHeader, response!("500", "when processing header, attempted to send an invalid content-length header - could not convert to a size_t")); // @suppress(dscanner.style.long_line)
                return Result.noError;

            case "transfer-encoding":
                if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
                    return Result.make(Http1Error.badLengthHeader, response!("500", "when processing header, attempted to send a transfer-encoding header when the body has a content-length")); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasTransferEncoding;

                import std.algorithm : endsWith;
                if(value.endsWith("chunked"))
                    this._message.bodyEncoding |= BodyEncoding.isChunked;
                return Result.noError;

            case "connection":
                if(value == "close")
                    this._message.summary.connectionClosed = true;
                else if(value == "keep-alive")
                    this._message.summary.connectionClosed = false;
                break;

            default: break;
        }

        return Result.noError;
    }
}
/// Http1 over an insecure TCP socket.
alias Http1Writer = Http1WriterBase!TcpSocket;

/**** Helper functions ****/

/++
 + Normalises a header name in-place. More specifically this converts the header name to lowercase,
 + while also checking that the header name is valid.
 +
 + Notes:
 +  If normalisation fails, the header name will be left in a half-modified state.
 +
 + Params:
 +  headerName = The header name to normalise.
 + 
 + Returns:
 +  `true` if the header name was valid, `false` otherwise.
 + ++/
bool http1CanonicalHeaderNameInPlace(ref scope ubyte[] headerName) @nogc nothrow pure
{
    foreach(ref ch; headerName)
    {
        auto old = ch;
        ch = g_headerNormaliseTable[ch];
        if(ch == INVALID_HEADER_CHAR)
        {
            ch = old;
            return false;
        }
    }
    return true;
}

/++
 + Checks if a string is a valid HTTP 'token' as defined by RFC 9110.
 +
 + Not the most useful function for user code, but there's no reason to not have it be public.
 +
 + Notes:
 +  An empty string is not considered a valid token.
 +
 + Params:
 +  token = The token to check.
 +
 + Returns:
 +  `true` if the token is valid, `false` otherwise.
 + ++/
bool isHttp1Token(scope const char[] token) @nogc nothrow pure
{
    if(token.length == 0)
        return false;

    foreach(ch; token)
    {
        if(!(g_rfc9110CharType[ch] & Rfc9110CharType.TCHAR))
            return false;
    }
    return true;
}

/++
 + Checks if a string is a valid HTTP header value as defined by RFC 9110.
 +
 + Not the most useful function for user code, but there's no reason to not have it be public.
 +
 + Notes:
 +  An empty string is not considered a valid header value.
 +
 + Params:
 +  value = The header value to check.
 +
 + Returns:
 +  `true` if the header value is valid, `false` otherwise.
 + ++/
bool isHttp1HeaderValue(scope const char[] value) @nogc nothrow pure
{
    if(value.length == 0)
        return false;

    if(!(g_rfc9110CharType[value[0]] & Rfc9110CharType.VCHAR)
    || !(g_rfc9110CharType[value[$-1]] & Rfc9110CharType.VCHAR))
        return false;

    foreach(i; 1..value.length)
    {
        if(!(g_rfc9110CharType[value[i]] & Rfc9110CharType.MIDDLE_OF_HEADER_MASK))
            return false;
    }

    return true;
}

/++
 + Checks if a string is a valid HTTP status line reason as defined by RFC 9110.
 +
 + Not the most useful function for user code, but there's no reason to not have it be public.
 +
 + Notes:
 +  An empty string is not considered a valid value.
 +
 + Params:
 +  value = The value to check.
 +
 + Returns:
 +  `true` if the value is valid, `false` otherwise.
 + ++/
bool isHttp1Reason(scope const char[] value) @nogc nothrow pure
{
    if(value.length == 0)
        return true;

    foreach(i; 0..value.length)
    {
        if(!(g_rfc9110CharType[value[i]] & Rfc9110CharType.REASON_MASK))
            return false;
    }

    return true;
}

/++
 + Checks whether the given path is valid for the given method, taking into account whether
 + the request is being proxied or not.
 +
 + Notes:
 +  HttpWriter and HttpReader already perform path validation, however keeping this logic
 +  private doesn't provide much benefit, so it's been made public.
 +
 +  This check should match the speficiation of Section 3.2 in RFC9112.
 +
 +  The overload that takes a `UriParseHints` is provided for performance reasons, as it allows
 +  the caller to avoid parsing the path twice. It is unable to handle `OPTIONS *` however as
 +  '*' is not a valid RFC 3986 URI so a trivial check must be manually performed beforehand.
 +
 +  Additionally another overload is provided that returns the parsed URI with hints, as it is likely that
 +  the caller will need to parse the URI anyway.
 +
 + Params:
 +  method = The method to check the path against.
 +  path = The path to check.
 +  isProxyRequest = Whether the request is being proxied or not.
 +
 + Returns:
 +  `true` if the path is valid for the given method, `false` otherwise.
 + ++/
bool http1IsPathValidForMethod(
    scope const char[] method, 
    const char[] path,
    bool isProxyRequest = false
) @safe @nogc nothrow
{
    Uri uri;
    return http1IsPathValidForMethod(method, path, uri, isProxyRequest);
}

/// ditto.
bool http1IsPathValidForMethod(
    scope const char[] method, 
    const char[] path,
    scope out Uri uri,
    bool isProxyRequest = false
) @safe @nogc nothrow
{
    switch(method) with(UriParseHints)
    {
        case "OPTIONS":
            if(path == "*")
                return true;
            goto default;

        case "CONNECT":
            auto result = uriParseNoCopy(path, uri, UriParseRules.allowUriSuffix);
            return !result.isError && http1IsPathValidForMethod(method, uri.hints, isProxyRequest);

        default:
            auto result = uriParseNoCopy(path, uri);
            if(isProxyRequest && method != "OPTIONS")
                return !result.isError && (uri.hints & isAbsolute);
            else
                return !result.isError && http1IsPathValidForMethod(method, uri.hints);
    }
}

/// ditto
bool http1IsPathValidForMethod(scope const char[] method, UriParseHints hints, bool isProxyRequest = false) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
{
    switch(method) with(UriParseHints)
    {
        case "CONNECT":
            return (
                (hints & isUriSuffix)
                && (hints & pathIsEmpty)
                && (hints & queryIsEmpty)
                && (hints & fragmentIsEmpty)
                && (hints & authorityHasPort)
                && !(hints & authorityHasUserInfo)
            );

        default:
            if(isProxyRequest && method != "OPTIONS")
                return (hints & isAbsolute) != 0;
            else
                return (
                    !(hints & isAbsolute)
                    && !(hints & isNetworkReference)
                    && (hints & pathIsAbsolute)
                );
    }
}

/**** Unit tests ****/

version(unittest) private Uri makePath(string path, string query, string fragment)
{
    import juptune.event.io : IpAddress;
    import std.typecons : Nullable;
    return Uri(
        null, null, null, Nullable!IpAddress.init, Nullable!ushort.init,
        path, query, fragment
    );
}

@("http1CanonicalHeaderNameInPlace")
unittest
{
    static struct T
    {
        char[] input;
        string expected;
        bool success;

        this(string input, string expected, bool success = true)
        {
            this.input = input.dup;
            this.expected = expected;
            this.success = success;
        }
    }

    T[] cases = [
        T("Content-Type", "content-type"),
        T("content-type", "content-type"),
        T("CONTENT-TYPE", "content-type"),
        T("Content-type", "content-type"),
        T("content-Type", "content-type"),
        T("content-Type", "content-type"),
        T("content-ty\0", "", false),
    ];

    foreach(test; cases)
    {
        ubyte[] input = cast(ubyte[])test.input;
        assert(http1CanonicalHeaderNameInPlace(input) == test.success);
        if(test.success)
            assert(input == cast(ubyte[])test.expected);
    }
}

@("Http1Reader - readRequestLine - simple success cases")
unittest
{
    import juptune.core.util, juptune.event;

    struct T
    {
        string request;
        string expectedMethod;
        Uri expectedPath;
        Http1Version expectedVersion;
    }

    static T[] cases = [
        T("GET / HTTP/1.0\r\n", "GET", makePath("/", null, null), Http1Version.http10),
        T("A / HTTP/1.1\r\n", "A", makePath("/", null, null), Http1Version.http11),
        T("A /abc HTTP/1.1\r\n", "A", makePath("/abc", null, null), Http1Version.http11),
        T("A /?a=b HTTP/1.1\r\n", "A", makePath("/", "a=b", null), Http1Version.http11),
        T("A /#a HTTP/1.1\r\n", "A", makePath("/", null, "a"), Http1Version.http11),
        T("A /a?b#c HTTP/1.1\r\n", "A", makePath("/a", "b", "c"), Http1Version.http11),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            foreach(test; cases)
                socket.put(test.request).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[32] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(test; cases)
            {
                Http1RequestLine requestLine;
                reader.readRequestLine(requestLine).resultAssert;

                reader._state.mustBeIn(Http1Reader.State.maybeEndOfHeaders);
                assert(reader._message.httpVersion == test.expectedVersion);
                assert(requestLine.httpVersion == test.expectedVersion);
                requestLine.access((method, path) {
                    assert(method == test.expectedMethod);
                    path.hints = UriParseHints.none; // We don't care about the hints
                    assert(path == test.expectedPath);
                });

                reader._state.forceState(Http1Reader.State.startLine);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - readRequestLine - simple error cases")
unittest
{
    import juptune.core.util, juptune.event;

    static struct T
    {
        string request;
        Http1Error expectedError;
    }

    static shared T[string] cases;
    cases = [
        "empty request method": T(" / HTTP/1.1\r\n", Http1Error.badRequestMethod),
        "empty request path": T("GET  HTTP/1.1\r\n", Http1Error.badRequestPath),
        "empty request version": T("GET / \r\n", Http1Error.badRequestVersion),
        "invalid request path": T("GET a.com b HTTP/1.1\r\n", Http1Error.badRequestPath),
        "invalid request version": T("GET / HTTP/1.2\r\n", Http1Error.badRequestVersion),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        try foreach(name, test; cases)
        {
            import std.algorithm : move;

            static struct CasePair
            {
                string name;
                T test;
                TcpSocket socket;
            }

            TcpSocket[2] pairs;
            TcpSocket.makePair(pairs).resultAssert;

            CasePair[2] casePairs;
            casePairs[0] = CasePair(name, test);
            casePairs[1] = CasePair(name, test);
            move(pairs[0], casePairs[0].socket);
            move(pairs[1], casePairs[1].socket);

            // Curious: ensuring order of async doesn't matter by placing the read before the write
            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                
                ubyte[32] buffer;
                Http1RequestLine requestLine;
                scope reader = Http1Reader(&pair.socket, buffer[], Http1Config());
                auto result = reader.readRequestLine(requestLine);
                assert(result.isError(pair.test.expectedError), pair.name);
            }, casePairs[1], &asyncMoveSetter!CasePair).resultAssert;

            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                pair.socket.put(pair.test.request).resultAssert;
            }, casePairs[0], &asyncMoveSetter!CasePair).resultAssert;
        }
        catch(Exception ex) assert(false, ex.msg);
    });
    loop.join();
}

@("Http1Reader - readHeader - simple success cases")
unittest
{
    import juptune.core.util, juptune.event;

    struct T
    {
        string request;
        string expectedName;
        string expectedValue;
    }

    static T[] cases = [
        T("Name:Value\r\n", "name", "Value"),
        T("Name: Value\r\n", "name", "Value"),
        T("Name:Value \r\n", "name", "Value"),
        T("Name: Value \r\n", "name", "Value"),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            foreach(test; cases)
                socket.put(test.request).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[16] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(test; cases)
            {
                reader._state.forceState(Http1Reader.State.headers);

                Http1Header header;
                reader.readHeader(header).resultAssert;

                reader._state.mustBeIn(Http1Reader.State.maybeEndOfHeaders);
                header.access((name, value) {
                    assert(name == test.expectedName);
                    assert(value == test.expectedValue);
                });

            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - readHeader - simple error cases")
unittest
{
    import juptune.core.util, juptune.event;

    static struct T
    {
        string request;
        Http1Error expectedError;
    }

    static shared T[string] cases;
    cases = [
        "empty header name": T(": gzip\r\n", Http1Error.badHeaderName),
        "space in header name": T("na me: value\r\n", Http1Error.badHeaderName),
        "invalid header name": T("%: value\r\n", Http1Error.badHeaderName),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        try foreach(name, test; cases)
        {
            import std.algorithm : move;

            static struct CasePair
            {
                string name;
                T test;
                TcpSocket socket;
            }

            TcpSocket[2] pairs;
            TcpSocket.makePair(pairs).resultAssert;

            CasePair[2] casePairs;
            casePairs[0] = CasePair(name, test);
            casePairs[1] = CasePair(name, test);
            move(pairs[0], casePairs[0].socket);
            move(pairs[1], casePairs[1].socket);

            // Curious: ensuring order of async doesn't matter by placing the read before the write
            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                
                ubyte[64] buffer;
                Http1Header requestLine;
                scope reader = Http1Reader(&pair.socket, buffer[], Http1Config());
                reader._state.forceState(Http1Reader.State.headers);
                auto result = reader.readHeader(requestLine);
                assert(result.isError(pair.test.expectedError), pair.name);
            }, casePairs[1], &asyncMoveSetter!CasePair).resultAssert;

            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                pair.socket.put(pair.test.request).resultAssert;
            }, casePairs[0], &asyncMoveSetter!CasePair).resultAssert;
        }
        catch(Exception ex) assert(false, ex.msg);
    });
    loop.join();
}

@("Http1Reader - checkEndOfHeaders - simple success")
unittest
{
    import juptune.core.util, juptune.event;

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            socket.put("\r\n\r\n").resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[16] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(_; 0..2)
            {
                bool isEnd;
                reader._state.forceState(Http1Reader.State.maybeEndOfHeaders);
                reader.checkEndOfHeaders(isEnd).resultAssert;
                assert(isEnd);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - readBody - single buffer read")
unittest
{
    import juptune.core.util, juptune.event;

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            socket.put("0123").resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[4] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            reader._state.forceState(Http1Reader.State.body);
            reader._message.bodyEncoding |= Http1Reader.BodyEncoding.hasContentLength;
            reader._message.contentLength = 4;

            Http1BodyChunk bodyChunk;
            reader.readBody(bodyChunk).resultAssert;
            bodyChunk.access((data) {
                assert(data == "0123");
                assert(!bodyChunk.hasDataLeft);
            });
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - readBody - content-length - multi buffer read")
unittest
{
    import juptune.core.util, juptune.event;

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            socket.put("0123").resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[2] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            reader._state.forceState(Http1Reader.State.body);
            reader._message.bodyEncoding |= Http1Reader.BodyEncoding.hasContentLength;
            reader._message.contentLength = 4;

            Http1BodyChunk bodyChunk;
            reader.readBody(bodyChunk).resultAssert;
            bodyChunk.access((data) {
                assert(data == "01");
                assert(bodyChunk.hasDataLeft);
            });

            bodyChunk = Http1BodyChunk.init;
            reader.readBody(bodyChunk).resultAssert;
            bodyChunk.access((data) {
                assert(data == "23");
                assert(!bodyChunk.hasDataLeft);
            });
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - readBody - chunked - success cases")
unittest
{
    import juptune.core.util, juptune.event;

    static struct T
    {
        string chunkBody;
        string expectedBody;
    }

    static T[] cases = [
        T("0\r\n\r\n", ""),
        T("8\r\n01234567\r\n0\r\n\r\n", "01234567"),
        T("A\r\n0123456789\r\nA\r\nabcdefghij\r\n0\r\n\r\n", "0123456789abcdefghij"),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            foreach(test; cases)
                socket.put(test.chunkBody).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[8] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(test; cases)
            {
                reader._state.forceState(Http1Reader.State.body);
                reader._message = Http1Reader.MessageState.init;
                reader._message.isRequest = true;
                reader._message.bodyEncoding |= Http1Reader.BodyEncoding.hasTransferEncoding;
                reader._message.bodyEncoding |= Http1Reader.BodyEncoding.isChunked;

                Http1BodyChunk bodyChunk;
                reader.readBody(bodyChunk).resultAssert;

                size_t totalRead;
                while(bodyChunk.hasDataLeft)
                {
                    bodyChunk.access((data) {
                        assert(data == test.expectedBody[totalRead..totalRead+data.length]);
                    });
                    totalRead += bodyChunk.data.length;
                    bodyChunk = Http1BodyChunk.init;
                    reader.readBody(bodyChunk).resultAssert;
                }

                assert(totalRead == test.expectedBody.length);
                assert(bodyChunk.data.length == 0);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - full requests - low-level API - success cases")
unittest
{
    import juptune.core.util, juptune.event;

    static struct H
    {
        string name;
        string value;
    }

    static struct T
    {
        string request;
        string expectedMethod;
        Uri expectedPath;
        Http1Version expectedVersion;
        H[] expectedHeaders;
        string expectedBody;
    }

    static T[] cases = [
        T(
`GET / HTTP/1.1
Host: localhost
Content-Length: 4

1234`,
            "GET", makePath("/", null, null), Http1Version.http11,
            [
                H("host", "localhost"),
                H("content-length", "4"),
            ], 
            "1234"
        ),

        T(
`POST / HTTP/1.0
Transfer-Encoding: chunked

5
01234
5
56789
0

`,
            "POST", makePath("/", null, null), Http1Version.http10,
            [
                H("transfer-encoding", "chunked"),
            ], 
            "0123456789"
        ),

        T(
`POST / HTTP/1.1
Transfer-Encoding: chunked

0

`,
            "POST", makePath("/", null, null), Http1Version.http11,
            [
                H("transfer-encoding", "chunked"),
            ], 
            ""
        ),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            foreach(test; cases)
                socket.put(test.request).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[64] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(test; cases)
            {
                Http1RequestLine requestLine;
                reader.readRequestLine(requestLine).resultAssert;
                assert(requestLine.httpVersion == test.expectedVersion);
                requestLine.access((method, path) {
                    assert(method == test.expectedMethod);
                    path.hints = UriParseHints.none; // We don't care about the hints
                    assert(path == test.expectedPath);
                });
                requestLine = Http1RequestLine.init;

                bool endOfHeaders;
                reader.checkEndOfHeaders(endOfHeaders).resultAssert;
                while(!endOfHeaders)
                {
                    Http1Header header;
                    reader.readHeader(header).resultAssert;
                    header.access((name, value) {
                        foreach(expected; test.expectedHeaders)
                        {
                            if(name == expected.name)
                            {
                                assert(value == expected.value);
                                return;
                            }
                        }
                        assert(false, "header not found");
                    });
                    header = Http1Header.init;
                    reader.checkEndOfHeaders(endOfHeaders).resultAssert;
                }

                size_t totalRead;
                Http1BodyChunk bodyChunk;
                bool loop = true;
                while(loop)
                {
                    reader.readBody(bodyChunk).resultAssert;
                    bodyChunk.access((data) {
                        assert(data == test.expectedBody[totalRead..totalRead+data.length]);
                    });
                    totalRead += bodyChunk.data.length;
                    loop = bodyChunk.hasDataLeft;
                    bodyChunk = Http1BodyChunk.init;
                }
                assert(totalRead == test.expectedBody.length);
                assert(!bodyChunk.hasDataLeft);

                Http1MessageSummary summary;
                reader.finishMessage(summary).resultAssert;

                if(test.expectedVersion == Http1Version.http11)
                    assert(!summary.connectionClosed);
                else
                    assert(summary.connectionClosed);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - full responses - low-level API - success cases")
unittest
{
    import juptune.core.util, juptune.event;

    static struct H
    {
        string name;
        string value;
    }

    static struct T
    {
        string response;
        Http1Version expectedVersion;
        uint expectedStatusCode;
        string expectedReasonPhrase;
        H[] expectedHeaders;
        string expectedBody;
        H[] expectedTrailers;
    }

    static T[] cases = [
        T(
`HTTP/1.1 200 OK
Content-Length: 0

`,
            Http1Version.http11, 200, "OK",
            [
                H("content-length", "0"),
            ], 
            "",
            []
        ),

        T(
`HTTP/1.1 200 OK
Content-Length: 4
Content-Type: text/plain

1234`,
            Http1Version.http11, 200, "OK",
            [
                H("content-length", "4"),
                H("content-type", "text/plain"),
            ], 
            "1234",
            []
        ),

        T(
`HTTP/1.1 200 OK
Transfer-Encoding: chunked

0

`,
            Http1Version.http11, 200, "OK",
            [
                H("transfer-encoding", "chunked"),
            ], 
            "",
            []
        ),

        T(
`HTTP/1.1 200 OK
Transfer-Encoding: chunked

0
X-Some-Trailer: yes

`,
            Http1Version.http11, 200, "OK",
            [
                H("transfer-encoding", "chunked"),
            ], 
            "",
            [
                H("x-some-trailer", "yes"),
            ]
        ),

        T(
`HTTP/1.1 200 OK
Transfer-Encoding: chunked

0
X-Some-Trailer: yes
X-Please: don't crash

`,
            Http1Version.http11, 200, "OK",
            [
                H("transfer-encoding", "chunked"),
            ], 
            "",
            [
                H("x-some-trailer", "yes"),
                H("x-please", "don't crash"),
            ]
        ),

        T(
`HTTP/1.1 200 
Content-Length: 0

`,
            Http1Version.http11, 200, "",
            [
                H("content-length", "0"),
            ], 
            "",
            []
        ),

        // Keep last - it leaves data in the socket we currently don't skip past.
        T(
`HTTP/1.1 100 OK
Content-Length: 512

Because this is a 1xx response, the reader should force treat this as bodyless`,
            Http1Version.http11, 100, "OK",
            [
                H("content-length", "512"),
            ],
            "",
            []
        ),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            foreach(test; cases)
                socket.put(test.response).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            ubyte[64] buffer;
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            auto reader = Http1Reader(socket, buffer[], Http1Config());

            foreach(test; cases)
            {
                Http1ResponseLine responseLine;
                reader.readResponseLine(responseLine).resultAssert;
                responseLine.access((reason) {
                    assert(responseLine.httpVersion == test.expectedVersion);
                    assert(responseLine.statusCode == test.expectedStatusCode);
                    assert(reason == test.expectedReasonPhrase);
                });
                responseLine = Http1ResponseLine.init;

                bool endOfHeaders;
                reader.checkEndOfHeaders(endOfHeaders).resultAssert;
                while(!endOfHeaders)
                {
                    Http1Header header;
                    reader.readHeader(header).resultAssert;
                    header.access((name, value) {
                        foreach(expected; test.expectedHeaders)
                        {
                            if(name == expected.name)
                            {
                                assert(value == expected.value);
                                return;
                            }
                        }
                        assert(false, "header not found");
                    });
                    header = Http1Header.init;
                    reader.checkEndOfHeaders(endOfHeaders).resultAssert;
                }

                size_t totalRead;
                Http1BodyChunk bodyChunk;
                bool loop = true;
                while(loop)
                {
                    reader.readBody(bodyChunk).resultAssert;
                    bodyChunk.access((data) {
                        assert(data == test.expectedBody[totalRead..totalRead+data.length]);
                    });
                    totalRead += bodyChunk.data.length;
                    loop = bodyChunk.hasDataLeft;
                    bodyChunk = Http1BodyChunk.init;
                }
                assert(totalRead == test.expectedBody.length);
                assert(!bodyChunk.hasDataLeft);

                bool endOfTrailers;
                reader.checkEndOfTrailers(endOfTrailers).resultAssert;
                while(!endOfTrailers)
                {
                    Http1Header header;
                    reader.readTrailer(header).resultAssert;
                    header.access((name, value) {
                        foreach(expected; test.expectedTrailers)
                        {
                            if(name == expected.name)
                            {
                                assert(value == expected.value);
                                return;
                            }
                        }
                        assert(false, "trailer not found");
                    });
                    header = Http1Header.init;
                    reader.checkEndOfTrailers(endOfTrailers).resultAssert;
                }

                Http1MessageSummary summary;
                reader.finishMessage(summary).resultAssert;

                if(test.expectedVersion == Http1Version.http11)
                    assert(!summary.connectionClosed);
                else
                    assert(summary.connectionClosed);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("Http1Reader - timeout")
unittest
{
    import core.time;
    import juptune.core.util, juptune.event;

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        ubyte[1] buffer;
        auto reader = Http1Reader(&pairs[0], buffer[], Http1Config().withReadTimeout(1.msecs));

        Http1RequestLine requestLine;
        auto result = reader.readRequestLine(requestLine);
        assert(result.isError(IoError.timeout));
    });
    loop.join();
}

@("Http1Writer - full-requests - simple success cases")
unittest
{
    import juptune.core.util, juptune.event;

    enum E
    {
        length,
        chunked
    }

    static struct H
    {
        string name;
        string value;
    }

    static struct T
    {
        string method;
        string path;
        Http1Version version_;
        H[] headers;
        E encoding;
        string[] chunks;
        string expectedRequest;
    }

    static shared T[string] cases;
    cases = [
        "request line only": T(
            "GET", "/", Http1Version.http11,
            [],
            E.length, [],
            "GET / HTTP/1.1\n\n"
        ),
        "request line and headers": T(
            "GET", "/", Http1Version.http11,
            [
                H("Host", "dlang.org"),
                H("User-Agent", "d boulderz"),
            ],
            E.length, [],
            "GET / HTTP/1.1\nhost: dlang.org\nuser-agent: d boulderz\n\n"
        ),
        "content-length": T(
            "GET", "/", Http1Version.http11,
            [],
            E.length, ["abc123"], "GET / HTTP/1.1\ncontent-length: 6\n\nabc123"
        ),
        "chunked zero": T(
            "GET", "/", Http1Version.http11,
            [],
            E.chunked, [], "GET / HTTP/1.1\ntransfer-encoding: chunked\n\n0\n\n"
        ),
        "chunked single": T(
            "GET", "/", Http1Version.http11,
            [],
            E.chunked, ["abc123"], "GET / HTTP/1.1\ntransfer-encoding: chunked\n\n6\nabc123\n0\n\n"
        ),
        "chunked multiple": T(
            "GET", "/", Http1Version.http11,
            [],
            E.chunked, ["abc", "123"], "GET / HTTP/1.1\ntransfer-encoding: chunked\n\n3\nabc\n3\n123\n0\n\n"
        ),
    ];

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() nothrow {
        try foreach(name, test; cases)
        {
            import std.algorithm : move;

            static struct CasePair
            {
                string name;
                T test;
                TcpSocket socket;
            }

            TcpSocket[2] pairs;
            TcpSocket.makePair(pairs).resultAssert;

            CasePair[2] casePairs;
            casePairs[0] = CasePair(name, cast()test);
            casePairs[1] = CasePair(name, cast()test);
            move(pairs[0], casePairs[0].socket);
            move(pairs[1], casePairs[1].socket);

            async((){
                import std.algorithm : joiner;
                import std.conv : to;
                import std.range : walkLength;
                
                auto pair = juptuneEventLoopGetContext!CasePair;
                
                Http1MessageSummary summary;
                ubyte[512] buffer;
                auto writer = Http1Writer(&pair.socket, buffer, Http1Config());

                writer.putRequestLine(pair.test.method, pair.test.path, pair.test.version_).resultAssert;
                foreach(header; pair.test.headers)
                    writer.putHeader(header.name, header.value).resultAssert;

                if(pair.test.encoding == E.length && pair.test.chunks.length > 0)
                    writer.putHeader("Content-Length", pair.test.chunks.joiner.walkLength.to!string).resultAssert;
                else if(pair.test.encoding == E.chunked)
                    writer.putHeader("Transfer-Encoding", "chunked").resultAssert;
                
                writer.finishHeaders().resultAssert;
                foreach(chunk; pair.test.chunks)
                    writer.putBody(chunk).resultAssert;
                writer.finishBody().resultAssert;
                writer.finishMessage(summary).resultAssert;
            }, casePairs[0], &asyncMoveSetter!CasePair).resultAssert;

            async((){
                import std.exception : assumeWontThrow;
                auto pair = juptuneEventLoopGetContext!CasePair;
                
                ubyte[512] buffer;
                void[] usedBuffer;
                pair.socket.recieve(buffer[], usedBuffer).resultAssert;

                import std.algorithm : equal, substitute;
                import std.format : format;
                assert(
                    (cast(char[])usedBuffer)
                    .substitute!("\r\n", "\n")
                    .equal(pair.test.expectedRequest)
                    .assumeWontThrow,
                    
                    format(
                        "Expected request to be \n---\n%s\n---\nbut was\n---\n%s\n---\n", 
                        pair.test.expectedRequest, 
                        cast(char[])usedBuffer
                    ).assumeWontThrow
                );
            }, casePairs[1], &asyncMoveSetter!CasePair).resultAssert;
        }
        catch(Exception ex) assert(false, ex.msg);
    });
    loop.join();
}