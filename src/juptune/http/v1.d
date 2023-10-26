/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.http.v1;

import juptune.core.ds   : MemoryBlockPoolAllocator, MemoryBlockAllocation;
import juptune.core.util : Result;
import juptune.event.io  : TcpSocket;
import juptune.http.uri  : ScopeUri, uriParseNoCopy, UriParseHints;

private enum INVALID_HEADER_CHAR = 0xFF;
private immutable ubyte[256] g_headerNormaliseTable = (){
    ubyte[256] table;
    table[] = INVALID_HEADER_CHAR;

    foreach(ch; 'A'..'Z')
        table[ch] = cast(ubyte)((ch - 'A') + 'a');

    foreach(ch; 'a'..'z')
        table[ch] = cast(ubyte)ch;

    foreach(ch; '0'..'9')
        table[ch] = cast(ubyte)ch;

    table['-'] = '-';
    return table;
}();

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

    badHeaderName,      /// Issue with header name
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
    private ScopeUri path;

    /// Accesses the request line data.
    void access(scope void delegate(scope const char[] method, scope ScopeUri path) @safe func) @safe
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
    }

    /// ditto.
    void access(scope void delegate(scope const char[] method, scope ScopeUri path) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
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
    void access(scope void delegate(scope ubyte[] data) @safe func) @safe
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
    void access(scope void delegate(scope const char[] name, scope const char[] value) @safe func) @safe
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
 + Configuration for the Http1Reader.
 + ++/
struct Http1Config
{
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
     + ++/
    size_t maxReadAttempts = 5;

    @safe @nogc nothrow pure:

    Http1Config withMaxReadAttempts(size_t v) return { this.maxReadAttempts = v; return this; }
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
 + Notes:
 +  A high-level API is planned, but for now not implemented.
 +
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
 + Issues:
 +  The reader is currently in a very early state, and is not yet ready for production use.
 +
 +  The current API is especially volatile and has no stability guarantees, as quite a lot of functionality
 +  is still missing or not yet exposed.
 +
 +  Only request parsing is currently implemented. Responses are not yet implemented.
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
struct Http1Reader 
{
    private enum State
    {
        FAILSAFE,
        startLine,
        headers,
        maybeEndOfHeaders,
        body,
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
        size_t contentLength;
        size_t contentLengthRead;
    }

    private
    {
        // General state
        Http1Config _config;
        TcpSocket* _socket;
        ubyte[] _buffer;

        // Current state
        MessageState _message;
        State _state;

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
    this(TcpSocket* socket, ubyte[] buffer, Http1Config config)
    in(socket !is null, "socket cannot be null")
    in(buffer !is null, "buffer cannot be null")
    in(buffer.length > 0, "buffer cannot be empty")
    {
        this._socket = socket;
        this._buffer = buffer;
        this._config = config;
        this._state  = State.startLine;
    }

    /// Enforces that all pinned slices have been released.
    ~this()
    {
        assert(this._pinnedSliceIsAlive == 0, "pinned slice was not freed before dtor of Http1Reader");
    }
    
    /++ 
     + Reads the entire request line. This will configure the reader to be a request parser for the
     + remainder message, until `finishMessage` is called.
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
     +  Anything the underlying I/O functions can throw. An attempt is made to map common errors to
     +  a standardised `Http1Error` value, but this is not guaranteed for every response.
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
    in(this._state == State.startLine, "cannot read request line when not in startLine state")
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

        // Path
        result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badRequestPath, response!("400", "Empty path in request line. A minimum of / is required")); // @suppress(dscanner.style.long_line)
        
        UriParseHints hints;
        result = uriParseNoCopy(cast(char[])slice, requestLine.path, hints);
        if(result.isError)
            return result;
        else if(
            (hints & (UriParseHints.isAbsolute | UriParseHints.isNetworkReference))
            || !(hints & UriParseHints.pathIsAbsolute)
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
        this._state = State.maybeEndOfHeaders;
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
     +  Anything the underlying I/O functions can throw. An attempt is made to map common errors to
     +  a standardised `Http1Error` value, but this is not guaranteed for every response.
     +
     +  `Http1Error.dataExceedsBuffer` if the entire header line is larger than the provided buffer.
     +
     +  `Http1Error.badHeaderName` if the header name is missing or invalid.
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
    Result readHeader(out scope Http1Header header)
    in(this._state == State.headers, "cannot read header when not in headers state")
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
        
        // Handle special headers
        result = this.processHeader(header);
        if(result.isError)
            return result;

        header.entireLine = Http1PinnedSlice(&this._pinnedSliceIsAlive);
        this._state = State.maybeEndOfHeaders;
        this._pinCursor = this._readCursor;
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
     +  Anything the underlying I/O functions can throw. An attempt is made to map common errors to
     +  a standardised `Http1Error` value, but this is not guaranteed for every response.
     +
     +  `Http1Error.badTransport` if it is determined that the transport layer is in a bad state, or if the
     +  sender appears to be malicious/poorly coded.
     +
     + Returns:
     +  A `Result` describing if an error ocurred. Any `Http1Error` will contain a valid HTTP error response
     +  that can be sent to the client as-is.
     + ++/
    alias checkEndOfHeaders = checkEndOfHeadersImpl!false;
    private Result checkEndOfHeadersImpl(bool internal)(out scope bool isEnd)
    in(this._pinCursor == this._readCursor, "pin cursor must be at the read cursor")
    in(this._state == State.maybeEndOfHeaders || internal, "cannot check end of headers when not in maybeEndOfHeaders state") // @suppress(dscanner.style.long_line)
    {
        // Fast path: if we already have enough data in the buffer we can
        //            skip the readUntil call.
        // TODO: readUntil could be completely avoided by using fetchData directly
        if(this._writeCursor - this._readCursor >= 2
        && this._buffer[this._readCursor] == '\r' 
        && this._buffer[this._readCursor+1] == '\n')
        {
            this._readCursor += 2;
            this._pinCursor = this._readCursor;
            this._state = State.body;
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
            this._state = State.body;
            isEnd = true;
        }
        else
        {
            this._state = State.headers;
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
     +  After this function is called, the reader will be in the `body` state if there's more data to read,
     +  or the `finalise` state if there's no more data to read.
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
     + Params:
     +  bodyChunk = Stores the body chunk data.
     +
     + Throws:
     +  If an error occurs, the reader will be in an invalid state and should not be used again.
     +
     +  Anything the underlying I/O functions can throw. An attempt is made to map common errors to
     +  a standardised `Http1Error` value, but this is not guaranteed for every response.
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
    in(this._state == State.body, "cannot read body when not in body state")
    in(this._pinCursor == this._readCursor, "pin cursor must be at the read cursor")
    {
        if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
            return this.readBodyContentLength(bodyChunk);
        else if(this._message.bodyEncoding & BodyEncoding.isChunked)
            return this.readBodyChunked(bodyChunk);
        else
        {
            bodyChunk.dataLeft = false;
            bodyChunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);
            this._state = State.finalise;
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
    in(this._state == State.finalise, "cannot finish message when not in finalise state")
    {
        summary = this._message.summary;
        this._state = State.startLine;
        return Result.noError;
    }

    private Result readBodyContentLength(out scope Http1BodyChunk chunk)
    {
        auto result = this.readBodyBytes(chunk);
        if(result.isError)
            return result;
        else if(!chunk.hasDataLeft)
            this._state = State.finalise;
        
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
                auto result = this.checkEndOfHeadersImpl!true(isEnd);
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
                chunk.dataLeft = false;
                chunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);
                this._state = State.finalise; // TODO: Trailer headers
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
        result = to!size_t(cast(char[])slice, chunkSize);
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
        auto result = this._socket.recieve(this._buffer[this._writeCursor..$], got);
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

/**** Unit tests ****/

version(unittest) private ScopeUri makePath(string path, string query, string fragment)
{
    import juptune.event.io : IpAddress;
    import std.typecons : Nullable;
    return ScopeUri(
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
        ScopeUri expectedPath;
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

                assert(reader._state == Http1Reader.State.maybeEndOfHeaders);
                assert(reader._message.httpVersion == test.expectedVersion);
                assert(requestLine.httpVersion == test.expectedVersion);
                requestLine.access((method, path) {
                    assert(method == test.expectedMethod);
                    assert(path == test.expectedPath);
                });

                reader._state = Http1Reader.State.startLine;
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
                reader._state = Http1Reader.State.headers;

                Http1Header header;
                reader.readHeader(header).resultAssert;

                assert(reader._state == Http1Reader.State.maybeEndOfHeaders);
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
                reader._state = Http1Reader.State.headers;
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
                reader._state = Http1Reader.State.maybeEndOfHeaders;
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

            reader._state = Http1Reader.State.body;
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

            reader._state = Http1Reader.State.body;
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
        T("0\r\n", ""),
        T("8\r\n01234567\r\n0\r\n", "01234567"),
        T("10\r\n0123456789\r\n10\r\nabcdefghij\r\n0\r\n", "0123456789abcdefghij"),
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
                reader._state = Http1Reader.State.body;
                reader._message = Http1Reader.MessageState.init;
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
        ScopeUri expectedPath;
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