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
import juptune.http.uri  : Http1RawPath;

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

enum Http1Version
{
    FAILSAFE,
    http10,
    http11,
}

enum Http1Error
{
    none,
    dataExceedsBuffer,
    badRequest,
}

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

    ~this()
    {
        if(this._pinned !is null)
        {
            *this._pinned -= 1;
            this._pinned = null;
        }
    }
}

struct Http1RawPath
{
    private
    {
        const(char)[] _path;
        const(char)[] _query;
        const(char)[] _fragment;
    }
}

struct Http1RequestLine
{
    Http1PinnedSlice entireLine;
    Http1Version httpVersion;
    private const(char)[] method;
    private Http1RawPath path;

    void access(scope void delegate(scope const char[] method, scope Http1RawPath path) @safe func) @safe
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
    }

    void access(scope void delegate(scope const char[] method, scope Http1RawPath path) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.method, this.path);
    }
}

struct Http1BodyChunk
{
    Http1PinnedSlice entireChunk;
    private ubyte[] data;
    private bool dataLeft;
    private const(char)[] extensionLine;

    void access(scope void delegate(scope ubyte[] data) @safe func) @safe
    in(this.entireChunk._pinned !is null, "entireChunk must be pinned")
    {
        func(this.data);
    }

    void access(scope void delegate(scope ubyte[] data) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireChunk._pinned !is null, "entireChunk must be pinned")
    {
        func(this.data);
    }

    bool hasDataLeft() @safe @nogc nothrow const
    {
        return this.dataLeft;
    }
}

struct Http1Header
{
    Http1PinnedSlice entireLine;
    private const(char)[] name;
    private const(char)[] value;

    void access(scope void delegate(scope const char[] name, scope const char[] value) @safe func) @safe
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.name, this.value);
    }

    void access(scope void delegate(scope const char[] name, scope const char[] value) @safe @nogc nothrow func) @safe @nogc nothrow // @suppress(dscanner.style.long_line)
    in(this.entireLine._pinned !is null, "entireLine must be pinned")
    {
        func(this.name, this.value);
    }
}

struct Http1Config
{
    size_t maxReadAttempts = 5;

    @safe @nogc nothrow pure:

    Http1Config withMaxReadAttempts(size_t v) return { this.maxReadAttempts = v; return this; }
}

struct Http1Reader 
{
    private enum State
    {
        FAILSAFE,
        startLine,
        headers,
        maybeEndOfHeaders,
        body,
        error, // End state, unable to recover
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

    ~this()
    {
        assert(this._pinnedSliceIsAlive == 0, "pinned slice was not freed before dtor of Http1Reader");
    }

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
            return Result.make(Http1Error.badRequest, "Client sent an empty method in request line");
        requestLine.method = cast(char[])slice[0..$];

        // Path
        result = this.readUntil!' '(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badRequest, "Client sent an empty path in request line. A minimum of a / is required"); // @suppress(dscanner.style.long_line)
        // TODO: parseUri

        // Version
        result = this.readUntil!'\n'(slice);
        if(result.isError)
            return result;
        else if(slice.length != 8)
            return Result.make(Http1Error.badRequest, "Client sent an invalid/unsupported http version in request line");
        else if(slice[0..8] == "HTTP/1.0")
            this._message.httpVersion = Http1Version.http10;
        else if(slice[0..8] == "HTTP/1.1")
            this._message.httpVersion = Http1Version.http11;
        else
            return Result.make(Http1Error.badRequest, "Client sent an unsupported http version in request line");

        requestLine.httpVersion = this._message.httpVersion;
        requestLine.entireLine = Http1PinnedSlice(&this._pinnedSliceIsAlive);
        this._state = State.maybeEndOfHeaders;
        this._pinCursor = this._readCursor;
        return Result.noError;
    }

    Result readHeader(out scope Http1Header header)
    in(this._state == State.headers, "cannot read header when not in headers state")
    {
        ubyte[] slice;

        // Name
        auto result = this.readUntil!':'(slice);
        if(result.isError)
            return result;
        else if(slice.length == 0)
            return Result.make(Http1Error.badRequest, "Client sent an empty header name");
        else if(slice[$-1] == ' ')
            return Result.make(Http1Error.badRequest, "RFC 7230 3.2.4 - No whitespace is allowed between the header field-name and colon"); // @suppress(dscanner.style.long_line)
        else if(!http1CanonicalHeaderNameInPlace(slice))
            return Result.make(Http1Error.badRequest, "Client sent an invalid header name");
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

    Result readBody(out scope Http1BodyChunk bodyChunk)
    in(this._state == State.body, "cannot read body when not in body state")
    in(this._pinCursor == this._readCursor, "pin cursor must be at the read cursor")
    {
        if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
            return this.readBodyContentLength(bodyChunk);
        else if(this._message.bodyEncoding & BodyEncoding.isChunked)
            return this.readBodyChunked(bodyChunk);
        else
            return Result.make(Http1Error.badRequest, "Client sent a request with a body, but has no content-length or transfer-encoding header"); // @suppress(dscanner.style.long_line)
    }

    private Result readBodyContentLength(out scope Http1BodyChunk chunk)
    {
        auto result = this.readBodyBytes(chunk);
        if(result.isError)
            return result;
        else if(!chunk.hasDataLeft)
            this._state = State.startLine;
        
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
                    return Result.make(Http1Error.badRequest, "Client sent an invalid chunk - expected CRLF to terminate chunk data"); // @suppress(dscanner.style.long_line)
            }

            auto result = this.readChunkSize(this._message.contentLength, chunk.extensionLine);
            if(result.isError)
                return result;

            if(this._message.contentLength == 0)
            {
                chunk.dataLeft = false;
                chunk.entireChunk = Http1PinnedSlice(&this._pinnedSliceIsAlive);
                this._state = State.startLine; // TODO: Trailer headers
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
            return Result.make(Http1Error.badRequest, "Client sent an invalid chunk size - could not convert to a size_t"); // @suppress(dscanner.style.long_line)

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
                return Result.make(Http1Error.dataExceedsBuffer, "when reading next body chunk, 0 bytes were read?");
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
            return Result.make(Http1Error.dataExceedsBuffer, "when fetching next set of data, the buffer was full");

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
            return Result.make(Http1Error.badRequest, "Took too many read calls during a readUntil, client may be malicious"); // @suppress(dscanner.style.long_line)

        while(this._readCursor < this._writeCursor && this._buffer[this._readCursor] != delimiter)
        {
            static if(delimiter != '\n')
            if(this._buffer[this._readCursor] == '\n')
                return Result.make(Http1Error.badRequest, "Client sent an unexpected new line character while reading until a delimiter"); // @suppress(dscanner.style.long_line)
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
                return Result.make(Http1Error.dataExceedsBuffer, "when reading until a delimiter, 0 bytes were read?");

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
                    return Result.make(Http1Error.badRequest, "Client sent multiple content-length headers"); // @suppress(dscanner.style.long_line)
                else if(this._message.bodyEncoding & BodyEncoding.hasTransferEncoding)
                    return Result.make(Http1Error.badRequest, "Client sent a content-length header alongside a transfer-encoding header"); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasContentLength;

                import juptune.core.util.conv : to;
                auto result = to!size_t(header.value, this._message.contentLength);
                if(result.isError)
                    return Result.make(Http1Error.badRequest, "Client sent an invalid content-length header - could not convert to a size_t"); // @suppress(dscanner.style.long_line)
                
                return Result.noError;

            case "transfer-encoding":
                if(this._message.bodyEncoding & BodyEncoding.hasContentLength)
                    return Result.make(Http1Error.badRequest, "Client sent a transfer-encoding header when the body has a content-length"); // @suppress(dscanner.style.long_line)

                this._message.bodyEncoding |= BodyEncoding.hasTransferEncoding;

                import std.algorithm : endsWith;
                if(header.value.endsWith("chunked"))
                    this._message.bodyEncoding |= BodyEncoding.isChunked;

                return Result.noError;

            default:
                return Result.noError;
        }
    }
}

/**** Helper functions ****/

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
        Http1RawPath expectedPath;
        Http1Version expectedVersion;
    }

    static T[] cases = [
        T("GET / HTTP/1.0\r\n", "GET", Http1RawPath(), Http1Version.http10),
        T("A / HTTP/1.1\r\n", "A", Http1RawPath(), Http1Version.http11),
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
                Http1RequestLine requestLine;
                reader.readRequestLine(requestLine).resultAssert;

                assert(reader._state == Http1Reader.State.maybeEndOfHeaders);
                assert(reader._message.httpVersion == test.expectedVersion);
                assert(requestLine.httpVersion == test.expectedVersion);
                requestLine.access((method, path) {
                    assert(method == test.expectedMethod);
                    // TODO: assert(path.path == "/");
                });

                reader._state = Http1Reader.State.startLine;
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
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
        Http1RawPath expectedPath;
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
            "GET", Http1RawPath(), Http1Version.http11,
            [
                H("host", "localhost"),
                H("content-length", "4"),
            ], 
            "1234"
        ),

        T(
`POST / HTTP/1.1
Transfer-Encoding: chunked

5
01234
5
56789
0
`,
            "POST", Http1RawPath(), Http1Version.http11,
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
                    // assert(path == test.expectedPath);
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

                assert(reader._state == Http1Reader.State.startLine);
            }
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}