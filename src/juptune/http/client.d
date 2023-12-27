module juptune.http.client;

import juptune.core.util : Result;

/++
 + Which version of HTTP to use/has been selected by a `HttpClient`.
 + ++/
enum HttpClientVersion
{
    FAILSAFE,

    /// Automatically select the highest version supported by the server.
    automatic,

    /// HTTP/1.1
    http1,
}

/++
 + Configuration for a `HttpClient`.
 + ++/
struct HttpClientConfig
{
    import core.time       : seconds;
    import juptune.http.v1 : Http1Config;

    /// Configuration for HTTP/1.1 - this defaults to a 30 second timeout for both reading and writing.
    Http1Config http1 = Http1Config().withReadTimeout(30.seconds).withWriteTimeout(30.seconds);

    /// Which version of HTTP to use when connecting to a server.
    HttpClientVersion httpVersion = HttpClientVersion.automatic;
    
    size_t readBufferSize  = 1024 * 8; /// The size of the read buffer to use.
    size_t writeBufferSize = 1024 * 8; /// The size of the write buffer to use.

    @safe @nogc nothrow pure:

    HttpClientConfig withHttp1Config(Http1Config v) return { this.http1 = v; return this; }
    HttpClientConfig withHttpVersion(HttpClientVersion v) return { this.httpVersion = v; return this; }
    HttpClientConfig withReadBufferSize(size_t v) return { this.readBufferSize = v; return this; }
    HttpClientConfig withWriteBufferSize(size_t v) return { this.writeBufferSize = v; return this; }
}

/++
 + An interface for a HTTP client.
 +
 + While Juptune is an @nogc-first library, it's silly to pretend that there's no place for
 + GC-oriented code. Such code is likely to make use of OOP, so this interface is provided
 + as a standard way to use a HTTP client.
 +
 + Please use the documentation from `HttpClient` as it in almost all cases applies to this interface.
 +
 + The only real difference is that `IHttpClient.streamRequest` correspeonds to `HttpClient.streamRequestGC`,
 + since there's no real reason to expose the @nogc version.
 + ++/
interface IHttpClient
{
    import juptune.http.common : HttpRequest, HttpResponse;
    import juptune.event.io    : IpAddress;

    nothrow:

    Result request(scope ref const HttpRequest request, scope out HttpResponse response);
    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope HttpClient.StreamRequestFuncGC bodyPutter, 
        scope HttpClient.StreamResponseFuncGC bodyReader,
    );
    Result connect(IpAddress ip);
    Result close();
    bool isConnected() const;
    HttpClientVersion selectedVersion() const;
}

/++
 + An adapter around `HttpClient` that allows it to be used as an `IHttpClient`.
 +
 + Please see the documentation for `HttpClient`.
 + ++/
final class HttpClientAdapter : IHttpClient
{
    private
    {
        HttpClient _client;
    }

    this(HttpClientConfig config)
    {
        this._client = HttpClient(config);
    }

    nothrow:

    Result request(scope ref const HttpRequest request, scope out HttpResponse response)
        => this._client.request(request, response);

    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope HttpClient.StreamRequestFuncGC bodyPutter, 
        scope HttpClient.StreamResponseFuncGC bodyReader,
    ) => this._client.streamRequestGC(request, response, bodyPutter, bodyReader);

    Result connect(IpAddress ip) => this._client.connect(ip);

    Result close() => this._client.close();

    bool isConnected() const => this._client.isConnected();

    HttpClientVersion selectedVersion() const => this._client.selectedVersion();
}

/++
 + A medium-level HTTP client, designed to be a good balance between ease of use, flexibility,
 + and performance.
 +
 + This client attempts to cater to both the @nogc and GC worlds, and as such has a few different
 + named overloads for its functions.
 +
 + It has two different ways to send a request currently: A 'Simple' way, and a 'Streamed' way.
 +
 + Simple:
 +  This is the easiest way to send a request, but isn't the most suitable for all situations,
 +  especially sending/receiving large amounts of data.
 +
 +  This method is used by calling the `request` function with a pre-built `HttpRequest` containing
 +  the entire request. Please consult the documentation for `HttpRequest` and `request` for more info.
 +
 + Streamed:
 +  This is the most flexible way to send a request beyond using the low-level primitives directly,
 +  but is more complex to use. This is the recommended way to send/receive large amounts of data.
 +
 +  This method is used by calling the `streamRequest` function which provides a callback-based
 +  pattern for sending/receiving data. Please consult the documentation for `streamRequest` for more info.
 + ++/
struct HttpClient
{
    import juptune.core.ds      : Array, String;
    import juptune.event.io     : TcpSocket, IpAddress;
    import juptune.http.common  : HttpRequest, HttpResponse;
    import juptune.http.uri     : ScopeUri;

    /// A function provided by `HttpClient` which can be used to push data into the request body.
    alias PutBodyFunc = Result delegate(scope const ubyte[] bodyChunk) @nogc nothrow;
    /// ditto
    alias PutBodyFuncGC = Result delegate(scope const ubyte[] bodyChunk) nothrow;

    /// A function provided by the user which is used to stream an entire request body.
    alias StreamRequestFunc = Result delegate(scope PutBodyFunc putter) @nogc nothrow;
    /// ditto
    alias StreamRequestFuncGC = Result delegate(scope PutBodyFuncGC putter) nothrow;

    /++
     + A function provided by `HttpClient` which can be used to stream read data from the response body.
     +
     + Please note that the `HttpResponse` does not contain a body - it only contains the headers and status line.
     +
     + Please note that this is marked `@safe` to help make it clear that the `scope` for `bodyChunk` is
     + _very_ important to adhear to.
     +
     + You can (and probably will have to) mark your func/lambda as `@trusted`, 
     + but that will also disable the compiler making sure that you don't accidentally 
     + escape the `bodyChunk` parameter.
     + ++/
    alias StreamResponseFunc = Result delegate(
        scope const ref HttpResponse statusAndHeaders, 
        scope const ubyte[] bodyChunk
    ) @safe @nogc nothrow;
    /// ditto
    alias StreamResponseFuncGC = Result delegate(
        scope const ref HttpResponse statusAndHeaders, 
        scope const ubyte[] bodyChunk
    ) @safe nothrow;

    private
    {
        // Config + Impls
        HttpClientConfig _config;
        Http1ClientImpl  _http1;
        
        // Static state
        TcpSocket   _socket;
        Array!ubyte _readBufferStorage;
        Array!ubyte _writeBufferStorage;
        ubyte[]     _readBuffer;
        ubyte[]     _writeBuffer;

        // Dynamic state
        bool                _isConnected;
        HttpClientVersion   _selectedVersion;
        bool                _lockClient;
        String              _hostName;

        invariant(_isConnected || _selectedVersion == HttpClientVersion.FAILSAFE, "bug: Incorrect state management");
        invariant(!_lockClient, "Attempted to use client while it was locked (or a bug where the lock wasn't released)"); // @suppress(dscanner.style.long_line)
    }

    @disable this(this){}

    /++
     + Creates a new `HttpClient` with the given configuration as well as allocating
     + internal buffers to the size specified in the config.
     +
     + Params:
     +  config = The configuration to use for this client.
     + ++/
    this(HttpClientConfig config) @nogc nothrow
    {
        this._config                    = config;
        this._readBufferStorage.length  = config.readBufferSize;
        this._writeBufferStorage.length = config.writeBufferSize;
        this._readBuffer                = this._readBufferStorage[];
        this._writeBuffer               = this._writeBufferStorage[];
    }

    version(unittest) private static void wrapPairedSocket(
        out HttpClient client,
        ref TcpSocket socket, 
        HttpClientConfig config
    ) @nogc nothrow
    {
        import std.algorithm : move;

        client = HttpClient(config);
        move(socket, client._socket);
        client._http1 = Http1ClientImpl(config, &client._socket, client._writeBuffer, client._readBuffer);
        client._selectedVersion = HttpClientVersion.http1;
        client._isConnected = true;
    }

    /++
     + Connects this client to the given IP address.
     +
     + Assertions:
     +  The client must not already be connected.
     +
     + Params:
     +  ip   = The IP address to connect to.
     +  host = The hostname to use for the `Host` header. If this is null, then the IP address will be used.
     +
     + Throws:
     +  Anything that `TcpSocket.connect` can throw.
     +
     + Returns:
     +  A `Result` indicating whether the connection was successful or not.
     + ++/
    Result connect(IpAddress ip, scope const char[] host = null) @nogc nothrow
    in(!this._isConnected, "This client is already connected")
    {
        if(host.length == 0)
        {
            this._hostName.length = 0;
            ip.toString(this._hostName);
        }
        else
        {
            this._hostName = host;

            if(ip.port != 80)
            {
                import juptune.core.util : IntToCharBuffer, toBase10;
                IntToCharBuffer port;
                this._hostName ~= ":";
                this._hostName ~= toBase10(ip.port, port);
            }
        }

        if(!this._socket.isOpen)
        {
            auto result = this._socket.open();
            if(result.isError)
                return result;
        }

        auto result = this._socket.connect(ip);
        if(result.isError)
            return result;
        
        this._http1 = Http1ClientImpl(this._config, &this._socket, this._writeBuffer, this._readBuffer);
        this._selectedVersion = HttpClientVersion.http1;
        this._isConnected = true;
        return Result.noError;
    }

    /++
     + Closes the connection to the server.
     +
     + Assertions:
     +  The client must be connected.
     +
     + Throws:
     +  Anything that `TcpSocket.close` can throw.
     +
     + Returns:
     +  A `Result` indicating whether the connection was closed successfully or not.
     + ++/
    Result close() @nogc nothrow
    in(this._isConnected, "This client is not connected")
    {
        auto closeResult = this.dispatch!"close"();
        auto socketResult = this._socket.close();

        this._isConnected = false;
        this._selectedVersion = HttpClientVersion.FAILSAFE;
        this._writeBuffer[] = 0;
        this._readBuffer[] = 0;

        if(closeResult.isError)
            return closeResult;
        if(socketResult.isError)
            return socketResult; // It's not too big a deal if this gets dropped in favour of closeResult
        return Result.noError;
    }

    /// Returns whether this client is connected to a server.
    bool isConnected() @nogc nothrow const => this._isConnected;

    /// Returns the version of HTTP that this client is using.
    HttpClientVersion selectedVersion() @nogc nothrow const
    in(this._isConnected, "This client is not connected")
        => this._selectedVersion;

    /++
     + Sends a request to the server and returns the response.
     +
     + This is the 'Simple' way to send a request, and is the easiest to use.
     +
     + Notes:
     +  This function will automatically add the `Host` header if it is not already present.
     +
     +  If the request has a body and does not have a `Content-Length` or `Transfer-Encoding` header,
     +  then this function will automatically add a `Transfer-Encoding: chunked` header.
     +
     +  If the request does not have a `Host` header, then this function will automatically add one
     +  using the `host` provided by the relevant connect function that was used.
     +
     +  The client will gracefully close the connection in normal circumstances such as
     +  the `Connection: close` header being present.
     +
     +  The state of the `response` parameter is undefined if this function returns an error.
     +
     +  This function will automatically close the connection if an error occurs.
     +
     + Assertions:
     +  The client must be connected.
     +
     + Params:
     +  request  = The request to send.
     +  response = The response to fill in. This will contain the entire response, including the body.
     +
     + Throws:
     +  Anything that `TcpSocket.send` or `TcpSocket.receive` can throw.
     +
     +  If using HTTP1, anything that `Http1Writer` or `Http1Reader` can throw (`Http1Error`).
     +
     + Returns:
     +  A `Result` indicating whether the request was successful or not.
     + ++/
    Result request(scope ref const HttpRequest request, scope out HttpResponse response) @nogc nothrow
    in(this._isConnected, "This client is not connected")
    {
        bool closeConnection;
        auto result = this.dispatch!"request"(request, response, this._hostName, closeConnection);
        if(result.isError || closeConnection)
            auto _ = this.close(); // request's error takes priority

        return result;
    }

    /++
     + Streams a request to the server and streams the response.
     +
     + This is the 'Streamed' way to send a request, and is the most flexible to use.
     +
     + Notes:
     +  The `response` parameter will only contain the status line, headers, and trailers (on return),
     +  and will not contain the body unless the user's callback puts it there.
     +
     +  The `request` parameter is used to provide the method, path, and headers, but the body is 
     +  always ignored.
     +
     +  The D compiler is really bad with error messages, so you may need to store `bodyPutter` and
     +  `bodyReader` in a variable before passing them to this function just to get a useful error message.
     +
     +  e.g. `scope HttpClient.StreamRequestFunc putter = (...) @trusted @nogc {...}`
     +
     +  This function will automatically add the `Host` header if it is not already present.
     +
     +  If the request has a body and does not have a `Content-Length` or `Transfer-Encoding` header,
     +  then this function will automatically add a `Transfer-Encoding: chunked` header.
     +
     +  If the request does not have a `Host` header, then this function will automatically add one
     +  using the `host` provided by the relevant connect function that was used.
     +
     +  The client will gracefully close the connection in normal circumstances such as
     +  the `Connection: close` header being present.
     +
     +  The state of the `response` parameter is undefined if this function returns an error.
     +
     +  This function will automatically close the connection if an error occurs.
     +
     + Assertions:
     +  The client must be connected.
     +
     + Params:
     +  request    = The request to send. Only the method, path, and headers are used.
     +  response   = The response to fill in. This will contain the status line, headers, and trailers.
     +  bodyPutter = A callback that will be called to stream the request body.
     +  bodyReader = A callback that will be called to stream the response body.
     +
     + Throws:
     +  Anything that `TcpSocket.send` or `TcpSocket.receive` can throw.
     +
     +  If using HTTP1, anything that `Http1Writer` or `Http1Reader` can throw (`Http1Error`).
     +
     +  Anything the user returns from `bodyPutter` or `bodyReader`.
     +
     + Returns:
     +  A `Result` indicating whether the request was successful or not.
     + ++/
    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope StreamRequestFunc bodyPutter, 
        scope StreamResponseFunc bodyReader,
    ) @nogc nothrow
    in(this._isConnected, "This client is not connected")
    {
        this._lockClient = true;
        scope(exit) this._lockClient = false;

        bool closeConnection;
        auto result = this.dispatch!"streamRequest"(
            request, 
            response, 
            bodyPutter, 
            bodyReader, 
            this._hostName,
            closeConnection
        );
        if(result.isError || closeConnection)
        {
            this._lockClient = false;
            auto _ = this.close(); // streamRequest's error takes priority
        }

        return result;
    }

    /// ditto
    Result streamRequestGC(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope StreamRequestFuncGC bodyPutter, 
        scope StreamResponseFuncGC bodyReader,
    ) nothrow
    in(this._isConnected, "This client is not connected")
    {
        this._lockClient = true;
        scope(exit) this._lockClient = false;

        bool closeConnection;
        auto result = this.dispatch!"streamRequest"(
            request, 
            response, 
            bodyPutter, 
            bodyReader, 
            this._hostName,
            closeConnection
        );
        if(result.isError || closeConnection)
        {
            this._lockClient = false;
            auto _ = this.close(); // streamRequest's error takes priority
        }

        return result;
    }

    private auto dispatch(string func, Args...)(auto ref Args args) nothrow // @suppress(dscanner.suspicious.unused_parameter)
    {
        final switch(this._selectedVersion) with(HttpClientVersion)
        {
            case http1:
                return mixin("this._http1." ~ func ~ "(args)");

            case automatic:
            case FAILSAFE:
                assert(false, "Not implemented");
        }
    }
}

private struct Http1ClientImpl
{
    import juptune.core.ds      : String;
    import juptune.event.io     : TcpSocket;
    import juptune.http.common  : HttpRequest, HttpResponse;
    
    import juptune.http.v1 : 
        Http1Version, Http1MessageSummary, Http1ResponseLine, Http1Header, 
        Http1BodyChunk, Http1ReadResponseConfig, Http1Writer, Http1Reader;

    Http1Writer writer;
    Http1Reader reader;
    
    nothrow:

    this(HttpClientConfig config, TcpSocket* socket, ubyte[] writeBuffer, ubyte[] readBuffer) @nogc
    in(socket !is null, "socket is null")
    {
        this.writer = Http1Writer(socket, writeBuffer, config.http1);
        this.reader = Http1Reader(socket, readBuffer, config.http1);
    }

    Result close() @nogc => Result.noError;

    Result request(
        scope ref const HttpRequest request, 
        scope ref HttpResponse response,
        scope ref const String defaultHost,
        scope out bool closeConnection,
    ) @nogc
    in(writer != Http1Writer.init, "Http1Writer is not initialized")
    in(reader != Http1Reader.init, "Http1Reader is not initialized")
    {
        Http1ReadResponseConfig readConfig;
        if(request.method == "HEAD")
            readConfig = readConfig.withIsBodyless(true);

        auto result = this.sendHead(request, defaultHost);
        if(result.isError)
            return result;

        result = this.sendBody(request, closeConnection);
        if(result.isError)
            return result;

        result = this.readHead(response, readConfig);
        if(result.isError)
            return result;

        result = this.readBody(response);
        if(result.isError)
            return result;

        result = this.readTrailers(response, closeConnection);
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result streamRequest(RequestFuncT, ResponseFuncT)(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope RequestFuncT bodyPutter, 
        scope ResponseFuncT bodyReader,
        scope ref const String defaultHost,
        scope out bool closeConnection,
    )
    in(writer != Http1Writer.init, "Http1Writer is not initialized")
    in(reader != Http1Reader.init, "Http1Reader is not initialized")
    {
        Http1ReadResponseConfig readConfig;
        if(request.method == "HEAD")
            readConfig = readConfig.withIsBodyless(true);

        auto result = this.sendHead(request, defaultHost);
        if(result.isError)
            return result;

        result = this.streamSendBody(request, bodyPutter, closeConnection);
        if(result.isError)
            return result;

        result = this.readHead(response, readConfig);
        if(result.isError)
            return result;

        result = this.streamReadBody(response, bodyReader);
        if(result.isError)
            return result;

        result = this.readTrailers(response, closeConnection);
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result sendHead(
        scope ref const HttpRequest request,
        scope ref const String defaultHost
    ) @nogc
    {
        auto result = this.writer.putRequestLine(request.method[], request.path[], Http1Version.http11);
        if(result.isError)
            return result;

        bool hasHostHeader;
        bool hasEncodingHeader;
        foreach(ref header; request.headers)
        {
            result = this.writer.putHeader(header.name[], header.value[]);
            if(result.isError)
                return result;

            if(header.name == "transfer-encoding" || header.name == "content-length")
                hasEncodingHeader = true;
            else if(header.name == "host")
                hasHostHeader = true;
        }

        if(!hasEncodingHeader)
        {
            result = this.writer.putHeader("Transfer-Encoding", "chunked");
            if(result.isError)
                return result;
        }

        if(!hasHostHeader)
        {
            result = this.writer.putHeader("Host", defaultHost[]);
            if(result.isError)
                return result;
        }

        result = this.writer.finishHeaders();
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result sendBody(
        scope ref const HttpRequest request,
        scope out bool closeConnection,
    ) @nogc
    {
        auto result = this.writer.putBody(request.body[]);
        if(result.isError)
            return result;

        result = this.writer.finishBody();
        if(result.isError)
            return result;

        Http1MessageSummary summary;
        result = this.writer.finishMessage(summary);
        if(result.isError)
            return result;

        closeConnection = closeConnection || summary.connectionClosed;
        return Result.noError;
    }

    Result streamSendBody(RequestFuncT)(
        scope ref const HttpRequest request,
        scope RequestFuncT bodyPutter,
        scope out bool closeConnection,
    )
    {
        auto result = bodyPutter(data => this.writer.putBody(data));
        if(result.isError)
            return result;

        result = this.writer.finishBody();
        if(result.isError)
            return result;

        Http1MessageSummary summary;
        result = this.writer.finishMessage(summary);
        if(result.isError)
            return result;

        closeConnection = closeConnection || summary.connectionClosed;
        return Result.noError;
    }

    Result readHead(scope ref HttpResponse response, const Http1ReadResponseConfig readConfig) @nogc
    {
        auto result = Result.noError;
        
        {
            Http1ResponseLine line;
            result = this.reader.readResponseLine(line, readConfig);
            if(result.isError)
                return result;

            line.access((scope reason){
                response.withStatus(line.statusCode);
                response.withReason(reason);
            });
        }

        bool endOfHeaders;
        result = this.reader.checkEndOfHeaders(endOfHeaders);
        if(result.isError)
            return result;

        while(!endOfHeaders)
        {
            {
                Http1Header header;
                result = this.reader.readHeader(header);
                if(result.isError)
                    return result;

                header.access((scope name, scope value){
                    response.setHeader(name, value);
                });
            }

            result = this.reader.checkEndOfHeaders(endOfHeaders);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    Result readBody(scope ref HttpResponse response) @nogc
    {
        auto result = Result.noError;

        Http1BodyChunk chunk;
        do
        {
            chunk = Http1BodyChunk();
            result = reader.readBody(chunk);
            if(result.isError)
                return result;

            chunk.access((scope ubyte[] data){
                if(data.length == 0)
                    return;
                response.putBody(data);
            });
        } while(chunk.hasDataLeft);

        return Result.noError;
    }

    Result readTrailers(
        scope ref HttpResponse response,
        scope out bool closeConnection,
    ) @nogc
    {
        bool endOfTrailers;
        auto result = this.reader.checkEndOfTrailers(endOfTrailers);
        if(result.isError)
            return result;

        while(!endOfTrailers)
        {
            {
                Http1Header header;
                result = this.reader.readTrailer(header);
                if(result.isError)
                    return result;

                header.access((scope name, scope value){
                    // response.setTrailer(name, value);
                });
            }

            result = this.reader.checkEndOfTrailers(endOfTrailers);
            if(result.isError)
                return result;
        }

        Http1MessageSummary summary;
        result = reader.finishMessage(summary);
        if(result.isError)
            return result;

        closeConnection = closeConnection || summary.connectionClosed;
        return Result.noError;
    }

    Result streamReadBody(ResponseFuncT)(
        scope ref HttpResponse response,
        scope ResponseFuncT bodyReader,
    )
    {
        auto result = Result.noError;
        static if(is(ResponseFuncT == HttpClient.StreamResponseFunc))
        {
            scope accessFunc = (scope ubyte[] data) @nogc nothrow {
                if(data.length == 0)
                    return;
                result = bodyReader(response, data);
            }; // For some reason the compiler thinks it needs to allocate a closure if we use a delegate inline.
        }
        else
        {
            scope accessFunc = (scope ubyte[] data) nothrow {
                if(data.length == 0)
                    return;
                result = bodyReader(response, data);
            };
        }

        Http1BodyChunk chunk;
        do
        {
            chunk = Http1BodyChunk();
            result = reader.readBody(chunk);
            if(result.isError)
                return result;

            chunk.access(accessFunc);

            // We close the connection if the bodyReader returns an error, so no need to fully read the message.
            // TODO: Should there be a way to signal that the user wants to keep the connection?
            //       On a similar vein, I think there's technically some responses we can always
            //       keep the connection open for, but I'm not sure if it's worth considering yet.
            if(result.isError)
                return result;
        } while(chunk.hasDataLeft);

        return Result.noError;
    }
}

version(unittest) private:

import juptune.core.util   : resultAssert;
import juptune.event;
import juptune.http.common : HttpRequest, HttpResponse;
import juptune.http.v1     : Http1Writer, Http1Reader, Http1Config;

HttpRequest collectRequest(scope ref Http1Writer writer, scope ref Http1Reader reader) @nogc nothrow
{
    import juptune.core.ds : String;
    import juptune.http.v1;

    HttpRequest request;

    {
        Http1RequestLine line;
        reader.readRequestLine(line).resultAssert;
        line.access((scope method, scope path) @trusted {
            request.withMethod(method);
        
            String pathStr;
            path.reconstruct(pathStr).resultAssert;
            request.withPath(pathStr[]);
        });
    }

    bool endOfHeaders;
    reader.checkEndOfHeaders(endOfHeaders).resultAssert;
    while(!endOfHeaders)
    {
        Http1Header header;
        reader.readHeader(header).resultAssert;
        header.access((scope name, scope value){
            request.setHeader(name, value);
        });
        reader.checkEndOfHeaders(endOfHeaders).resultAssert;
    }

    Http1BodyChunk chunk;
    do
    {
        chunk = Http1BodyChunk();
        reader.readBody(chunk).resultAssert;
        chunk.access((scope ubyte[] data){
            request.putBody(data);
        });
    } while(chunk.hasDataLeft);

    Http1MessageSummary summary;
    writer.putResponseLine(Http1Version.http11, 200, "OK").resultAssert;
    writer.putHeader("Content-Length", "5").resultAssert;
    writer.putHeader("Connection", "close").resultAssert;
    writer.finishHeaders().resultAssert;
    writer.putBody(cast(ubyte[])"Hello").resultAssert;
    writer.finishBody().resultAssert;
    writer.finishTrailers().resultAssert;
    writer.finishMessage(summary).resultAssert;

    return request;
}

@("HttpClient - Full Request - Simple")
unittest
{
    static struct T
    {
        HttpRequest toSend;
        HttpRequest expected;

        this(scope ref return typeof(this) src)
        {
            this.toSend = src.toSend;
            this.expected = src.expected;
        }
    }

    __gshared T[string] cases;
    cases["Simple - automatic chunking"] = (){
        auto t = T();
        t.toSend.withMethod("GET");
        t.toSend.withPath("/test");
        t.toSend.setHeader("host", "localhost");
        t.toSend.putBody(cast(ubyte[])"Hello, world!");
        t.expected = t.toSend;
        t.expected.setHeader("transfer-encoding", "chunked");
        return t;
    }();

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
                auto pair = juptuneEventLoopGetContext!CasePair;
                auto writer = Http1Writer(&pair.socket, new ubyte[512], Http1Config());
                auto reader = Http1Reader(&pair.socket, new ubyte[512], Http1Config());
                auto request = collectRequest(writer, reader);

                assert(request.method == pair.test.expected.method, "method mismatch - " ~ pair.name);
                assert(request.path == pair.test.expected.path, "path mismatch - " ~ pair.name);
                assert(request.headers == pair.test.expected.headers, "headers mismatch - " ~ pair.name);
                assert(request.body == pair.test.expected.body, "body mismatch - " ~ pair.name);
            }, casePairs[0], &asyncMoveSetter!CasePair).resultAssert;

            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                HttpClient client;
                HttpClient.wrapPairedSocket(client, pair.socket, HttpClientConfig());

                HttpResponse response;
                client.request(pair.test.toSend, response).resultAssert;

                HttpResponse expectedResponse;
                with(expectedResponse)
                {
                    withStatus(200);
                    withReason("OK");
                    setHeader("Content-Length", "5");
                    setHeader("Connection", "close");
                    putBody(cast(ubyte[])"Hello");
                }
                assert(response == expectedResponse, "response mismatch - " ~ pair.name);
            }, casePairs[1], &asyncMoveSetter!CasePair).resultAssert;
        }
        catch(Exception ex) assert(false, ex.msg);
    });
    loop.join();
}

@("HttpClient - Full Request - Streamed")
unittest
{
    static struct T
    {
        HttpRequest toSend;
        const(ubyte)[] body;
        HttpRequest expected;

        this(scope ref return typeof(this) src)
        {
            this.toSend = src.toSend;
            this.body = src.body;
            this.expected = src.expected;
        }
    }

    __gshared T[string] cases;
    cases["Simple - automatic chunking"] = (){
        auto t = T();
        t.toSend.withMethod("GET");
        t.toSend.withPath("/test");
        t.toSend.setHeader("host", "localhost");
        t.body = cast(ubyte[])"Hello, world!";
        t.expected = t.toSend;
        t.expected.setHeader("transfer-encoding", "chunked");
        return t;
    }();

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
                auto pair = juptuneEventLoopGetContext!CasePair;
                auto writer = Http1Writer(&pair.socket, new ubyte[512], Http1Config());
                auto reader = Http1Reader(&pair.socket, new ubyte[512], Http1Config());
                auto request = collectRequest(writer, reader);

                assert(request.method == pair.test.expected.method, "method mismatch - " ~ pair.name);
                assert(request.path == pair.test.expected.path, "path mismatch - " ~ pair.name);
                assert(request.headers == pair.test.expected.headers, "headers mismatch - " ~ pair.name);
                assert(request.body == pair.test.body, "body mismatch - " ~ pair.name);
            }, casePairs[0], &asyncMoveSetter!CasePair).resultAssert;

            async((){
                auto pair = juptuneEventLoopGetContext!CasePair;
                HttpClient client;
                HttpClient.wrapPairedSocket(client, pair.socket, HttpClientConfig());

                HttpResponse response;
                client.streamRequest(
                    pair.test.toSend, 
                    response,
                    (scope put) {
                        // Test that calling `put` multiple times works.
                        put(pair.test.body[0..$/2]).resultAssert;
                        put(pair.test.body[$/2..$]).resultAssert;
                        return Result.noError;
                    },
                    (scope const ref resp, scope const ubyte[] data) @trusted {
                        assert(data == cast(ubyte[])"Hello", pair.name);
                        return Result.noError;
                    }
                ).resultAssert;

                HttpResponse expectedResponse;
                with(expectedResponse)
                {
                    withStatus(200);
                    withReason("OK");
                    setHeader("Content-Length", "5");
                    setHeader("Connection", "close");
                }
                assert(response == expectedResponse, "response mismatch - " ~ pair.name);
            }, casePairs[1], &asyncMoveSetter!CasePair).resultAssert;
        }
        catch(Exception ex) assert(false, ex.msg);
    });
    loop.join();
}