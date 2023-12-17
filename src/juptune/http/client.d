module juptune.http.client;

import juptune.core.util : Result;

enum HttpClientVersion
{
    FAILSAFE,
    automatic,
    http1,
}

struct HttpClientConfig
{
    import core.time       : seconds;
    import juptune.http.v1 : Http1Config;

    Http1Config http1 = Http1Config().withReadTimeout(30.seconds).withWriteTimeout(30.seconds);
    HttpClientVersion httpVersion = HttpClientVersion.automatic;
    
    size_t readBufferSize  = 1024 * 8;
    size_t writeBufferSize = 1024 * 8;

    @safe @nogc nothrow pure:

    HttpClientConfig withHttp1Config(Http1Config v) return { this.http1 = v; return this; }
    HttpClientConfig withHttpVersion(HttpClientVersion v) return { this.httpVersion = v; return this; }
}

interface IHttpClient
{
    import juptune.http.common : HttpRequest, HttpResponse;
    import juptune.event.io    : IpAddress;

    nothrow:

    Result request(scope ref const HttpRequest request, scope out HttpResponse response);
    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope HttpClient.StreamRequestFunc bodyPutter, 
        scope HttpClient.StreamResponseFunc bodyReader,
    );
    Result connect(IpAddress ip);
    Result close();
    bool isConnected() const;
    HttpClientVersion selectedVersion() const;
}

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
        scope HttpClient.StreamRequestFunc bodyPutter, 
        scope HttpClient.StreamResponseFunc bodyReader,
    ) => this._client.streamRequest(request, response, bodyPutter, bodyReader);

    Result connect(IpAddress ip) => this._client.connect(ip);

    Result close() => this._client.close();

    bool isConnected() const => this._client.isConnected();

    HttpClientVersion selectedVersion() const => this._client.selectedVersion();
}

struct HttpClient
{
    import juptune.core.ds      : Array;
    import juptune.event.io     : TcpSocket, IpAddress;
    import juptune.http.common  : HttpRequest, HttpResponse;
    import juptune.http.uri     : ScopeUri;

    /// A function provided by `HttpClient` which can be used to push data into the request body.
    alias PutBodyFunc = Result delegate(scope const ubyte[] bodyChunk) @nogc nothrow;

    /// A function provided by the user which is used to stream an entire request body.
    alias StreamRequestFunc = Result delegate(scope PutBodyFunc putter) @nogc nothrow;

    /++
     + A function provided by `HttpClient` which can be used to stream read data from the response body.
     +
     + Please note that the `HttpResponse` does not contain a body - it only contains the headers and status line.
     +
     + Please note that this is marked `@safe`` to help make it clear that the `scope` for `bodyChunk` is
     + _very_ important to adhear to.
     +
     + You can (and probably will ahve to) mark your func/lambda as `@trusted`, 
     + but that will also disable the compiler making sure that you don't accidentally 
     + escape the `bodyChunk` parameter.
     + ++/   
    alias StreamResponseFunc = Result delegate(
        scope const ref HttpResponse statusAndHeaders, 
        scope const ubyte[] bodyChunk
    ) @safe @nogc nothrow;

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

        invariant(_isConnected || _selectedVersion == HttpClientVersion.FAILSAFE, "bug: Incorrect state management");
        invariant(!_lockClient, "Attempted to use client while it was locked (or a bug where the lock wasn't released)");
    }

    @disable this(this){}

    @nogc nothrow:

    this(HttpClientConfig config)
    {
        this._config                    = config;
        this._readBufferStorage.length  = config.readBufferSize;
        this._writeBufferStorage.length = config.writeBufferSize;
        this._readBuffer                = this._readBufferStorage[];
        this._writeBuffer               = this._writeBufferStorage[];
    }

    private static void wrapPairedSocket(
        out HttpClient client,
        ref TcpSocket socket, 
        HttpClientConfig config
    )
    {
        import std.algorithm : move;

        client = HttpClient(config);
        move(socket, client._socket);
        client._http1 = Http1ClientImpl(config, &client._socket, client._writeBuffer, client._readBuffer);
        client._selectedVersion = HttpClientVersion.http1;
        client._isConnected = true;
    }

    Result connect(IpAddress ip)
    in(!this._isConnected, "This client is already connected")
    {
        auto result = this._socket.connect(ip);
        if(result.isError)
            return result;
        
        this._http1 = Http1ClientImpl(this._config, &this._socket, this._writeBuffer, this._readBuffer);
        this._selectedVersion = HttpClientVersion.http1;
        this._isConnected = true;
        return Result.noError;
    }

    Result close()
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

    bool isConnected() const => this._isConnected;

    HttpClientVersion selectedVersion() const
    in(this._isConnected, "This client is not connected")
        => this._selectedVersion;

    Result request(scope ref const HttpRequest request, scope out HttpResponse response)
    in(this._isConnected, "This client is not connected")
    {
        auto result = this.dispatch!"request"(request, response);
        if(result.isError)
            auto _ = this.close(); // request's error takes priority

        return result;
    }

    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope StreamRequestFunc bodyPutter, 
        scope StreamResponseFunc bodyReader,
    )
    in(this._isConnected, "This client is not connected")
    {
        this._lockClient = true;
        scope(exit) this._lockClient = false;

        auto result = this.dispatch!"streamRequest"(request, response, bodyPutter, bodyReader);
        if(result.isError)
            auto _ = this.close(); // streamRequest's error takes priority

        return result;
    }

    private auto dispatch(string func, Args...)(auto ref Args args) // @suppress(dscanner.suspicious.unused_parameter)
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
    import juptune.event.io     : TcpSocket;
    import juptune.http.common  : HttpRequest, HttpResponse;
    
    import juptune.http.v1 : 
        Http1Version, Http1MessageSummary, Http1ResponseLine, Http1Header, 
        Http1BodyChunk, Http1ReadResponseConfig, Http1Writer, Http1Reader;

    Http1Writer writer;
    Http1Reader reader;
    
    @nogc nothrow:

    this(HttpClientConfig config, TcpSocket* socket, ubyte[] writeBuffer, ubyte[] readBuffer)
    in(socket !is null, "socket is null")
    {
        this.writer = Http1Writer(socket, writeBuffer, config.http1);
        this.reader = Http1Reader(socket, readBuffer, config.http1);
    }

    Result close() => Result.noError;

    Result request(scope ref const HttpRequest request, scope ref HttpResponse response)
    in(writer != Http1Writer.init, "Http1Writer is not initialized")
    in(reader != Http1Reader.init, "Http1Reader is not initialized")
    {
        Http1ReadResponseConfig readConfig;
        if(request.method == "HEAD")
            readConfig = readConfig.withIsBodyless(true);

        auto result = this.sendHead(request);
        if(result.isError)
            return result;

        result = this.sendBody(request);
        if(result.isError)
            return result;

        result = this.readHead(response, readConfig);
        if(result.isError)
            return result;

        result = this.readBody(response);
        if(result.isError)
            return result;

        result = this.readTrailers(response);
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result streamRequest(
        scope ref const HttpRequest request,
        scope out HttpResponse response,
        scope HttpClient.StreamRequestFunc bodyPutter, 
        scope HttpClient.StreamResponseFunc bodyReader,
    )
    in(writer != Http1Writer.init, "Http1Writer is not initialized")
    in(reader != Http1Reader.init, "Http1Reader is not initialized")
    {
        Http1ReadResponseConfig readConfig;
        if(request.method == "HEAD")
            readConfig = readConfig.withIsBodyless(true);

        auto result = this.sendHead(request);
        if(result.isError)
            return result;

        result = this.streamSendBody(request, bodyPutter);
        if(result.isError)
            return result;

        result = this.readHead(response, readConfig);
        if(result.isError)
            return result;

        result = this.streamReadBody(response, bodyReader);
        if(result.isError)
            return result;

        result = this.readTrailers(response);
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result sendHead(scope ref const HttpRequest request)
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
            result = this.writer.putHeader("Host", "TODO");
            if(result.isError)
                return result;
        }

        result = this.writer.finishHeaders();
        if(result.isError)
            return result;

        return Result.noError;
    }

    Result sendBody(scope ref const HttpRequest request)
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

        return Result.noError;
    }

    Result streamSendBody(
        scope ref const HttpRequest request,
        scope HttpClient.StreamRequestFunc bodyPutter,
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

        return Result.noError;
    }

    Result readHead(scope ref HttpResponse response, const Http1ReadResponseConfig readConfig)
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

    Result readBody(scope ref HttpResponse response)
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

    Result readTrailers(scope ref HttpResponse response)
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

        return Result.noError;
    }

    Result streamReadBody(
        scope ref HttpResponse response,
        scope HttpClient.StreamResponseFunc bodyReader,
    )
    {
        auto result = Result.noError;
        scope accessFunc = (scope ubyte[] data) @nogc nothrow {
            if(data.length == 0)
                return;
            result = bodyReader(response, data);
        }; // For some reason the compiler thinks it needs to allocate a closure if we use a delegate inline.

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

@("HttpClient - Full Request")
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
    T t;
    
    t = T();
    t.toSend.withMethod("GET");
    t.toSend.withPath("/test");
    t.toSend.setHeader("host", "localhost");
    t.toSend.putBody(cast(ubyte[])"Hello, world!");
    t.expected = t.toSend;
    t.expected.setHeader("transfer-encoding", "chunked");
    cases["Simple - automatic chunking"] = t;

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