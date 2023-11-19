// Purpose: This is a simple HTTP server that uses the proper HTTP support of Juptune, via the low-level API.
//          It is intended to be used to stress the the low-level HTTP primitives to uncover any
//          potential bugs or issues with how fibers are being handled.

import core.time;
import juptune.event, juptune.core.util, juptune.core.ds, juptune.event.fiber, juptune.http;

void main(string[] args)
{
    const type = args.length < 2 ? "nogc" : args[1];

    if(type == "nogc")
        nogcInsaneServer();
    else if(type == "nogc-sane")
        nogcSaneServer();
    else if (type == "gc")
        gcServer();
}

// No sane person would ever do this, but it's a good test of the low-level API as a whole.
void nogcInsaneServer()
{
    __gshared TcpSocket server;
    auto loop = EventLoop(
        EventLoopConfig()
        .withFiberAllocatorConfig(
            FiberAllocatorConfig()
            .withBlockStackSize(1024 * 16)
        )
    );
    loop.addNoGCThread(() @nogc nothrow {
        server.open().resultAssert;
        server.listen("127.0.0.1:19000", 4000).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();

    foreach(i; 0..8)
    {
        loop.addNoGCThread(() @nogc nothrow {
            TcpSocket client;
            static MemoryBlockPool pool;
            static MemoryBlockPoolAllocator allocator;
            allocator = MemoryBlockPoolAllocator(&pool);

            while(true)
            {
                server.accept(client).resultAssert;
                async((){
                    import core.bitop : bsf;
                    
                    MemoryBlockAllocation allocation;
                    allocator.allocate(1024.bsf, 3, allocation).resultAssert;

                    auto client     = juptuneEventLoopGetContext!TcpSocket;
                    auto inBlock    = allocation.head.block;
                    auto outBlock   = allocation.head.next.block;
                    auto bufBlock   = allocation.head.next.next.block;
                    auto reader     = Http1Reader(client, inBlock, Http1Config().withReadTimeout(1000.msecs));
                    auto writer     = Http1Writer(client, outBlock, Http1Config().withWriteTimeout(1000.msecs));

                    size_t cursor;
                    bool put(T)(T[] data) @safe @nogc nothrow
                    {
                        if(cursor + data.length > bufBlock.length)
                            return false;
                        bufBlock[cursor..cursor+data.length] = cast(const ubyte[])data[0..$];
                        cursor += data.length;
                        return true;
                    }

                    Http1MessageSummary summary;
                    do
                    {
                        cursor = 0;
                        bool exit = false;

                        Http1RequestLine requestLine;
                        auto result = reader.readRequestLine(requestLine);
                        if(result.isError)
                        {
                            handleErrorNoGC(result, &writer);
                            return;
                        }
                        requestLine.access((method, path) @trusted
                        {
                            string verString = requestLine.httpVersion == Http1Version.http10 ? "HTTP/1.0" : "HTTP/1.1";
                            if(!(
                                put(method)
                                && put(" ")
                                && put(path.path)
                                && put(path.query)
                                && put(path.fragment)
                                && put(" ")
                                && put(verString)
                                && put("\r\n")
                            ))
                            {
                                auto _ = putErrorNoGC(413, "Request exceeds buffer", &writer);
                                exit = true;
                                return;
                            }
                        });
                        if(exit) return;
                        requestLine = Http1RequestLine();

                        bool foundEndOfHeaders;
                        while(!foundEndOfHeaders)
                        {
                            result = reader.checkEndOfHeaders(foundEndOfHeaders);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, &writer);
                                return;
                            }
                            else if(foundEndOfHeaders)
                                break;

                            Http1Header header;
                            result = reader.readHeader(header);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, &writer);
                                return;
                            }

                            header.access((name, value) @trusted
                            {
                                if(!(
                                    put(name)
                                    && put(": ")
                                    && put(value)
                                    && put("\r\n")
                                ))
                                {
                                    auto _ = putErrorNoGC(413, "Request exceeds buffer", &writer);
                                    exit = true;
                                    return;
                                }
                            });
                            if(exit) return;
                        }
                        if(!put("\r\n"))
                        {
                            auto _ = putErrorNoGC(413, "Request exceeds buffer", &writer);
                            return;
                        }

                        Http1BodyChunk chunk;
                        do
                        {
                            chunk = Http1BodyChunk();
                            result = reader.readBody(chunk);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, &writer);
                                return;
                            }

                            chunk.access((scope ubyte[] data) @trusted {
                                if(data.length == 0)
                                    return;
                                if(!put(data))
                                {
                                    auto _ = putErrorNoGC(413, "Request exceeds buffer", &writer);
                                    exit = true;
                                    return;
                                }
                            });
                            if(exit) return;
                        } while(chunk.hasDataLeft);

                        result = reader.finishMessage(summary);
                        if(result.isError)
                        {
                            handleErrorNoGC(result, &writer);
                            return;
                        }

                        result = writer.putResponseLine(Http1Version.http11, 200, "OK");
                        if(result.isError) return;

                        IntToCharBuffer buffer;
                        auto bufferSlice = cursor.toBase10(buffer);
                        result = writer.putHeader("Content-Length", bufferSlice);
                        if(result.isError) return;

                        result = writer.putHeader("Content-Type", "text/plain");
                        if(result.isError) return;

                        result = writer.finishHeaders();
                        if(result.isError) return;

                        result = writer.putBody(bufBlock[0..cursor]);
                        if(result.isError) return;

                        result = writer.finishBody();
                        if(result.isError) return;

                        result = writer.finishTrailers();
                        if(result.isError) return;

                        result = writer.finishMessage(summary);
                        if(result.isError) return;
                    } while(!summary.connectionClosed);
                }, client, &asyncMoveSetter!TcpSocket).resultAssert;
            }
        });
    }
    loop.join();
}

// A much more sane version of the above, which I think actually ends up being faster.
void nogcSaneServer()
{
    __gshared TcpSocket server;
    auto loop = EventLoop(
        EventLoopConfig()
        .withFiberAllocatorConfig(
            FiberAllocatorConfig()
            .withBlockStackSize(1024 * 16)
        )
    );
    loop.addNoGCThread(() @nogc nothrow {
        server.open().resultAssert;
        server.listen("127.0.0.1:19000", 4000).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();

    foreach(i; 0..8)
    {
        loop.addNoGCThread(() @nogc nothrow {
            while(true)
            {
                TcpSocket client;
                server.accept(client).resultAssert;
                async((){
                    Array!ubyte buffer;
                    buffer.length = 1024*2;

                    auto client = juptuneEventLoopGetContext!TcpSocket;
                    auto reader = Http1Reader(client, buffer[0..1024], Http1Config().withReadTimeout(1000.msecs));
                    auto writer = Http1Writer(client, buffer[1024..$], Http1Config().withWriteTimeout(1000.msecs));

                    Http1MessageSummary summary;
                    do
                    {
                        String response;

                        Http1RequestLine requestLine;
                        auto result = reader.readRequestLine(requestLine);
                        if(result.isError) return;
                        
                        requestLine.access((method, path)
                        {
                            response.putMany(
                                method,
                                " ",
                                path.path,
                                path.query,
                                path.fragment,
                                " ",
                                requestLine.httpVersion == Http1Version.http10 ? "HTTP/1.0" : "HTTP/1.1",
                                "\r\n"
                            );
                        });
                        requestLine = Http1RequestLine();

                        bool foundEndOfHeaders;
                        while(!foundEndOfHeaders)
                        {
                            result = reader.checkEndOfHeaders(foundEndOfHeaders);
                            if(result.isError){ handleErrorNoGC(result, &writer); return; }
                            
                            if(foundEndOfHeaders)
                                break;

                            Http1Header header;
                            result = reader.readHeader(header);
                            if(result.isError) { handleErrorNoGC(result, &writer); return; }

                            header.access((name, value)
                            {
                                response.putMany(name, ": ", value, "\r\n");
                            });
                        }
                        response.put("\r\n");

                        Http1BodyChunk chunk;
                        do
                        {
                            chunk = Http1BodyChunk();
                            result = reader.readBody(chunk);
                            if(result.isError) { handleErrorNoGC(result, &writer); return; }

                            chunk.access((scope ubyte[] data) {
                                if(data.length == 0)
                                    return;
                                response.put(cast(char[])data); // A bit dodgy for binary data, but it works.
                            });
                        } while(chunk.hasDataLeft);

                        result = reader.finishMessage(summary);
                        if(result.isError){ handleErrorNoGC(result, &writer); return; }

                        Http1MessageSummary outSummary;
                        result = writer.putResponseLine(Http1Version.http11, 200, "OK").then!(
                            () => writer.putHeader("Content-Type", "text/plain"),
                            () => writer.putHeader("Transfer-Encoding", "chunked"),
                            () => writer.finishHeaders(),
                            () => writer.putBody(response[0..$]),
                            () => writer.finishBody(),
                            () => writer.putTrailer("X-Connection-Closed", summary.connectionClosed ? "true" : "false"),
                            () => writer.finishTrailers(),
                            () => writer.finishMessage(outSummary),
                        );
                        if(result.isError)
                            return; // Can't call handleErrorNoGC here as the request may be in a half-written state.
                    } while(!summary.connectionClosed);
                }, client, &asyncMoveSetter!TcpSocket).resultAssert;
            }
        });
    }
    loop.join();
}

void handleErrorNoGC(Result result, scope Http1Writer* writer) @nogc nothrow
{
    import std : writeln;
    debug writeln(result); // Bypasses @nogc nothrow checks.
    
    if(result.isErrorType!Http1Error)
    {
        result = writer.putResultResponse(result);
        debug if(result.isError)
            writeln(result);
    }
}

Result putErrorNoGC(uint statusCode, string reason, scope Http1Writer* writer) @nogc nothrow
{
    import std : writeln;
    debug writeln(statusCode, " ", reason); // Bypasses @nogc nothrow checks.

    auto result = writer.putResponseLine(Http1Version.http11, statusCode, reason);
    if(result.isError)
        return result;

    result = writer.putHeader("Content-Length", "0");
    if(result.isError)
        return result;

    result = writer.putHeader("Connection", "close");
    if(result.isError)
        return result;

    result = writer.finishHeaders();
    if(result.isError)
        return result;

    Http1MessageSummary _;
    return writer.finishMessage(_);
}

void gcServer()
{
}