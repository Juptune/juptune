// Purpose: This is a simple HTTP server that uses the proper HTTP support of Juptune, via the low-level API.
//          It is intended to be used to stress the the low-level HTTP primitives to uncover any
//          potential bugs or issues with how fibers are being handled.

import core.time;
import juptune.event, juptune.core.util, juptune.core.ds, juptune.event.fiber, juptune.http;

void main(string[] args)
{
    const type = args.length < 2 ? "nogc" : args[1];

    if(type == "nogc")
        nogcServer();
    else if (type == "gc")
        gcServer();
}

void nogcServer()
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
                    allocator.allocate(1024.bsf, 2, allocation).resultAssert;

                    auto client = juptuneEventLoopGetContext!TcpSocket;
                    auto block = allocation.head.block;
                    auto outBuffer = allocation.head.next.block; // TODO: This is a hack until the HTTP writer is implemented.
                    auto reader = Http1Reader(client, block, Http1Config());
                    client.timeout = 1000.msecs;

                    size_t cursor;
                    void put(T)(T[] data) @safe @nogc nothrow // TODO: This is a hack until the HTTP writer is implemented.
                    {
                        outBuffer[cursor..cursor+data.length] = cast(const ubyte[])data[0..$];
                        cursor += data.length;
                    }

                    Http1MessageSummary summary;
                    do
                    {
                        cursor = 0;

                        Http1RequestLine requestLine;
                        auto result = reader.readRequestLine(requestLine);
                        if(result.isError)
                            return;
                        requestLine.access((method, path)
                        {
                            put(method);
                            put(" ");
                            put(path.path);
                            put(path.query);
                            put(path.fragment);
                            put(" ");
                            if(requestLine.httpVersion == Http1Version.http10)
                                put("HTTP/1.0\r\n");
                            else
                                put("HTTP/1.1\r\n");
                        });
                        requestLine = Http1RequestLine();

                        bool foundEndOfHeaders;
                        while(!foundEndOfHeaders)
                        {
                            result = reader.checkEndOfHeaders(foundEndOfHeaders);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, client);
                                return;
                            }
                            else if(foundEndOfHeaders)
                                break;

                            Http1Header header;
                            result = reader.readHeader(header);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, client);
                                return;
                            }

                            header.access((name, value)
                            {
                                put(name);
                                put(": ");
                                put(value);
                                put("\r\n");
                            });
                        }
                        put("\r\n");

                        Http1BodyChunk chunk;
                        do
                        {
                            chunk = Http1BodyChunk();
                            result = reader.readBody(chunk);
                            if(result.isError)
                            {
                                handleErrorNoGC(result, client);
                                return;
                            }

                            bool wasError;
                            chunk.access((scope ubyte[] data) @safe @nogc nothrow {
                                if(data.length == 0)
                                    return;
                                put(data);
                            });
                            if(wasError)
                                return;
                        } while(chunk.hasDataLeft);

                        result = reader.finishMessage(summary);
                        if(result.isError)
                        {
                            handleErrorNoGC(result, client);
                            return;
                        }

                        // TODO: Reminder to redo all of this once the HTTP writer is implemented.
                        result = client.put("HTTP/1.1 200 OK\r\n");
                        if(result.isError){ handleErrorNoGC(result, client); return; }

                        result = client.put("Content-Length: ");
                        if(result.isError){ handleErrorNoGC(result, client); return; }

                        IntToCharBuffer buffer;
                        auto bufferSlice = cursor.toBase10(buffer);
                        result = client.put(bufferSlice);
                        if(result.isError){ handleErrorNoGC(result, client); return; }

                        result = client.put("\r\n\r\n");
                        if(result.isError){ handleErrorNoGC(result, client); return; }

                        result = client.put(outBuffer[0..cursor]);
                        if(result.isError){ handleErrorNoGC(result, client); return; }
                    } while(!summary.connectionClosed);
                }, client, &asyncMoveSetter!TcpSocket).resultAssert;
            }
        });
    }
    loop.join();
}

void handleErrorNoGC(Result result, scope TcpSocket* socket) @nogc nothrow
{
    import std : writeln;
    debug writeln(result); // Bypasses @nogc nothrow checks.
    
    if(result.isErrorType!Http1Error)
    {
        result = socket.put(result.error);
        debug if(result.isError)
            writeln(result);
    }
}

void gcServer()
{
}