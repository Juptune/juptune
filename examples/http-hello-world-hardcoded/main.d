// Purpose: A very simple "HTTP Server" (it's not even that) that can be easily placed under load.
//          This is mainly to place stress on the core event loop and fiber scheduler, as well as
//          place the system into an unordered state to ensure fiber reentrancy is handled correctly.

import juptune.event, juptune.core.util, juptune.core.ds, juptune.event.fiber;

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
    auto loop = EventLoop(EventLoopConfig());
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
            static Array!ubyte buffer;
            buffer.length = 1024;

            while(true)
            {
                server.accept(client).resultAssert;
                async((){
                    auto client = juptuneEventLoopGetContext!TcpSocket;
                    client.readAll(buffer).resultAssert;
                    client.put("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 13\r\n\r\nHello, World!").resultAssert;
                    client.close().resultAssert;
                }, client, &asyncMoveSetter!TcpSocket).resultAssert;
            }
        });
    }
    loop.join();
}

void gcServer()
{
    __gshared TcpSocket server;
    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() @nogc nothrow {
        server.open().resultAssert;
        server.listen("127.0.0.1:19000", 4000).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();

    foreach(i; 0..8)
    {
        loop.addGCThread(() nothrow {
            TcpSocket client;
            static ubyte[] buffer;
            buffer.length = 1024;

            while(true)
            {
                server.accept(client).resultAssert;
                async((){
                    auto client = juptuneEventLoopGetContext!TcpSocket;
                    client.readAllGC(buffer).resultAssert;
                    client.put("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 13\r\n\r\nHello, World!").resultAssert;
                    client.close().resultAssert;
                }, client, &asyncMoveSetter!TcpSocket).resultAssert;
            }
        });
    }
    loop.join();
}