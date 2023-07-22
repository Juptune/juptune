import juptune.event, juptune.core.util, juptune.core.ds, juptune.event.fiber;

void main(string[] args)
{
    if(args.length < 2 || args[1] == "nogc")
        nogcServer();
    else
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