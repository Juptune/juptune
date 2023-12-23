// Purpose: This is a simple command line tool that uses the higher-level HttpClient stuff
//          to send out a simple HTTP request and print the response to stdout.
//
//          Additionally this example is showing a more GC-friendly way of using Juptune.

import core.time;
import juptune.core.ds, juptune.core.util, juptune.event, juptune.http;

__gshared string[] g_args;
__gshared int g_statusCode;

int main(string[] args)
{
    g_args = args;

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() nothrow {
        try curl();
        catch(Exception ex)
        {
            import std.stdio     : stderr;
            import std.exception : assumeWontThrow;

            stderr.writeln(ex).assumeWontThrow;
            g_statusCode = 1;
        }
    });
    loop.join();

    return g_statusCode;
}

void curl()
{
    // CLI interface is super raw because this is just a barebones example right now.
    // I want to make this a lot more elaborate in the future.
    IpAddress address;
    IpAddress.parse(address, g_args[1], 80).throwIfError;

    scope client = HttpClient(HttpClientConfig());
    client.connect(address).throwIfError;

    scope request = HttpRequest();
    request.withMethod("GET");
    request.withPath("/");
    request.setHeader("Connection", "close");

    scope HttpResponse response;
    client.request(request, response).throwIfError;

    // Print the response to stdout.
    import std.stdio : writefln;

    writefln("%s %s", response.status, response.reason[]);
    foreach(ref header; response.headers[])
        writefln("%s: %s", header.name[], header.value[]);
    writefln("\n%s", cast(char[])response.body[]);
}

void throwIfError(Result result)
{
    if(result.isError)
        throw new Exception(result.error);
}