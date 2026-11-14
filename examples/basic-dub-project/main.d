import juptune.core.util : Result, resultAssert;
import juptune.dns       : dnsLookupIp;
import juptune.event     : EventLoop, EventLoopConfig, IpAddress;
import juptune.http      : HttpClient, HttpClientConfig, HttpRequest, HttpResponse;

void main()
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        /** 
            This is still really bulky since some stuff is still TODO, 
            e.g. HttpClient supporting DNS lookups natively; simpler GET and POST interface, etc. 
        **/
        IpAddress ip;
        dnsLookupIp("forum.dlang.org", ip).resultAssert;

        auto client = HttpClient(HttpClientConfig());
        client.connectTls(ip, "forum.dlang.org").resultAssert;

        HttpRequest req;
        req.withPath("/");
        req.withMethod("GET");

        HttpResponse res;
        client.request(req, res).resultAssert;

        import core.stdc.stdio : printf;
        printf("%d %s: Received %lld bytes from forum.dlang.org!", res.status, res.reason.slice.ptr, res.body.length);
    });
    loop.join();
}