// Purpose: A small, silly example that reaches out to a (third party) example API to demonstrate using HTTPS.

import juptune.core.ds, juptune.core.util, juptune.data, juptune.event, juptune.http;

struct Wine
{
    static struct Rating
    {
        @Json String average;
        @Json String reviews;

        // For some reason the compiler can't figure out how to generate this automatically ;_;
        this(scope ref return const Rating rating) @nogc nothrow
        {
            this.average = average;
            this.reviews = reviews;
        }
    }

    @Json String winery;
    @Json String wine;
    @Json String location;
    @Json String image;
    @Json Rating rating;
    @Json int    id;

    // For some reason the compiler can't figure out how to generate this automatically ;_;
    this(scope ref return const Wine wine) @nogc nothrow
    {
        this.winery = wine.winery;
        this.wine = wine.wine;
        this.location = wine.location;
        this.image = wine.image;
        this.rating = wine.rating;
        this.id = wine.id;
    }
}

struct WineGC
{
    static struct Rating
    {
        @Json string average;
        @Json string reviews;
    }

    @Json string winery;
    @Json string wine;
    @Json string location;
    @Json string image;
    @Json Rating rating;
    @Json int    id;
}

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
    import core.stdc.stdio : printf;
    import std.random : uniform;

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        // I still don't have DNS implemented lol
        const IP_ADDRESS = "172.67.196.224"; // https://api.sampleapis.com/ as of 2026/02/08 (I know this is bad)

        IpAddress ip;
        IpAddress.parse(ip, IP_ADDRESS, 443).resultAssert;

        auto client = HttpClient(HttpClientConfig());
        client.connectTls(ip, "api.sampleapis.com").resultAssert;

        HttpResponse resp;
        HttpRequest req;
        req.withMethod("GET");
        req.withPath("/wines/reds");
        req.setHeader("Accept", "application/json");
        client.request(req, resp).resultAssert;

        assert(resp.status == 200, "non-200 response");

        Array!Wine wines;

        ubyte[8] depth;
        scope json = JsonParser(cast(const(char)[])resp.body.slice, depth);
        json.jsonDeserialise(wines).resultAssert;
        json.finish().resultAssert;

        // Having to use debug so I can use RNG in @nogc... I love @nogc I love @nogc I love @nogc.
        debug const index = uniform(0, wines.length);
        else const index = 0;

        printf(
            "At %s in %s, I'd suggest the %s which has an average rating of %s\n",
            wines[index].winery.slice.ptr,
            wines[index].location.slice.ptr,
            wines[index].wine.slice.ptr,
            wines[index].rating.average.slice.ptr,
        );
    });
    loop.join();
}

void gcServer()
{
    import std.stdio : writefln;
    import std.random : uniform;

    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() nothrow {
        try
        {

            // I still don't have DNS implemented lol
            const IP_ADDRESS = "172.67.196.224"; // https://api.sampleapis.com/ as of 2026/02/08 (I know this is bad)

            IpAddress ip;
            IpAddress.parse(ip, IP_ADDRESS, 443).resultEnforce;

            auto client = HttpClient(HttpClientConfig());
            client.connectTls(ip, "api.sampleapis.com").resultEnforce;

            HttpResponse resp;
            HttpRequest req;
            req.withMethod("GET");
            req.withPath("/wines/reds");
            req.setHeader("Accept", "application/json");
            client.request(req, resp).resultEnforce;

            assert(resp.status == 200, "non-200 response");

            WineGC[] wines;

            ubyte[8] depth;
            scope json = JsonParser(cast(const(char)[])resp.body.slice, depth);
            json.jsonDeserialise(wines).resultEnforce;
            json.finish().resultEnforce;

            const index = uniform(0, wines.length);
            writefln(
                "At %s in %s, I'd suggest the %s which has an average rating of %s",
                wines[index].winery,
                wines[index].location,
                wines[index].wine,
                wines[index].rating.average,
            );
        }
        catch(Exception ex)
        {
            import std.exception : assumeWontThrow;
            writefln("error: %s", ex).assumeWontThrow;
        }
    });
    loop.join();
}