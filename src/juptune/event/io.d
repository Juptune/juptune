/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.io;

import core.time : Duration;
import std.range : ElementEncodingType;
import juptune.core.ds, juptune.core.util;
import juptune.event.loop, juptune.event.iouring;

/++++ Platform configuration ++++/

version(linux) private
{
    import core.sys.linux.errno;
    import juptune.event.internal.linux;
}

version(Posix) private
{
    alias PlatformGenericIoDriver = PosixGenericIoDriver;

    /// An alias to the platform's default tcp socket implementation.
    public alias TcpSocket = PosixTcpSocket;

    import core.sys.posix.netinet.in_ : in_addr;
    extern(C) int inet_aton(const scope char*, scope in_addr*) @nogc nothrow;
}

/++++ Non-IO helper structs ++++/

/++
 + Describe and IP address. Supports IPv4 and IPv6.
 + ++/
struct IpAddress
{
    import core.sys.posix.netinet.in_ : 
        AF_INET, AF_INET6, sockaddr, sockaddr_in, sockaddr_in6, htons,
        in_addr, in6_addr, ssize_t, INET6_ADDRSTRLEN, inet_pton, inet_ntop,
        socklen_t;

    @nogc nothrow:

    /// Which IP version the address is for.
    enum Kind
    {
        FAILSAFE,
        ipv4 = AF_INET,
        ipv6 = AF_INET6
    }

    /// `Result` error enum
    enum Error
    {
        none,

        /// The given IP string was in an unsupported format, or maybe it's just completely incorrect.
        invalidAddress
    }

    private
    {
        Kind _kind;
        union
        {
            uint        _ipv4;
            ubyte[16]   _ipv6;
        }
    }

    /// The port represented by the IP address. A value of 0 can mean either "explicit 0" or "no port was provided".
    ushort port;

    /++
     + Constructor for a raw IPv4 address.
     +
     + Parameters:
     +  ipv4 = The raw IPv4 address. Expected to be in network order already.
     +  port = The port. Expected to be in host order.
     + ++/
    this(uint ipv4, ushort port) pure
    {
        this._kind = Kind.ipv4;
        this._ipv4 = ipv4;
        this.port  = port;
    }

    /++
     + Constructor for a raw IPv6 address.
     +
     + Parameters:
     +  ipv6 = The raw IPv6 address. Expected to be in network order already.
     +  port = The port. Expected to be in host order.
     + ++/
    this(ubyte[16] ipv6, ushort port) pure
    {
        this._kind = Kind.ipv6;
        this._ipv6 = ipv6;
        this.port  = port;
    }

    /++
     + Returns:
     +  The `Kind` of IP stored.
     + ++/
    Kind kind() const pure
    {
        return this._kind;
    }

    /++
     + The raw IPv4 address in network order.
     +
     + Throws:
     +  Asserts that the `Kind` to already be `Kind.ipv4`
     +
     + Returns:
     +  The raw IPv4 address in network order.
     + ++/
    uint asIpv4() const pure
    {
        assert(this.kind == Kind.ipv4, "This is not an IPv4 address");
        return this._ipv4;
    }

    /++
     + The raw IPv6 address in network order.
     +
     + This property expects the `Kind` to already be `Kind.ipv6`, if you'd like to
     + perform a conversion please use `toIpv6` instead.
     +
     + Throws:
     +  Asserts that the `Kind` to already be `Kind.ipv6`
     +
     + Returns:
     +  The raw IPv6 address in network order.
     + ++/
    ubyte[16] asIpv6() const pure
    {
        assert(this._kind == Kind.ipv6, "This is not an IPv6 address");
        return this._ipv6;
    }
    
    /++ 
     + Converts the current address into an IPv6 address.
     +
     + For IPv4 addresses: If the address is 127.0.0.1 then it is converted into ::1
     +
     + For IPv4 addresses: If the address is 0.0.0.0 then it is converted into ::
     +
     + Returns:
     +  A new `IpAddress` containing an IPv6 address.
     + ++/
    IpAddress toIpv6() const pure
    {
        assert(this.kind != Kind.FAILSAFE, "This IpAddress hasn't been initialised yet.");

        if(this.kind == Kind.ipv6)
            return this;

        // Ip is always assumed to be in network order
        ubyte[4] ipBytes = (cast(ubyte*)(&this._ipv4))[0..4];

        IpAddress ip;
        ip._ipv6[$-4..$]   = ipBytes[0..$];
        ip._ipv6[$-6..$-4] = 0xFF;
        ip._kind           = Kind.ipv6;
        ip.port            = this.port;

        if(ipBytes == [0x7F, 0, 0, 1]) // 127.0.0.1 -> ::1
        {
            ip._ipv6[] = 0;
            ip._ipv6[$-1] = 1;
        }
        else if(ipBytes == [0, 0, 0, 0]) // 0.0.0.0 -> ::
            ip._ipv6[] = 0;

        return ip;
    }

    version(Posix)
    void asSocketAddr(
        ref sockaddr* used, 
        ref size_t usedLength, 
        ref sockaddr_in ipv4, 
        ref sockaddr_in6 ipv6
    )
    {
        assert(this.kind != Kind.FAILSAFE, "This IpAddress hasn't been initialised yet.");

        if(this.kind == Kind.ipv4)
        {
            ipv4.sin_family         = AF_INET;
            ipv4.sin_port           = htons(this.port);
            ipv4.sin_addr.s_addr    = this.asIpv4;
            used                    = cast(sockaddr*)&ipv4;
            usedLength              = sockaddr_in.sizeof;
        }
        else
        {
            ipv6.sin6_family        = AF_INET6;
            ipv6.sin6_port          = htons(this.port);
            ipv6.sin6_addr.s6_addr  = this.asIpv6;
            used                    = cast(sockaddr*)&ipv6;
            usedLength              = sockaddr_in6.sizeof;
        }
    }

    version(Posix)
    void toString(Sink)(scope auto ref Sink sink, bool withPort = true) const
    {
        import juptune.core.util.conv : toStringSink;
        assert(this.kind != Kind.FAILSAFE, "This IpAddress hasn't been initialised yet.");

        in_addr ipv4 = in_addr(this._ipv4);
        in6_addr ipv6 = in6_addr(this._ipv6);
        void* ip = (this.kind == Kind.ipv4) ? cast(void*)&ipv4 : cast(void*)&ipv6;

        char[INET6_ADDRSTRLEN] buffer = '\0';
        inet_ntop(
            cast(int)this.kind,
            ip,
            buffer.ptr,
            cast(socklen_t)buffer.length
        );

        import core.stdc.string : strlen;
        const len = strlen(buffer.ptr);

        if(!withPort)
        {
            sink.put(buffer[0..len]);
            return;
        }

        if(this.kind == Kind.ipv4)
        {
            sink.put(buffer[0..len]);
            sink.put(":");
            toStringSink(this.port, sink);
        }
        else
        {
            sink.put("[");
            sink.put(buffer[0..len]);
            sink.put("]");
            sink.put(":");
            toStringSink(this.port, sink);
        }
    }
    ///
    @("toString")
    unittest
    {
        import juptune.core.ds.string : String;
        import juptune.core.util.conv : to;

        IpAddress ip;
        IpAddress.parse(ip, "127.255.1.69").resultAssert;
        assert(ip.to!String == String("127.255.1.69:0"));

        IpAddress.parse(ip, "::1", 12_345).resultAssert;
        assert(ip.to!String == String("[::1]:12345"));

        IpAddress.parse(ip, "127.255.1.69:20").resultAssert;
        assert(ip.to!String == String("127.255.1.69:20"));

        IpAddress.parse(ip, "[::1]:12345").resultAssert;
        assert(ip.to!String == String("[::1]:12345"));

        IpAddress.parse(ip, "127.255.1.69:69").resultAssert;
        assert(ip.toIpv6.to!String == String("[::ffff:127.255.1.69]:69"));

        IpAddress.parse(ip, "[::ffff:127.255.1.69]:69").resultAssert;
        assert(ip.toIpv6.to!String == String("[::ffff:127.255.1.69]:69"));

        IpAddress.parse(ip, "2a00:23c5:c685:8401:6ebb:f30:9d9b:ca40").resultAssert;
        assert(ip.to!String == String("[2a00:23c5:c685:8401:6ebb:f30:9d9b:ca40]:0"));
    }

    /++
     + Parses an IPv4 or IPv6 address string into an `IpAddress` object.
     +
     + Addresses can either be a raw address, or a raw address with a port in the IP version's
     + standard form.
     +
     + Implementation Note: Currently this function uses inet_aton and inet_pton for the raw
     + address parsing.
     +
     + Params:
     +  ip = The `IpAddress` to store the result in.
     +  address = The address string to parse.
     +  defaultPort = The port to give `ip` if `address` does not specify one.
     +
     + Throws:
     +  `IpAddress.Error.invalidAddress` if `address` could not be parsed.
     +
     + Returns:
     +  A `Result`
     + ++/
    static Result parse(
        scope out IpAddress ip,
        scope const char[] address,
        ushort defaultPort = 0
    )
    {
        char[129] buffer;
        
        if(address.length >= 128)
            return Result.make(IpAddress.Error.invalidAddress, "Address is too large");
        buffer[0..address.length] = address[0..$];
        buffer[address.length] = '\0';

        in_addr v4;
        in6_addr v6;

        uint colonCount;
        bool probablyHasIpv6StylePort = false;
        foreach(ch; address)
        {
            colonCount += ch == ':';
            probablyHasIpv6StylePort = probablyHasIpv6StylePort || ch == ']';
        }

        // Parse port if we see one.
        if(colonCount == 1 || probablyHasIpv6StylePort)
        {
            for(ssize_t i = address.length - 1; i >= 0; i--) // @suppress(dscanner.suspicious.length_subtraction)
            {
                if(address[i] != ':')
                    continue;

                import juptune.core.util.conv : to;
                buffer[i] = '\0';
                
                Result convResult = Result.noError;
                defaultPort = buffer[i+1..address.length].to!ushort(convResult);

                if(convResult.isError)
                    return convResult;

                if(i > 1 && buffer[i-1] == ']')
                {
                    buffer[i-1] = '\0';
                    foreach(j; 1..i)
                        buffer[j-1] = buffer[j];
                }
                break;
            }
        }

        if(inet_aton(buffer.ptr, &v4) == 1)
        {
            ip = IpAddress(v4.s_addr, defaultPort);
            return Result.noError;
        }
        else if(inet_pton(AF_INET6, buffer.ptr, &v6) == 1)
        {
            ip = IpAddress(v6.s6_addr, defaultPort);
            return Result.noError;
        }

        return Result.make(IpAddress.Error.invalidAddress, "Address is invalid");
    }
}

/++++ Implementations ++++/

/++
 + A `TcpSocket` implementation that uses the standard POSIX socket functions
 + for when io_uring doesn't provide a native opcode.
 +
 + When a function has to use a standard POSIX function instead of io_uring, *it may block* the thread.
 +
 + As with all IO Driver implementations, this struct inherits `GenericIoDriver` for common IO functions.
 +
 + See_Also:
 +  `GenericIoDriver`
 + ++/
version(Posix)
struct PosixTcpSocket
{
    import core.sys.posix.sys.socket 
        : socket, clisten = listen, bind, setsockopt, SO_REUSEADDR, SO_REUSEPORT, SOL_SOCKET,
            SO_KEEPALIVE, socklen_t, getsockname, caccept = accept, cconnect = connect,
            socketpair;
    import core.sys.posix.arpa.inet 
        : AF_INET6, AF_UNIX, SOCK_STREAM, ntohs;
    import core.sys.posix.netinet.in_ 
        : sockaddr, sockaddr_in, sockaddr_in6, IPPROTO_IPV6, IPV6_V6ONLY;

    private
    {
        IpAddress _ip;
    }

    GenericIoDriver _driver;
    alias _driver this;

    nothrow @nogc:

    /++
     + Creates the underlying socket.
     +
     + The following options are enabled: `REUSEPORT`; `REUSEADDR`; `KEEPALIVE`.
     +
     + The socket is created a dual-stack IPv4-IPv6 socket.
     +
     + Throws:
     +  Asserts that the socket isn't already open.
     +
     +  Any `LinuxError` reported by the `socket` syscall.
     +
     +  Anything thrown by `yield`.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result open()
    in(!this._driver.isOpen, "This socket is already open, please call close() first.")
    {
        version(linux)
        if(g_linuxKernal.major > 5 || (g_linuxKernal.major == 5 && g_linuxKernal.minor >= 19))
        {
            // TODO: This version of linux supports socket() in io_uring, so use that instead.
        }

        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if(fd == -1)
        {
            version(linux)
                return linuxErrorAsResult("failed to open socket", errno());
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)errno(), "failed to open socket");
            }
        }

        int enable = 1;
        int disable = 0;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, int.sizeof);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, int.sizeof);
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, int.sizeof);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &disable, int.sizeof);
        this._driver.wrap(fd);
        
        auto yieldResult = yield(); // Emulate using io_uring for the socket call.
        if(yieldResult.isError)
            return yieldResult;

        return Result.noError;
    }

    /++
     + Accepts a client socket from a listening server socket.
     +
     + The client's ip address will be populated.
     +
     + Params:
     +  client = The resulting client.
     +
     + Throws:
     +  Asserts that `open` has been called first.
     +
     +  Anything thrown by `juptuneEventLoopSubmitEvent`.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result accept(scope out TcpSocket client)
    in(_driver.isOpen, "Cannot accept on a closed socket. Did you forget to call open() first?")
    {
        sockaddr addr;
        socklen_t len;

        auto op = IoUringAccept();
        op.fd = this.fd;
        op.addr = &addr;
        op.addrlen = &len;

        IoUringCompletion cqe;
        auto result = juptuneEventLoopSubmitEvent(op, cqe);
        if(result.isError)
            return result;

        IpAddress ip;
        if(len)
        {
            if(len == sockaddr_in.sizeof)
                ip = IpAddress((cast(sockaddr_in*)&addr).sin_addr.s_addr, (cast(sockaddr_in*)&addr).sin_port.ntohs);
            else if(len == sockaddr_in6.sizeof)
                ip = IpAddress((cast(sockaddr_in6*)&addr).sin6_addr.s6_addr, (cast(sockaddr_in6*)&addr).sin6_port.ntohs); // @suppress(dscanner.style.long_line)
        }

        client.wrap(cqe.result);
        client._ip = ip;
        return Result.noError;
    }

    /++
     + Binds the socket to an address, and begins listening for connections.
     +
     + This overload is for convenience, as it will call `IpAddress.parse` on the
     + given `address`.
     +
     + Params:
     +  address = The IP address string to parse, and listen for connections on.
     +  backlog = The suggested size of the accept backlog.
     +  defaultPort = The port to listen to if `address` doesn't contain one.
     +
     + Throws:
     +  Asserts that `open` has been called first.
     +
     +  Anything thrown by `IpAddress.parse`.
     +
     +  Anything thrown by the main overload.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result listen(scope const char[] address, uint backlog, ushort defaultPort = 0)
    in(_driver.isOpen, "Cannot listen on a closed socket. Did you forget to call open() first?")
    {
        IpAddress addr;
        auto result = IpAddress.parse(addr, address, defaultPort);
        if(result.isError)
            return result;

        return this.listen(addr, backlog);
    }

    /++
     + Binds the socket to an address, and begins listening for connections.
     +
     + Note that `address` will be converted into an IPv6 address before listening
     + starts.
     +
     + Note that io_uring currently doesn't provide a `listen` or `bind` command, so
     + the syscalls are immediately made.
     +
     + Params:
     +  address = The address to listen for connections on.
     +  backlog = The suggested size of the accept backlog.
     +
     + Throws:
     +  Asserts that `open` has been called first.
     +
     +  Any `LinuxError` thrown by libc's `bind`.
     +
     +  Any `LinuxError` thrown by libc's `listen`.
     +
     +  Anything thrown by `yield`.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result listen(IpAddress address, uint backlog)
    in(_driver.isOpen, "Cannot listen on a closed socket. Did you forget to call open() first?")
    {
        sockaddr_in ip4;
        sockaddr_in6 ip6;
        sockaddr* used;
        size_t usedLength;

        address = address.toIpv6();
        address.asSocketAddr(used, usedLength, ip4, ip6);

        const bindResult = bind(this.fd, used, cast(socklen_t)usedLength);
        if(bindResult == -1)
        {
            version(linux)
                return linuxErrorAsResult("failed to bind socket", errno());
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)errno(), "failed to bind socket");
            }
        }

        const listenResult = clisten(this._driver.fd, backlog);
        if(listenResult < 0)
        {
            version(linux)
                return linuxErrorAsResult("failed to listen socket", errno());
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)errno(), "failed to listen socket");
            }
        }
        auto yieldResult = yield(); // Emulate using io_uring
        if(yieldResult.isError)
            return yieldResult;

        return Result.noError;
    }

    /++
     + Connects to the target address.
     +
     + This overload is for convenience as it will call `IpAddress.parse` on `address`.
     +
     + This overload, if parsing of `address` fails, will attempt a DNS lookup
     + to find the IP address instead.
     +
     + Params:
     +  address = The address to parse/lookup, and attempt to connect to.
     +  lookupWasPerformed = Set to `true` if `address` wasn't a valid IP Address, and so triggered a DNS lookup.
     +  defaultPort = The default port used to connect to the address, if `address` does not specify one.
     +
     + Throws:
     +  Asserts that `open` has been called first.
     +
     +  Anything thrown by `IpAddress.parse`.
     +
     +  Anything thrown by the main overload.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result connect(scope const char[] address, out bool lookupWasPerformed, ushort defaultPort = 0)
    in(_driver.isOpen, "Cannot connect using a closed socket. Did you forget to call open() first?")
    {
        IpAddress addr;
        auto result = IpAddress.parse(addr, address, defaultPort);
        if(result.isError) // TODO: DNS lookup on failure
            return result;

        return this.connect(addr);
    }

    /++
     + Connects to the target address.
     +
     + The `address` is converted into an IPv6 address before the connection is attempted.
     +
     + Params:
     +  address = The address to attempt to connect to.
     +
     + Throws:
     +  Asserts that `open` has been called first.
     +
     +  Any `LinuxError` thrown by libc's `connect` syscall.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result connect(IpAddress address)
    in(_driver.isOpen, "Cannot connect using a closed socket. Did you forget to call open() first?")
    {
        sockaddr_in ip4;
        sockaddr_in6 ip6;
        sockaddr* used;
        size_t usedLength;

        address = address.toIpv6();
        address.asSocketAddr(used, usedLength, ip4, ip6);

        const result = cconnect(this.fd, used, cast(socklen_t)usedLength);
        if(result < 0)
        {
            version(linux)
                return linuxErrorAsResult("failed to connect to server", errno());
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)errno(), "failed to connect to server");
            }
        }

        return Result.noError;
    }

    static Result makePair(out PosixTcpSocket[2] sockets)
    {
        int[2] fds;

        const result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        if(result < 0)
        {
            version(linux)
                return linuxErrorAsResult("failed to create socket pairs", result);
            else assert(false);
        }

        PosixTcpSocket[2] wrapped;
        sockets[0]._driver.wrap(fds[0]);
        sockets[1]._driver.wrap(fds[1]);

        return Result.noError;
    }

    /++
     + The IP address of this socket.
     +
     + Note that this can sometimes be `IpAddress.init`, even for open sockets.
     +
     + Returns:
     +  This socket's `IpAddress`.
     + ++/
    IpAddress ip() const
    {
        return this._ip;
    }
}

/++
 + Provides generic IO functionality.
 +
 + All platform-specific IO drivers will provide an `alias this` to this struct,
 + so that all drivers have the same facilities for writing and reading.
 + ++/
struct GenericIoDriver
{
    private
    {
    }
    PlatformGenericIoDriver _driver;
    alias _driver this;

    nothrow:

    /++
     + Writes an entire buffer.
     +
     + This is a high level helper around the `send` function.
     +
     + Params:
     +  buffer = The buffer to write.
     +
     + Throws:
     +  Any error that the platform's underlying `send` command returns. (e.g. `LinuxError` on Linux)
     +
     + Returns:
     +  A `Result`
     + ++/
    Result put(const(void)[] buffer) @nogc
    {
        while(buffer.length > 0)
        {
            size_t bytesSent;
            auto result = this._driver.send(buffer, bytesSent);
            if(result.isError)
                return result;
            buffer = buffer[bytesSent..$];
        }

        return Result.noError;
    }

    /++
     + Continue to write data from a range until it's empty.
     +
     + This is a high level helper around the `send` function.
     +
     + The range's element type must be some sort of slice.
     +
     + Params:
     +  range = The range to write.
     +
     + Throws:
     +  Any error that the `void[]` overload of `put` returns.
     +
     + Returns:
     +  A `Result`
     + ++/
    Result put(RangeT)(scope RangeT range)
    if(is(ElementEncodingType!RangeT : const(T)[], T) && !is(RangeT : const(void)[]))
    {
        while(!range.empty)
        {
            auto result = this.put(range.front);
            if(result.isError)
                return result;
            range.popFront();
        }

        return Result.noError;
    }

    /++
     + Continues to read data into a buffer until no bytes are left to read.
     +
     + If the buffer needs to be grown, then the `growFunc` is called.
     + If the `growFunc` is null, then the default action is to first grow to 4096 bytes, and then
     + keep doubling the length.
     +
     + This is a high level helper around the `recieve` function.
     +
     + This overload is specifically @nogc, and makes use of `juptune.core.ds.array.Array` for storage.
     +
     + Params:
     +  buffer = The buffer to read all of the data into.
     +  cursor = The cursor to start writing data into.
     +  growFunc = The function to call when `buffer` needs to grow. Can be null to trigger a default behaviour.
     +
     + Throws:
     +  Asserts that `growFunc` has grown `buffer.length` if it returns a non-error `Result`.
     +
     +  Any error that the platform-specific `recieve` function returns.
     +
     + Returns:
     +  A `Result`
     +
     + See_Also:
     +  `readAllGC`
     + ++/
    alias readAll = readAllImpl!(Array!ubyte, Result delegate(scope ref Array!ubyte) nothrow @nogc);

    /++
     + Continues to read data into a buffer until no bytes are left to read.
     +
     + If the buffer needs to be grown, then the `growFunc` is called.
     + If the `growFunc` is null, then the default action is to first grow to 4096 bytes, and then
     + keep doubling the length.
     +
     + This is a high level helper around the `recieve` function.
     +
     + This overload is specifically @gc, and makes use of normal D arrays for storage.
     +
     + Params:
     +  buffer = The buffer to read all of the data into.
     +  cursor = The cursor to start writing data into.
     +  growFunc = The function to call when `buffer` needs to grow. Can be null to trigger a default behaviour.
     +
     + Throws:
     +  Asserts that `growFunc` has grown `buffer.length` if it returns a non-error `Result`.
     +
     +  Any error that the platform-specific `recieve` function returns.
     +
     + Returns:
     +  A `Result`
     +
     + See_Also:
     +  `readAll`
     + ++/
    alias readAllGC = readAllImpl!(ubyte[], Result delegate(scope ref ubyte[]) nothrow);

    private Result readAllImpl(BufferT, GrowFuncT)(
        scope ref BufferT buffer,
        size_t cursor = 0,
        scope GrowFuncT growFunc = null
    )
    {
        if(growFunc is null)
        {
            growFunc = (scope ref b)
            {
                if(b.length > 0) 
                    b.length = b.length * 2; 
                else
                    b.length = 4096;
                return Result.noError; 
            };
        }

        while(true)
        {
            import std.stdio;
            if(cursor >= buffer.length)
            {
                auto result = growFunc(buffer);
                if(result.isError)
                    return result;
                assert(cursor < buffer.length, "Buffer didn't grow large enough/at all");
            }

            void[] inSlice;
            auto result = this._driver.recieve(buffer[cursor..$], inSlice);
            if(result.isError)
                return result;
            else if(inSlice.length == 0 || inSlice.length < (buffer.length - cursor))
                break;

            cursor += inSlice.length;
        }

        return Result.noError;
    }
    static assert(
        __traits(compiles, ()nothrow @nogc{ Array!ubyte b; TcpSocket.init.readAll(b).resultAssert; }),
        "readAll no longer compiles under @nogc"
    );
}

version(Posix)
private struct PosixGenericIoDriver
{
    import core.sys.posix.sys.uio : iovec;

    @disable this(this){}
    enum IOVEC_STATIC_SIZE = 32;

    private
    {
        int fd;
    }

    Duration timeout = Duration.zero;

    nothrow @nogc:

    void wrap(int fd) pure
    in(fd != 0, "File descriptor is 0, did you forget to check for failure?")
    in(this.fd == 0, "This PosixGenericIoDriver hasn't been closed yet. Please call .close")
    {
        this.fd = fd;
    }

    ~this()
    {
        if(this.fd)
            this.close().resultAssert;
    }

    bool isOpen() => this.fd != 0;

    Result close()
    in(fd != 0, "File descriptor is 0, did you forget to check isOpen?")
    {
        auto op = IoUringClose();
        op.fd = this.fd;
        juptuneEventLoopSubmitEvent(
            op,
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false)
        ).resultAssert;
        this.fd = 0;

        return Result.noError;
    }

    Result send(const(void)[] buffer, scope out size_t bytesSent)
    {
        auto op = IoUringSend();
        op.fd = this.fd;
        op.buffer = cast(void[])buffer;

        IoUringCompletion cqe;
        auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, this.submitConfig());
        if(submitResult.isError)
            return submitResult;

        if(cqe.result < 0)
        {
            // TODO: Figure out how to standardise the errors a bit
            version(linux)
                return linuxErrorAsResult("failed to send data to socket", cqe.result);
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)cqe.result, "failed to send data to socket");
            }
        }

        assert(cqe.result >= 0);
        bytesSent = cqe.result;
        return Result.noError;
    }

    Result recieve(void[] buffer, out void[] sliceWithData)
    {
        auto op = IoUringRecv();
        op.fd = this.fd;
        op.buffer = buffer;

        IoUringCompletion cqe;
        auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, this.submitConfig());
        if(submitResult.isError)
            return submitResult;

        if(cqe.result < 0)
        {
            // TODO: Figure out how to standardise the errors a bit
            version(linux)
                return linuxErrorAsResult("failed to recieve data from socket", cqe.result);
            else
            {
                enum SocketError { a }
                return Result.make(cast(SocketError)cqe.result, "failed to recieve data from socket");
            }
        }

        assert(cqe.result >= 0);
        sliceWithData = buffer[0..cqe.result];
        return Result.noError;
    }

    Result writev(scope ref MemoryBlockAllocation buffers, out size_t bytesRead)
    {
        return this.vectorMBAImpl!IoUringWritev(buffers, bytesRead);
    }

    Result writev(scope void[][] buffers, ref size_t bytesRead)
    {
        return this.vectorVoidArrayImpl!IoUringWritev(buffers, bytesRead);
    }

    Result readv(scope ref MemoryBlockAllocation buffers, out size_t bytesRead)
    {
        return this.vectorMBAImpl!IoUringReadv(buffers, bytesRead);
    }

    Result readv(scope void[][] buffers, ref size_t bytesRead)
    {
        return this.vectorVoidArrayImpl!IoUringReadv(buffers, bytesRead);
    }

    private Result vectorMBAImpl(alias OpT)(scope ref MemoryBlockAllocation buffers, ref size_t bytesRead)
    {
        return this.vectorIoImpl!OpT((iovecs) @nogc nothrow {
            size_t index;
            auto head = buffers.head;
            while(head !is null)
            {
                iovecs[index].iov_base = head.block.ptr;
                iovecs[index].iov_len = head.block.length;
                head = head.next;
                index++;
            }

            assert(index == buffers.blockCount);
        }, buffers.blockCount, bytesRead);
    }

    private Result vectorVoidArrayImpl(alias OpT)(scope void[][] buffers, ref size_t bytesRead)
    {
        return this.vectorIoImpl!OpT((iovecs) @nogc nothrow {
            foreach(i, buffer; buffers)
            {
                iovecs[i].iov_base = buffer.ptr;
                iovecs[i].iov_len = buffer.length;
            }
        }, buffers.length, bytesRead);
    }

    private Result vectorIoImpl(alias OpT)(
        scope void delegate(iovec[]) @nogc nothrow setter,
        size_t bufferCount,
        ref size_t bytesUsed,
    )
    {
        import core.stdc.stdlib : calloc, free;

        iovec[IOVEC_STATIC_SIZE] iovecsStatic;
        iovec* iovecsDynamic;
        iovec[] iovecs;

        scope(exit) if(iovecsDynamic !is null) free(iovecsDynamic);

        if(bufferCount > IOVEC_STATIC_SIZE)
        {
            iovecsDynamic = cast(iovec*)calloc(bufferCount, iovec.sizeof);
            iovecs = iovecsDynamic[0..bufferCount];
        }
        else
            iovecs = iovecsStatic[0..bufferCount];

        setter(iovecs);

        auto op = OpT();
        op.fd = this.fd;
        op.iovecs = iovecs;

        IoUringCompletion cqe;
        auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, this.submitConfig());
        if(submitResult.isError)
            return submitResult;

        if(cqe.result < 0)
        {
            static if(is(OpT == IoUringReadv))
                static immutable message = "failed to recieve data from socket via scatter input";
            else
                static immutable message = "failed to send data to socket via gather output";

            version(linux)
                return linuxErrorAsResult(message, cqe.result);
            else assert(false);
        }

        assert(cqe.result >= 0);
        bytesUsed = cqe.result;
        return Result.noError;
    }

    private SubmitEventConfig submitConfig() pure
    {
        return SubmitEventConfig().withTimeout(this.timeout);
    }
}

/++++ Tests ++++/

version(Posix):

@("TcpSocket - simple server")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket server;
        server.open().resultAssert;
        server.listen("127.0.0.1:0", 1).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("TcpSocket - simple client -> server")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        async((){
            TcpSocket server;
            server.open().resultAssert;
            server.listen("127.0.0.1:15000", 1).resultAssert;

            TcpSocket client;
            server.accept(client).resultAssert;

            juptuneEventLoopCancelThread();
        }).resultAssert;
        async((){
            TcpSocket server;
            server.open().resultAssert;

            bool lookupWasPerformed;
            server.connect("127.0.0.1:15000", lookupWasPerformed).resultAssert;
            assert(!lookupWasPerformed);
        }).resultAssert;
    });
    loop.join();
}

@("TcpSocket - readv single buffer test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            
            ubyte[128] buffer;
            foreach(i; 0..buffer.length)
                buffer[i] = cast(ubyte)i;

            socket.put(buffer).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            ubyte[128] buffer;
            size_t bytesRead;

            socket.readv([buffer[]], bytesRead).resultAssert;

            assert(bytesRead == buffer.length);
            foreach(i; 0..buffer.length)
                assert(buffer[i] == cast(ubyte)i);
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("TcpSocket - readv multi buffer test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            
            ubyte[128] buffer;
            foreach(i; 0..buffer.length)
                buffer[i] = cast(ubyte)i;

            socket.put(buffer).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            ubyte[64] buf1;
            ubyte[36] buf2;
            ubyte[28] buf3;
            size_t bytesRead;

            socket.readv([buf1[], buf2[], buf3[]], bytesRead).resultAssert;
            assert(bytesRead == buf1.length + buf2.length + buf3.length);

            foreach(i; 0..buf1.length)
                assert(buf1[i] == cast(ubyte)i);
            foreach(i; 0..buf2.length)
                assert(buf2[i] == cast(ubyte)(i + buf1.length));
            foreach(i; 0..buf3.length)
                assert(buf3[i] == cast(ubyte)(i + buf1.length + buf2.length));
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("TcpSocket - writev multi buffer test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        TcpSocket.makePair(pairs).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            ubyte[64] buf1;
            ubyte[36] buf2;
            ubyte[28] buf3;
            size_t bytesSent;

            foreach(i; 0..buf1.length)
                buf1[i] = cast(ubyte)i;
            foreach(i; 0..buf2.length)
                buf2[i] = cast(ubyte)(i + buf1.length);
            foreach(i; 0..buf3.length)
                buf3[i] = cast(ubyte)(i + buf1.length + buf2.length);

            socket.writev([buf1[], buf2[], buf3[]], bytesSent).resultAssert;
            assert(bytesSent == buf1.length + buf2.length + buf3.length);
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            ubyte[128] buffer;
            void[] got;

            socket.recieve(buffer[], got).resultAssert;

            assert(got.length == buffer.length);
            foreach(i; 0..buffer.length)
                assert(buffer[i] == cast(ubyte)i);
        }, pairs[1], &asyncMoveSetter!TcpSocket).resultAssert;
    });
    loop.join();
}

@("TcpSocket - timeout test")
unittest
{
    import core.time : msecs;
    import juptune.event.internal.linux : LinuxError;

    static void testResult(Result r)
    {
        assert(r.isError);
        version(linux)
            assert(r.isError(LinuxError.cancelled));
    }

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        ubyte[128] buffer;
        void[] slice;
        size_t bytes;

        TcpSocket.makePair(pairs).resultAssert;
        pairs[0].timeout = 1.msecs;
        assert(pairs[0].submitConfig().timeout == 1.msecs);

        testResult(pairs[0].readv([buffer[]], bytes));
        testResult(pairs[0].recieve(buffer[], slice));
        // Hard to tests writes currently, as I have no idea how to consistently block the write call.
    });
    loop.join();
}