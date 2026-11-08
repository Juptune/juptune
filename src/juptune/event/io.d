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
    import juptune.core.internal.linux;
}

version(Posix) private
{
    alias PlatformGenericIoDriver = PosixGenericIoDriver;

    /// An alias to the platform's default tcp socket implementation.
    public alias TcpSocket = PosixTcpSocket;

    /// An alias to the platform's default file implementation.
    public alias File = PosixFile;

    /// An alias to the platform's default directory implementation.
    public alias Directory = PosixDirectory;

    import core.sys.posix.netinet.in_ : in_addr;
    extern(C) int inet_aton(const scope char*, scope in_addr*) @nogc nothrow;
}

/++++ Error helpers ++++/

/// A `Result` error enum.
enum IoError
{
    none,

    /// A request timed out, or was cancelled.
    timeout,

    /// The resource already exists (e.g. trying to create a file that already exists).
    alreadyExists,

    /// Attempted to perform a file-only operation against a directory.
    isDirectory,

    /// Attempted to perform a directory-only operation against a file.
    notDirectory,

    /// Access was denied for any number of various reasons.
    accessDenied,

    /// The resource wasn't found (e.g. trying to open a file that doesn't exist).
    notFound,
}

private void wrapIOResult(scope ref Result result) @trusted @nogc nothrow
{
    version(linux)
    if(result.isErrorType!LinuxError)
    {
        import core.sys.linux.errno : ECANCELED, ETIME;
        switch(result.errorCode)
        {
            case ECANCELED:
            case ETIME:
                result.changeErrorType(IoError.timeout);
                break;

            case EEXIST:
                result.changeErrorType(IoError.alreadyExists);
                break;

            case EISDIR:
                result.changeErrorType(IoError.isDirectory);
                break;

            case ENOTDIR:
                result.changeErrorType(IoError.notDirectory);
                break;

            case EACCES:
                result.changeErrorType(IoError.accessDenied);
                break;

            case ENOENT:
                result.changeErrorType(IoError.notFound);
                break;

            default: break;
        }
    }
}

private Result getPosixResult(string errorMessage, int errno) @trusted @nogc nothrow
{
    version(linux)
        auto result = linuxErrorAsResult(errorMessage, errno);
    else version(Posix)
        auto result = Result.make(cast(IoError)errno, errorMessage);
    else assert(false, "This function shouldn't have been called on this platform.");

    wrapIOResult(result);
    return result;
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
    this(uint ipv4, ushort port) @safe pure
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
    this(ubyte[16] ipv6, ushort port) @safe pure
    {
        this._kind = Kind.ipv6;
        this._ipv6 = ipv6;
        this.port  = port;
    }

    /++
     + Returns:
     +  The `Kind` of IP stored.
     + ++/
    Kind kind() @safe const pure
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
    uint asIpv4() @safe const pure
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
    ubyte[16] asIpv6() @safe const pure
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
    IpAddress toIpv6() @trusted const pure
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
    
    /++ 
     + Creates a copy of this `IpAddress` with the given port.
     +
     + Params:
     +   port = The port to set.
     +
     + Returns: 
     +   A copy of this `IpAddress` with the given port.
     +/
    IpAddress withPort(ushort port) @safe pure
    {
        IpAddress copy = this;
        copy.port = port;
        return copy;
    }

    version(Posix)
    void asSocketAddr(
        ref sockaddr* used, 
        ref size_t usedLength, 
        ref sockaddr_in ipv4, 
        ref sockaddr_in6 ipv6
    ) @trusted
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
    static IpAddress fromSocketAddr(scope const sockaddr* addr)
    in(addr !is null, "bug: addr is null, please add a null check")
    in(addr.sa_family == AF_INET || addr.sa_family == AF_INET6, "addr is not IPv4 or IPv4, please check .sa_family first")
    {
        IpAddress result;

        if(addr.sa_family == AF_INET)
        {
            const addr4 = cast(sockaddr_in*)addr;

            result._kind = Kind.ipv4;
            result._ipv4 = addr4.sin_addr.s_addr;
            result.port  = addr4.sin_port;
            return result;
        }
        else if(addr.sa_family == AF_INET6)
        {
            const addr6 = cast(sockaddr_in6*)addr;

            result._kind = Kind.ipv6;
            result._ipv6 = addr6.sin6_addr.s6_addr;
            result.port  = addr6.sin6_port;
            return result;
        }

        assert(false, "(why didn't the contract trigger?)");
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
    ) @trusted
    {
        char[129] buffer;
        
        if(address.length > buffer.length - 1) // @suppress(dscanner.suspicious.length_subtraction)
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

    static IpAddress mustParse(
        scope const char[] address, 
        ushort defaultPort = 0
    )
    {
        IpAddress ip;
        IpAddress.parse(ip, address, defaultPort).resultAssert;
        return ip;
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

    GenericIoDriver!(FileDescriptorReadWriteType.sendAndRecieve) _driver;
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
        int fd = -1;

        if(g_linuxKernal.major > 5 || (g_linuxKernal.major == 5 && g_linuxKernal.minor >= 19))
        {
            IoUringSocket op;
            op.domain = AF_INET6;
            op.type = SOCK_STREAM;
            op.protocol = 0;

            IoUringCompletion cqe;
            auto result = juptuneEventLoopSubmitEvent(op, cqe);
            if(result.isError)
                return result;

            fd = cqe.result;
        }
        else
        {
            fd = socket(AF_INET6, SOCK_STREAM, 0);
            if(fd == -1)
                return getPosixResult("failed to open socket", errno());
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
            return getPosixResult("failed to bind socket", errno());

        const listenResult = clisten(this._driver.fd, backlog);
        if(listenResult < 0)
            return getPosixResult("failed to listen on socket", errno());

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
            return getPosixResult("failed to connect to server", errno());

        return Result.noError;
    }

    static Result makePair(out PosixTcpSocket[2] sockets)
    {
        int[2] fds;

        const result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        if(result < 0)
            return getPosixResult("failed to create socket pairs", result);

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
 + A `UdpSocket` implementation that uses the standard POSIX socket functions
 + for when io_uring doesn't provide a native opcode.
 +
 + When a function has to use a standard POSIX function instead of io_uring, *it may block* the thread.
 +
 + Due to the nature of UDP, `GenericIoDriver` isn't used and so a bit of a different interface is 
 + provided.
 +
 + See_Also:
 +  `GenericIoDriver`
 + ++/
version(Posix)
struct PosixUdpSocket
{
    import core.sys.posix.sys.socket 
        : socket, clisten = listen, bind, setsockopt, SO_REUSEADDR, SO_REUSEPORT, SOL_SOCKET,
            SO_KEEPALIVE, socklen_t, getsockname, caccept = accept, cconnect = connect,
            socketpair;
    import core.sys.posix.arpa.inet 
        : AF_INET6, AF_UNIX, SOCK_DGRAM, ntohs;
    import core.sys.posix.netinet.in_ 
        : sockaddr, sockaddr_in, sockaddr_in6, IPPROTO_IPV6, IPV6_V6ONLY;

    private
    {
        IpAddress _ip;
        int _fd;
    }

    nothrow @nogc:

    void wrap(int fd) pure
    in(fd != 0, "File descriptor is 0, did you forget to check for failure?")
    in(this._fd == 0, "This PosixGenericIoDriver hasn't been closed yet. Please call .close")
    {
        this._fd = fd;
    }

    ~this()
    {
        if(this._fd)
            this.close().resultAssert;
    }

    bool isOpen() => this._fd != 0;

    Result close()
    in(_fd != 0, "File descriptor is 0, did you forget to check isOpen?")
    {
        auto op = IoUringClose();
        op.fd = this._fd;
        juptuneEventLoopSubmitEvent(
            op,
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false)
        ).resultAssert;
        this._fd = 0;

        return Result.noError;
    }

    /++
     + Creates the underlying socket.
     +
     + The following options are enabled: `REUSEPORT`; `REUSEADDR`.
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
    in(!this.isOpen, "This socket is already open, please call close() first.")
    {
        int fd = -1;

        if(g_linuxKernal.major > 5 || (g_linuxKernal.major == 5 && g_linuxKernal.minor >= 19))
        {
            IoUringSocket op;
            op.domain = AF_INET6;
            op.type = SOCK_DGRAM;
            op.protocol = 0;

            IoUringCompletion cqe;
            auto result = juptuneEventLoopSubmitEvent(op, cqe);
            if(result.isError)
                return result;

            fd = cqe.result;
        }
        else
        {
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if(fd == -1)
                return getPosixResult("failed to open socket", errno());
        }

        int enable = 1;
        int disable = 0;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, int.sizeof);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, int.sizeof);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &disable, int.sizeof);
        this.wrap(fd);
        
        auto yieldResult = yield(); // Emulate using io_uring for the socket call.
        if(yieldResult.isError)
            return yieldResult;

        return Result.noError;
    }

    /++
     + Connects to the target address.
     +
     + This overload is for convenience as it will call `IpAddress.parse` on `address`.
     +
     + Params:
     +  address     = The IPv4 or IPv6 address to parse, and attempt to connect to.
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
    Result connect(scope const char[] address, ushort defaultPort = 0)
    in(this.isOpen, "Cannot connect using a closed socket. Did you forget to call open() first?")
    {
        IpAddress addr;
        auto result = IpAddress.parse(addr, address, defaultPort);
        if(result.isError)
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
    in(this.isOpen, "Cannot connect using a closed socket. Did you forget to call open() first?")
    {
        sockaddr_in ip4;
        sockaddr_in6 ip6;
        sockaddr* used;
        size_t usedLength;

        address = address.toIpv6();
        address.asSocketAddr(used, usedLength, ip4, ip6);

        const result = cconnect(this._fd, used, cast(socklen_t)usedLength);
        if(result < 0)
            return getPosixResult("failed to connect to server", errno());

        return Result.noError;
    }

    static Result makePair(out PosixTcpSocket[2] sockets)
    {
        int[2] fds;

        const result = socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        if(result < 0)
            return getPosixResult("failed to create socket pairs", result);

        sockets[0].wrap(fds[0]);
        sockets[1].wrap(fds[1]);

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
 + A `File` implementation that's probably not actually POSIX compatible.
 +
 + As with all IO Driver implementations, this struct inherits `GenericIoDriver` for common IO functions.
 +
 + See_Also:
 +  `GenericIoDriver`
 + ++/
version(Posix)
struct PosixFile
{
    import core.sys.linux.fcntl :
        O_CLOEXEC,
        O_CREAT,
        O_DIRECT,
        O_DSYNC,
        O_EXCL,
        O_NOATIME,
        O_NOFOLLOW,
        O_RDONLY,
        O_WRONLY,
        O_RDWR,
        O_TRUNC,
        S_IRUSR,
        S_IWUSR,
        S_IXUSR,
        S_IRGRP,
        S_IWGRP,
        S_IXGRP,
        S_IROTH,
        S_IWOTH,
        S_IXOTH,
        AT_FDCWD
    ;

    private enum ALWAYS_USED_FLAGS = O_CLOEXEC; // O_CLOEXEC stops child processes from using any files opened by this process - it's a good security practice.

    GenericIoDriver!(FileDescriptorReadWriteType.writeAndRead) _driver;
    alias _driver this;

    /// Determines whether the file can be written to and/or read from.
    enum AccessMode
    {
        FAILSAFE = -1,

        /// The file can only be read from.
        readOnly = O_RDONLY,

        /// The file can only be written to.
        writeOnly = O_WRONLY,

        /// The file can be both written to and read from.
        readWrite = O_RDWR,
    }

    /// Determines how to deal with files that don't/already exist.
    enum CreateMode
    {
        /// Don't create a new file. If the file doesn't exist then you'll run into an error result.
        dontCreate = 0,

        /// Always attempt to create a new file. If the file already exists, then you'll run into an error result.
        create = O_CREAT | O_EXCL,

        /// Always attempt to create a new file. If the file already exists then it'll be truncated.
        truncate = O_CREAT | O_TRUNC,
    }

    /// Additional flags related to opening the file. This is a bit mask that can be ORed together.
    enum Flags
    {
        none = 0,

        /// Attempt to bypass any kernal-level caching and data duplication.
        direct = O_DIRECT,

        /// Writes will not return until all of the data & metadata required for the file to still function, have been fully committed to disk.
        dsync = O_DSYNC,

        /// The file access timestamp won't be updated.
        noAccessTime = O_NOATIME,

        /// If the last segment of the path is a symlink, you'll run into an error result instead of opening the file.
        noFollowTrailingSymlink = O_NOFOLLOW,
    }

    /// Flags related to changing the behaviour for how file paths are resolved. This is a bit mask that can be ORed together.
    enum ResolveFlags
    {
        /// No changes. They work as you'd expect.
        asNormal = 0,

        /// The path to the file being opened MUST belong to the same mounting point as the current working directory.
        mustBeOnSameMountAsCwd = 1 << 0,

        /// "Magic links" (google it) will generate an error result upon being opened.
        noMagicLinks = 1 << 1,

        /// The path to the file being opened MUST NOT contain a symlink at any point in its path.
        noSymlinksAtAnyPoint = 1 << 2,
        
        /// The path MUST NOT contain a starting "/", and MUST NOT contain any usage of things like "../". This guarentees that the file being opened,
        /// is directly under the current working directory. (TODO: Would be really nice to detach this functionality from the CWD).
        mustBeBeneathCwd = 1 << 3,

        /// The current working directory is treated as a fake root, so "/" resolves to the CWD, and "../" cannot break out of the CWD.
        cwdIsFakeRoot = 1 << 4,
    }

    enum PermissionFlags
    {
        none = 0,
        ownerRead = S_IRUSR,
        ownerWrite = S_IWUSR,
        ownerExecute = S_IXUSR,
        groupRead = S_IRGRP,
        groupWrite = S_IWGRP,
        groupExecute = S_IXGRP,
        otherRead = S_IROTH,
        otherWrite = S_IWOTH,
        otherExecute = S_IXOTH,

        ownerAll = ownerRead | ownerWrite | ownerExecute,
        groupAll = groupRead | groupWrite | groupExecute,
    }

    /// Helper function around `.open` for when you want to create a new file (the file must not exist already).
    static Result createNew(
        scope const(char)[] path,
        scope out PosixFile file,
        PermissionFlags     permissions = PermissionFlags.ownerAll | PermissionFlags.groupAll,
        ResolveFlags        resolveFlags = ResolveFlags.asNormal,
        scope Directory*    cwd = null,
        bool                pathIsNullTerminated = false,
    ) @nogc nothrow
    {
        return File.open(
            path, 
            AccessMode.readWrite, 
            CreateMode.create,
            Flags.none, 
            resolveFlags, 
            permissions,
            cwd,
            file,
            pathIsNullTerminated
        );
    }

    /// Helper function around `.open` for when you want to create a new file if it doesn't exist, or truncate it if it already exists.
    static Result createOrTruncate(
        scope const(char)[] path,
        scope out PosixFile file,
        PermissionFlags     permissions = PermissionFlags.ownerAll | PermissionFlags.groupAll,
        ResolveFlags        resolveFlags = ResolveFlags.asNormal,
        scope Directory*    cwd = null,
        bool                pathIsNullTerminated = false,
    ) @nogc nothrow
    {
        return File.open(
            path, 
            AccessMode.readWrite, 
            CreateMode.truncate,
            Flags.none, 
            resolveFlags, 
            permissions,
            cwd,
            file,
            pathIsNullTerminated
        );
    }

    /// Helper function around `.open` for when you want to open a prexisting file for reading.
    static Result openForReading(
        scope const(char)[] path,
        scope out PosixFile file,
        ResolveFlags        resolveFlags = ResolveFlags.asNormal,
        scope Directory*    cwd = null,
        bool                pathIsNullTerminated = false,
    ) @nogc nothrow
    {
        return File.open(
            path, 
            AccessMode.readOnly, 
            CreateMode.dontCreate,
            Flags.none, 
            resolveFlags, 
            PermissionFlags.none,
            cwd,
            file,
            pathIsNullTerminated
        );
    }

    /++
     + Opens/creates a file at the given path, using the provided flags & modes to determine the exact behaviour of the opened file.
     +
     + Notes:
     +  The `O_CLOEXEC` flag is always specified when opening a file, due to its security benefits.
     +
     + Params:
     +  path                    = The path - relative or absolute - to the file to open/create.
     +  accessMode              = Controls whether the file can be read from and/or written to.
     +  createMode              = Controls whether the file is created; truncated, or simply opened if it already exists.
     +  flags                   = Additional flags to control low-level details.
     +  resolveFlags            = Controls how `path` gets resolved, and what additional limitations may be placed on it.
     +  permissions             = The permission mask that gets applied to the file if it ends up being created.
     +  cwd                     = If not null, then this directory is used as the "current working directory" for purposes of resolving the `path`.
     +                            If null, then the process' globally set CWD is used instead.
     +  file                    = The opened file. If this function returns an error, then the result of this value is undefined.
     +  pathIsNullTerminated    = If true, then `path` is treated as if it's already null terminated, and so a pointer to it is passed directly to the underlying syscall.
     +                            If false, then `path` is copied into a short-lived buffer which will be given a null terminator. Default to false unless you're absolutely certain.
     +
     + Throws:
     +  Anything that `juptuneEventLoopSubmitEvent`.
     +
     +  Anything that the `openat2` syscall can generate (some errors are wrapped into an `IoError`, others will be a `LinuxError` instead).
     +
     + Returns:
     +  A `Result` indicating whether something went wrong or not.
     + ++/
    static Result open(
        scope const(char)[] path, 
        AccessMode          accessMode, 
        CreateMode          createMode,
        Flags               flags,
        ResolveFlags        resolveFlags,
        PermissionFlags     permissions,
        scope Directory*    cwd,
        scope out PosixFile file,
        bool                pathIsNullTerminated = false,
    ) @nogc nothrow
    {
        FileDescriptor fd;
        auto result = File.openImpl(path, accessMode, createMode, flags, resolveFlags, permissions, pathIsNullTerminated, cwd, fd); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        file.wrap(fd);
        return Result.noError;
    }

    private static Result openImpl(
        scope const(char)[] path, 
        AccessMode accessMode, 
        CreateMode createMode,
        Flags flags,
        ResolveFlags resolveFlags,
        PermissionFlags permissions,
        bool pathIsNullTerminated,
        scope Directory* cwd,
        scope out FileDescriptor fd,
        uint extraFlags = 0,
    ) @nogc nothrow
    in(accessMode != AccessMode.FAILSAFE, "bug: accessMode cannot be FAILSAFE")
    in(cwd is null || cwd.isOpen, "bug: cwd is not null, but isOpen is returning false?")
    {
        import core.stdc.string : strlen;

        // We don't have to do an awful lot of validation, since openat2 is defined to do most of it for us!

        IoUringOpenAt2.OpenHow how;
        how.flags   |= accessMode;
        how.flags   |= createMode;
        how.flags   |= flags;
        how.flags   |= ALWAYS_USED_FLAGS;
        how.flags   |= extraFlags;
        how.mode    |= permissions;
        how.resolve |= resolveFlags;

        // If needed, add a null terminator onto the string.
        String pathBuffer;
        scope const(char)* pathCString;
        if(!pathIsNullTerminated)
        {
            pathBuffer = String(path); // Non-sliced Strings are guarenteed to be null terminated.
            pathCString = pathBuffer.slice.ptr;
        }
        else
            pathCString = path.ptr;

        assert(strlen(pathCString) == path.length, "bug: safety check failed, pathCString's strlen != path.length, null terminator issue?"); // @suppress(dscanner.style.long_line)

        // Submit the command
        auto op = IoUringOpenAt2();
        op.dirfd = (cwd !is null) ? cwd.fd : AT_FDCWD;
        op.pathnameCString = pathCString;
        op.openHow = &how;

        IoUringCompletion cqe;
        auto result = juptuneEventLoopSubmitEvent(op, cqe);
        if(result.isError)
        {
            wrapIOResult(result);
            return result;
        }

        fd = cqe.result;
        return Result.noError;
    }
}

/++
 + A `Directory` implementation that's probably not actually POSIX compatible.
 +
 + As with all IO Driver implementations, this struct inherits `GenericIoDriver` for common IO functions.
 +
 + See_Also:
 +  `GenericIoDriver`
 + ++/
version(Posix)
struct PosixDirectory
{
    GenericIoDriver!(FileDescriptorReadWriteType.writeAndRead) _driver;
    alias _driver this;

    alias AccessMode = File.AccessMode;
    alias CreateMode = File.CreateMode;
    alias Flags = File.Flags;
    alias ResolveFlags = File.ResolveFlags;
    alias PermissionFlags = File.PermissionFlags;

    /// NOTE: Because directories on POSIX systems are just specially flagged files, please refer to the documentation for
    ///       `File.open` as almost everything will apply to this function as well.
    static Result open(
        scope const(char)[] path, 
        AccessMode accessMode, 
        CreateMode createMode,
        Flags flags,
        ResolveFlags resolveFlags,
        PermissionFlags permissions,
        scope Directory* cwd,
        scope out PosixDirectory dir,
        bool pathIsNullTerminated = false,
    ) @nogc nothrow
    {
        import core.sys.linux.fcntl : O_DIRECTORY;

        FileDescriptor fd;
        auto result = File.openImpl(path, accessMode, createMode, flags, resolveFlags, permissions, pathIsNullTerminated, cwd, fd, extraFlags: O_DIRECTORY); // @suppress(dscanner.style.long_line)
        if(result.isError)
            return result;

        dir.wrap(fd);
        return Result.noError;
    }
}

/++
 + Provides generic IO functionality.
 +
 + All platform-specific IO drivers will provide an `alias this` to this struct,
 + so that all drivers have the same facilities for writing and reading.
 + ++/
struct GenericIoDriver(FileDescriptorReadWriteType ReadWriteType)
{
    private
    {
    }
    PlatformGenericIoDriver!ReadWriteType _driver;
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
    Result put(const(void)[] buffer, Duration timeout = Duration.zero) @nogc
    {
        while(buffer.length > 0)
        {
            size_t bytesSent;
            auto result = this._driver.send(buffer, bytesSent, timeout);
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
    Result put(RangeT)(scope RangeT range, Duration timeout = Duration.zero)
    if(is(ElementEncodingType!RangeT : const(T)[], T) && !is(RangeT : const(void)[]))
    {
        while(!range.empty)
        {
            auto result = this.put(range.front, timeout);
            if(result.isError)
                return result;
            range.popFront();
        }

        return Result.noError;
    }

    /++
     + Writes an entire set of buffers.
     +
     + This is a high level helper around the `writev` function.
     +
     + Notes:
     +  This function can sometimes modify the entries of `buffers` during partial write scenarios, so please
     +  treat `buffers` as completely ephermeral.
     +
     + Params:
     +  buffers = The buffers to write.
     +
     + Throws:
     +  Any error that the platform's underlying `writev` command returns. (e.g. `LinuxError` on Linux)
     +
     + Returns:
     +  A `Result`
     + ++/
    Result putScattered(scope const(void)[][] buffers, Duration timeout = Duration.zero) @nogc
    {
        while(buffers.length > 0)
        {
            size_t bytesWritten;
            auto result = this._driver.writev(buffers, bytesWritten, timeout);
            if(result.isError)
                return result;

            while(bytesWritten > 0)
            {
                assert(buffers.length > 0);
                if(buffers[0].length <= bytesWritten)
                {
                    bytesWritten -= buffers[0].length;
                    buffers = buffers[1..$];
                }
                else
                {
                    buffers[0] = buffers[0][bytesWritten..$];
                    bytesWritten -= buffers[0].length;
                }
            }
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
     + This is a high level helper around the `receive` function.
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
     +  Any error that the platform-specific `receive` function returns.
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
     + This is a high level helper around the `receive` function.
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
     +  Any error that the platform-specific `receive` function returns.
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
        scope GrowFuncT growFunc = null,
        Duration timeout = Duration.zero
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
            auto result = this._driver.receive(buffer[cursor..$], inSlice, timeout);
            if(result.isError)
                return result;
            
            cursor += inSlice.length;
            if(inSlice.length == 0 || inSlice.length < (buffer.length - cursor))
            {
                buffer.length = cursor;
                break;
            }
        }

        return Result.noError;
    }
    // static assert(
    //     __traits(compiles, ()nothrow @nogc{ Array!ubyte b; TcpSocket.init.readAll(b).resultAssert; }),
    //     "readAll no longer compiles under @nogc"
    // );
}

private enum FileDescriptorReadWriteType
{
    sendAndRecieve,
    writeAndRead,
}

version(Posix)
private struct PosixGenericIoDriver(FileDescriptorReadWriteType ReadWriteType)
{
    import core.sys.posix.sys.uio : iovec;

    @disable this(this){}
    enum IOVEC_STATIC_SIZE = 4;

    private
    {
        int fd;
    }

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

    Result send(const(void)[] buffer, scope out size_t bytesSent, Duration timeout = Duration.zero)
    {
        static if(ReadWriteType == FileDescriptorReadWriteType.sendAndRecieve)
        {
            auto op = IoUringSend();
            op.fd = this.fd;
            op.buffer = cast(void[])buffer;

            IoUringCompletion cqe;
            auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, SubmitEventConfig().withTimeout(timeout));
            if(submitResult.isError)
                return submitResult;

            if(cqe.result < 0)
                return getPosixResult("failed to send data to socket", cqe.result);

            assert(cqe.result >= 0);
            bytesSent = cqe.result;
            return Result.noError;
        }
        else static if(ReadWriteType == FileDescriptorReadWriteType.writeAndRead)
        {
            auto op = IoUringWrite();
            op.fd = this.fd;
            op.buffer = cast(void[])buffer;

            IoUringCompletion cqe;
            auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, SubmitEventConfig().withTimeout(timeout));
            if(submitResult.isError)
                return submitResult;

            if(cqe.result < 0)
                return getPosixResult("failed to send data to file descriptor", cqe.result);

            assert(cqe.result >= 0);
            bytesSent = cqe.result;
            return Result.noError;
        }
        else static assert(false, "Missing ReadWriteType case");
    }

    Result receive(void[] buffer, out void[] sliceWithData, Duration timeout = Duration.zero)
    {
        static if(ReadWriteType == FileDescriptorReadWriteType.sendAndRecieve)
        {
            auto op = IoUringRecv();
            op.fd = this.fd;
            op.buffer = buffer;

            IoUringCompletion cqe;
            auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, SubmitEventConfig().withTimeout(timeout));
            if(submitResult.isError)
                return submitResult;

            if(cqe.result < 0)
                return getPosixResult("failed to receive data from socket", cqe.result);

            assert(cqe.result >= 0);
            sliceWithData = buffer[0..cqe.result];
            return Result.noError;
        }
        else static if(ReadWriteType == FileDescriptorReadWriteType.writeAndRead)
        {
            auto op = IoUringRead();
            op.fd = this.fd;
            op.buffer = buffer;

            IoUringCompletion cqe;
            auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, SubmitEventConfig().withTimeout(timeout));
            if(submitResult.isError)
                return submitResult;

            if(cqe.result < 0)
                return getPosixResult("failed to read data from file descriptor", cqe.result);

            assert(cqe.result >= 0);
            sliceWithData = buffer[0..cqe.result];
            return Result.noError;
        }
        else static assert(false, "Missing ReadWriteType case");
    }

    Result writev(scope ref MemoryBlockAllocation buffers, out size_t bytesRead, Duration timeout = Duration.zero)
    {
        return this.vectorMBAImpl!IoUringWritev(buffers, bytesRead, timeout);
    }

    Result writev(scope const void[][] buffers, ref size_t bytesRead, Duration timeout = Duration.zero)
    {
        return this.vectorVoidArrayImpl!IoUringWritev(buffers, bytesRead, timeout);
    }

    Result readv(scope ref MemoryBlockAllocation buffers, out size_t bytesRead, Duration timeout = Duration.zero)
    {
        return this.vectorMBAImpl!IoUringReadv(buffers, bytesRead, timeout);
    }

    Result readv(scope void[][] buffers, ref size_t bytesRead, Duration timeout = Duration.zero)
    {
        return this.vectorVoidArrayImpl!IoUringReadv(buffers, bytesRead, timeout);
    }

    private Result vectorMBAImpl(alias OpT)(
        scope ref MemoryBlockAllocation buffers, 
        ref size_t bytesRead, 
        Duration timeout = Duration.zero
    )
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
        }, buffers.blockCount, bytesRead, timeout);
    }

    private Result vectorVoidArrayImpl(alias OpT)(
        scope const void[][] buffers, 
        ref size_t bytesRead, 
        Duration timeout = Duration.zero
    )
    {
        return this.vectorIoImpl!OpT((iovecs) @nogc nothrow {
            foreach(i, buffer; buffers)
            {
                iovecs[i].iov_base = cast(void*)buffer.ptr;
                iovecs[i].iov_len = buffer.length;
            }
        }, buffers.length, bytesRead, timeout);
    }

    private Result vectorIoImpl(alias OpT)(
        scope void delegate(iovec[]) @nogc nothrow setter,
        size_t bufferCount,
        ref size_t bytesUsed,
        Duration timeout = Duration.zero
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
        auto submitResult = juptuneEventLoopSubmitEvent(op, cqe, SubmitEventConfig().withTimeout(timeout));
        if(submitResult.isError)
            return submitResult;

        if(cqe.result < 0)
        {
            static if(is(OpT == IoUringReadv))
                static immutable message = "failed to receive data from socket via scatter input";
            else
                static immutable message = "failed to send data to socket via gather output";

            return getPosixResult(message, cqe.result);
        }

        assert(cqe.result >= 0);
        bytesUsed = cqe.result;
        return Result.noError;
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
    // TODO: This seems to hang every so often - look into it.
    // auto loop = EventLoop(EventLoopConfig());
    // loop.addNoGCThread(() @nogc nothrow {
    //     async((){
    //         TcpSocket server;
    //         server.open().resultAssert;
    //         server.listen("127.0.0.1:15000", 1).resultAssert;

    //         TcpSocket client;
    //         server.accept(client).resultAssert;

    //         juptuneEventLoopCancelThread();
    //     }).resultAssert;
    //     async((){
    //         TcpSocket server;
    //         server.open().resultAssert;

    //         bool lookupWasPerformed;
    //         server.connect("127.0.0.1:15000", lookupWasPerformed).resultAssert;
    //         assert(!lookupWasPerformed);
    //     }).resultAssert;
    // });
    // loop.join();
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

            // socket.writev([buf1[], buf2[], buf3[]], bytesSent).resultAssert;
            // assert(bytesSent == buf1.length + buf2.length + buf3.length);
            socket.putScattered([buf1[], buf2[], buf3[]]).resultAssert;
        }, pairs[0], &asyncMoveSetter!TcpSocket).resultAssert;

        async((){
            auto socket = juptuneEventLoopGetContext!TcpSocket;
            ubyte[128] buffer;
            void[] got;

            socket.receive(buffer[], got).resultAssert;

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

    static void testResult(Result r)
    {
        assert(r.isError);
        assert(r.isError(IoError.timeout));
    }

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        TcpSocket[2] pairs;
        ubyte[128] buffer;
        void[] slice;
        size_t bytes;

        TcpSocket.makePair(pairs).resultAssert;

        testResult(pairs[0].readv([buffer[]], bytes, 1.msecs));
        testResult(pairs[0].receive(buffer[], slice, 1.msecs));
        // Hard to tests writes currently, as I have no idea how to consistently block the write call.
    });
    loop.join();
}