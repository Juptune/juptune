module juptune.dns.clients.rfc1035;

import juptune.core.util : Result;
import juptune.dns.types : DnsQuery;
import juptune.event     : IpAddress, UdpSocket, TcpSocket;

/// Min UDP buffer size allowed for EDNS. This is the smallest that `readBuffer` should ever be.
enum DNS_RFC1035_MIN_BUFFER_SIZE = 512;

/// Recommended size of `readBuffer` that should work on most networks.
enum DNS_RFC1035_RECOMMENDED_BUFFER_SIZE = 1232;

/// Config for performing a DNS query using `dnsQueryRfc1035`.
struct DnsRfc1035QueryConfig
{
    import core.time : Duration, seconds;

    /// Timeout to use when sending and reading data via UDP.
    Duration udpTimeout = 3.seconds;

    /// The amount of times to try querying DNS via UDP. After this many attempts have failed, a single TCP attempt is made.
    uint udpRetries = 3;

    /// Timeout to use when sending and reading data via TCP.
    Duration tcpTimeout = 3.seconds;

    /// Force the use of TCP, completely skipping UDP.
    bool forceTcp = false;
}

/// A `Result` error enum.
enum DnsRfc103ClientError
{
    none,

    /// The server is sending data very... very... VERY slowly.
    slowConnection,

    /// The server sent a response that is too large for the provided buffer.
    bufferTooSmall,
}

/++
 + Performs a DNS query using the unencrypted UDP/TCP format initially described in RFC1035.
 +
 + Notes:
 +  This client supports EDNS. If `readBuffer` is larger than `DNS_RFC1035_MIN_BUFFER_SIZE` then EDNS is used to specify
 +  that `readBuffer.length` is our max supported response size.
 +
 +  It is recommended to set `readBuffer`'s length to `DNS_RFC1035_RECOMMENDED_BUFFER_SIZE` in most cases.
 +
 +  If this function throws an error, the contents of `readBuffer` and `readBufferUsed` are undefined.
 +
 +  While this function does call `dnsDecodePayload` to ensure the payload is valid, it is left to the caller to
 +  _also_ call `dnsDecodePayload` for its own purposes.
 +
 +  This function does not automatically throw if the payload contains an error code.
 +
 + TCP:
 +  This client will switch to TCP under the following conditions:
 +      * The UDP connection times out too many times (controlled by `config`).
 +      * The UDP response is truncated.
 +      * TCP is forced by `config.forceTcp`.
 +
 + Params:
 +  nameServerIp    = The IP of the nameserver to query.
 +  query           = The query itself to perform.
 +  readBuffer      = The buffer to read the server's response into.
 +  readBufferUsed  = The amount of bytes used in readBuffer.
 +
 + Throws:
 +  `DnsRfc103ClientError.slowConnection` if the server sends the header length prefix too slowly.
 +
 +  `DnsRfc103ClientError.bufferTooSmall` if the read buffer is unable to fit the server's full response.
 +
 +  Anything that `dnsEncodeQuery` and `dnsDecodePayload` can throw.
 +
 +  Anything that `UdpSocket` and `TcpSocket` may throw.
 +
 + Returns:
 +  A `Result`
 + ++/
Result dnsQueryRfc1035(
    IpAddress                   nameserverIp,
    const DnsQuery              query,
    scope ubyte[]               readBuffer,
    scope out size_t            readBufferUsed,
    const DnsRfc1035QueryConfig config = DnsRfc1035QueryConfig()
) @nogc nothrow
in(readBuffer.length >= DNS_RFC1035_MIN_BUFFER_SIZE, "readBuffer.length should be at least DNS_RFC1035_MIN_BUFFER_SIZE")
in(readBuffer.length < ushort.max, "readBuffer is too large")
{
    import juptune.data  : MemoryWriter;
    import juptune.dns   : dnsEncodeQuery, DnsRecordType;
    import juptune.event : IoError;

    UdpSocket udp;
    TcpSocket tcp;

    ubyte[DNS_RFC1035_MIN_BUFFER_SIZE] writeBuffer;
    auto writeMemory = MemoryWriter(writeBuffer[]);

    /++++ Encode the query. If the read buffer is a non-min size then we'll use EDNS and pray ++++/

    auto result = dnsEncodeQuery(
        id: 0,
        writer: writeMemory,
        putQuestions: (scope put) => put(query.domainName, query.recordType, query.recordClass),
        putAdditionalRecords: (scope startNextRecord) {
            if(readBuffer.length > DNS_RFC1035_MIN_BUFFER_SIZE)
            {
                MemoryWriter* writer;
                auto result = startNextRecord(
                    "",                            // (null/root domain)
                    DnsRecordType.opt,
                    cast(ushort)readBuffer.length, // UDP size we're able to support
                    0,                             // No special RCODE; flags, and version 0 of the OPT payload
                    writer,
                );
                if(result.isError)
                    return result;

                // (we're not setting any extended attributes, so the writer goes unused)
            }
            return Result.noError;
        },
        query.opcode,
    );
    if(result.isError)
        return result;

    /++++ We'll try UDP a few times, and if it keeps failing or if the response is truncated, then we'll switch to TCP ++++/

    bool udpSuccess;
    if(!config.forceTcp)
    {
        foreach(attempt; 0..config.udpRetries)
        {
            bool retry;
            result = sendOverUdp(
                udp, 
                writeMemory.usedBuffer, 
                readBuffer, 
                readBufferUsed, 
                nameserverIp, 
                config, 
                udpSuccess,
                retry
            );
            if(result.isError)
                return result;
            if(udpSuccess)
                break;
            if(!retry)
                break;
        }
    }

    if(udpSuccess)
        return Result.noError;

    /++++ UDP failed for one acceptable reason or another, so try TCP ++++/

    return sendOverTcp(
        tcp,
        writeMemory.usedBuffer,
        readBuffer,
        readBufferUsed,
        nameserverIp,
        config,
    );
}

private Result sendOverUdp(
    scope ref UdpSocket         udp,
    scope const(ubyte)[]        payload,
    scope ubyte[]               readBuffer,
    scope out size_t            readBufferUsed,
    IpAddress                   nameserverIp,
    const DnsRfc1035QueryConfig config,
    scope out bool              success,
    scope out bool              retry,
) @nogc nothrow
{
    import std.typecons : Nullable;

    import juptune.data         : MemoryReader;
    import juptune.dns.encoding : dnsDecodePayload;
    import juptune.event        : IoError;

    auto result = udp.open();
    if(result.isError)
        return result;

    if(nameserverIp.port == 0)
        nameserverIp.port = 53;

    result = udp.connect(nameserverIp);
    if(result.isError)
        return result;

    result = udp.sendmsg([payload], timeout: config.udpTimeout);
    if(result.isError)
    {
        if(result.isError(IoError.timeout))
        {
            retry = true;
            return Result.noError; // This shouldn't really happen, but if it does let the caller upgrade to TCP/retry
        }
        return result;
    }

    Nullable!IpAddress _;
    result = udp.recvmsg([readBuffer], readBufferUsed, _);
    if(result.isError)
    {
        // The datagram got truncated for some non-DNS-related reason, so return without an error to upgrade to TCP/retry
        if(result.isError(IoError.messageTooLarge))
        {
            retry = true;
            return Result.noError;
        }
        return result;
    }

    // We have to decode it here for both validation, and to ensure that the response wasn't truncated (which'd require a TCP upgrade)
    auto reader = MemoryReader(readBuffer[0..readBufferUsed]);
    return dnsDecodePayload(reader,
        onHeader: (scope header) {
            success = !header.wasTruncated;
            retry   = false;
            return Result.noError;
        },
        onQuestion: (_) => Result.noError,
        onAnswer: (_) => Result.noError,
        onAuthority: (_) => Result.noError,
        onAdditional: (_) => Result.noError,
    );
}

private Result sendOverTcp(
    scope ref TcpSocket         tcp,
    scope const(ubyte)[]        payload,
    scope ubyte[]               readBuffer,
    scope out size_t            readBufferUsed,
    IpAddress                   nameserverIp,
    const DnsRfc1035QueryConfig config,
) @nogc nothrow
{
    import std.typecons : Nullable;

    import juptune.data         : MemoryReader, MemoryWriter;
    import juptune.dns.encoding : dnsDecodePayload;
    import juptune.event        : IoError;

    auto result = tcp.open();
    if(result.isError)
        return result;

    if(nameserverIp.port == 0)
        nameserverIp.port = 53;

    result = tcp.connect(nameserverIp);
    if(result.isError)
        return result;

    // (TCP messages need a 2 byte length prefix)
    ubyte[2] lengthPrefix;

    auto lengthWriter = MemoryWriter(lengthPrefix[]);
    const couldWriteLength = lengthWriter.putU16BE(cast(ushort)payload.length);
    assert(couldWriteLength, "bug: this can't fail?");

    result = tcp.putScattered([lengthPrefix[], payload], timeout: config.tcpTimeout);
    if(result.isError)
        return result;

    // (Similarly, when we receive the message we need to read in the length bytes)
    size_t bytesRead;
    result = tcp.readv([lengthPrefix[], readBuffer], bytesRead, timeout: config.tcpTimeout);
    if(result.isError)
        return result;

    if(bytesRead < 2)
        return Result.make(DnsRfc103ClientError.slowConnection, "when reading TCP length prefix, the server somehow didn't send more than 1 byte"); // @suppress(dscanner.style.long_line)

    ushort expectedLength;
    auto lengthReader = MemoryReader(lengthPrefix[]);
    const couldReadLength = lengthReader.readU16BE(expectedLength);
    assert(couldReadLength, "bug: this can't fail?");

    if(expectedLength > readBuffer.length)
        return Result.make(DnsRfc103ClientError.bufferTooSmall, "when reading TCP payload, the server produced a payload larger than the provided read buffer"); // @suppress(dscanner.style.long_line)

    readBufferUsed = bytesRead - 2; // "- 2" since we don't need to take the length prefix into account.

    while(readBufferUsed < expectedLength)
    {
        void[] got;
        const left = readBufferUsed - expectedLength;

        result = tcp.receive(readBuffer[readBufferUsed..readBufferUsed + left], got, timeout: config.tcpTimeout);
        if(result.isError)
            return result;

        readBufferUsed += got.length;
    }

    // We have to decode it here for validation
    auto reader = MemoryReader(readBuffer[0..readBufferUsed]);
    return dnsDecodePayload(reader,
        onHeader: (_) => Result.noError,
        onQuestion: (_) => Result.noError,
        onAnswer: (_) => Result.noError,
        onAuthority: (_) => Result.noError,
        onAdditional: (_) => Result.noError,
    );
}