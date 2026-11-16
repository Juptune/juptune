/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.dns.resolver;

import juptune.core.ds      : Array;
import juptune.core.util    : Result;
import juptune.event        : IpAddress, Mutex;

enum DnsResolverError
{
    none,

    resolvConfError,
    noNameservers,
    notFound,
    badResponse,
    noResponse,
}

/++++ Easy to use public API ++++/

/++
 + Performs a DNS for the given domain name, either for IPv4 or IPv6 depending on the `ipKind` parameter.
 +
 + Notes:
 +  This function will ask every nameserver it knows of in order until one produces a response. Regardless
 +  of whether this response was a success or a failure, it'll stop once it receives said response.
 +
 + Nameservers:
 +  This function supports "/etc/resolve.conf", but only understands "nameserver" directives.
 +
 + Params:
 +  domainName = The domain name to lookup an IP for.
 +  ip         = The resulting IP - the port is always set to 0.
 +  ipKind     = Whether we're looking up A (v4) or AAAA (v6) records.
 +
 + Throws:
 +  `DnsResolverError.noNameservers` if no nameservers could be loaded.
 +
 +  `DnsResolverError.notFound` if a nameserver was unable to find any suitable records for the domain.
 +
 +  `DnsResolverError.badResponse` if a nameserver produced any other kind of error response that's not explicitly handled.
 +
 +  Anything that `dnsQueryRfc1035` and `dnsDecodePayload` can throw.
 +
 + Returns:
 +  A `Result`.
 + ++/
Result dnsLookupIp(
    scope const(char)[] domainName, 
    scope out IpAddress ip,
    IpAddress.Kind ipKind = IpAddress.Kind.ipv4, // *Grumble* unfortunately IPv4 is still the "default" to lookup.
) @nogc nothrow
{
    import juptune.data                 : MemoryReader;
    import juptune.dns.clients.rfc1035  : dnsQueryRfc1035, DnsRfc1035QueryConfig, DNS_RFC1035_RECOMMENDED_BUFFER_SIZE;
    import juptune.dns.encoding         : dnsDecodePayload;
    import juptune.dns.types            : DnsQuery, DnsRecordType, DnsResponseCode, DnsRecordClass;

    auto result = ensureNameserversLoaded();
    if(result.isError)
        return result;

    if(g_nameservers.length == 0)
        return Result.make(DnsResolverError.noNameservers, "cannot perform a DNS lookup when no nameservers are registered"); // @suppress(dscanner.style.long_line)

    /++++ Try each nameserver in order ++++/
    const rfc1035Config = DnsRfc1035QueryConfig(
        udpRetries: 1
    );

    const expectedRecordType = (ipKind == IpAddress.Kind.ipv4) ? DnsRecordType.a : DnsRecordType.aaaa;

    foreach(server; g_nameservers.slice)
    {
        final switch(server.clientType) with(Nameserver.ClientType)
        {
            case rfc1035:
                ubyte[DNS_RFC1035_RECOMMENDED_BUFFER_SIZE] buffer = void;
                size_t bufferUsed;

                result = dnsQueryRfc1035(
                    nameserverIp: server.ip,
                    query: DnsQuery(domainName, expectedRecordType),
                    readBuffer: buffer,
                    readBufferUsed: bufferUsed,
                    config: rfc1035Config,
                );
                if(result.isError)
                    return result;

                auto reader = MemoryReader(buffer[0..bufferUsed]);
                IpAddress ipToUse;
                DnsResponseCode rcode;

                result = dnsDecodePayload(reader,
                    onHeader: (header) {
                        rcode = header.rcode;
                        return Result.noError;
                    },
                    onAnswer: (record) {
                        if(rcode != DnsResponseCode.none || ipToUse != IpAddress.init)
                            return Result.noError;

                        if(record.recordType != expectedRecordType || record.recordClass != DnsRecordClass.in_)
                            return Result.noError;
                        if(!caseInsensitiveCompare(domainName, record.domainNameDoNotEscape))
                            return Result.noError;

                        auto rdata = MemoryReader(record.rdata);
                        if(expectedRecordType == DnsRecordType.a)
                        {
                            if(rdata.bytesLeft != 4)
                                return Result.noError;

                            const(ubyte)[] ipBytes;
                            const couldRead = rdata.readBytes(4, ipBytes);
                            assert(couldRead, "bug: how did this fail?");

                            const ipReinterpret = *(cast(uint*)&ipBytes[0]);
                            ipToUse = IpAddress(ipReinterpret, port: 0);
                        }
                        else
                        {
                            if(rdata.bytesLeft != 16)
                                return Result.noError;

                            const(ubyte)[] ipBytes;
                            const couldRead = rdata.readBytes(16, ipBytes);
                            assert(couldRead, "bug: how did this fail?");

                            ipToUse = IpAddress(ipBytes[0..16], port: 0);
                        }
                        return Result.noError;
                    },
                    onQuestion: (_) => Result.noError, 
                    onAuthority: (_) => Result.noError, 
                    onAdditional: (_) => Result.noError, 
                );
                if(result.isError)
                    return result;

                if(rcode != DnsResponseCode.none)
                {
                    import juptune.core.ds : String;
                    switch(rcode)
                    {
                        case DnsResponseCode.nameError:
                            return Result.make(
                                DnsResolverError.notFound,
                                "when looking up IP for domain, nameserver was unable to find domain",
                                String("domain:", domainName, " kind:", ipKind)
                            );

                        default:
                            return Result.make(
                                DnsResolverError.badResponse,
                                "when looking up IP for domain, nameserver produced a bad response",
                                String("domain:", domainName, " kind:", ipKind, " rcode:", rcode)
                            );
                    }
                }

                if(ipToUse == IpAddress.init)
                    break; // Move onto the next nameserver

                ip = ipToUse;
                return Result.noError;

            case FAILSAFE: assert(false);
        }
    }

    return Result.make(DnsResolverError.noResponse, "when looking up IP for domain, no nameservers responded at all");
}

/++++ Nameserver store & functions for loading common DNS config ++++/

private struct Nameserver
{
    enum ClientType
    {
        FAILSAFE,
        rfc1035
    }

    IpAddress  ip;
    ClientType clientType;
}

// TODO: I need to make a Once type - this is just the x509 certificate store code copy-pasted lol.
private __gshared Array!Nameserver g_nameservers;
private __gshared bool g_nameserversHasBeenLoaded;
private Array!Nameserver* g_nameserversThreadLocalPointer;
private shared Mutex g_nameserversMutex;

private Result ensureNameserversLoaded() @nogc nothrow
{
    import core.atomic : atomicLoad, atomicStore, MemoryOrder;
    import juptune.core.util : resultAssert;
    import juptune.event     : IoError;

    // If we've already cached a pointer for this thread (indicating it's been created), just return that (fast path)
    if(g_nameserversThreadLocalPointer !is null)
        return Result.noError;

    // Otherwise we can use an atomic to check if the store has been previously marked as created (relatively fast path)
    if(atomicLoad!(MemoryOrder.acq)(g_nameserversHasBeenLoaded))
    {
        g_nameserversThreadLocalPointer = &g_nameservers;
        return Result.noError;
    }

    // Otherwise try to obtain the Mutex; do a safety check to make sure it still hasn't been created, and then create the store in this thread (slow path).
    g_nameserversMutex.lock().resultAssert;
    scope(exit) g_nameserversMutex.unlock().resultAssert;

    if(atomicLoad!(MemoryOrder.acq)(g_nameserversHasBeenLoaded)) // Multiple threads may be waiting on the mutex, so double check that none of the previous threads have ran first.
    {
        g_nameserversThreadLocalPointer = &g_nameservers;
        return Result.noError;
    }
    
    version(linux)
    {
        auto result = loadResolvConf();
        if(result.isError)
        {
            // It's safe to ignore `noDefaultCertificatesFound`, though I wish I had a better way to signal this to the user without having to return a result.
            if(
                !result.isError(IoError.notFound) 
                && !result.isError(IoError.accessDenied) 
                && !result.isError(DnsResolverError.resolvConfError)
            )
            {
                resultAssert(result);
            }
        }
    }
    
    g_nameserversThreadLocalPointer = &g_nameservers;
    atomicStore!(MemoryOrder.rel)(g_nameserversHasBeenLoaded, true);
    return Result.noError;
}

version(linux) private Result loadResolvConf() @nogc nothrow
{
    import std.algorithm : countUntil;
    import std.string    : lineSplitter;
    import std.utf       : byCodeUnit;

    import juptune.event : File;

    /++++ Try to open the file and read it into memory. ++++/
    File file;
    auto result = File.openForReading("/etc/resolv.conf", file, pathIsNullTerminated: true);
    if(result.isError)
        return result;

    Array!ubyte buffer;
    result = file.readAll(buffer);
    if(result.isError)
        return result;

    /++++ Parse line by line, currently we only support the "nameserver" directive. ++++/
    foreach(line; (cast(char[])buffer.slice).lineSplitter)
    {
        // Skip empty lines and comments
        if(line.length == 0 || line[0] == ';' || line[0] == '#')
            continue;

        // Find the first space so we can split by it
        const firstSpaceIndex = line.byCodeUnit.countUntil(' ');
        if(firstSpaceIndex == -1) // (I think this is technically a malformed resolv.conf but meh, just skip it)
            continue;

        const directive = line[0..firstSpaceIndex];
        const value     = line[firstSpaceIndex+1..$];

        switch(directive)
        {
            case "nameserver":
                // Try to parse the IP (skipping if we run into an error)
                IpAddress ip;
                result = IpAddress.parse(ip, value);
                if(result.isError)
                    break;

                g_nameservers.put(Nameserver(ip: ip, clientType: Nameserver.ClientType.rfc1035));
                break;

            default:
                break; // Ignore any unknown directives.
        }
    }

    return Result.noError;
}

/++++ Helpers ++++/

private bool caseInsensitiveCompare(scope const(char)[] a, scope const(char)[] b) @nogc nothrow pure
{
    if(a.length != b.length)
        return false;

    const toLower = 'A' - 'a';
    foreach(i; 0..a.length)
    {
        const chA = (a[i] >= 'A' && a[i] <= 'Z') ? (a[i] - toLower) : a[i];
        const chB = (b[i] >= 'A' && b[i] <= 'Z') ? (b[i] - toLower) : b[i];
        if(chA != chB)
            return false;
    }

    return true;
}