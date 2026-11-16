/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.dns.types;

/++
 + The query object used by the medium-level APIs.
 + ++/
struct DnsQuery
{
    import juptune.event     : IpAddress;
    import juptune.dns.types : DnsRecordClass, DnsRecordType, DnsHeaderOpcode;

    /// The domain name to lookup, e.g. "google.com"
    const(char)[] domainName;

    /// The record type to lookup.
    DnsRecordType recordType;
    
    DnsHeaderOpcode opcode = DnsHeaderOpcode.query;
    DnsRecordClass recordClass = DnsRecordClass.in_;
}

/++
 + Specs:
 +   RFC1035 4.1.1
 + ++/
enum DnsHeaderOpcode : ubyte
{
    FAILSAFE = ubyte.max,

    query       = 0,
    iquery      = 1,
    status      = 2,
}

/++
 + Specs:
 +   RFC1035 3.2.2
 +   RFC3596 2
 +   RFC6891 6.1.1
 + ++/
enum DnsRecordType : ushort
{
    FAILSAFE,
    a       = 1,
    ns      = 2,
    md      = 3,
    mf      = 4,
    cname   = 5,
    soa     = 6,
    mb      = 7,
    mg      = 8,
    mr      = 9,
    null_   = 10,
    wks     = 11,
    ptr     = 12,
    hinfo   = 13,
    minfo   = 14,
    mx      = 15,
    txt     = 16,
    aaaa    = 28,

    // Pseudo
    opt     = 41,

    // Queries only
    axfr        = 252,
    mailb       = 253,
    maila       = 254,
}

/++
 + Specs:
 +   RFC1035 3.2.3
 + ++/
enum DnsRecordClass : ushort
{
    FAILSAFE,
    in_     = 1,
    cs      = 2,
    ch      = 3,
    hs      = 4,

    // Queries only
    wildcard    = 255
}

/++
 + Specs:
 +   RFC1035 4.1.1
 + ++/
enum DnsResponseCode : ubyte
{
    FAILSAFE = ubyte.max,
    
    none            = 0,
    formatError     = 1,
    serverFailure   = 2,
    nameError       = 3,
    notImplemented  = 4,
    refused         = 5,
    reserved6       = 6,
    reserved7       = 7,
    reserved8       = 8,
    reserved9       = 9,
    reserved10      = 10,
    reserved11      = 11,
    reserved12      = 12,
    reserved13      = 13,
    reserved14      = 14,
    reserved15      = 15,
}