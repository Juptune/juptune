/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.http.uri;

import std.typecons : Flag, Nullable;
import juptune.core.util : Result, resultAssert;
import juptune.event.io : IpAddress;

private
{
    enum Rfc3986CharType : ulong
    {
        RESERVED_NONE               = 1 << 1,
        RESERVED_GEN_DELIM          = 1 << 2,
        RESERVED_SUB_DELIM          = 1 << 3,
        RESERVED_PCT_ENCODE         = 1 << 4,
        RESERVED_MASK               = RESERVED_NONE | RESERVED_GEN_DELIM | RESERVED_SUB_DELIM | RESERVED_PCT_ENCODE,

        SCHEME_ALPHA                = 1 << 5,
        SCHEME_NON_ALPHA            = 1 << 6,
        SCHEME_MASK                 = SCHEME_ALPHA | SCHEME_NON_ALPHA,

        AUTHORITY_TERMINAL          = 1 << 7,
        AUTHORITY_MASK              = AUTHORITY_TERMINAL,

        AUTHORITY_USERINFO_ALLOWED  = 1 << 8,
        AUTHORITY_USERINFO_MASK     = AUTHORITY_USERINFO_ALLOWED | RESERVED_NONE | RESERVED_SUB_DELIM,
        
        AUTHORITY_HOST_MASK         = RESERVED_NONE | RESERVED_SUB_DELIM,

        PATH_ALLOWED                = 1 << 9,
        PATH_TERMINAL               = 1 << 10,
        PATH_MASK                   = PATH_TERMINAL | PATH_ALLOWED | RESERVED_NONE | RESERVED_SUB_DELIM,

        QUERY_ALLOWED               = 1 << 11,
        QUERY_TERMINAL              = 1 << 12,
        QUERY_MASK                  = QUERY_TERMINAL | QUERY_ALLOWED | RESERVED_NONE | RESERVED_SUB_DELIM,

        FRAGMENT_ALLOWED            = 1 << 13,
        FRAGMENT_MASK               = FRAGMENT_ALLOWED | RESERVED_NONE | RESERVED_SUB_DELIM,

        IS_HEX_DIGIT                = 1 << 14,
    }

    immutable g_rfc3986CharType = (){
        Rfc3986CharType[256] charType;

        // Reserved set
        with(Rfc3986CharType)
        {
            foreach(i; 0..256)
                charType[i] = RESERVED_PCT_ENCODE;

            foreach(ch; [':', '/', '?', '#', '[', ']', '@'])
                charType[ch] = RESERVED_GEN_DELIM;
            foreach(ch; ['!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '='])
                charType[ch] = RESERVED_SUB_DELIM;
            foreach(ch; ['-', '.', '_', '~'])
                charType[ch] = RESERVED_NONE;
            foreach(ch; 'a'..'z'+1)
                charType[ch] = RESERVED_NONE;
            foreach(ch; 'A'..'Z'+1)
                charType[ch] = RESERVED_NONE;
            foreach(ch; '0'..'9'+1)
                charType[ch] = RESERVED_NONE;
        }

        // Scheme set
        with(Rfc3986CharType)
        {
            foreach(ch; 'a'..'z'+1)
                charType[ch] |= SCHEME_ALPHA;
            foreach(ch; 'A'..'Z'+1)
                charType[ch] |= SCHEME_ALPHA;
            foreach(ch; ['+', '-', '.'])
                charType[ch] |= SCHEME_NON_ALPHA;
            foreach(ch; '0'..'9'+1)
                charType[ch] |= SCHEME_NON_ALPHA;
        }

        // Authority set
        with(Rfc3986CharType)
        {
            foreach(ch; ['/', '?', '#'])
                charType[ch] |= AUTHORITY_TERMINAL;
        }

        // Authority user info set
        with(Rfc3986CharType)
        {
            foreach(ch; [':'])
                charType[ch] |= AUTHORITY_USERINFO_ALLOWED;
        }

        // Hex digit set
        with(Rfc3986CharType)
        {
            foreach(ch; '0'..'9'+1)
                charType[ch] |= IS_HEX_DIGIT;
            foreach(ch; 'a'..'f'+1)
                charType[ch] |= IS_HEX_DIGIT;
            foreach(ch; 'A'..'F'+1)
                charType[ch] |= IS_HEX_DIGIT;
        }

        // Path set
        with(Rfc3986CharType)
        {
            foreach(ch; [':', '@'])
                charType[ch] |= PATH_ALLOWED;
            foreach(ch; ['?', '#'])
                charType[ch] |= PATH_TERMINAL;
        }

        // Query set
        with(Rfc3986CharType)
        {
            foreach(ch; ['?', '/'])
                charType[ch] |= QUERY_ALLOWED;
            foreach(ch; ['#'])
                charType[ch] |= QUERY_TERMINAL;
        }

        return charType;
    }();
}

enum UriParseHints
{
    none = 0,

    isAbsolute              = 1 << 0, /// e.g. "scheme://authority/path?query#fragment"
    isNetworkReference      = 1 << 1, /// e.g. "//authority/path?query#fragment"
    isUriSuffix             = 1 << 2, /// e.g. "authority/path?query#fragment"

    authorityHasPort        = 1 << 3, /// e.g. "host:port"
    authorityHasUserInfo    = 1 << 4, /// e.g. "user:info@host"

    authorityHostIsIpv6     = 1 << 5, /// e.g. "[::1]"
    authorityHostIsIpv4     = 1 << 6, /// e.g. "127.0.0.1"
    authorityHostIsDomain   = 1 << 7, /// e.g. "localhost"

    pathIsAbsolute          = 1 << 8,  /// e.g. "/some/path"
    pathIsRootless          = 1 << 9,  /// e.g. "some/path"
    pathIsEmpty             = 1 << 10, /// e.g. ""
    pathHasStartColon       = 1 << 11, /// e.g. "abc:123/abd"

    queryIsEmpty            = 1 << 12, /// e.g. ""

    fragmentIsEmpty         = 1 << 13, /// e.g. ""

    percentEncodedUserInfo  = 1 << 14, /// e.g. "user%40info@host"
    percentEncodedHost      = 1 << 15, /// e.g. "[::1%25%3a%3a1]"
    percentEncodedPath      = 1 << 16, /// e.g. "/some%2fpath"
    percentEncodedQuery     = 1 << 17, /// e.g. "?some%3fquery"
    percentEncodedFragment  = 1 << 18, /// e.g. "#some%23fragment"
}

enum UriError
{
    none,
    schemeIsInvalid,
    authorityRequired,
    authorityUserInfoIsInvalid,
    authorityPortIsInvalid,
    authorityHostIsInvalid,
    pathIsInvalid,
    queryIsInvalid,
    fragmentIsInvalid,
}

enum UriParseRules
{
    /// Strict parsing rules as defined in RFC 3986, may be too strict for common use cases.
    strict = 0,

    /++
     + It is common for applications to accept URIs in the form "abc.com/path" as absolute URIs,
     + this is technically not allowed by RFC 3986 and is referred to as a "URI Suffix".
     +
     + Without this flag, the parser will not detect "abc.com" as the URI authority, but instead
     + will assume that it is a relative path (e.g. the path field would be set to "abc.com/path" instead of just "/path").
     +
     + With this flag, the parser will detect "abc.com" as the URI authority, and the path field will be set to "/path",
     + the additional side effect is that the URI will be marked as absolute (`UriParseHints.isAbsolute`) which may
     + need additional changes to the caller's logic to handle, as it can no longer assume the existance of a scheme
     + for every `UriParseHints.isAbsolute` URI.
     +
     + This detection cannot be done automatically under strict parsing as it introduces ambiguity 
     + within the defined grammar of RFC 3986, and thus must be explicitly enabled by the caller.
     +
     + You can detect whether a URI is a URI suffix by checking for the `UriParseHints.isUriSuffix` flag.
     + ++/
    allowUriSuffix = 1 << 0,
}


/++
 + TODO: This one does not own the data, it is just a view into the data
 + ++/
struct ScopeUri
{
    const(char)[] scheme;
    const(char)[] userInfo;
    const(char)[] host;
    Nullable!IpAddress hostAsIp;
    Nullable!ushort port;
    const(char)[] path;
    const(char)[] query;
    const(char)[] fragment;
}

/**** Higher level Uri parsing functions ****/

Result uriParseNoCopy(
    const(char)[] input,
    out scope ScopeUri uri,
    out scope UriParseHints hints,
    UriParseRules rules = UriParseRules.strict
) @nogc @safe nothrow
in(input.length > 0, "Attempting to parse an empty string seems like incorrect logic")
{
    const(char)[] next;

    auto result = uriParseScheme(input, uri.scheme, next, hints);
    if(result.isError) // Schemaless URIs are allowed. Difficult to determine if it is a schemaless URI or an invalid schema
        next = input;

    result = uriParseAuthority(next, uri.userInfo, uri.host, uri.hostAsIp, uri.port, next, hints, rules);
    if(result.isError)
        return result;

    result = uriParsePath(next, uri.path, next, hints);
    if(result.isError)
        return result;

    if(next.length > 0 && next[0] != '#') // Special case: query is empty but fragment is not
    {
        result = uriParseQuery(next, uri.query, next, hints);
        if(result.isError)
            return result;
    }
    else
        hints |= UriParseHints.queryIsEmpty;

    result = uriParseFragment(next, uri.fragment, next, hints);
    if(result.isError)
        return result;

    return Result.noError;
}

/**** "Low level" Uri parsing functions ****/

Result uriParseScheme(
    const(char)[] chars, 
    out scope const(char)[] scheme,
    out scope const(char)[] next,
    ref scope UriParseHints hints
) @nogc @safe nothrow
in(chars.length > 0, "URI must not be empty")
{
    if(!(g_rfc3986CharType[chars[0]] & Rfc3986CharType.SCHEME_ALPHA))
        return Result.make(UriError.schemeIsInvalid, "First character of a URI scheme must be an alpha character");

    foreach(i, ch; chars)
    {
        if(ch == ':')
        {
            if(i == 0)
                return Result.make(UriError.schemeIsInvalid, "URI scheme must not be empty");

            scheme = chars[0..i];
            next = chars[i + 1..$];
            hints |= UriParseHints.isAbsolute;
            return Result.noError;
        }

        switch(g_rfc3986CharType[ch] & Rfc3986CharType.SCHEME_MASK)
        {
            case Rfc3986CharType.SCHEME_ALPHA:
            case Rfc3986CharType.SCHEME_NON_ALPHA:
                continue;
            default:
                return Result.make(UriError.schemeIsInvalid, "Invalid character in URI scheme");
        }
    }

    return Result.make(UriError.schemeIsInvalid, "Unable to find ':' in URI scheme");
}

Result uriParseAuthority(
    const(char)[] chars, 
    out scope const(char)[] userInfo,
    out scope const(char)[] host,
    out scope Nullable!IpAddress hostAsIp,
    out scope Nullable!ushort port,
    out scope const(char)[] next,
    ref scope UriParseHints hints,
    UriParseRules rules = UriParseRules.strict
) @nogc @safe nothrow
{
    size_t cursor = 2;
    if(chars.length < 2 || chars[0] != '/' || chars[1] != '/')
    {
        if(hints & UriParseHints.isAbsolute)
            return Result.make(UriError.authorityRequired, "URI must have an authority when it is absolute (has a scheme)"); // @suppress(dscanner.style.long_line)
        else if((rules & UriParseRules.allowUriSuffix) && chars.length > 0 && chars[0] != '/')
        {
            hints |= UriParseHints.isUriSuffix;
            cursor = 0; // Since we no longer expect "//"
        }
        else
        {
            next = chars;
            return Result.noError;
        }
    }

    if(!(hints & (UriParseHints.isAbsolute | UriParseHints.isUriSuffix)))
        hints |= UriParseHints.isNetworkReference;

    uriAuthorityLookahead(chars[cursor..$], hints);

    if(hints & UriParseHints.authorityHasUserInfo)
    {
        auto result = uriParseAuthorityUserInfo(chars, cursor, userInfo, hints);
        if(result.isError)
            return result;
    }

    auto result = uriParseAuthorityHost(chars, cursor, host, hostAsIp, hints);
    if(result.isError)
        return result;

    if(hints & UriParseHints.authorityHasPort)
    {
        ushort portTemp;
        result = uriParseAuthorityPort(chars, cursor, portTemp, hints);
        if(result.isError)
            return result;
        port = portTemp;

        if(!hostAsIp.isNull)
            hostAsIp = hostAsIp.get().withPort(portTemp);
    }

    next = chars[cursor..$];
    return Result.noError;
}

void uriAuthorityLookahead(const(char)[] chars, ref scope UriParseHints hints) @safe @nogc nothrow pure // @suppress(dscanner.style.long_line)
{
    bool probablyInIpv6 = false;
    foreach(ch; chars)
    {
        switch(ch)
        {
            case '@':
                hints |= UriParseHints.authorityHasUserInfo;
                hints &= ~(UriParseHints.authorityHasPort); // Reset port flag, as `:` coming before `@` means it is part of the user info
                break;
            case ':':
                if(!probablyInIpv6)
                    hints |= UriParseHints.authorityHasPort;
                break;
            case '[':
                probablyInIpv6 = true;
                break;
            case ']':
                probablyInIpv6 = false;
                break;
            default:
                if(g_rfc3986CharType[ch] & Rfc3986CharType.AUTHORITY_TERMINAL)
                    return;
                break;
        }
    }
}

Result uriParseAuthorityUserInfo(
    const(char)[] chars,
    ref scope size_t cursor,
    out scope const(char)[] userInfo,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    const userInfoStart = cursor;
    for(; cursor < chars.length; cursor++)
    {
        const ch = chars[cursor];
        switch(ch)
        {
            case '@':
                userInfo = chars[userInfoStart..cursor];
                cursor++;
                return Result.noError;

            case '%':
                if(cursor + 2 >= chars.length)
                    return Result.make(UriError.authorityUserInfoIsInvalid, "Expected 2 chars to be available after seeing '%'"); // @suppress(dscanner.style.long_line)
                if(!(g_rfc3986CharType[chars[cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT) || !(g_rfc3986CharType[chars[cursor + 2]] & Rfc3986CharType.IS_HEX_DIGIT)) // @suppress(dscanner.style.long_line)
                    return Result.make(UriError.authorityUserInfoIsInvalid, "Invalid hex digit used for percent encoded character"); // @suppress(dscanner.style.long_line)
                cursor += 2;
                hints |= UriParseHints.percentEncodedUserInfo;
                break;

            default:
                if(!(g_rfc3986CharType[ch] & Rfc3986CharType.AUTHORITY_USERINFO_MASK))
                    return Result.make(UriError.authorityUserInfoIsInvalid, "Invalid character in URI authority user info"); // @suppress(dscanner.style.long_line)
                break;
        }
    }

    return Result.make(UriError.authorityUserInfoIsInvalid, "Unable to find '@' in URI authority user info");
}

Result uriParseAuthorityHost(
    const(char)[] chars,
    ref scope size_t cursor,
    out scope const(char)[] host,
    out scope Nullable!IpAddress hostAsIp,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(cursor == chars.length)
        return Result.make(UriError.authorityHostIsInvalid, "Host section is empty");

    return (chars[cursor] == '[') 
        ? uriParseAuthorityHostAsIpv6(chars, cursor, host, hostAsIp, hints) 
        : uriParseAuthorityHostAsIpv4OrDomain(chars, cursor, host, hostAsIp, hints);
}

Result uriParseAuthorityHostAsIpv6(
    const(char)[] chars,
    ref scope size_t cursor,
    out scope const(char)[] host,
    out scope Nullable!IpAddress hostAsIp,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(cursor == chars.length || chars[cursor] != '[')
        return Result.make(UriError.authorityHostIsInvalid, "Expected '[' to open IPv6 address");

    const start = ++cursor;
    while(cursor < chars.length && chars[cursor] != ']')
        cursor++;
    if(cursor == chars.length)
        return Result.make(UriError.authorityHostIsInvalid, "Expected ']' to close IPv6 address");

    host = chars[start..cursor++]; // Skip ']'
    
    IpAddress ipTemp;
    auto result = IpAddress.parse(ipTemp, host);
    if(result.isError)
        return Result.make(UriError.authorityHostIsInvalid, result.error);
    hostAsIp = ipTemp;

    hints |= UriParseHints.authorityHostIsIpv6;
    return Result.noError;
}

Result uriParseAuthorityHostAsIpv4OrDomain(
    const(char)[] chars,
    ref scope size_t cursor,
    out scope const(char)[] host,
    out scope Nullable!IpAddress hostAsIp,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    const start = cursor;
    For: for(; cursor < chars.length; cursor++)
    {
        const ch = chars[cursor];
        switch(ch)
        {
            case ':':
                break For;
            case '%':
                if(cursor + 2 >= chars.length)
                    return Result.make(UriError.authorityHostIsInvalid, "Expected 2 chars to be available after seeing '%'"); // @suppress(dscanner.style.long_line)
                if(!(g_rfc3986CharType[chars[cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT) || !(g_rfc3986CharType[chars[cursor + 2]] & Rfc3986CharType.IS_HEX_DIGIT)) // @suppress(dscanner.style.long_line)
                    return Result.make(UriError.authorityHostIsInvalid, "Invalid hex digit used for percent encoded character"); // @suppress(dscanner.style.long_line)
                cursor += 2; // Skip % and first digit, the second digit will be skipped by the for loop
                hints |= UriParseHints.percentEncodedHost;
                break;
            default:
                if(g_rfc3986CharType[ch] & Rfc3986CharType.AUTHORITY_TERMINAL)
                    break For;
                if(!(g_rfc3986CharType[ch] & Rfc3986CharType.AUTHORITY_HOST_MASK))
                    return Result.make(UriError.authorityHostIsInvalid, "Invalid character in URI authority host"); // @suppress(dscanner.style.long_line)
                break;
        }
    }

    host = chars[start..cursor];

    IpAddress ipTemp;
    auto result = IpAddress.parse(ipTemp, host);
    if(!result.isError)
    {
        hints |= UriParseHints.authorityHostIsIpv4;
        hostAsIp = ipTemp;
    }
    else
        hints |= UriParseHints.authorityHostIsDomain;

    return Result.noError;
}

Result uriParseAuthorityPort(
    const(char)[] chars,
    ref scope size_t cursor,
    out scope ushort port,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(cursor == chars.length)
        return Result.make(UriError.authorityPortIsInvalid, "Input string is empty");

    if(chars[cursor] != ':')
        return Result.make(UriError.authorityPortIsInvalid, "Expected port number after ':'");
    cursor++;

    const start = cursor;
    while(cursor < chars.length && !(g_rfc3986CharType[chars[cursor]] & Rfc3986CharType.AUTHORITY_TERMINAL))
        cursor++;
    
    import juptune.core.util : to;
    auto result = to!ushort(chars[start..cursor], port);
    if(result.isError)
        return Result.make(UriError.authorityPortIsInvalid, result.error);
    
    return Result.noError;
}

Result uriParsePath(
    const(char)[] chars,
    out scope const(char)[] path,
    out scope const(char)[] next,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(chars.length == 0)
    {
        hints |= UriParseHints.pathIsEmpty;
        next = chars;
        return Result.noError;
    }

    size_t cursor;
    if(chars[0] == '/')
    {
        hints |= UriParseHints.pathIsAbsolute;
        cursor++;
    }
    else
    {
        if(hints & UriParseHints.isAbsolute)
            return Result.make(UriError.pathIsInvalid, "Path must be absolute when URI is absolute");
        hints |= UriParseHints.pathIsRootless;
    }

    const firstSegmentStart = cursor;
    size_t firstSegmentEnd;
    For: for(; cursor < chars.length; cursor++)
    {
        const ch = chars[cursor];
        switch(ch)
        {
            case '/':
                if(cursor == firstSegmentStart && (hints & UriParseHints.pathIsAbsolute))
                    return Result.make(UriError.pathIsInvalid, "Absolute paths cannot start with '//'"); // @suppress(dscanner.style.long_line)
                if(firstSegmentEnd == 0)
                    firstSegmentEnd = cursor;
                break;

            case ':':
                if(firstSegmentEnd == 0 && !(hints & UriParseHints.isAbsolute))
                    return Result.make(UriError.pathIsInvalid, "Relative paths cannot contain ':' in their first segment"); // @suppress(dscanner.style.long_line)
                hints |= UriParseHints.pathHasStartColon;
                break;

            case '%':
                if(cursor + 2 >= chars.length)
                    return Result.make(UriError.pathIsInvalid, "Expected 2 chars to be available after seeing '%'"); // @suppress(dscanner.style.long_line)
                if(!(g_rfc3986CharType[chars[cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT) || !(g_rfc3986CharType[chars[cursor + 2]] & Rfc3986CharType.IS_HEX_DIGIT)) // @suppress(dscanner.style.long_line)
                    return Result.make(UriError.pathIsInvalid, "Invalid hex digit used for percent encoded character"); // @suppress(dscanner.style.long_line)
                cursor += 2; // Skip % and first digit, the second digit will be skipped by the for loop
                hints |= UriParseHints.percentEncodedPath;
                break;

            default:
                if(g_rfc3986CharType[ch] & Rfc3986CharType.PATH_TERMINAL)
                    break For;
                if(!(g_rfc3986CharType[ch] & Rfc3986CharType.PATH_MASK))
                    return Result.make(UriError.pathIsInvalid, "Invalid character in URI path");
                break;
        }
    }

    path = chars[0..cursor];
    next = chars[cursor..$];
    return Result.noError;
}

Result uriParseQuery(
    const(char)[] chars,
    out scope const(char)[] query,
    out scope const(char)[] next,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(chars.length == 0)
    {
        hints |= UriParseHints.queryIsEmpty;
        next = chars;
        return Result.noError;
    }

    if(chars[0] != '?')
        return Result.make(UriError.queryIsInvalid, "Expected '?' to start query");

    size_t cursor = 1;
    const start = cursor;
    For: for(; cursor < chars.length; cursor++)
    {
        const ch = chars[cursor];
        switch(ch)
        {
            case '%':
                if(cursor + 2 >= chars.length)
                    return Result.make(UriError.queryIsInvalid, "Expected 2 chars to be available after seeing '%'"); // @suppress(dscanner.style.long_line)
                if(!(g_rfc3986CharType[chars[cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT) || !(g_rfc3986CharType[chars[cursor + 2]] & Rfc3986CharType.IS_HEX_DIGIT)) // @suppress(dscanner.style.long_line)
                    return Result.make(UriError.queryIsInvalid, "Invalid hex digit used for percent encoded character"); // @suppress(dscanner.style.long_line)
                cursor += 2; // Skip % and first digit, the second digit will be skipped by the for loop
                hints |= UriParseHints.percentEncodedQuery;
                break;

            default:
                if(g_rfc3986CharType[ch] & Rfc3986CharType.QUERY_TERMINAL)
                    break For;
                if(!(g_rfc3986CharType[ch] & Rfc3986CharType.QUERY_MASK))
                    return Result.make(UriError.queryIsInvalid, "Invalid character in URI query");
                break;
        }
    }

    query = chars[start..cursor];
    next = chars[cursor..$];
    return Result.noError;
}

Result uriParseFragment(
    const(char)[] chars,
    out scope const(char)[] fragment,
    out scope const(char)[] next,
    ref scope UriParseHints hints,
) @nogc @safe nothrow
{
    if(chars.length == 0)
    {
        hints |= UriParseHints.fragmentIsEmpty;
        next = chars;
        return Result.noError;
    }

    if(chars[0] != '#')
        return Result.make(UriError.fragmentIsInvalid, "Expected '#' to start fragment");

    size_t cursor = 1;
    const start = cursor;
    for(; cursor < chars.length; cursor++)
    {
        const ch = chars[cursor];
        switch(ch)
        {
            case '%':
                if(cursor + 2 >= chars.length)
                    return Result.make(UriError.fragmentIsInvalid, "Expected 2 chars to be available after seeing '%'"); // @suppress(dscanner.style.long_line)
                if(!(g_rfc3986CharType[chars[cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT) || !(g_rfc3986CharType[chars[cursor + 2]] & Rfc3986CharType.IS_HEX_DIGIT)) // @suppress(dscanner.style.long_line)
                    return Result.make(UriError.fragmentIsInvalid, "Invalid hex digit used for percent encoded character"); // @suppress(dscanner.style.long_line)
                cursor += 2; // Skip % and first digit, the second digit will be skipped by the for loop
                hints |= UriParseHints.percentEncodedFragment;
                break;

            default:
                if(!(g_rfc3986CharType[ch] & Rfc3986CharType.FRAGMENT_MASK))
                    return Result.make(UriError.fragmentIsInvalid, "Invalid character in URI fragment");
                break;
        }
    }

    fragment = chars[start..cursor];
    next = chars[cursor..$];
    return Result.noError;
}

/**** Helpers ****/

struct UriDecoder
{
    private
    {
        const(char)[] _input;
        char _front;
        size_t _cursor;
        bool _empty;
    }

    @safe @nogc nothrow:

    this(const(char)[] input)
    {
        this._input = input;
        this.popFront();
    }

    bool empty() const
    {
        return this._empty;
    }

    char front() const
    {
        return this._front;
    }

    void popFront()
    {
        if(this._cursor >= this._input.length)
        {
            this._empty = true;
            return;
        }

        const ch = this._input[this._cursor++];
        if(ch == '%')
        {
            if(this._cursor + 2 > this._input.length
            || !(g_rfc3986CharType[this._input[this._cursor]] & Rfc3986CharType.IS_HEX_DIGIT)
            || !(g_rfc3986CharType[this._input[this._cursor + 1]] & Rfc3986CharType.IS_HEX_DIGIT))
                assert(false, "Invalid percent encoded character when decoding URI - not enough chars - this should've been detected at an earlier stage"); // @suppress(dscanner.style.long_line)

            const hex = this._input[this._cursor..this._cursor + 2];
            this._cursor += 2;

            import juptune.core.util.conv : to;
            Result result = Result.noError;
            this._front = cast(char)to!ubyte(hex, result, 16);

            if(result.isError)
                assert(false, "Invalid percent encoded character when decoding URI - invalid hex - this should've been detected at an earlier stage"); // @suppress(dscanner.style.long_line)
        }
        else
            this._front = ch;
    }
}

UriDecoder uriDecoder(const(char)[] input) @safe @nogc nothrow
{
    return UriDecoder(input);
}

/**** Unittests ****/

@("uriParseScheme - error - first character is not alpha")
unittest
{
    const(char)[] _, __;
    UriParseHints ___;
    assert(uriParseScheme("1", _, __, ___).isError(UriError.schemeIsInvalid));
}

@("uriParseScheme - error - invalid character")
unittest
{
    const(char)[] _, __;
    UriParseHints ___;
    assert(uriParseScheme("a!", _, __, ___).isError(UriError.schemeIsInvalid));
}

@("uriParseScheme - error - no ':'")
unittest
{
    const(char)[] _, __;
    UriParseHints ___;
    assert(uriParseScheme("a", _, __, ___).isError(UriError.schemeIsInvalid));
}

@("uriParseScheme - error - empty scheme")
unittest
{
    const(char)[] _, __;
    UriParseHints ___;
    assert(uriParseScheme(":", _, __, ___).isError(UriError.schemeIsInvalid));
}

@("uriParseScheme - success")
unittest
{
    const(char)[] scheme, next;
    UriParseHints hints;
    uriParseScheme("a://", scheme, next, hints).resultAssert;

    assert(scheme == "a");
    assert(next == "//");
    assert(hints & UriParseHints.isAbsolute);
}

@("uriParseAuthorityPort - error - no port")
unittest
{
    size_t cursor;
    ushort __;
    UriParseHints ___;
    assert(uriParseAuthorityPort("", cursor, __, ___).isError(UriError.authorityPortIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityPort(":", cursor, __, ___).isError(UriError.authorityPortIsInvalid));
}

@("uriParseAuthorityPort - error - invalid port")
unittest
{
    size_t cursor;
    ushort __;
    UriParseHints ___;
    assert(uriParseAuthorityPort(":a", cursor, __, ___).isError(UriError.authorityPortIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityPort(":1a", cursor, __, ___).isError(UriError.authorityPortIsInvalid));
}

@("uriParseAuthorityPort - error - port too large")
unittest
{
    size_t cursor;
    ushort __;
    UriParseHints ___;
    uriParseAuthorityPort(":65535", cursor, __, ___).resultAssert;
    cursor = 0;
    assert(uriParseAuthorityPort(":65536", cursor, __, ___).isError(UriError.authorityPortIsInvalid));
}

@("uriParseAuthorityPort - success")
unittest
{
    size_t cursor;
    ushort port;
    UriParseHints hints;

    uriParseAuthorityPort(":1", cursor, port, hints).resultAssert;
    assert(cursor == 2);
    assert(port == 1);

    cursor = 0;
    uriParseAuthorityPort(":123/", cursor, port, hints).resultAssert;
    assert(cursor == 4);
    assert(port == 123);
}

@("uriAuthorityLookahead")
unittest
{
    static struct T
    {
        const(char)[] input;
        UriParseHints containsHints;
    }

    const tests = 
    [
        T("", UriParseHints.none),
        T("/:@", UriParseHints.none),
        T("[::1]", UriParseHints.none),
        T(":", UriParseHints.authorityHasPort),
        T("@", UriParseHints.authorityHasUserInfo),
        T("@:", UriParseHints.authorityHasUserInfo | UriParseHints.authorityHasPort),
        T(":@", UriParseHints.authorityHasUserInfo),
    ];

    foreach(test; tests)
    {
        UriParseHints hints;
        uriAuthorityLookahead(test.input, hints);
        assert(hints == test.containsHints, "Failed for input: " ~ test.input);
    }
}

@("uriParseAuthorityUserInfo - error - no '@'")
unittest
{
    size_t cursor;
    const(char)[] __;
    UriParseHints ___;
    assert(uriParseAuthorityUserInfo("", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityUserInfo("a", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityUserInfo("a:", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
}

@("uriParseAuthorityUserInfo - error - invalid character")
unittest
{
    size_t _;
    const(char)[] __;
    UriParseHints ___;
    assert(uriParseAuthorityUserInfo("!", _, __, ___).isError(UriError.authorityUserInfoIsInvalid));
}

@("uriParseAuthorityUserInfo - error - invalid percent encoded character")
unittest
{
    size_t cursor;
    const(char)[] __;
    UriParseHints ___;
    assert(uriParseAuthorityUserInfo("%", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityUserInfo("%1", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityUserInfo("%1_", cursor, __, ___).isError(UriError.authorityUserInfoIsInvalid));
}

@("uriParseAuthorityUserInfo - success")
unittest
{
    size_t cursor;
    const(char)[] userInfo;
    UriParseHints hints;

    uriParseAuthorityUserInfo("@", cursor, userInfo, hints).resultAssert;
    assert(cursor == 1);
    assert(userInfo == "");

    cursor = 0;
    uriParseAuthorityUserInfo("a@", cursor, userInfo, hints).resultAssert;
    assert(cursor == 2);
    assert(userInfo == "a");

    hints = UriParseHints.none;
    cursor = 0;
    uriParseAuthorityUserInfo("a%20@", cursor, userInfo, hints).resultAssert;
    assert(cursor == 5);
    assert(userInfo == "a%20");
    assert(hints & UriParseHints.percentEncodedUserInfo);
}

@("uriParseAuthorityHostAsIpv6 - error - no '['")
unittest
{
    size_t cursor;
    const(char)[] __;
    Nullable!IpAddress ___;
    UriParseHints ____;
    assert(uriParseAuthorityHostAsIpv6("", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityHostAsIpv6("a", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthorityHostAsIpv6 - error - no ']'")
unittest
{
    size_t cursor;
    const(char)[] __;
    Nullable!IpAddress ___;
    UriParseHints ____;
    assert(uriParseAuthorityHostAsIpv6("[", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityHostAsIpv6("[a", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthorityHostAsIpv6 - error - invalid address")
unittest
{
    size_t cursor;
    const(char)[] __;
    Nullable!IpAddress ___;
    UriParseHints ____;
    assert(uriParseAuthorityHostAsIpv6("[]", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityHostAsIpv6("[::1", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthorityHostAsIpv6 - success")
unittest
{
    size_t cursor;
    const(char)[] host;
    Nullable!IpAddress hostAsIp;
    UriParseHints hints;

    uriParseAuthorityHostAsIpv6("[::1]", cursor, host, hostAsIp, hints).resultAssert;
    assert(cursor == 5);
    assert(host == "::1");
    assert(hostAsIp.get() == IpAddress.mustParse("::1"));
    assert(hints & UriParseHints.authorityHostIsIpv6);
}

@("uriParseAuthorityHostAsIpv4OrDomain - error - invalid character")
unittest
{
    size_t cursor;
    const(char)[] __;
    Nullable!IpAddress ___;
    UriParseHints ____;
    assert(uriParseAuthorityHostAsIpv4OrDomain("^", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthorityHostAsIpv4OrDomain - error - invalid percent encoded character")
unittest
{
    size_t cursor;
    const(char)[] __;
    Nullable!IpAddress ___;
    UriParseHints ____;
    assert(uriParseAuthorityHostAsIpv4OrDomain("%", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityHostAsIpv4OrDomain("%1", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
    cursor = 0;
    assert(uriParseAuthorityHostAsIpv4OrDomain("%1_", cursor, __, ___, ____).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthorityHostAsIpv4OrDomain - success - ipv4")
unittest
{
    size_t cursor;
    const(char)[] host;
    Nullable!IpAddress hostAsIp;
    UriParseHints hints;

    uriParseAuthorityHostAsIpv4OrDomain("127.0.0.1", cursor, host, hostAsIp, hints).resultAssert;
    assert(cursor == 9);
    assert(host == "127.0.0.1");
    assert(hostAsIp.get() == IpAddress.mustParse("127.0.0.1"));
    assert(hints & UriParseHints.authorityHostIsIpv4);
}

@("uriParseAuthorityHostAsIpv4OrDomain - success - domain")
unittest
{
    size_t cursor;
    const(char)[] host;
    Nullable!IpAddress hostAsIp;
    UriParseHints hints;

    uriParseAuthorityHostAsIpv4OrDomain("localhost", cursor, host, hostAsIp, hints).resultAssert;
    assert(cursor == 9);
    assert(host == "localhost");
    assert(hostAsIp.isNull);
    assert(hints & UriParseHints.authorityHostIsDomain);
}

@("uriParseAuthority - error - no authority") // Jackie Weaver, none at all!
unittest
{
    const(char)[] _, __, _____;
    Nullable!IpAddress ___;
    Nullable!ushort ____;
    UriParseHints hints = UriParseHints.isAbsolute;
    assert(uriParseAuthority("", _, __, ___, ____, _____, hints).isError(UriError.authorityRequired));
}

@("uriParseAuthority - error - invalid user info")
unittest
{
    const(char)[] _, __, _____;
    Nullable!IpAddress ___;
    Nullable!ushort ____;
    UriParseHints hints = UriParseHints.isAbsolute;
    assert(uriParseAuthority("//^@", _, __, ___, ____, _____, hints).isError(UriError.authorityUserInfoIsInvalid));
}

@("uriParseAuthority - error - invalid port")
unittest
{
    const(char)[] _, __, _____;
    Nullable!IpAddress ___;
    Nullable!ushort ____;
    UriParseHints hints = UriParseHints.isAbsolute;
    assert(uriParseAuthority("//abc:", _, __, ___, ____, _____, hints).isError(UriError.authorityPortIsInvalid));
}

@("uriParseAuthority - error - invalid host")
unittest
{
    const(char)[] _, __, _____;
    Nullable!IpAddress ___;
    Nullable!ushort ____;
    UriParseHints hints = UriParseHints.isAbsolute;
    assert(uriParseAuthority("//^", _, __, ___, ____, _____, hints).isError(UriError.authorityHostIsInvalid));
}

@("uriParseAuthority - success")
unittest
{
    static struct T
    {
        const(char)[] input;
        const(char)[] expectedUserInfo;
        const(char)[] expectedHost;
        const(char)[] expectedNext;
        Nullable!IpAddress expectedHostAsIp;
        Nullable!ushort expectedPort;
        UriParseHints containsHints;
        UriParseRules rules;
    }

    const tests = [
        "domain alone": T(
            "//chatha.dev",
            "",
            "chatha.dev",
            "",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.authorityHostIsDomain
        ),
        "domain with port": T(
            "//chatha.dev:8080",
            "",
            "chatha.dev",
            "",
            Nullable!IpAddress.init,
            Nullable!ushort(8080),
            UriParseHints.authorityHostIsDomain | UriParseHints.authorityHasPort
        ),
        "domain with userinfo": T(
            "//abc:123@chatha.dev",
            "abc:123",
            "chatha.dev",
            "",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.authorityHostIsDomain | UriParseHints.authorityHasUserInfo
        ),
        "domain with userinfo and port": T(
            "//abc:123@chatha.dev:8080",
            "abc:123",
            "chatha.dev",
            "",
            Nullable!IpAddress.init,
            Nullable!ushort(8080),
            UriParseHints.authorityHostIsDomain | UriParseHints.authorityHasUserInfo | UriParseHints.authorityHasPort
        ),
        
        "ipv4 alone": T(
            "//127.0.0.1",
            "",
            "127.0.0.1",
            "",
            Nullable!IpAddress(IpAddress.mustParse("127.0.0.1")),
            Nullable!ushort.init,
            UriParseHints.authorityHostIsIpv4
        ),
        "ipv4 with port": T(
            "//127.0.0.1:8080",
            "",
            "127.0.0.1",
            "",
            Nullable!IpAddress(IpAddress.mustParse("127.0.0.1:8080")),
            Nullable!ushort(8080),
            UriParseHints.authorityHostIsIpv4 | UriParseHints.authorityHasPort
        ),
        
        "ipv6 alone": T(
            "//[::1]",
            "",
            "::1",
            "",
            Nullable!IpAddress(IpAddress.mustParse("::1")),
            Nullable!ushort.init,
            UriParseHints.authorityHostIsIpv6
        ),
        "ipv6 with port": T(
            "//[::1]:8080",
            "",
            "::1",
            "",
            Nullable!IpAddress(IpAddress.mustParse("[::1]:8080")),
            Nullable!ushort(8080),
            UriParseHints.authorityHostIsIpv6 | UriParseHints.authorityHasPort
        ),

        "domain with leftover": T(
            "//chatha.dev/abc",
            "",
            "chatha.dev",
            "/abc",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.authorityHostIsDomain
        ),
        "ipv4 with leftover": T(
            "//127.0.0.1/abc",
            "",
            "127.0.0.1",
            "/abc",
            Nullable!IpAddress(IpAddress.mustParse("127.0.0.1")),
            Nullable!ushort.init,
            UriParseHints.authorityHostIsIpv4
        ),
        "ipv6 with leftover": T(
            "//[::1]/abc",
            "",
            "::1",
            "/abc",
            Nullable!IpAddress(IpAddress.mustParse("::1")),
            Nullable!ushort.init,
            UriParseHints.authorityHostIsIpv6
        ),
        "port with leftover": T(
            "//localhost:8080/abc",
            "",
            "localhost",
            "/abc",
            Nullable!IpAddress.init,
            Nullable!ushort(8080),
            UriParseHints.authorityHostIsDomain | UriParseHints.authorityHasPort
        ),
        "URI suffix without flag": T(
            "chatha.dev/path",
            "",
            "",
            "chatha.dev/path",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.none,
        ),
        "URI suffix with flag": T(
            "chatha.dev/path",
            "",
            "chatha.dev",
            "/path",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.isUriSuffix,
            UriParseRules.allowUriSuffix,
        ),
        "absolute relative reference with URI suffix flag": T(
            "/chatha.dev/path",
            "",
            "",
            "/chatha.dev/path",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.none,
            UriParseRules.allowUriSuffix,
        ),
        "network reference with URI suffix flag": T(
            "//chatha.dev/path",
            "",
            "chatha.dev",
            "/path",
            Nullable!IpAddress.init,
            Nullable!ushort.init,
            UriParseHints.isNetworkReference,
            UriParseRules.allowUriSuffix,
        ),
    ];

    foreach(name, test; tests)
    {
        const(char)[] userInfo, host, next;
        Nullable!IpAddress hostAsIp;
        Nullable!ushort port;
        UriParseHints hints;

        auto result = uriParseAuthority(test.input, userInfo, host, hostAsIp, port, next, hints, test.rules);
        assert(!result.isError, "[" ~ name ~ "]: " ~ result.error);
        assert(userInfo == test.expectedUserInfo, "Failed for test: " ~ name);
        assert(host == test.expectedHost, "Failed for test: " ~ name);
        assert(next == test.expectedNext, "Failed for test: " ~ name);
        assert(hostAsIp == test.expectedHostAsIp, "Failed for test: " ~ name);
        assert(port == test.expectedPort, "Failed for test: " ~ name);
        assert((hints & test.containsHints) == test.containsHints, "Failed for test: " ~ name);
    }
}

@("uriParsePath - error - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        UriError expectedError;
        UriParseHints inputHints;
    }

    const tests = 
    [
        "Non-absolute path in absolute URI": T("a", UriError.pathIsInvalid, UriParseHints.isAbsolute),
        "Absolute path cannot start with //": T("//", UriError.pathIsInvalid, UriParseHints.isAbsolute),
        "Relative path cannot contain : in first segment": T("a:", UriError.pathIsInvalid),
        "Incorrect percent encoding 1": T("%", UriError.pathIsInvalid),
        "Incorrect percent encoding 2": T("%1", UriError.pathIsInvalid),
        "Incorrect percent encoding 3": T("%1_", UriError.pathIsInvalid),
        "Invalid character": T("^", UriError.pathIsInvalid),
    ];

    foreach(name, test; tests)
    {
        const(char)[] path, next;
        UriParseHints hints = test.inputHints;
        auto result = uriParsePath(test.input, path, next, hints);
        assert(result.isError(test.expectedError), "[" ~ name ~ "]: " ~ result.error);
    }
}

@("uriParsePath - success - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        const(char)[] expectedPath;
        const(char)[] expectedNext;
        UriParseHints expectedHints;
        UriParseHints inputHints;
    }

    const tests = 
    [
        "Empty path": T("", "", "", UriParseHints.pathIsEmpty),
        "Rootless path": T("a", "a", "", UriParseHints.pathIsRootless),
        "Absolute path": T("/a", "/a", "", UriParseHints.pathIsAbsolute),
        "Absolute path with start colon": T("/:a", "/:a", "", UriParseHints.pathHasStartColon, UriParseHints.isAbsolute), // @suppress(dscanner.style.long_line)
        "Valid Percent encoding": T("%20", "%20", ""),
        "Terminal character 1": T("a#abc", "a", "#abc"),
        "Terminal character 2": T("/a/b/c?abc", "/a/b/c", "?abc"),
    ];

    foreach(name, test; tests)
    {
        const(char)[] path, next;
        UriParseHints hints = test.inputHints;
        auto result = uriParsePath(test.input, path, next, hints);
        assert(!result.isError, "[" ~ name ~ "]: " ~ result.error);
        assert(path == test.expectedPath, "Failed for test: " ~ name);
        assert(next == test.expectedNext, "Failed for test: " ~ name);
        assert((hints & test.expectedHints) == test.expectedHints, "Failed for test: " ~ name);
    }
}

@("uriParseQuery - error - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        UriError expectedError;
    }

    const tests = 
    [
        "Incorrect percent encoding 1": T("?%", UriError.queryIsInvalid),
        "Incorrect percent encoding 2": T("?%1", UriError.queryIsInvalid),
        "Incorrect percent encoding 3": T("?%1_", UriError.queryIsInvalid),
        "Invalid character": T("?^", UriError.queryIsInvalid),
    ];

    foreach(name, test; tests)
    {
        const(char)[] query, next;
        UriParseHints hints;
        auto result = uriParseQuery(test.input, query, next, hints);
        assert(result.isError(test.expectedError), "[" ~ name ~ "]: " ~ result.error);
    }
}

@("uriParseQuery - success - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        const(char)[] expectedQuery;
        const(char)[] expectedNext;
        UriParseHints expectedHints;
    }

    const tests = 
    [
        "Empty query": T("", "", "", UriParseHints.queryIsEmpty),
        "Valid Percent encoding": T("?%20", "%20", ""),
        "Terminal character": T("?a#abc", "a", "#abc"),
    ];

    foreach(name, test; tests)
    {
        const(char)[] query, next;
        UriParseHints hints;
        auto result = uriParseQuery(test.input, query, next, hints);
        assert(!result.isError, "[" ~ name ~ "]: " ~ result.error);
        assert(query == test.expectedQuery, "Failed for test: " ~ name);
        assert(next == test.expectedNext, "Failed for test: " ~ name);
        assert((hints & test.expectedHints) == test.expectedHints, "Failed for test: " ~ name);
    }
}

@("uriParseFragment - error - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        UriError expectedError;
    }

    const tests = 
    [
        "Incorrect percent encoding 1": T("#%", UriError.fragmentIsInvalid),
        "Incorrect percent encoding 2": T("#%1", UriError.fragmentIsInvalid),
        "Incorrect percent encoding 3": T("#%1_", UriError.fragmentIsInvalid),
        "Invalid character": T("#^", UriError.fragmentIsInvalid),
    ];

    foreach(name, test; tests)
    {
        const(char)[] fragment, next;
        UriParseHints hints;
        auto result = uriParseFragment(test.input, fragment, next, hints);
        assert(result.isError(test.expectedError), "[" ~ name ~ "]: " ~ result.error);
    }
}

@("uriParseFragment - success - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        const(char)[] expectedFragment;
        const(char)[] expectedNext;
        UriParseHints expectedHints;
    }

    const tests = 
    [
        "Empty fragment": T("", "", "", UriParseHints.fragmentIsEmpty),
        "Valid Percent encoding": T("#%20", "%20", ""),
        "Terminal character": T("#a", "a", ""),
    ];

    foreach(name, test; tests)
    {
        const(char)[] fragment, next;
        UriParseHints hints;
        auto result = uriParseFragment(test.input, fragment, next, hints);
        assert(!result.isError, "[" ~ name ~ "]: " ~ result.error);
        assert(fragment == test.expectedFragment, "Failed for test: " ~ name);
        assert(next == test.expectedNext, "Failed for test: " ~ name);
        assert((hints & test.expectedHints) == test.expectedHints, "Failed for test: " ~ name);
    }
}

@("uriParseNoCopy - success - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        ScopeUri expectedUri;
        UriParseHints expectedHints;
        UriParseRules rules;
    }

    const tests = [
        "scheme & host": T(
            "https://chatha.dev",
            ScopeUri("https", null, "chatha.dev"),
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain | UriParseHints.pathIsEmpty | UriParseHints.queryIsEmpty | UriParseHints.fragmentIsEmpty // @suppress(dscanner.style.long_line)
        ),
        "scheme & host & root path": T(
            "https://chatha.dev/",
            ScopeUri("https", null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/"),
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain | UriParseHints.pathIsAbsolute | UriParseHints.queryIsEmpty | UriParseHints.fragmentIsEmpty // @suppress(dscanner.style.long_line)
        ),
        "scheme & host & path & query": T(
            "https://chatha.dev/blog?post=1&sort=time",
            ScopeUri("https", null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/blog", "post=1&sort=time"), // @suppress(dscanner.style.long_line)
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain | UriParseHints.pathIsAbsolute | UriParseHints.fragmentIsEmpty // @suppress(dscanner.style.long_line)
        ),
        "scheme & host & path & fragment": T(
            "https://chatha.dev/blog#post-1",
            ScopeUri("https", null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/blog", "", "post-1"), // @suppress(dscanner.style.long_line)
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain | UriParseHints.pathIsAbsolute | UriParseHints.queryIsEmpty // @suppress(dscanner.style.long_line)
        ),
        "scheme & host & path & query & fragment": T(
            "https://chatha.dev/bl%20og?post=1&sort=%20time#post%201",
            ScopeUri("https", null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/bl%20og", "post=1&sort=%20time", "post%201"), // @suppress(dscanner.style.long_line)
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain | UriParseHints.pathIsAbsolute // @suppress(dscanner.style.long_line)
        ),
        "network reference": T(
            "//chatha.dev",
            ScopeUri(null, null, "chatha.dev"),
            UriParseHints.isNetworkReference | UriParseHints.authorityHostIsDomain
        ),
        "URI suffix without flag": T(
            "chatha.dev/path",
            ScopeUri(null, null, "", Nullable!IpAddress.init, Nullable!ushort.init, "chatha.dev/path"),
            UriParseHints.pathIsRootless
        ),
        "URI suffix with flag": T(
            "chatha.dev/path",
            ScopeUri(null, null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/path"),
            UriParseHints.isUriSuffix | UriParseHints.pathIsAbsolute,
            UriParseRules.allowUriSuffix
        ),
        "absolute relative reference with URI suffix flag": T(
            "/chatha.dev/path",
            ScopeUri(null, null, "", Nullable!IpAddress.init, Nullable!ushort.init, "/chatha.dev/path"),
            UriParseHints.pathIsAbsolute,
            UriParseRules.allowUriSuffix
        ),
        "network reference with URI suffix flag": T(
            "//chatha.dev/path",
            ScopeUri(null, null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort.init, "/path"),
            UriParseHints.isNetworkReference | UriParseHints.pathIsAbsolute,
            UriParseRules.allowUriSuffix
        ),
        "absolute relative reference": T(
            "/chatha.dev/path",
            ScopeUri(null, null, "", Nullable!IpAddress.init, Nullable!ushort.init, "/chatha.dev/path"),
            UriParseHints.pathIsAbsolute
        ),
        "ip host": T(
            "https://127.0.0.1",
            ScopeUri("https", null, "127.0.0.1", Nullable!IpAddress(IpAddress.mustParse("127.0.0.1"))),
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsIpv4
        ),
        "ip host with port": T(
            "https://127.0.0.1:8080",
            ScopeUri("https", null, "127.0.0.1", Nullable!IpAddress(IpAddress.mustParse("127.0.0.1:8080")), Nullable!ushort(8080)), // @suppress(dscanner.style.long_line)
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsIpv4
        ),
        "domain host with port": T(
            "https://chatha.dev:8080",
            ScopeUri("https", null, "chatha.dev", Nullable!IpAddress.init, Nullable!ushort(8080)),
            UriParseHints.isAbsolute | UriParseHints.authorityHostIsDomain
        ),
    ];

    foreach(name, test; tests)
    {
        import std.format : format;

        ScopeUri uri;
        UriParseHints hints;
        auto result = uriParseNoCopy(test.input, uri, hints, test.rules);
        assert(!result.isError, "[" ~ name ~ "]: " ~ result.error);
        assert(
            uri == test.expectedUri, 
            format(
                "Failed for test: %s\nExpected: %s\nActual: %s",
                name,
                test.expectedUri,
                uri
            )
        );
        assert((hints & test.expectedHints) == test.expectedHints, "Failed for test: " ~ name);
    }
}

@("uriDecoder - success - general cases")
unittest
{
    static struct T
    {
        const(char)[] input;
        const(char)[] expectedOutput;
    }

    const tests = 
    [
        "Empty": T("", ""),
        "No percent encoding": T("abc", "abc"),
        "Percent encoding": T("%20", " "),
        "Percent encoding with non-ascii": T("%C3%A9", "é"),
        "Percent encoding with non-ascii and non-utf8": T("%C3%A9%80", "é\x80"),
        "Percent encoding with non-encoded non-ascii": T("a%20b%20c", "a b c"),
    ];

    foreach(name, test; tests)
    {
        import std.algorithm : equal;
        import std.format    : format;
        auto range = test.input.uriDecoder;
        assert(range.equal(test.expectedOutput), format("Failed for test: %s\nGot: %s\nWanted: %s", name, range, test.expectedOutput)); // @suppress(dscanner.style.long_line)
    }
}