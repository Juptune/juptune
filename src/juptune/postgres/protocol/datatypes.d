/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.protocol.datatypes;

import core.time : Duration;

import juptune.core.ds : String;
import juptune.core.util : Result;
import juptune.data.buffer : MemoryReader;

import juptune.postgres.protocol.connection : PostgresParameters;

enum PostgresDataTypeOid
{
    FAILSAFE = -1,

    boolean = 16,       // BOOLEAN
    int2 = 21,          // SMALLINT
    int4 = 23,          // INTEGER, SERIAL, etc.
    text = 25,          // TEXT
    float4 = 700,       // REAL
    float8 = 701,       // DOUBLE PRECISION
    bpchar = 1042,      // CHARACTER (10)
    varchar = 1043,     // CHARACTER VARYING (10)
    date = 1082,        // DATE
    time = 1083,        // TIME
    timestamp = 1114,   // TIMESTAMP
    timestamptz = 1184, // TIMESTAMP WITH TIME ZONE
    timetz = 1266,      // TIME WITH TIME ZONE
    uuid = 2950,        // UUID
}

enum PostgresDataTypeError
{
    none,
    invalidEncoding,
    limitation,
}

/++ BOOLEAN ++/

Result decodeBooleanText(scope ref MemoryReader reader, scope out bool value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // "t" for true, "f" for false

    if(reader.bytesLeft != 1)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding BOOLEAN text format, expected only 1 byte of data"); // @suppress(dscanner.style.long_line)

    ubyte ch;
    auto success = reader.readU8(ch);
    assert(success, "bug: success can't be false here?");

    value = (ch == 't');
    return Result.noError;
}

Result decodeBooleanBinary(scope ref MemoryReader reader, scope out bool value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // 0 for false, anything else for true

    if(reader.bytesLeft != 1)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding BOOLEAN binary format, expected only 1 byte of data"); // @suppress(dscanner.style.long_line)

    ubyte b;
    auto success = reader.readU8(b);
    assert(success, "bug: success can't be false here?");

    value = (b != 0);
    return Result.noError;
}

/++ SMALLINT ++/

Result decodeInt2Text(scope ref MemoryReader reader, scope out short value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // Normal numeric string
    import juptune.core.util : fromBase10;

    if(reader.bytesLeft == 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding SMALLINT text format, expected at least 1 byte of data"); // @suppress(dscanner.style.long_line)

    string error;
    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];
    value = fromBase10!short(slice, error);

    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding SMALLINT text format, fromBase10 failed", String(error)); // @suppress(dscanner.style.long_line)

    return Result.noError;
}

Result decodeInt2Binary(scope ref MemoryReader reader, scope out short value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // Standard big-endian int

    if(reader.bytesLeft == 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding SMALLINT binary format, expected only 1 byte of data"); // @suppress(dscanner.style.long_line)

    auto success = reader.readI16BE(value);
    assert(success, "bug: success can't be false here?");
    return Result.noError;
}

/++ INTEGER ++/

Result decodeInt4Text(scope ref MemoryReader reader, scope out int value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // Normal numeric string
    import juptune.core.util : fromBase10;

    if(reader.bytesLeft == 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding INTEGER text format, expected at least 1 byte of data"); // @suppress(dscanner.style.long_line)

    string error;
    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];
    value = fromBase10!int(slice, error);

    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding INTEGER text format, fromBase10 failed", String(error)); // @suppress(dscanner.style.long_line)

    return Result.noError;
}

Result decodeInt4Binary(scope ref MemoryReader reader, scope out int value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // Standard big-endian int

    if(reader.bytesLeft == 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding INTEGER binary format, expected only 1 byte of data"); // @suppress(dscanner.style.long_line)

    auto success = reader.readI32BE(value);
    assert(success, "bug: success can't be false here?");
    return Result.noError;
}

/++ TEXT & CHARACTER & CHARACTER VARYING ++/

Result decodeTextText(scope ref MemoryReader reader, scope out const(char)[] value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // Normal zero terminated string
    if(reader.bytesLeft == 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TEXT text format, expected at least 1 byte of data"); // @suppress(dscanner.style.long_line)

    value = cast(const(char)[])reader.buffer[reader.cursor..$];
    return Result.noError;
}

Result decodeTextBinary(scope ref MemoryReader reader, scope out const(char)[] value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // I think it's just a 4-byte length prefix then the string data, I need to look over it in Wireshark properly
    assert(false, "TODO: Not implemented");
}

/++ DATE (TODO: A proper ISO-compliant parser for date & time) ++/

// Phobos' std.datetime.Date can throw in its ctor lol.
struct PostgresDate
{
    uint year;
    uint month;
    uint day;
}

Result decodeDateText(scope ref MemoryReader reader, scope out PostgresDate value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : fromBase10;

    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];

    if(slice.length < 8)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding DATE text format, expected at least 8 bytes of data"); // @suppress(dscanner.style.long_line)

    const probablyIsoYMD = (slice[4] == '-');
    if(!probablyIsoYMD)
        return Result.make(PostgresDataTypeError.limitation, "TODO: use params to figure out format");

    if(slice.length != 10)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding DATE text format, expected exactly 10 bytes of data for ISO YMD style"); // @suppress(dscanner.style.long_line)

    const year = slice[0..4];
    const month = slice[5..7];
    const day = slice[8..9];

    string error;
    value.year = fromBase10!uint(year, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding DATE text format, failed to convert year to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.month = fromBase10!uint(month, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding DATE text format, failed to convert month to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.day = fromBase10!uint(day, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding DATE text format, failed to convert day to an integer", String(error)); // @suppress(dscanner.style.long_line)

    return Result.noError;
}

Result decodeDateBinary(scope ref MemoryReader reader, scope out PostgresDate value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // It's some wacky integer-based format I cba to figure out (would be easier to just port Postgres' decoder function).
    assert(false, "TODO: Not implemented");
}

/++ TIME ++/

Result decodeTimeText(scope ref MemoryReader reader, scope out Duration value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import core.time : hours, minutes, seconds, msecs;

    import juptune.core.util : fromBase10;

    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];

    if(slice.length < 6)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, expected at least 6 bytes of data"); // @suppress(dscanner.style.long_line)

    uint hoursStr;
    uint minutesStr;
    uint secondsStr;
    uint msecsStr;

    string error;
    hoursStr = fromBase10!uint(slice[0..2], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, failed to convert hours to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    minutesStr = fromBase10!uint(slice[3..5], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, failed to convert minutes to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    secondsStr = fromBase10!uint(slice[6..8], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, failed to convert seconds to an integer", String(error)); // @suppress(dscanner.style.long_line)

    if(slice.length > 8)
    {
        if(slice[8] != '.')
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, expected '.' following seconds component"); // @suppress(dscanner.style.long_line)
    
        msecs = fromBase10!uint(slice[9..$], error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, failed to convert msecs to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    value = hoursStr.hours;
    value += minutesStr.minutes;
    value += secondsStr.seconds;
    value += msecsStr.msecs;
    return Result.noError;
}

Result decodeTimeBinary(scope ref MemoryReader reader, scope out Duration value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // It's some integer-based format I cba to figure out yet.
    assert(false, "TODO: Not implemented");
}

/++ TIME WITH TIME ZONE ++/

struct PostgresTimetz
{
    Duration time;
    Duration timezone;
}

Result decodeTimetzText(scope ref MemoryReader reader, scope out PostgresTimetz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import core.time : hours, minutes, seconds, msecs;

    import juptune.core.util : fromBase10;

    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];

    if(slice.length < 6)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME text format, expected at least 6 bytes of data"); // @suppress(dscanner.style.long_line)

    uint hoursStr;
    uint minutesStr;
    uint secondsStr;
    uint msecsStr;
    uint timezone;

    string error;
    hoursStr = fromBase10!uint(slice[0..2], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert hours to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    minutesStr = fromBase10!uint(slice[3..5], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert minutes to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    secondsStr = fromBase10!uint(slice[6..8], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert seconds to an integer", String(error)); // @suppress(dscanner.style.long_line)

    size_t cursor = 8;
    if(cursor < slice.length && slice[cursor] == '.')
    {
        cursor++; // Skip '.'

        const start = cursor;
        while(cursor < slice.length && slice[cursor] != '+' && slice[cursor] != '-')
            cursor++;
        const number = slice[start..cursor];

        msecs = fromBase10!uint(number, error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert msecs to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    if(cursor < slice.length)
    {
        const sign = slice[cursor++];
        if(sign != '+' && sign != '-')
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, expected '+' or '-' after parsing seconds/msecs components", String(error)); // @suppress(dscanner.style.long_line)

        timezone = fromBase10!uint(slice[cursor..$], error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert timezone to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    value.time = hoursStr.hours;
    value.time += minutesStr.minutes;
    value.time += secondsStr.seconds;
    value.time += msecsStr.msecs;
    value.timezone = timezone.hours;
    return Result.noError;
}

Result decodeTimetzBinary(scope ref MemoryReader reader, scope out PostgresTimetz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // It's some integer-based format I cba to figure out yet.
    assert(false, "TODO: Not implemented");
}

/++ TIMESTAMP (TODO: DRY) ++/

struct PostgresTimestamp
{
    PostgresDate date;
    Duration time;
}

Result decodeTimestampText(scope ref MemoryReader reader, scope out PostgresTimestamp value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import core.time : hours, minutes, seconds, msecs;

    import juptune.core.util : fromBase10;

    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];

    if(slice.length < 19)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, expected at least 19 bytes of data"); // @suppress(dscanner.style.long_line)

    const probablyIsoYMD = (slice[4] == '-');
    if(!probablyIsoYMD)
        return Result.make(PostgresDataTypeError.limitation, "TODO: use params to figure out format (And DRY this)");

    const year = slice[0..4];
    const month = slice[5..7];
    const day = slice[8..10];

    string error;
    value.date.year = fromBase10!uint(year, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert year to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.date.month = fromBase10!uint(month, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert month to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.date.day = fromBase10!uint(day, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert day to an integer", String(error)); // @suppress(dscanner.style.long_line)

    uint hoursStr;
    uint minutesStr;
    uint secondsStr;
    uint msecsStr;

    hoursStr = fromBase10!uint(slice[11..13], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert hours to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    minutesStr = fromBase10!uint(slice[14..16], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert minutes to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    secondsStr = fromBase10!uint(slice[17..19], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert seconds to an integer", String(error)); // @suppress(dscanner.style.long_line)

    size_t cursor = 19;
    if(cursor < slice.length && slice[cursor] == '.')
    {
        cursor++; // Skip '.'

        const start = cursor;
        while(cursor < slice.length && slice[cursor] != '+' && slice[cursor] != '-')
            cursor++;
        const number = slice[start..cursor];

        msecs = fromBase10!uint(number, error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert msecs to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    value.time = hoursStr.hours;
    value.time += minutesStr.minutes;
    value.time += secondsStr.seconds;
    value.time += msecsStr.msecs;
    return Result.noError;
}

Result decodeTimestampBinary(scope ref MemoryReader reader, scope out PostgresTimestamp value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // It's some integer-based format I cba to figure out yet.
    assert(false, "TODO: Not implemented");
}

/++ TIMESTAMP WITH TIME ZONE (TODO: DRY) ++/

struct PostgresTimestamptz
{
    PostgresDate date;
    PostgresTimetz time;
}

Result decodeTimestamptzText(scope ref MemoryReader reader, scope out PostgresTimestamptz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import core.time : hours, minutes, seconds, msecs;

    import juptune.core.util : fromBase10;

    const slice = cast(const(char)[])reader.buffer[reader.cursor..$];

    if(slice.length < 19)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, expected at least 19 bytes of data"); // @suppress(dscanner.style.long_line)

    const probablyIsoYMD = (slice[4] == '-');
    if(!probablyIsoYMD)
        return Result.make(PostgresDataTypeError.limitation, "TODO: use params to figure out format (And DRY this)");

    const year = slice[0..4];
    const month = slice[5..7];
    const day = slice[8..10];

    string error;
    value.date.year = fromBase10!uint(year, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert year to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.date.month = fromBase10!uint(month, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert month to an integer", String(error)); // @suppress(dscanner.style.long_line)

    value.date.day = fromBase10!uint(day, error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert day to an integer", String(error)); // @suppress(dscanner.style.long_line)

    uint hoursStr;
    uint minutesStr;
    uint secondsStr;
    uint msecsStr;
    uint timezone;

    hoursStr = fromBase10!uint(slice[11..13], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert hours to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    minutesStr = fromBase10!uint(slice[14..16], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert minutes to an integer", String(error)); // @suppress(dscanner.style.long_line)
    
    secondsStr = fromBase10!uint(slice[17..19], error);
    if(error.length > 0)
        return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert seconds to an integer", String(error)); // @suppress(dscanner.style.long_line)

    size_t cursor = 19;
    if(cursor < slice.length && slice[cursor] == '.')
    {
        cursor++; // Skip '.'

        const start = cursor;
        while(cursor < slice.length && slice[cursor] != '+' && slice[cursor] != '-')
            cursor++;
        const number = slice[start..cursor];

        msecs = fromBase10!uint(number, error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIMESTAMP text format, failed to convert msecs to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    if(cursor < slice.length)
    {
        const sign = slice[cursor++];
        if(sign != '+' && sign != '-')
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, expected '+' or '-' after parsing seconds/msecs components", String(error)); // @suppress(dscanner.style.long_line)

        timezone = fromBase10!uint(slice[cursor..$], error);
        if(error.length > 0)
            return Result.make(PostgresDataTypeError.invalidEncoding, "when decoding TIME WITH TIME ZONE text format, failed to convert timezone to an integer", String(error)); // @suppress(dscanner.style.long_line)
    }

    value.time.time = hoursStr.hours;
    value.time.time += minutesStr.minutes;
    value.time.time += secondsStr.seconds;
    value.time.time += msecsStr.msecs;
    value.time.timezone = timezone.hours;
    return Result.noError;
}

Result decodeTimestamptzBinary(scope ref MemoryReader reader, scope out PostgresTimestamptz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    // It's some integer-based format I cba to figure out yet.
    assert(false, "TODO: Not implemented");
}