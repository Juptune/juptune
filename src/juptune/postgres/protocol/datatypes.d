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

import juptune.postgres.protocol.connection : PostgresParameters, PostgresProtocol;

enum PostgresDataTypeOid
{
    FAILSAFE = -1,
    unspecified = 0,

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

Result encodeBooleanText(scope ref PostgresProtocol psql, bool value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    return psql.putBytes([value ? cast(ubyte)'t' : cast(ubyte)'f']);
}

Result encodeBooleanBinary(scope ref PostgresProtocol psql, bool value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    return psql.putBytes([value ? 1 : 0]);
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

Result encodeInt2Text(scope ref PostgresProtocol psql, short value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : IntToCharBuffer, toBase10;

    IntToCharBuffer buffer;
    const slice = toBase10(value, buffer);

    return psql.putString(slice);
}

Result encodeInt2Binary(scope ref PostgresProtocol psql, short value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    return psql.putInt!short(value);
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

Result encodeInt4Text(scope ref PostgresProtocol psql, int value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : IntToCharBuffer, toBase10;

    IntToCharBuffer buffer;
    const slice = toBase10(value, buffer);

    return psql.putString(slice);
}

Result encodeInt4Binary(scope ref PostgresProtocol psql, int value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    return psql.putInt!int(value);
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

Result encodeTextText(scope ref PostgresProtocol psql, scope const(char)[] value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    return psql.putString(value);
}

Result encodeTextBinary(scope ref PostgresProtocol psql, scope const(char)[] value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
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
    const day = slice[8..10];

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

Result encodeDateText(scope ref PostgresProtocol psql, PostgresDate value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : IntToCharBuffer, toBase10;

    char[10] dateBuffer;

    void putInt(size_t at, uint value, size_t minLength)
    {
        IntToCharBuffer buffer;
        const slice = toBase10(value, buffer);

        size_t cursor = at;
        if(slice.length < minLength)
        {
            const diff = minLength - slice.length;
            foreach(_; 0..diff)
                dateBuffer[cursor++] = '0';
        }
        dateBuffer[cursor..cursor+slice.length] = slice;
    }

    dateBuffer[4] = '-';
    dateBuffer[7] = '-';
    putInt(0, value.year, 4);
    putInt(5, value.month, 2);
    putInt(8, value.day, 2);

    return psql.putString(dateBuffer);
}

Result encodeDateBinary(scope ref PostgresProtocol psql, PostgresDate value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
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
    
        msecsStr = fromBase10!uint(slice[9..$], error);
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

Result encodeTimeText(scope ref PostgresProtocol psql, Duration value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : IntToCharBuffer, toBase10;

    char[12] timeBuffer;

    void putInt(size_t at, uint value, size_t minLength)
    {
        IntToCharBuffer buffer;
        const slice = toBase10(value, buffer);

        size_t cursor = at;
        if(slice.length < minLength)
        {
            const diff = minLength - slice.length;
            foreach(_; 0..diff)
                timeBuffer[cursor++] = '0';
        }
        timeBuffer[cursor..cursor+slice.length] = slice;
    }

    uint hours, minutes, seconds, msecs;
    value.split!("hours", "minutes", "seconds", "msecs")(hours, minutes, seconds, msecs);

    timeBuffer[2] = ':';
    timeBuffer[5] = ':';
    timeBuffer[8] = '.';
    putInt(0, hours, 2);
    putInt(3, minutes, 2);
    putInt(6, seconds, 2);
    putInt(9, msecs, 3);

    return psql.putString(timeBuffer);
}

Result encodeTimeBinary(scope ref PostgresProtocol psql, Duration value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
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

        msecsStr = fromBase10!uint(number, error);
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

Result encodeTimetzText(scope ref PostgresProtocol psql, PostgresTimetz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import std.math : abs;
    import juptune.core.util : IntToCharBuffer, toBase10;

    char[15] timeBuffer;

    void putInt(size_t at, uint value, size_t minLength)
    {
        IntToCharBuffer buffer;
        const slice = toBase10(value, buffer);

        size_t cursor = at;
        if(slice.length < minLength)
        {
            const diff = minLength - slice.length;
            foreach(_; 0..diff)
                timeBuffer[cursor++] = '0';
        }
        timeBuffer[cursor..cursor+slice.length] = slice;
    }

    int tz;
    uint hours, minutes, seconds, msecs;
    value.time.split!("hours", "minutes", "seconds", "msecs")(hours, minutes, seconds, msecs);
    tz = cast(int)value.timezone.total!"hours";

    timeBuffer[2] = ':';
    timeBuffer[5] = ':';
    timeBuffer[8] = '.';
    timeBuffer[12] = (tz < 0) ? '-' : '+';
    putInt(0, hours, 2);
    putInt(3, minutes, 2);
    putInt(6, seconds, 2);
    putInt(9, msecs, 3);
    putInt(13, tz.abs, 2);

    return psql.putString(timeBuffer);
}

Result encodeTimetzBinary(scope ref PostgresProtocol psql, PostgresTimetz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
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

        msecsStr = fromBase10!uint(number, error);
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

Result encodeTimestampText(scope ref PostgresProtocol psql, PostgresTimestamp value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import juptune.core.util : IntToCharBuffer, toBase10;

    char[23] timeBuffer;

    void putInt(size_t at, uint value, size_t minLength)
    {
        IntToCharBuffer buffer;
        const slice = toBase10(value, buffer);

        size_t cursor = at;
        if(slice.length < minLength)
        {
            const diff = minLength - slice.length;
            foreach(_; 0..diff)
                timeBuffer[cursor++] = '0';
        }
        timeBuffer[cursor..cursor+slice.length] = slice;
    }

    uint hours, minutes, seconds, msecs;
    value.time.split!("hours", "minutes", "seconds", "msecs")(hours, minutes, seconds, msecs);

    // YYYY-MM-DD hh:mm:ss.mmm
    // 01234567890123456789012
    // 00000000001111111111222
    timeBuffer[4] = '-';
    timeBuffer[7] = '-';
    timeBuffer[10] = ' ';
    timeBuffer[13] = ':';
    timeBuffer[16] = ':';
    timeBuffer[19] = '.';
    putInt(0, value.date.year, 4);
    putInt(5, value.date.month, 2);
    putInt(8, value.date.day, 2);
    putInt(11, hours, 2);
    putInt(14, minutes, 2);
    putInt(17, seconds, 2);
    putInt(20, msecs, 3);

    return psql.putString(timeBuffer);
}

Result encodeTimestampBinary(scope ref PostgresProtocol psql, PostgresTimestamp value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
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

        msecsStr = fromBase10!uint(number, error);
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

Result encodeTimestamptzText(scope ref PostgresProtocol psql, PostgresTimestamptz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    import std.math : abs;
    import juptune.core.util : IntToCharBuffer, toBase10;

    char[26] timeBuffer;

    void putInt(size_t at, uint value, size_t minLength)
    {
        IntToCharBuffer buffer;
        const slice = toBase10(value, buffer);

        size_t cursor = at;
        if(slice.length < minLength)
        {
            const diff = minLength - slice.length;
            foreach(_; 0..diff)
                timeBuffer[cursor++] = '0';
        }
        timeBuffer[cursor..cursor+slice.length] = slice;
    }

    int tz;
    uint hours, minutes, seconds, msecs;
    value.time.time.split!("hours", "minutes", "seconds", "msecs")(hours, minutes, seconds, msecs);
    tz = cast(int)value.time.timezone.total!"hours";

    // YYYY-MM-DD hh:mm:ss.mmm+tz
    // 01234567890123456789012345
    // 00000000001111111111222222
    timeBuffer[4] = '-';
    timeBuffer[7] = '-';
    timeBuffer[10] = ' ';
    timeBuffer[13] = ':';
    timeBuffer[16] = ':';
    timeBuffer[19] = '.';
    timeBuffer[23] = (tz < 0) ? '-' : '+';
    putInt(0, value.date.year, 4);
    putInt(5, value.date.month, 2);
    putInt(8, value.date.day, 2);
    putInt(11, hours, 2);
    putInt(14, minutes, 2);
    putInt(17, seconds, 2);
    putInt(20, msecs, 3);
    putInt(24, tz.abs, 2);

    return psql.putString(timeBuffer);
}

Result encodeTimestamptzBinary(scope ref PostgresProtocol psql, PostgresTimestamptz value, scope const ref PostgresParameters params) @nogc nothrow // @suppress(dscanner.style.long_line)
{
    assert(false, "TODO: Not implemented");
}