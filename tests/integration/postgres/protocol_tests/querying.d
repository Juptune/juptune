module protocol_tests.querying;

import std.exception : enforce;
import std.format    : format;

import juptune.core.util         : Result, resultEnforce;
import juptune.data              : MemoryReader;
import juptune.postgres.protocol : PostgresProtocol, PostgresColumnDescription, PostgresDataTypeOid;

import config  : connectToPsql;
import testlib : Test, RegisterTests;

mixin RegisterTests!(protocol_tests.querying);

@Test("onRowDescription & onDataRow - most types with a directly provided decoder - text format")
Result onRowDescription_onDataRow_supportedTypes_text()
{
    PostgresProtocol psql = connectToPsql();
    psql.simpleQueryGc(`
        DROP TABLE IF EXISTS onRowDescription_onDataRow_supportedTypes_text;
        CREATE TABLE onRowDescription_onDataRow_supportedTypes_text(
            id SERIAL PRIMARY KEY NOT NULL,

            b BOOLEAN,
            cn CHARACTER (10),
            cnv CHARACTER VARYING (10),
            d DATE,
            dp DOUBLE PRECISION,
            i INTEGER,
            r REAL,
            si SMALLINT,
            t TEXT,
            ti TIME,
            tiz TIME WITH TIME ZONE,
            ts TIMESTAMP,
            tsz TIMESTAMP WITH TIME ZONE,
            u UUID
        );

        INSERT INTO onRowDescription_onDataRow_supportedTypes_text(
            b,
            cn,
            cnv,
            d,
            dp,
            i,
            r,
            si,
            t,
            ti,
            tiz,
            ts,
            tsz,
            u
        ) VALUES 
            (TRUE, '123', '1234', '1234-01-02', 123.456, 123, 123.456, 123, '123', '01:02:03.456', '01:02:03.456+7', '1234-01-02 01:02:03', '1234-01-02 01:02:03.456+7', 'dfc17952-6eaa-4aca-a455-0b7f5eed2b46')
        ;

        SELECT * FROM onRowDescription_onDataRow_supportedTypes_text;
    `,
    (ushort columnCount, scope PostgresProtocol.NextColumnDescriptionT nextColumnDescription) {
        foreach(i; 0..columnCount)
        {
            PostgresColumnDescription desc;
            auto result = nextColumnDescription(desc);
            if(result.isError)
                return result;

            enforce(desc.format == PostgresColumnDescription.Format.text);
            enforce(desc.columnAttributeNumber == i + 1);

            switch(i)
            {
                case 0:
                    enforce(desc.nameDoNotCopy == "id");
                    enforce(desc.dataType == PostgresDataTypeOid.int4);
                    break;
                case 1:
                    enforce(desc.nameDoNotCopy == "b");
                    enforce(desc.dataType == PostgresDataTypeOid.boolean);
                    break;
                case 2:
                    enforce(desc.nameDoNotCopy == "cn");
                    enforce(desc.dataType == PostgresDataTypeOid.bpchar);
                    break;
                case 3:
                    enforce(desc.nameDoNotCopy == "cnv");
                    enforce(desc.dataType == PostgresDataTypeOid.varchar);
                    break;
                case 4:
                    enforce(desc.nameDoNotCopy == "d");
                    enforce(desc.dataType == PostgresDataTypeOid.date);
                    break;
                case 5:
                    enforce(desc.nameDoNotCopy == "dp");
                    enforce(desc.dataType == PostgresDataTypeOid.float8);
                    break;
                case 6:
                    enforce(desc.nameDoNotCopy == "i");
                    enforce(desc.dataType == PostgresDataTypeOid.int4);
                    break;
                case 7:
                    enforce(desc.nameDoNotCopy == "r");
                    enforce(desc.dataType == PostgresDataTypeOid.float4);
                    break;
                case 8:
                    enforce(desc.nameDoNotCopy == "si");
                    enforce(desc.dataType == PostgresDataTypeOid.int2);
                    break;
                case 9:
                    enforce(desc.nameDoNotCopy == "t");
                    enforce(desc.dataType == PostgresDataTypeOid.text);
                    break;
                case 10:
                    enforce(desc.nameDoNotCopy == "ti");
                    enforce(desc.dataType == PostgresDataTypeOid.time);
                    break;
                case 11:
                    enforce(desc.nameDoNotCopy == "tiz");
                    enforce(desc.dataType == PostgresDataTypeOid.timetz);
                    break;
                case 12:
                    enforce(desc.nameDoNotCopy == "ts");
                    enforce(desc.dataType == PostgresDataTypeOid.timestamp);
                    break;
                case 13:
                    enforce(desc.nameDoNotCopy == "tsz");
                    enforce(desc.dataType == PostgresDataTypeOid.timestamptz);
                    break;
                case 14:
                    enforce(desc.nameDoNotCopy == "u");
                    enforce(desc.dataType == PostgresDataTypeOid.uuid);
                    break;

                default: throw new Exception("out of bounds");
            }
        }

        return Result.noError;
    },
    (ushort columnCount, scope PostgresProtocol.NextColumnDataT nextData){
        import core.time : Duration, hours, minutes, seconds, msecs;
        import juptune.postgres.protocol.datatypes;

        foreach(i; 0..columnCount)
        {
            MemoryReader memory;
            bool isNull;
            auto result = nextData(memory, isNull);
            if(result.isError)
                return result;

            enforce(!isNull);

            switch(i)
            {
                case 0:
                    int v;
                    decodeInt4Text(memory, v, psql.params).resultEnforce;
                    enforce(v == 1);
                    break;
                case 1:
                    bool v;
                    decodeBooleanText(memory, v, psql.params).resultEnforce;
                    enforce(v);
                    break;
                case 2:
                    const(char)[] v;
                    decodeTextText(memory, v, psql.params).resultEnforce;
                    enforce(v == "123       "); // Since CHARACTER (nn) will add padding to match (nn)
                    break;
                case 3:
                    const(char)[] v;
                    decodeTextText(memory, v, psql.params).resultEnforce;
                    enforce(v == "1234");
                    break;
                case 4:
                    PostgresDate v;
                    decodeDateText(memory, v, psql.params).resultEnforce;
                    enforce(v == PostgresDate(1234, 1, 2));
                    break;
                case 5:
                    // TODO: need float support
                    break;
                case 6:
                    int v;
                    decodeInt4Text(memory, v, psql.params).resultEnforce;
                    enforce(v == 123);
                    break;
                case 7:
                    // TODO: need float support
                    break;
                case 8:
                    short v;
                    decodeInt2Text(memory, v, psql.params).resultEnforce;
                    enforce(v == 123);
                    break;
                case 9:
                    const(char)[] v;
                    decodeTextText(memory, v, psql.params).resultEnforce;
                    enforce(v == "123");
                    break;
                case 10:
                    Duration v;
                    decodeTimeText(memory, v, psql.params).resultEnforce;
                    enforce(v == 1.hours + 2.minutes + 3.seconds + 456.msecs);
                    break;
                case 11:
                    PostgresTimetz v;
                    decodeTimetzText(memory, v, psql.params).resultEnforce;
                    enforce(v == PostgresTimetz(
                        1.hours + 2.minutes + 3.seconds + 456.msecs,
                        7.hours
                    ));
                    break;
                case 12:
                    PostgresTimestamp v;
                    decodeTimestampText(memory, v, psql.params).resultEnforce;
                    enforce(v == PostgresTimestamp(
                        PostgresDate(1234, 1, 2),
                        1.hours + 2.minutes + 3.seconds
                    ));
                    break;
                case 13:
                    PostgresTimestamptz v;
                    decodeTimestamptzText(memory, v, psql.params).resultEnforce;
                    enforce(v == PostgresTimestamptz(
                        // Postgres automatically applies the timezone in this case.
                        PostgresDate(1234, 1, 1),
                        PostgresTimetz(
                            18.hours + 2.minutes + 3.seconds + 456.msecs,
                            Duration.zero
                        )
                    ), format("%s", v));
                    break;
                case 14:
                    // NOTE: There's no special UUIDv4 decoding yet.
                    const(char)[] v;
                    decodeTextText(memory, v, psql.params).resultEnforce;
                    enforce(v == "dfc17952-6eaa-4aca-a455-0b7f5eed2b46");
                    break;

                default: throw new Exception("out of bounds");
            }
        }

        return Result.noError;
    }).resultEnforce;

    return Result.noError;
}

@Test("bindParameter - most types with a directly provided encoder - text format")
Result bindParameter_supportedTypes_text()
{
    PostgresProtocol psql = connectToPsql();
    psql.simpleQueryGc(`
        DROP TABLE IF EXISTS bindParameter_supportedTypes_text;
        CREATE TABLE bindParameter_supportedTypes_text(
            id SERIAL PRIMARY KEY NOT NULL,

            b BOOLEAN,
            cn CHARACTER (10),
            cnv CHARACTER VARYING (10),
            d DATE,
            dp DOUBLE PRECISION,
            i INTEGER,
            r REAL,
            si SMALLINT,
            t TEXT,
            ti TIME,
            tiz TIME WITH TIME ZONE,
            ts TIMESTAMP,
            tsz TIMESTAMP WITH TIME ZONE,
            u UUID
        );
    `, null, null).resultEnforce;

    psql.prepare(
        "bindParameter_supportedTypes_text",
        `
            INSERT INTO bindParameter_supportedTypes_text(
                b,
                cn,
                cnv,
                d,
                dp,
                i,
                r,
                si,
                t,
                ti,
                tiz,
                ts,
                tsz,
                u
            ) VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ;
        `,
        null
    ).resultEnforce;

    psql.bindDescribeExecuteGc(
        "bindParameter_supportedTypes_text",
        null,
        null,
        bindParameterOrNull: (const paramIndex, scope ref psql, scope out moreParamsLeftToBind){
            import core.time : Duration, hours, minutes, seconds, msecs;
            import juptune.postgres.protocol.datatypes;

            moreParamsLeftToBind = paramIndex < 13;

            switch(paramIndex)
            {
                case 0: encodeBooleanText(psql, true, psql.params).resultEnforce; break;
                case 1: encodeTextText(psql, "123", psql.params).resultEnforce; break;
                case 2: encodeTextText(psql, "1234", psql.params).resultEnforce; break;
                case 3: encodeDateText(psql, PostgresDate(1234, 1, 2), psql.params).resultEnforce; break;
                case 4: /*TODO: float support*/ encodeTextText(psql, "0", psql.params).resultEnforce; break;
                case 5: encodeInt4Text(psql, 123, psql.params).resultEnforce; break;
                case 6: /*TODO: float support*/ encodeTextText(psql, "0", psql.params).resultEnforce; break;
                case 7: encodeInt2Text(psql, 123, psql.params).resultEnforce; break;
                case 8: encodeTextText(psql, "text", psql.params).resultEnforce; break;
                case 9: encodeTimeText(psql, 1.hours + 2.minutes + 34.seconds + 567.msecs, psql.params).resultEnforce; break; // @suppress(dscanner.style.long_line)
                case 10: encodeTimetzText(psql, PostgresTimetz(1.hours + 2.minutes + 34.seconds, 1.hours), psql.params).resultEnforce; break; // @suppress(dscanner.style.long_line)
                case 11: encodeTimestampText(psql, PostgresTimestamp(PostgresDate(1234, 1, 2), 1.hours + 2.minutes + 34.seconds + 567.msecs), psql.params).resultEnforce; break; // @suppress(dscanner.style.long_line)
                case 12: encodeTimestamptzText(psql, PostgresTimestamptz(PostgresDate(1234, 1, 2), PostgresTimetz(1.hours + 2.minutes + 34.seconds, 1.hours)), psql.params).resultEnforce; break; // @suppress(dscanner.style.long_line)
                case 13: /*TODO: Dedicated UUIDv4 type & encoder*/ encodeTextText(psql, "dfc17952-6eaa-4aca-a455-0b7f5eed2b46", psql.params).resultEnforce; break; // @suppress(dscanner.style.long_line)

                default: throw new Exception("out of bounds");
            }
            return Result.noError;
        },
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.noError,
        onDataRowOrNull: (columnCount, scope nextData) => Result.noError,
    ).resultEnforce;

    psql.simpleQueryGc(
        `
            SELECT 1 FROM bindParameter_supportedTypes_text
            WHERE
                b = TRUE
                AND cn = '123'
                AND cnv = '1234'
                AND d = '1234-01-02'
                AND dp = 0
                AND i = 123
                AND r = 0
                AND si = 123
                AND t = 'text'
                AND ti = '01:02:34.567'
                AND tiz = '01:02:34+01'
                AND ts = '1234-01-02 01:02:34.567'
                AND tsz = '1234-01-02 01:02:34+01'
        `,
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.noError,
        onDataRowOrNull: (columnCount, scope nextData) {
            import juptune.postgres.protocol.datatypes : decodeInt4Text;

            MemoryReader reader;
            bool isNull;
            nextData(reader, isNull).resultEnforce;
            assert(!isNull);

            int exists;
            decodeInt4Text(reader, exists, psql.params).resultEnforce;

            enforce(exists == 1);
            return Result.noError;
        },
    ).resultEnforce;

    return Result.noError;
}