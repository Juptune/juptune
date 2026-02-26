module client_tests.querying;

import std.exception : enforce;

import juptune.core.util       : Result, resultEnforce;
import juptune.postgres.client : PostgresClient;

import config  : connectToPsqlClient;
import testlib : Test, RegisterTests;

mixin RegisterTests!(client_tests.querying);

@Test("exec & queryRow - all supported types from D to Postgres")
Result test_scratchpad()
{
    import core.time : Duration, hours;

    import juptune.core.ds : String;
    import juptune.postgres.protocol.datatypes : PostgresDate, PostgresTimestamp, PostgresTimestamptz, PostgresTimetz;

    PostgresClient psql = connectToPsqlClient();
    psql.protocol.simpleQuery(`
        DROP TABLE IF EXISTS test_scratchpad;
        CREATE TABLE test_scratchpad (
            id SERIAL PRIMARY KEY,

            cn CHARACTER (10),
            cnv CHARACTER VARYING (10),
            t TEXT,
            i INT,
            si SMALLINT,
            b BOOLEAN,
            ti TIME,
            tiz TIME WITH TIME ZONE,
            d DATE,
            ts TIMESTAMP,
            tstz TIMESTAMP WITH TIME ZONE
        );
    `, null, null).resultEnforce;

    psql.exec(
        `
            INSERT INTO test_scratchpad (
                cn,
                cnv,
                t,
                i,
                si,
                b,
                ti,
                tiz,
                d,
                ts,
                tstz
            ) VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                $7,
                $8,
                $9,
                $10,
                $11
            )
        `,
        "cn val",           // $1
        "cnv val",          // $2
        "text val",         // $3
        int.max,            // $4
        short.max,          // $5
        true,               // $6
        2.hours,            // $7
        PostgresTimetz(     // $8
            4.hours,
            0.hours
        ),
        PostgresDate(       // $9
            1234,
            6,
            7
        ),
        PostgresTimestamp(  // $10
            PostgresDate(1234, 5, 6),
            3.hours
        ),
        PostgresTimestamptz(// $11
            PostgresDate(1234, 5, 6),
            PostgresTimetz(6.hours, 0.hours)
        ),
    ).resultEnforce;
    
    int id;
    String cn, cnv;
    string t;
    int i;
    short si;
    bool b;
    Duration ti;
    PostgresTimetz tiz;
    PostgresDate d;
    PostgresTimestamp ts;
    PostgresTimestamptz tstz;
    psql.rowScanner(id, cn, cnv, t, i, si, b, ti, tiz, d, ts, tstz)
        .queryRow(`SELECT * FROM test_scratchpad;`)
        .resultEnforce;

    enforce(id == 1);
    enforce(cn == "cn val    "); // CHARACTER (nn) adds padding
    enforce(cnv == "cnv val");
    enforce(t == "text val");
    enforce(i == int.max);
    enforce(si == short.max);
    enforce(b);
    enforce(ti == 2.hours);
    enforce(tiz == PostgresTimetz(4.hours, 0.hours));
    enforce(d == PostgresDate(1234, 6, 7));
    enforce(ts == PostgresTimestamp(PostgresDate(1234, 5, 6), 3.hours));
    enforce(tstz == PostgresTimestamptz(PostgresDate(1234, 5, 6), PostgresTimetz(6.hours, 0.hours)));

    return Result.noError;
}
