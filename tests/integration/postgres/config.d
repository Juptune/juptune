module config;

import core.time : seconds;

import juptune.core.util : resultAssert, resultEnforce;
import juptune.event : IpAddress;
import juptune.postgres.protocol : PostgresProtocol, PostgresConnectInfo, PostgresTlsMode, PostgresProtocolConfig;
import juptune.postgres.client : PostgresClient;

static immutable POSTGRES_USER = "user";
static immutable POSTGRES_PASSWORD = "password";
static IpAddress POSTGRES_HOST;

static this()
{
    POSTGRES_HOST = IpAddress.mustParse("127.0.0.1", 10_000);
}

PostgresProtocol connectToPsqlProtocol()
{
    // NRVO kicks in so this is allowed to be returned, despite being non-copyable.
    auto psql = PostgresProtocol(PostgresProtocolConfig(
        writeTimeout: 5.seconds,
        readTimeout: 5.seconds,
    ));
    psql.connect(POSTGRES_HOST, PostgresConnectInfo(
        user: POSTGRES_USER,
        plaintextPassword: POSTGRES_PASSWORD,
        tlsMode: PostgresTlsMode.never,
    )).resultEnforce;

    return psql;
}

PostgresClient connectToPsqlClient()
{
    // NRVO kicks in so this is allowed to be returned, despite being non-copyable.
    auto psql = PostgresClient(PostgresProtocolConfig(
        writeTimeout: 5.seconds,
        readTimeout: 5.seconds,
    ));
    psql.connect(POSTGRES_HOST, PostgresConnectInfo(
        user: POSTGRES_USER,
        plaintextPassword: POSTGRES_PASSWORD,
        tlsMode: PostgresTlsMode.never,
    )).resultEnforce;

    return psql;
}