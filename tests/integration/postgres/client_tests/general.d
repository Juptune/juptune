module client_tests.general;

import juptune.core.util       : Result;
import juptune.postgres.client : PostgresClient;

import config  : connectToPsqlClient;
import testlib : Test, RegisterTests;

mixin RegisterTests!(client_tests.general);

@Test("should be able to connect via SCRAM-SHA-256")
Result test_connect()
{
    PostgresClient _ = connectToPsqlClient();
    return Result.noError;
}
