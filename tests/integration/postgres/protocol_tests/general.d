module protocol_tests.general;

import juptune.core.util : Result;

import config  : connectToPsqlProtocol;
import testlib : Test, RegisterTests;

mixin RegisterTests!(protocol_tests.general);

@Test("should be able to connect via SCRAM-SHA-256")
Result test_connect()
{
    auto _ = connectToPsqlProtocol();
    return Result.noError;
}
