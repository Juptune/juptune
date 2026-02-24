module protocol_tests.errors;

import std.exception : enforce;

import juptune.core.util : Result, resultEnforce;
import juptune.postgres.protocol : PostgresProtocol, PostgresProtocolError;

import config  : connectToPsql;
import testlib : Test, ExpectResult, RegisterTests;

mixin RegisterTests!(protocol_tests.errors);

enum DummyError { e }

@Test("simpleQuery - onRowDescriptionOrNull error is forwarded")
@ExpectResult!DummyError
Result test_onRowDescriptionOrNull_error_forwarded()
{
    PostgresProtocol psql = connectToPsql();
    auto result = psql.simpleQueryGc(
        `
            DROP TABLE IF EXISTS test_onRowDescriptionOrNull_error_forwarded;
            
            CREATE TABLE test_onRowDescriptionOrNull_error_forwarded(id INTEGER PRIMARY KEY);
            
            INSERT INTO test_onRowDescriptionOrNull_error_forwarded(id) VALUES (0);
            
            SELECT * FROM test_onRowDescriptionOrNull_error_forwarded;
        `,
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.make(DummyError.e),
        onDataRowOrNull: (columnCount, scope nextData) => Result.noError,
    );
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

@Test("simpleQuery - onDataRowOrNull error is forwarded")
@ExpectResult!DummyError
Result test_onDataRowOrNull_error_forwarded()
{
    PostgresProtocol psql = connectToPsql();
    auto result = psql.simpleQueryGc(
        `
            DROP TABLE IF EXISTS test_onDataRowOrNull_error_forwarded;
            
            CREATE TABLE test_onDataRowOrNull_error_forwarded(id INTEGER PRIMARY KEY);
            
            INSERT INTO test_onDataRowOrNull_error_forwarded(id) VALUES (0);
            
            SELECT * FROM test_onDataRowOrNull_error_forwarded;
        `,
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.noError,
        onDataRowOrNull: (columnCount, scope nextData) => Result.make(DummyError.e),
    );
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

@Test("simpleQuery - emptyQuery")
@ExpectResult!PostgresProtocolError(PostgresProtocolError.emptyQuery)
Result test_simpleQuery_emptyQuery()
{
    PostgresProtocol psql = connectToPsql();
    auto result = psql.simpleQueryGc("", null, null);
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

// NOTE: Since every single message is handled via nextMessageImpl (only one part of .connect disables automatic ErrorResponse handling),
//       this test effectively applies to all other public API functions.
@Test("all - error repsonse is handled")
@ExpectResult!PostgresProtocolError(PostgresProtocolError.errorResponse)
Result test_errorResponse()
{
    string queryWithInvalidChar;
    queryWithInvalidChar.length = 1;

    PostgresProtocol psql = connectToPsql();
    auto result = psql.simpleQueryGc(queryWithInvalidChar, null, null);
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

@Test("bindDescribeExecute - onRowDescriptionOrNull error is forwarded")
@ExpectResult!DummyError
Result test_bindDescribeExecute_onRowDescriptionOrNull_error_forwarded()
{
    PostgresProtocol psql = connectToPsql();
    psql.simpleQuery(`
        DROP TABLE IF EXISTS test_onRowDescriptionOrNull_error_forwarded;
        
        CREATE TABLE test_onRowDescriptionOrNull_error_forwarded(id INTEGER PRIMARY KEY);
        
        INSERT INTO test_onRowDescriptionOrNull_error_forwarded(id) VALUES (0);
    `, null, null).resultEnforce;

    psql.prepare(
        "test_onRowDescriptionOrNull_error_forwarded", 
        "SELECT * FROM test_onRowDescriptionOrNull_error_forwarded", 
        null
    ).resultEnforce;
    auto result = psql.bindDescribeExecuteGc(
        "test_onRowDescriptionOrNull_error_forwarded",
        null,
        null,
        bindParameterOrNull: null,
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.make(DummyError.e),
        onDataRowOrNull: (columnCount, scope nextData) => Result.noError,
    );
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

@Test("bindDescribeExecute - onDataRowOrNull error is forwarded")
@ExpectResult!DummyError
Result test_bindDescribeExecute_onDataRowOrNull_error_forwarded()
{
    PostgresProtocol psql = connectToPsql();
    psql.simpleQuery(`
        DROP TABLE IF EXISTS test_onDataRowOrNull_error_forwarded;
        
        CREATE TABLE test_onDataRowOrNull_error_forwarded(id INTEGER PRIMARY KEY);
        
        INSERT INTO test_onDataRowOrNull_error_forwarded(id) VALUES (0);
    `, null, null).resultEnforce;

    psql.prepare(
        "test_onDataRowOrNull_error_forwarded", 
        "SELECT * FROM test_onDataRowOrNull_error_forwarded", 
        null
    ).resultEnforce;
    auto result = psql.bindDescribeExecuteGc(
        "test_onDataRowOrNull_error_forwarded",
        null,
        null,
        bindParameterOrNull: null,
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.noError,
        onDataRowOrNull: (columnCount, scope nextData) => Result.make(DummyError.e),
    );
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}

@Test("bindDescribeExecute - bindParameterOrNull error is forwarded")
@ExpectResult!DummyError
Result test_bindDescribeExecute_bindParameterOrNull_error_forwarded()
{
    PostgresProtocol psql = connectToPsql();
    psql.simpleQuery(`
        DROP TABLE IF EXISTS test_bindDescribeExecute_bindParameterOrNull_error_forwarded;
        
        CREATE TABLE test_bindDescribeExecute_bindParameterOrNull_error_forwarded(id INTEGER PRIMARY KEY);
        
        INSERT INTO test_bindDescribeExecute_bindParameterOrNull_error_forwarded(id) VALUES (0);
    `, null, null).resultEnforce;

    psql.prepare(
        "test_bindDescribeExecute_bindParameterOrNull_error_forwarded", 
        "SELECT * FROM test_bindDescribeExecute_bindParameterOrNull_error_forwarded WHERE id = $1", 
        null
    ).resultEnforce;
    auto result = psql.bindDescribeExecuteGc(
        "test_bindDescribeExecute_bindParameterOrNull_error_forwarded",
        null,
        null,
        bindParameterOrNull: (const paramIndex, scope ref psql, scope out moreParamsLeftToBind) => Result.make(DummyError.e), // @suppress(dscanner.style.long_line)
        onRowDescriptionOrNull: (columnCount, scope nextDescription) => Result.noError,
        onDataRowOrNull: (columnCount, scope nextData) => Result.noError,
    );
    enforce(psql.isReadyToQuery, "PostgresProtocol should've error corrected");
    return result;
}