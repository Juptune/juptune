module testlib;

import std.sumtype : SumType, match;

import juptune.core.util : Result;

/++ UDAs for tests ++/

enum TestRunType
{
    FAILSAFE,
    
    /// The test is happy to run in an event loop thread shared with other tests of this type.
    /// May still be executed in a multithreaded environment, if multiple threads are spun up for tests of this type.
    sharedEventLoopThread,
}

struct Test
{
    string name;
    TestRunType runType = TestRunType.sharedEventLoopThread;
}

/++ Test Runner ++/

alias TestResult = SumType!(TestPassed, TestFailed);

struct TestPassed
{

}

struct TestFailed
{
    Result* thrownResult; // may be null if an exception was thrown instead
    Exception thrownException; // may be null if a result was thrown instead.
}

mixin template RegisterTests(alias ModuleSymbol)
{
    shared static this()
    {
        import std.format   : format;
        import std.traits   : fullyQualifiedName, getSymbolsByUDA, getUDAs;
        import testlib;

        static immutable ModuleFqn = fullyQualifiedName!ModuleSymbol;
        alias TestFuncTuple = getSymbolsByUDA!(ModuleSymbol, Test);

        static foreach(TestFuncSymbol; TestFuncTuple)
        {{
            enum TestUda = getUDAs!(TestFuncSymbol, Test)[0];

            TestHarness.Case testCase;
            testCase.name = format("[%s] %s", ModuleFqn, TestUda.name);
            testCase.runType = TestUda.runType;
            testCase.testFunc = () => TestFuncSymbol();

            TestHarness.instance.add(ModuleFqn, testCase);
        }}
    }
}

shared synchronized class TestHarness
{
    alias TestFuncT = Result delegate();

    static struct Case
    {
        string name;
        TestRunType runType;
        TestFuncT testFunc;
    }

    private static struct CaseExecution
    {
        Case testCase;
        TestResult result;
    }

    private
    {
        Case[][string] _casesByModuleFqn;
    }

    void add(string moduleFqn, Case case_)
    {
        scope ptr = moduleFqn in this._casesByModuleFqn;
        if(!ptr)
        {
            this._casesByModuleFqn[moduleFqn] = [];
            ptr = moduleFqn in this._casesByModuleFqn;
        }
        (*ptr) ~= case_;
    }

    static shared(TestHarness) instance()
    {
        __gshared TestHarness _instance;
        if(_instance is null)
            _instance = new TestHarness();
        return _instance;
    }

    int runAllTests(string[] args)
    {
        import std.array     : array;
        import std.algorithm : filter, map;

        import juptune.event : EventLoop, EventLoopConfig;

        /++ Split the tests into execution groups ++/
        __gshared CaseExecution[] sharedEventLoopTests;

        foreach(cases; this._casesByModuleFqn)
        {
            sharedEventLoopTests ~= cases
                                    .filter!(c => c.runType == TestRunType.sharedEventLoopThread)
                                    .map!(c => CaseExecution(c))
                                    .array;
        }

        /++ Begin execution of each group ++/
        auto loop = EventLoop(EventLoopConfig());
        loop.addGCThread((){ executeTestGroup(sharedEventLoopTests); });
        loop.join();

        /++ Print out results ++/
        const _ = printResultsAsTap(sharedEventLoopTests);
        return 0;
    }
}

private bool printResultsAsTap(TestHarness.CaseExecution[][] groups...)
{
    import std.string : lineSplitter;
    import std.stdio  : writeln, writefln;

    bool anyErrors;

    size_t totalTestCount;
    foreach(group; groups)
        totalTestCount += group.length;

    writeln("1..", totalTestCount);

    size_t indexOffset = 0;
    foreach(group; groups)
    {
        foreach(i, exec; group)
        {
            const index = indexOffset + i + 1;

            exec.result.match!(
                (TestPassed _) { writefln("ok %s - %s", index, exec.testCase.name); },
                (TestFailed failed) {
                    anyErrors = true;

                    writefln("not ok %s - %s", index, exec.testCase.name);
                    writeln("#  ---");
                    if(failed.thrownException !is null)
                    {
                        writeln("#  failType: exception");
                        writeln("#  exception:");
                        writeln("#    message: |");

                        const msg = failed.thrownException.toString();
                        foreach(line; msg.lineSplitter)
                            writeln("#      ", line);
                    }
                    else if(failed.thrownResult !is null)
                    {
                        writeln("#  failType: result");
                        writeln("#  result:");
                        writeln("#    errorType: ", failed.thrownResult.errorType);
                        writeln("#    errorCode: ", failed.thrownResult.errorCode);
                        writeln("#    location:  ", failed.thrownResult.file, ":", failed.thrownResult.line);
                        writeln("#    function:  ", failed.thrownResult.function_);
                        writeln("#    fullMessage: |");

                        const msg = failed.thrownResult.error ~ "\n" ~ failed.thrownResult.context.slice;
                        foreach(line; msg.lineSplitter)
                            writeln("#      ", line);
                    }
                    writeln("#  ...\n");
                }
            );
        }
        indexOffset += group.length;
    }

    return anyErrors;
}

private void executeTestGroup(scope TestHarness.CaseExecution[] group) nothrow
{
    foreach(ref exec; group)
    {
        try
        {
            auto result = exec.testCase.testFunc();
            if(result.isError)
            {
                import core.memory : GC;

                TestFailed failed;
                failed.thrownResult = cast(Result*)GC.malloc(Result.sizeof);
                (*failed.thrownResult) = result;

                exec.result = failed;
                continue;
            }

            exec.result = TestPassed();
        }
        catch(Exception ex)
        {
            exec.result = TestFailed(thrownException: ex);
        }
    }
}