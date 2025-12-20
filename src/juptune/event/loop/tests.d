module juptune.event.loop.tests;

import core.atomic, core.thread;
import juptune.core.ds, juptune.core.util;
import juptune.event.fiber, juptune.event.iouring, juptune.event.loop;

/++++ Tests (TODO: Migrate them to the correct files.) ++++/

@("EventLoop - @nogc - simple sanity test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        yield().resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("EventLoop - @gc - simple sanity test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() nothrow {
        auto forceGCFiber = new int(); // @suppress(dscanner.suspicious.unused_variable)
        yield().resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("EventLoop - @nogc - simple submit test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        juptuneEventLoopSubmitEvent(IoUringNop(), IoUringCompletion.ignore).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.addNoGCThread(() @nogc nothrow {
        juptuneEventLoopSubmitEvent(
            IoUringNop(),
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false)
        ).resultAssert;
        yield().resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("EventLoop - @gc - simple submit test")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addGCThread(() nothrow {
        auto forceGCFiber = new int(); // @suppress(dscanner.suspicious.unused_variable)
        juptuneEventLoopSubmitEvent(IoUringNop(), IoUringCompletion.ignore).resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.addGCThread(() nothrow {
        auto forceGCFiber = new int(); // @suppress(dscanner.suspicious.unused_variable)
        juptuneEventLoopSubmitEvent(
            IoUringNop(),
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false)
        ).resultAssert;
        yield().resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("EventLoop - @nogc - small async spam test")
unittest
{
    // import core.atomic : atomicOp, atomicLoad;

    // // NOTE: Run `sudo sysctl -n vm.max_map_count` to see how many mappings by default
    // //       an application can have.
    // //
    // //       You can't really set these values too high if your map count is low,
    // //       and on some systems you'll find that the program hangs; likely because
    // //       the fault handler also can't create mappings anymore.
    // enum THREADS        = 8;
    // enum FIBERS         = 1;
    // enum EXPECTED_COUNT = THREADS * FIBERS;
    // static shared int count;

    // auto loop = EventLoop(EventLoopConfig());
    // foreach(_; 0..THREADS)
    // {
    //     loop.addNoGCThread(() @nogc nothrow {
    //         static int threadCount;
    //         foreach(__; 0..FIBERS)
    //         {
    //             async(()@nogc nothrow{
    //                 threadCount++;

    //                 if(threadCount == FIBERS)
    //                     atomicOp!"+="(count, threadCount);
    //             }).resultAssert;
    //         }
    //     });
    // }
    // while(count.atomicLoad != EXPECTED_COUNT){}
    // loop._cancelToken.cancel();
    // loop.join();
}

@("EventLoop - @nogc - async with context")
unittest
{
    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        int a = 21;
        async((){
            assert(*juptuneEventLoopGetContext!int() == 21);
            juptuneEventLoopCancelThread();
        }, a).resultAssert;
    });
    loop.join();
}

@("EventLoop - @nogc - context dtor on fiber end")
unittest
{
    __gshared int i;

    static struct S
    {
        bool enabled;
        ~this() @nogc nothrow
        {
            if(this.enabled)
                i++;
        }
    }

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        foreach(_; 0..4)
        {
            S s = S(true);
            async((){}, s, &asyncMoveSetter!S).resultAssert;
        }

        yield().resultAssert;
        juptuneEventLoopCancelThread();
    });
    loop.join();
    assert(i == 4);
}

@("EventLoop - @nogc - context dtor on thread cancel")
unittest
{
    __gshared int i;

    static struct S
    {
        bool enabled;
        ~this() @nogc nothrow
        {
            if(this.enabled)
                i++;
        }
    }

    auto loop = EventLoop(EventLoopConfig());
    loop.addNoGCThread(() @nogc nothrow {
        foreach(_; 0..4)
        {
            S s = S(true);
            async((){}, s, &asyncMoveSetter!S).resultAssert;
        }
        juptuneEventLoopCancelThread();
    });
    loop.join();
    assert(i == 4);
}