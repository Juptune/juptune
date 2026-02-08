/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.loop.mutex;

version(linux):

import juptune.core.internal.linux : linuxErrorAsResult;
import juptune.core.util : Result;

enum MutexError
{
    none,
    mutexTornDown, /// The mutex's dtor was called while waiting to lock it, this is a failsafe state, please try to never actually rely on this functionality.
}

/++
 + A basic, thread-safe mutex that's properly integrated with Juptune's event loop.
 +
 + Notes:
 +  When the mutex's dtor is called it will attempt to signal an error to 
 +  all waiters in an attempt to prevent fibers from permanently sleeping.
 +
 +  If the mutex has any waiters, it is not safe to move it.
 +
 +  This is - unfortunately - not 100% reliable currently so please try not to rely on this failsafe functionality.
 + ++/
shared struct Mutex
{
    // Base implementation is from: https://eorlov.org/posts/2023/basics-of-futexes/#implementing-a-mutex-with-futexes
    // (which is ultimately from this paper: https://dept-info.labri.fr/~denis/Enseignement/2008-IR/Articles/01-futex.pdf)

    enum UNLOCKED = 0;
    enum LOCKED = 1;
    enum LOCKED_WITH_WAITERS = 2;
    enum TEARDOWN = 10;

    private
    {
        int _futexValue;
    }

    @disable this(this){}

    @nogc nothrow:

    ~this()
    {
        import core.atomic : atomicStore;
        import juptune.event.loop.async : juptuneEventLoopSubmitEvent, SubmitEventConfig;
        import juptune.event.iouring : IoUringFutexWake, IoUringCompletion;

        atomicStore(this._futexValue, TEARDOWN);

        IoUringFutexWake op;
        op.forThisPointer = cast(int*)&this._futexValue; // cast away shared
        op.wakeThisManyWaiters = int.max;
        op.bitmask = ulong.max;

        cast(void)juptuneEventLoopSubmitEvent(
            op,
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false),
        );
    }

    /++
     + Acquires the mutex's lock, yielding the current fiber until the lock has been acquired if needed.
     +
     + Notes:
     +  Since this integrates with Juptune's event loop, if the fiber is yielded it won't have another chance to run
     +  until the next tick of the event loop.
     +
     + Throws:
     +  `MutexError.mutexTornDown` sometimes if this mutex's dtor was somehow called while we're waiting to acquire its lock (not 100% reliable failsafe to prevent stuck fibers).
     +
     +  Anything that `juptuneEventLoopSubmitEvent` can.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result lock()
    {
        import core.atomic : cas;
        import juptune.event.loop.async : juptuneEventLoopSubmitEvent;
        import juptune.event.iouring : IoUringFutexWait, IoUringCompletion;

        auto compare = UNLOCKED;
        cas(&this._futexValue, &compare, LOCKED);
        if(compare != UNLOCKED)
        {
            do
            {
                if(compare == LOCKED_WITH_WAITERS)
                {
                    compare = LOCKED;
                    cas(&this._futexValue, &compare, LOCKED_WITH_WAITERS);
                    if(compare != UNLOCKED)
                    {
                        IoUringCompletion cqe;

                        IoUringFutexWait op;
                        op.watchThisPointer = cast(int*)&this._futexValue; // cast away shared
                        op.untilItsThisValue = LOCKED_WITH_WAITERS;
                        op.bitmask = ulong.max;

                        auto result = juptuneEventLoopSubmitEvent(op, cqe);
                        if(result.isError)
                            return result; // safe, since we don't have the lock anyway.
                    }
                }
                else if(compare >= TEARDOWN)
                    return Result.make(MutexError.mutexTornDown, "mutex was destroyed while waiting to lock (try to fix this in your own code please!)"); // @suppress(dscanner.style.long_line)

                compare = UNLOCKED;
                cas(&this._futexValue, &compare, LOCKED_WITH_WAITERS);
            } while(compare != UNLOCKED);
        }

        return Result.noError;
    }

    /++
     + Unlocks the mutex, regardless of whether the current fiber owns it or not (as exact ownership isn't tracked).
     +
     + Assertions:
     +  This mutex must be locked.
     +
     + Throws:
     +  Anything that `juptuneEventLoopSubmitEvent` can.
     +
     + Returns:
     +  An errorful `Result` if something went wrong.
     + ++/
    Result unlock()
    {
        import core.atomic : atomicFetchSub, atomicStore;
        import juptune.event.loop.async : juptuneEventLoopSubmitEvent;
        import juptune.event.iouring : IoUringFutexWake, IoUringCompletion;

        const oldValue = atomicFetchSub(this._futexValue, 1);
        assert(oldValue != UNLOCKED, "attempted to unlock an already unlocked fiber - you probably have a data race");
        if(oldValue != LOCKED)
        {
            const inTeardownState = oldValue < TEARDOWN-1;
            if(!inTeardownState)
                atomicStore(this._futexValue, UNLOCKED);

            IoUringCompletion cqe;

            IoUringFutexWake op;
            op.forThisPointer = cast(int*)&this._futexValue; // cast away shared
            op.wakeThisManyWaiters = ((inTeardownState) ? int.max : 1);
            op.bitmask = ulong.max;

            auto result = juptuneEventLoopSubmitEvent(op, cqe);
            if(result.isError)
                return result; // safe, since we've just released the lock (although rip to any waiting fibers who are perma sleeping).
        }

        return Result.noError;
    }
}

/++ Unittests ++/

// @("manual debug (since it needs to sleep)")
// unittest
// {
//     import core.time : seconds;
//     import core.thread : Thread;

//     import std.stdio : writeln;

//     import juptune.core.util : resultAssert;
//     import juptune.event;

//     __gshared Mutex mutex;

//     auto loop = EventLoop(EventLoopConfig());
//     loop.addGCThread(() nothrow {
//         debug writeln("1 - start");
//         mutex.lock().resultAssert;
//         debug writeln("1 - got");
//         Thread.sleep(2.seconds);
//         debug writeln("1 - slept");
//         mutex.unlock().resultAssert;
//         debug writeln("1 - unlocked");
//         // mutex.__xdtor();
//     });
//     loop.addGCThread(() nothrow {
//         debug writeln("2 - start");
//         mutex.lock().resultAssert;
//         debug writeln("2 - got");
//         Thread.sleep(2.seconds);
//         debug writeln("2 - slept");
//         mutex.unlock().resultAssert;
//         debug writeln("2 - unlocked");
//     });
//     loop.join();
// }