/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.loop.core;

import core.atomic, core.thread;
import juptune.core.ds, juptune.core.util;
import juptune.event.fiber, juptune.event.iouring, juptune.event.loop;

/++++ Configuration ++++/

package
{
    enum USER_DATA_IGNORE = null;
}

/// Configuration for an `EventLoop`
struct EventLoopConfig
{
    IoUringConfig ioUring; /// Configuration for the EventLoop's io_uring driver.
    FiberAllocatorConfig fiberAllocator; /// Configuration for the EventLoop's fiber allocator.
    
    version(unittest)
        bool handleSigterm = false; // handleSigterm enforces a single EventLoop if true - not suitable for unittests
    else
        bool handleSigterm = true;

    @safe @nogc nothrow pure:

    EventLoopConfig withIoUringConfig(IoUringConfig conf) return { this.ioUring = conf; return this; }
    EventLoopConfig withFiberAllocatorConfig(FiberAllocatorConfig conf) return { this.fiberAllocator = conf; return this; } // @suppress(dscanner.style.long_line)
    EventLoopConfig withSigtermHandler(bool value) return { this.handleSigterm = value; return this; }
}

shared struct CancelToken
{
    shared @nogc nothrow:

    private bool _cancelled;

    @disable this(this){}

    bool isCancelled() @safe
    {
        return this._cancelled.atomicLoad;
    }

    void cancel() @safe
    {
        this._cancelled.atomicStore(true);
    }
}

/++++ Event loop ++++/

/++
 + Provides an EventLoop.
 +
 + Please see the repo's documentation for more information about the event loop and how it works.
 +
 + Multiple event loops may exist per thread.
 + ++/
struct EventLoop
{
    import core.atomic : cas;
    version(Posix) import core.sys.posix.signal : SIGTERM, SIGABRT;
    version(linux) import juptune.core.internal.linux;

    private
    {
        __gshared bool g_sigtermLock;
        bool _hasLock;

        LoopThread*[] _threads;
        immutable EventLoopConfig _config;
        shared CancelToken* _cancelToken;
    }

    nothrow:

    @disable this(this){}

    this(EventLoopConfig config)
    {
        this._config = config;
        this._cancelToken = new shared CancelToken();

        version(linux)
        if(config.handleSigterm)
        {
            this._hasLock = cas(&g_sigtermLock, false, true);
            assert(this._hasLock, "Only one EventLoop with sigterm handling can exist at any given time.");

            linuxSetSignalHandler!SIGTERM(() shared {
                this._cancelToken.cancel();
            });
        }
    }
    
    ~this()
    {
        this._cancelToken.cancel();
        this.join();

        version(linux)
        if(this._config.handleSigterm && this._hasLock)
        {
            linuxResetSignalHandler!SIGTERM();

            this._hasLock = !cas(&g_sigtermLock, true, false);
            assert(!this._hasLock, "Something else already unlocked sigterm handling?");
        }
    }

    /++
     + Creates a new thread that is specifically for @nogc code.
     +
     + The thread is started immediately.
     +
     + The thread is not managed by the DRuntime, so it is free from being paused by the GC.
     +
     + However please note that this means pointers into GC memory should never be present
     + in the thread, as the GC does not scan any of the memory used by the thread.
     +
     + You are also limited to @nogc fibers. Attempting to start an @gc fiber will fail an assert.
     +
     + Please refer to the repo's documentation for any further info, as it's a bit too cumbersome
     + for a source code comment.
     +
     + Params:
     +  initialFiber = The initial fiber to run within the thread.
     + ++/
    void addNoGCThread(JuptuneFiber.EntryPointNoGC initialFiber)
    {
        this._threads ~= new LoopThread();
        this._threads[$-1].loop = cast(shared)&this;
        this._threads[$-1].isGCThread = false;
        this._threads[$-1].lowLevelEntry = initialFiber;
        this._threads[$-1].fiberAllocatorConfig = this._config.fiberAllocator;
        this._threads[$-1].ioUringConfig = this._config.ioUring;

        const index = this._threads.length-1; // @suppress(dscanner.suspicious.length_subtraction)
        this._threads[$-1].lowLevelThread = createLowLevelThread((){
            loopThreadMain!false(this._threads[index]);
        });
    }

    /++
     + Creates a new thread.
     +
     + The thread is started immediately.
     +
     + The thread is managed by the DRuntime, so it can be paused by the GC.
     +
     + However this means you are free to use the GC within this thread, and are not restricted
     + to @nogc fibers.
     +
     + Please refer to the repo's documentation for any further info, as it's a bit too cumbersome
     + for a source code comment.
     +
     + Params:
     +  initialFiber = The initial fiber to run within the thread.
     + ++/
    void addGCThread(JuptuneFiber.EntryPointGC initialFiber)
    {
        this._threads ~= new LoopThread();
        this._threads[$-1].loop = cast(shared)&this;
        this._threads[$-1].isGCThread = true;
        this._threads[$-1].gcEntry = initialFiber;
        this._threads[$-1].fiberAllocatorConfig = this._config.fiberAllocator;
        this._threads[$-1].ioUringConfig = this._config.ioUring;

        const index = this._threads.length-1; // @suppress(dscanner.suspicious.length_subtraction)
        this._threads[$-1].gcThread = new Thread((){
            loopThreadMain!true(this._threads[index]);
        });
        this._threads[$-1].gcThread.start();
    }

    /++
     + Blocks the current thread until all threads have finished.
     +
     + It should go without saying since this function isn't `shared`, but this function
     + is not thread-safe.
     +
     + Throws:
     +  If an @gc thread for some reason throws an uncaught exception, an assert will fail.
     +  This _shouldn't_ happen unless you somehow bypass the fact that fibers are `nothrow`.
     + ++/
    void join()
    {
        import std.exception : assumeWontThrow;

        foreach(ref thread; this._threads)
        {
            if(thread.isGCThread)
                thread.gcThread.join(false).assumeWontThrow;
            else
                joinLowLevelThread(thread.lowLevelThread);
        }

        this._threads.length = 0;
        *_cancelToken = CancelToken();
    }

    /++
     + Cancels all active threads.
     +
     + See_Also:
     +  `juptuneEventLoopCancelThread` for information on what canceling entails.
     + ++/
    void cancelAllThreads() @nogc shared
    {
        this._cancelToken.cancel();
    }
}

/++++ Event thread ++++/

package LoopThread* g_thisLoopThread;
package struct LoopThread
{
    @disable this(this){}

    shared EventLoop* loop;
    
    // Config
    IoUringConfig ioUringConfig;
    FiberAllocatorConfig fiberAllocatorConfig;

    // Management info
    bool isGCThread;
    shared CancelToken cancelToken;
    union
    {
        struct 
        {
            ThreadID lowLevelThread;
            JuptuneFiber.EntryPointNoGC lowLevelEntry;
        }

        struct
        {
            Thread gcThread;
            JuptuneFiber.EntryPointGC gcEntry;
        }
    }

    // State
    FiberAllocator fiberAllocator;
    IoUring ioUring;
    ArrayNonShrink!(JuptuneFiber*) yieldedFibers;
    ArrayNonShrink!(JuptuneFiber*) yieldedFibersSubmitQueueIsFull;
    ArrayNonShrink!(JuptuneFiber*) fibersToWakeUpLast;
    EventLoopThreadStats stats;
    bool submitQueueIsFull;
}

/++
 + A simple struct used to track certain stats of the EventLoop.
 + ++/
struct EventLoopThreadStats
{
    ulong cqeTotal; /// How many CQEs have been generated in total
    ulong cqeIgnored; /// How many CQEs have been ignored (e.g because their user data is USER_DATA_IGNORE) in total
    ulong cqeAwokeFiber; /// How many CQEs have caused a fiber to wake up in total
    invariant(cqeTotal == cqeIgnored + cqeAwokeFiber);

    ulong fibersWaitingOnIo; /// How many fibers are actively waiting for an io_uring CQE to wake them up
}

package void loopThreadOnAfterFiberSwap(scope ref JuptuneFiber* fiber) @nogc nothrow
{
    if(fiber.state != JuptuneFiber.State.finished)
        return;

    scope loopThread = juptuneLoopThreadGetThis();
    loopThread.fiberAllocator.freeFiber(fiber);
}

package LoopThread* juptuneLoopThreadGetThis() @nogc nothrow
in(g_thisLoopThread !is null, "This function was called outside of the event loop")
{
    return g_thisLoopThread;
}

package size_t juptuneLoopThreadGetFiberCount() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    size_t sum;
    
    sum += loopThread.fiberAllocator.allocatedFiberCount;
    sum += loopThread.stats.fibersWaitingOnIo;

    return sum;
}

package IoUringCompletion juptuneEventLoopGetLastCompletion() @nogc nothrow
{
    scope fiber = juptuneFiberGetThis();
    assert(!fiber.lastCqe.isNull, "No completion since last call. This is likely a procesing flow bug.");

    auto ret = fiber.lastCqe.get();
    fiber.lastCqe.nullify();
    return ret;
}

/++++ User Facing stuff ++++/


/++
 + Cancels the current event loop thread.
 +
 + More specifically, canceling a thread means that `juptuneEventLoopIsThreadCanceled` will now return
 + `true`, and it will also cause functions like `yield` to start returning a `Result` that contains an error.
 +
 + Canceling is intended for when the thread needs to gracefully shutdown ASAP. Application code should
 + currently refrain from attempting to perform any action that generates an io_uring event, as it
 + may be dropped or completely ignored.
 +
 + The exact behaviour of canceling threads is in a bit of development limbo right now, so try
 + to not make too many assumptions on what you're allowed to do. I hope to properly refine this
 + over time into something more exact.
 +
 + See_Also:
 +  `juptuneEventLoopCancelAllThreads`, `juptuneEventLoopIsthreadCanceled`, `yield`
 + ++/
void juptuneEventLoopCancelThread() @nogc nothrow
{
    juptuneLoopThreadGetThis().cancelToken.cancel();
}

/++
 + Cancels all threads in the event loop.
 +
 + Please see `juptuneEventLoopCancelThread` for more specifics on what canceling a thread entails.
 +
 + See_Also:
 +  `juptuneEventLoopCancelThread`, `juptuneEventLoopIsthreadCanceled`, `yield`
 + ++/
void juptuneEventLoopCancelAllThreads() @nogc nothrow
{
    juptuneLoopThreadGetThis().loop._cancelToken.cancel();
}

/++
 + Determines if the current thread has been canceled.
 +
 + It's best practice to write your code in a way that supports gracefully exiting,
 + especially when explicitly requested from a thread being canceled.
 +
 + There's some mechanisms in place to encourage this, such as `yield`-like functions
 + returning an error-containing `Result` when a thread is canceled, however
 + sometimes manually checking the state of the thread's cancel status is desirable.
 +
 + Returns:
 +  `true` if the thread has been canceled, `false` otherwise.
 + ++/
bool juptuneEventLoopIsThreadCanceled() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    return loopThread.cancelToken.isCancelled
        || loopThread.loop._cancelToken.isCancelled;
}

/++
 + Accesses the current event loop's `EventLoopThreadStats`.
 +
 + This is a pointer to the live underlying data, so will always be up to date.
 +
 + Returns:
 +  A pointer to the event loop's `EventLoopThreadStats`.
 + ++/
const(EventLoopThreadStats)* juptuneEventLoopGetStats() scope @nogc nothrow
{
    return &juptuneLoopThreadGetThis().stats;
}