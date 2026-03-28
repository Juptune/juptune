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
        this._threads ~= this.initThreadNoGc(initialFiber);

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
        this._threads ~= this.initThreadGc(initialFiber);

        const index = this._threads.length-1; // @suppress(dscanner.suspicious.length_subtraction)
        this._threads[$-1].gcThread = new Thread((){
            loopThreadMain!true(this._threads[index]);
        });
        this._threads[$-1].gcThread.start();
    }

    /++
     + Similar to `addNoGCThread` and `addGCThread`, except the caller thread will immediately block until, 
     + waiting until the thread spawned by this function resolves.
     +
     + This function is useful if some preliminary or one-off work that makes use of Juptune's event loop is needed
     + before calling `join`.
     +
     + e.g. This function can be used to open a socket that is then shared across multiple different event loop threads.
     + ++/
    void execNoGC(JuptuneFiber.EntryPointNoGC fiber)
    {
        auto thread = this.initThreadNoGc(fiber);
        thread.lowLevelThread = createLowLevelThread((){
            loopThreadMain!false(thread);
        });
        this.joinThread(thread);
    }

    /// ditto.
    void execGC(JuptuneFiber.EntryPointGC fiber)
    {
        auto thread = this.initThreadGc(fiber);
        thread.gcThread = new Thread((){
            loopThreadMain!true(thread);
        });
        thread.gcThread.start();
        this.joinThread(thread);
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
        foreach(ref thread; this._threads)
            this.joinThread(thread);

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

    private void joinThread(LoopThread* thread)
    {
        import std.exception : assumeWontThrow;

        if(thread.isGCThread)
            thread.gcThread.join(false).assumeWontThrow;
        else
            joinLowLevelThread(thread.lowLevelThread);
}

    private LoopThread* initThreadNoEntrypoint()
    {
        auto thread = new LoopThread();
        thread.loop = cast(shared)&this;
        thread.fiberAllocatorConfig = this._config.fiberAllocator;
        thread.ioUringConfig = this._config.ioUring;

        return thread;
    }

    private LoopThread* initThreadNoGc(JuptuneFiber.EntryPointNoGC initialFiber)
    {
        auto thread = this.initThreadNoEntrypoint();
        thread.isGCThread = false;
        thread.lowLevelEntry = initialFiber;
        return thread;
    }

    private LoopThread* initThreadGc(JuptuneFiber.EntryPointGC initialFiber)
    {
        auto thread = this.initThreadNoEntrypoint();
        thread.isGCThread = true;
        thread.gcEntry = initialFiber;
        return thread;
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
    bool submitQueueIsFull;
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
    return loopThread.fiberAllocator.allocatedFiberCount;
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