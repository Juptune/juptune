/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.loop;

import core.atomic, core.thread;
import juptune.core.ds, juptune.core.util;
import juptune.event.fiber, juptune.event.iouring;

/++++ Configuration ++++/

private
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
    EventLoopConfig withFiberAllocatorConfig(FiberAllocatorConfig conf) return { this.fiberAllocator = conf; return this; }
    EventLoopConfig withSigtermHandler(bool value) return { this.handleSigterm = value; return this; }
}

struct CancelToken
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
    version(linux) import juptune.event.internal.linux;

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

private LoopThread* g_thisLoopThread;
private struct LoopThread
{
    @disable this(this){}

    shared EventLoop* loop;

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
    EventLoopThreadStats stats;
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

private void loopThreadMain(bool IsGCThread)(scope LoopThread* loopThread) nothrow
{
    assert(g_thisLoopThread is null);
    g_thisLoopThread = loopThread;

    loopThread.fiberAllocator = FiberAllocator(loopThread.loop._config.fiberAllocator);
    loopThread.ioUring = IoUring(loopThread.loop._config.ioUring);
    scope(exit) loopThread.__xdtor();

    juptuneFiberThreadInit();

    static if(!IsGCThread)
    {
        if(loopThread.lowLevelEntry !is null)
            async(loopThread.lowLevelEntry).resultAssert;
    }
    else
    {
        if(loopThread.gcEntry !is null)
            async(loopThread.gcEntry).resultAssert;
    }

    while(true)
    {
        // Handle io_uring
        loopThread.ioUring.opDispatch!"enter"(loopThread.yieldedFibers.length > 0 ? 0 : 1); // Only wait if we have no yields to attend to
        loopThread.ioUring.opDispatch!"processCompletions"((IoUringCompletion c) nothrow @nogc 
        {
            loopThread.stats.cqeTotal++;

            if(c.userData is USER_DATA_IGNORE)
            {
                loopThread.stats.cqeIgnored++;
                return;
            }

            const tag = cast(JuptuneUringUserDataTag)*cast(ubyte*)c.userData;

            final switch(tag)
            {
                case JuptuneUringUserDataTag.JuptuneFiber:
                    scope fiber = cast(JuptuneFiber*)c.userData;
                    assert(fiber.isInWaitingState);

                    loopThread.stats.cqeAwokeFiber++;
                    fiber.state = JuptuneFiber.state.running;
                    fiber.lastCqe = c;
                    juptuneFiberSwap(fiber);
                    loopThreadOnAfterFiberSwap(fiber);
                    break;

                case JuptuneUringUserDataTag.FAILSAFE:
                    assert(false, "Unexpected tag value for CQE userdata");
            }
        });

        // Handle non-io yielded fibers
        const yieldedFiberCount = loopThread.yieldedFibers.length;
        foreach(i; 0..yieldedFiberCount)
        {
            scope fiber = loopThread.yieldedFibers[i];
            fiber.state = JuptuneFiber.State.running;
            juptuneFiberSwap(fiber);
            loopThreadOnAfterFiberSwap(fiber);
            loopThread.yieldedFibers[i] = null;
        }

        const yieldedFiberDiff = loopThread.yieldedFibers.length - yieldedFiberCount;
        if(yieldedFiberDiff == 0)
            loopThread.yieldedFibers.length = 0;
        else
        {
            loopThread.yieldedFibers[0..yieldedFiberDiff] = loopThread.yieldedFibers[yieldedFiberCount..$];
            loopThread.yieldedFibers.length = yieldedFiberDiff;
        }

        if(juptuneLoopThreadGetFiberCount() == 0)
            break;

        // Keep informing fibers that the thread is canceled until they all finish up.
        if(loopThread.loop._cancelToken.isCancelled)
        {
            // TODO: mmmm, needs a lot more thought since this breaks the expected data flow
            // loopThread.fiberAllocator.iterateAliveFibers((scope fiber)
            // {
            //     fiber.state = JuptuneFiber.state.running;
            //     fiber.lastCqe = IoUringCompletion.init;
            //     fiber.lastCqe.get.juptuneFlags = IoUringCompletion.JuptuneFlags.threadWasCanceled;
            //     fiber.lastCqe.get.result = uint.max;
            //     juptuneFiberSwap(fiber);
            //     loopThreadOnAfterFiberSwap(fiber);
            // });
            break;
        }
    }
}

private void loopThreadOnAfterFiberSwap(scope ref JuptuneFiber* fiber) @nogc nothrow
{
    if(fiber.state != JuptuneFiber.State.finished)
        return;

    scope loopThread = juptuneLoopThreadGetThis();
    loopThread.fiberAllocator.freeFiber(fiber);
}

private LoopThread* juptuneLoopThreadGetThis() @nogc nothrow
in(g_thisLoopThread !is null, "This function was called outside of the event loop")
{
    return g_thisLoopThread;
}

private size_t juptuneLoopThreadGetFiberCount() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    size_t sum;
    
    sum += loopThread.fiberAllocator.allocatedFiberCount;
    sum += loopThread.stats.fibersWaitingOnIo;

    return sum;
}

private void juptuneLoopThreadAsyncYield() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    loopThread.stats.fibersWaitingOnIo++;

    scope fiber = juptuneFiberGetThis();
    fiber.state = JuptuneFiber.State.waitingForCompletionEvent;
    juptuneFiberSwap(juptuneFiberGetRoot());
    loopThread.stats.fibersWaitingOnIo--;
}

private IoUringCompletion juptuneEventLoopGetLastCompletion() @nogc nothrow
{
    scope fiber = juptuneFiberGetThis();
    assert(!fiber.lastCqe.isNull, "No completion since last call. This is likely a procesing flow bug.");

    auto ret = fiber.lastCqe.get();
    fiber.lastCqe.nullify();
    return ret;
}

/++++ User Facing stuff ++++/

import std.typecons : Flag;

/// See `yield`
alias YieldUntilCompletion = Flag!"yieldUntilCompletion";

/// Configuration for submitting an event
struct SubmitEventConfig
{
    YieldUntilCompletion yieldUntilComplete = YieldUntilCompletion.yes; /// Whether the fiber should yield until a CQE is generated

    @nogc nothrow pure:

    SubmitEventConfig shouldYieldUntilCompletion(bool value) return { this.yieldUntilComplete = cast(YieldUntilCompletion)value; return this; }
}

/// Configuration for creating an async fiber
struct AsyncConfig
{
    /// Configures where a fiber's user context is placed in memory.
    enum ContextMethod
    {
        /++
         + Automatically decides which method to use based on the user context's size.
         +
         + Otherwise `endOfStack` is chosen as the main fallback.
         + ++/
        defaultBySize,

        /++
         + Places the user context at the very end of the fiber's stack.
         +
         + This is fast in the sense the memory is already allocated.
         +
         + This is unsafe in the sense that, if the fiber manages to reach the end the stack, the
         + context is at risk of being overwritten.
         +
         + On the other hand if the fiber is that far into its stack, chances are it will crash anyway
         + from bleeding over into a guard page.
         + ++/
        endOfStack,
    }
    ContextMethod contextMethod; /// Where to place the user context in memory.

    @nogc nothrow pure:

    AsyncConfig withContextMethod(ContextMethod value) return { this.contextMethod = value; return this; }
}

/// A `Result` error enum
enum JuptuneEventLoopError
{
    none,

    /++
     + Returned by some functions to inform the fiber that the thread has been canceled,
     + and should begin to gracefully exit.
     + ++/
    threadWasCanceled
}

/++
 + Creates an async fiber, and schedules it to run on the next event loop tick.
 +
 + Async fibers are fibers that run on the current event loop thread, and so are
 + safe to make use of thread local storage and other thread local techniques.
 +
 + This overload doesn't create a user context.
 +
 + Params:
 +  func = The function to call into once the fiber is started.
 +  config = The configuration used for launching the fiber.
 +
 + Throws:
 +  (For the @gc overload) Asserts that this event loop thread is a GC thread.
 +
 +  Anything that `FiberAllocator.allocateFiber` throws.
 + ++/
Result async(JuptuneFiber.EntryPointNoGC func, AsyncConfig config = AsyncConfig()) @nogc nothrow
{
    return asyncNoContextImpl(func, config);
}

/// ditto
Result async(JuptuneFiber.EntryPointGC func, AsyncConfig config = AsyncConfig()) @nogc nothrow
{
    if(!juptuneLoopThreadGetThis().isGCThread)
        assert(false, "Attempted to create @gc fiber in @nogc event loop thread. Perhaps mark the fiber function explicitly with @nogc, or use addGCThread instead of addNoGCThread."); // @suppress(dscanner.style.long_line)
    return asyncNoContextImpl(func, config);
}

private Result asyncNoContextImpl(EntryPointT)(EntryPointT func, AsyncConfig config)
{
    scope loopThread = juptuneLoopThreadGetThis();

    JuptuneFiber* fiber;
    auto result = loopThread.fiberAllocator.allocateFiber(0, func, fiber);
    if(result.isError)
        return result;
    assert(fiber !is null, "Fiber is somehow null");

    if(loopThread.isGCThread)
        fiber.block.informGC();

    fiber.state = JuptuneFiber.State.waitingForReschedule;
    loopThread.yieldedFibers.put(fiber);
    return Result.noError;
}

/++
 + The default setter. Simply tries to do `b = a`.
 +
 + Throws:
 +  Asserts that `ContextT` is a copyable type.
 + ++/
void asyncDefaultSetter(ContextT)(scope ref ContextT a, scope out ContextT b) @nogc nothrow 
{ 
    static if(__traits(isCopyable, ContextT))
        b = a;
    else
        assert(false, ContextT.stringof~" isn't copyable, please use a different setter func");
}

/++
 + A setter that uses `std.algorithm.move` to perform a move operation into the user context's
 + shared memory location.
 +
 + This is best to use for types that are non-copyable, e.g. `TcpSocket`.
 +
 + This, being a move operation, will of course mean your source input will be reverted to .init without
 + having its dtor called.
 +
 + Please note that as with any move operation, be very careful if your context contains an internal pointer.
 +
 + Throws:
 +  Asserts that `ContextT` is a copyable type.
 + ++/
void asyncMoveSetter(ContextT)(scope ref ContextT a, scope out ContextT b) @nogc nothrow
{
    import std.algorithm : move;
    move(a, b);
}

/++
 + Creates an async fiber, and schedules it to run on the next event loop tick.
 +
 + Async fibers are fibers that run on the current event loop thread, and so are
 + safe to make use of thread local storage and other thread local techniques.
 +
 + This overload creates a user context, allowing you to make additional data available to the fiber.
 +
 + Please see `AsyncConfig.ContextMethod` to see how to configure the memory location for the user context.
 +
 + The `setter` function is responsible for setting up the user context memory to best reflect
 + the given `context`.
 +
 + Please see `asyncDefaultSetter` and `asyncMoveSetter` to see what your options are.
 +
 + The user context will have its `__xdtor` called when the fiber finishes.
 +
 + The user context can be accessed by the fiber by calling `juptuneEventLoopGetContext`.
 +
 + D doesn't really have a way to prevent you from passing through a stack point as user context.
 + Do such a thing at your own risk.
 +
 + Params:
 +  func = The function to call into once the fiber is started.
 +  context = The user context.
 +  setter = The function used to setup the user context in its shared memory location.
 +  config = The configuration used for launching the fiber.
 +
 + Throws:
 +  (For the @gc overload) Asserts that this event loop thread is a GC thread.
 +
 +  Anything that `FiberAllocator.allocateFiber` throws.
 +
 + See_Also:
 +  `juptuneEventLoopGetContext`, `asyncDefaultSetter`, `asyncMoveSetter`
 + ++/
Result async(ContextT)(
    JuptuneFiber.EntryPointNoGC func,
    auto ref ContextT context,
    void function(scope ref ContextT value, scope out ContextT contextValue) @nogc nothrow setter = &asyncDefaultSetter!ContextT,
    AsyncConfig config = AsyncConfig(),
) @nogc nothrow
{
    return asyncWithContextImpl!(JuptuneFiber.EntryPointNoGC, ContextT)(func, context, setter, config);
}

/// ditto
Result async(ContextT)(
    JuptuneFiber.EntryPointGC func,
    auto ref ContextT context,
    void function(scope ref ContextT value, scope out ContextT contextValue) @nogc nothrow setter = &asyncDefaultSetter!ContextT,
    AsyncConfig config = AsyncConfig(),
) @nogc nothrow
{
    if(!juptuneLoopThreadGetThis().isGCThread)
        assert(false, "Attempted to create @gc fiber in @nogc event loop thread. Perhaps mark the fiber function explicitly with @nogc, or use addGCThread instead of addNoGCThread."); // @suppress(dscanner.style.long_line)
    return asyncWithContextImpl!(JuptuneFiber.EntryPointGC, ContextT)(func, context, setter, config);
}

private Result asyncWithContextImpl(EntryPointT, ContextT)(
    EntryPointT func,
    auto ref ContextT context,
    void function(scope ref ContextT value, scope out ContextT contextValue) @nogc nothrow setter,
    AsyncConfig config,
) @nogc nothrow
{
    auto result = async(func, config);
    if(result.isError)
        return result;

    scope loopThread = juptuneLoopThreadGetThis();
    scope fiber = loopThread.yieldedFibers[$-1];
    fiber.contextType = typeid(ContextT);
    fiber.contextDtor = function (scope fiberPtr)
    {
        assert(fiberPtr);
        assert(fiberPtr.contextPtr);
        static if(__traits(hasMember, ContextT, "__xdtor"))
            (cast(ContextT*)fiberPtr.contextPtr).__xdtor();
    };

    if(config.contextMethod == AsyncConfig.ContextMethod.defaultBySize)
    {
        config.contextMethod = AsyncConfig.ContextMethod.endOfStack;
    }

    final switch(config.contextMethod) with(AsyncConfig.ContextMethod)
    {
        case defaultBySize: assert(false);

        case endOfStack:
            auto slice = fiber.block.fiberStack[0..ContextT.sizeof];
            auto ptr = &(cast(ContextT[])slice)[0];
            fiber.contextPtr = ptr;
            setter(context, *ptr);
            break;
    }

    return Result.noError;
}

/++
 + Manually yields the current fiber so that other fibers can be ran.
 +
 + Since yielded fibers aren't waiting for IO to complete, the event loop thread will
 + not sleep while there are manually yielded fibers waiting to be woken up.
 +
 + This means that the event loop thread will keep spinning its CPU usage.
 +
 + If you need/want to delay execution of the fiber then please use the (not currently implemented!) `yieldSleep`
 + function instead. This will allow the event loop thread to sleep, easing CPU usage.
 +
 + Throws:
 +  `JuptuneEventLoopError.threadWasCanceled` if the thread has been canceled. This is not
 +  an actual error, but is simply used as a mechanism to encourage you to write code that can gracefully exit
 +  instead of relying on `.resultAssert`
 +
 + Returns:
 +  A `Result`
 + ++/
Result yield() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    auto fiber = juptuneFiberGetThis();
    fiber.state = JuptuneFiber.State.waitingForReschedule;
    loopThread.yieldedFibers.put(fiber);
    juptuneFiberSwap(juptuneFiberGetRoot());

    if(juptuneEventLoopIsThreadCanceled())
        return Result.make(JuptuneEventLoopError.threadWasCanceled, "Thread has been canceled; please abort the fiber gracefully.");

    return Result.noError;
}

/++
 + Submits an event to be processed asynchronously.
 +
 + Note that the `Command` type should be any of the `IoUringXXX` structs found in
 + `juptune.event.iouring`, for example `IoUringAccept`.
 +
 + By default the fiber will be suspended until a completion is generated.
 +
 + If you disable yielding via `SubmitEventConfig.yieldUntilComplete` then the fiber
 + will continue directly after calling this function, however there is currently
 + no mechanism to observe the completion, or if a completion is even generated.
 +
 + You can use `IoUringCompletion.ignore` for the `cqe` parameter if you don't yield, or if
 + you don't care about the completion.
 +
 + Definitely a lot of work left around this area, but for now this should be useable.
 +
 + Generally most users don't need to actually use this function, as it should be wrapped
 + inside a more high-level struct, such as `TcpSocket`.
 +
 + This function will continously yield, regardless of configuration, if the submission
 + queue is too full.
 +
 + Params:
 +  command = The command to submit to io_uring
 +  cqe = The resulting completion. This is only set if the fiber waits for completion.
 +
 + Throws:
 +  Anything that `yield` throws.
 + ++/
Result juptuneEventLoopSubmitEvent(Command)(
    Command command,
    out IoUringCompletion cqe,
    SubmitEventConfig config = SubmitEventConfig()
) @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    auto fiber = juptuneFiberGetThis();

    if(config.yieldUntilComplete)
        command.userData = fiber;
    else
        command.userData = USER_DATA_IGNORE;

    while(loopThread.ioUring.opDispatch!"submit"(command) == SubmitQueueIsFull.yes)
    {
        auto yieldResult = yield();
        if(yieldResult.isError)
            return yieldResult;
    }

    if(config.yieldUntilComplete)
    {
        juptuneLoopThreadAsyncYield();
        cqe = juptuneEventLoopGetLastCompletion();
    }

    return Result.noError;
}

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

/++
 + Accesses the current fibers's user context.
 +
 + When you use the contextful `async` overload it creates a user context in the fiber.
 + This function is how you access the user context.
 +
 + This function is type safe as it uses `TypeInfo` to enforce the user context
 + is the type you expect it to be.
 +
 + Currently I consider it a bug for there to be a mismatch, as it makes no sense
 + to me to optionally support a user context, so this is enforced with an `assert`.
 +
 + Throws:
 +  Asserts that `ContextT` is the same type that was passed into the `async` function.
 +
 +  Asserts that a user context exists for this fiber.
 +
 + Returns:
 +  A pointer to the user context.
 + ++/
ContextT* juptuneEventLoopGetContext(ContextT)() scope @nogc nothrow
{
    scope fiber = juptuneFiberGetThis();
    assert(fiber.contextType is typeid(ContextT), "Context type mismatch");
    assert(fiber.contextPtr !is null, "No context was passed to this fiber");

    return cast(ContextT*)fiber.contextPtr;
}

/++++ Tests ++++/

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
        assert(juptuneEventLoopGetStats().cqeTotal == 1);
        assert(juptuneEventLoopGetStats().cqeIgnored == 0);
        assert(juptuneEventLoopGetStats().cqeAwokeFiber == 1);
        juptuneEventLoopCancelThread();
    });
    loop.addNoGCThread(() @nogc nothrow {
        juptuneEventLoopSubmitEvent(
            IoUringNop(),
            IoUringCompletion.ignore,
            SubmitEventConfig().shouldYieldUntilCompletion(false)
        ).resultAssert;
        yield().resultAssert;
        assert(juptuneEventLoopGetStats().cqeTotal == 1);
        assert(juptuneEventLoopGetStats().cqeIgnored == 1);
        assert(juptuneEventLoopGetStats().cqeAwokeFiber == 0);
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
        assert(juptuneEventLoopGetStats().cqeTotal == 1);
        assert(juptuneEventLoopGetStats().cqeIgnored == 0);
        assert(juptuneEventLoopGetStats().cqeAwokeFiber == 1);
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
        assert(juptuneEventLoopGetStats().cqeTotal == 1);
        assert(juptuneEventLoopGetStats().cqeIgnored == 1);
        assert(juptuneEventLoopGetStats().cqeAwokeFiber == 0);
        juptuneEventLoopCancelThread();
    });
    loop.join();
}

@("EventLoop - @nogc - small async spam test")
unittest
{
    import core.atomic : atomicOp, atomicLoad;

    // NOTE: Run `sudo sysctl -n vm.max_map_count` to see how many mappings by default
    //       an application can have.
    //
    //       You can't really set these values too high if your map count is low,
    //       and on some systems you'll find that the program hangs; likely because
    //       the fault handler also can't create mappings anymore.
    enum THREADS        = 8;
    enum FIBERS         = 1;
    enum EXPECTED_COUNT = THREADS * FIBERS;
    static shared int count;

    auto loop = EventLoop(EventLoopConfig());
    foreach(_; 0..THREADS)
    {
        loop.addNoGCThread(() @nogc nothrow {
            static int threadCount;
            foreach(__; 0..FIBERS)
            {
                async(()@nogc nothrow{
                    threadCount++;

                    if(threadCount == FIBERS)
                        atomicOp!"+="(count, threadCount);
                }).resultAssert;
            }
        });
    }
    while(count.atomicLoad != EXPECTED_COUNT){}
    loop._cancelToken.cancel();
    loop.join();
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