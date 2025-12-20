/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.loop.async;

import core.atomic, core.thread;
import juptune.core.ds, juptune.core.util;
import juptune.event.fiber, juptune.event.iouring, juptune.event.loop;

import std.typecons : Flag;

package void juptuneLoopThreadAsyncYield() @nogc nothrow
{
    scope loopThread = juptuneLoopThreadGetThis();
    scope fiber = juptuneFiberGetThis();
    fiber.state = JuptuneFiber.State.waitingForCompletionEvent;
    juptuneFiberSwap(juptuneFiberGetRoot());
}

/++++ User Facing stuff ++++/

/// See `yield`
alias YieldUntilCompletion = Flag!"yieldUntilCompletion";

/// Configuration for submitting an event
struct SubmitEventConfig
{
    YieldUntilCompletion yieldUntilComplete = YieldUntilCompletion.yes; /// Whether the fiber should yield until a CQE is generated
    
    /++
     + The timeout for the event. 
     +
     + If this is exceeded then the underlying operation will attempt to be canceled, 
     + likely causing a canceled error to be thrown.
     +
     + If this is set to `Duration.zero` then no timeout will be used.
     +
     + Please note that currently a very minor side effect of using a timeout is that the
     + ignored CQE count will be incremented by 1 due to an implementation detail.
     + ++/
    Duration timeout = Duration.zero; 

    @nogc nothrow pure:

    SubmitEventConfig shouldYieldUntilCompletion(bool value) return { this.yieldUntilComplete = cast(YieldUntilCompletion)value; return this; } // @suppress(dscanner.style.long_line)
    SubmitEventConfig withTimeout(Duration value) return { this.timeout = value; return this; }
}

/// Configuration for creating an async fiber
struct AsyncConfig
{
    @nogc nothrow pure:
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

/// The main reason for yielding a fiber.
enum YieldReason
{
    FAILSAFE,

    /// The fiber is being yielded because the io_uring submit queue is full.
    submitQueueIsFull,

    /// The fiber is being yielded for some other reason.
    other,
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
 + As a technical side note: the user context is stored at the very top of the fiber's stack
 + which shouldn't cause issues.
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
    void function(scope ref ContextT value, scope out ContextT contextValue) @nogc nothrow setter = &asyncDefaultSetter!ContextT, // @suppress(dscanner.style.long_line)
    AsyncConfig config = AsyncConfig(),
) @nogc nothrow
{
    return asyncWithContextImpl!(JuptuneFiber.EntryPointNoGC, ContextT)(func, context, setter, config);
}

/// ditto
Result async(ContextT)(
    JuptuneFiber.EntryPointGC func,
    auto ref ContextT context,
    void function(scope ref ContextT value, scope out ContextT contextValue) @nogc nothrow setter = &asyncDefaultSetter!ContextT, // @suppress(dscanner.style.long_line)
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

    auto ptr = fiber.rawFiber.makeRoomFor!ContextT();
    fiber.contextPtr = ptr;
    setter(context, *ptr);

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
 + Reasons:
 +  When `reason` is `YieldReason.submitQueueIsFull`, this allows the event loop to optimise its "wake up" loop
 +  so that the current fiber is only ever called when the submit queue is guarenteed to be empty. Without this
 +  reason, the fiber may be woken up only to then see that the submit queue is once again full, and immediately yields.
 +
 + Params:
 +  reason = The reason for yielding the fiber.
 +
 + Throws:
 +  `JuptuneEventLoopError.threadWasCanceled` if the thread has been canceled. This is not
 +  an actual error, but is simply used as a mechanism to encourage you to write code that can gracefully exit
 +  instead of relying on `.resultAssert`
 +
 + Returns:
 +  A `Result`
 + ++/
Result yield(YieldReason reason = YieldReason.other) @nogc nothrow
in(reason != YieldReason.FAILSAFE, "bug: reason is FAILSAFE?")
{
    scope loopThread = juptuneLoopThreadGetThis();
    auto fiber = juptuneFiberGetThis();
    fiber.state = JuptuneFiber.State.waitingForReschedule;
    
    if(reason == YieldReason.submitQueueIsFull)
        loopThread.yieldedFibersSubmitQueueIsFull.put(fiber);
    else
        loopThread.yieldedFibers.put(fiber);
    
    juptuneFiberSwap(juptuneFiberGetRoot());

    if(juptuneEventLoopIsThreadCanceled())
        return Result.make(JuptuneEventLoopError.threadWasCanceled, "Thread has been canceled; please abort the fiber gracefully."); // @suppress(dscanner.style.long_line)

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
 + You can use `IoUringCompletion.ignore` for the `cqe` parameter if you disable yielding, or if
 + you don't care about the completion at all.
 +
 + You can specify a timeout via `SubmitEventConfig.timeout`. If the timeout is exceeded then
 + the operation will attempt to be canceled, likely causing an error result to be returned. This can be
 + detected by calling `Result.isError(LinuxError.cancelled)` on the returned result object.
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
 +  config = The configuration for submitting the event.
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
    command.userData = config.yieldUntilComplete ? fiber : USER_DATA_IGNORE;

    while(loopThread.ioUring.opDispatch!"submitTimeout"(command, config.timeout) == SubmitQueueIsFull.yes)
    {
        loopThread.submitQueueIsFull = true;

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