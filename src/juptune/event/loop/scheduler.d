/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.loop.scheduler;

import core.atomic, core.thread;
import juptune.core.ds, juptune.core.util;
import juptune.event.fiber, juptune.event.iouring, juptune.event.loop;

package void loopThreadMain(bool IsGCThread)(scope LoopThread* loopThread) nothrow
{
    scope(exit) loopThread.__xdtor();

    schedulerInit!IsGCThread(loopThread);
    schedulerLoop(loopThread);
}

private void schedulerInit(bool IsGCThread)(scope LoopThread* loopThread) nothrow
{
    // Setup global state + drivers
    assert(g_thisLoopThread is null);
    g_thisLoopThread = loopThread;

    loopThread.fiberAllocator = FiberAllocator(loopThread.fiberAllocatorConfig);
    loopThread.ioUring = IoUring(loopThread.ioUringConfig);

    juptuneFiberThreadInit();

    // Schedule initial fiber
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
}

private void schedulerLoop(scope LoopThread* loopThread) @nogc nothrow
{
    while(true)
    {
        schedulerHandleCqes(loopThread);
        schedulerWakeUpFibers(loopThread);

        if(juptuneLoopThreadGetFiberCount() == 0)
            break;

        // Keep informing fibers that the thread is canceled until they all finish up.
        // if(loopThread.loop._cancelToken.isCancelled)
        // {
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
            // break;
        // }
    }
}

private void schedulerHandleCqes(scope LoopThread* loopThread) @nogc nothrow
{
    loopThread.submitQueueIsFull = false;

    const fibersWaiting = 
        loopThread.yieldedFibers.length // Manually yielded
        + loopThread.yieldedFibersSubmitQueueIsFull.length // Yielded because the submit queue was full
    ;
    
    loopThread.ioUring.opDispatch!"enter"(fibersWaiting > 0 ? 0 : 1); // Only block the thread if we have no yields to attend to
    loopThread.ioUring.processCompletions((cqe) { 
        schedulerOnCqe(cqe, fibersWaiting);
    });
}

private void schedulerOnCqe(IoUringCompletion c, size_t fibersWaiting) nothrow @nogc 
{
    auto loopThread = g_thisLoopThread;
    loopThread.stats.cqeTotal++;

    // USER_DATA_IGNORE means "this CQE was generated for an SQE that we don't care about the results of"
    if(c.userData is USER_DATA_IGNORE)
    {
        loopThread.stats.cqeIgnored++;
        return;
    }

    // In all other cases, the userData will be a struct that mixes in the JuptuneUringUserDataType template,
    // which will set the first byte to a JuptuneUringUserDataTag for us to switch on.
    const tag = cast(JuptuneUringUserDataTag)*cast(ubyte*)c.userData;

    final switch(tag)
    {
        case JuptuneUringUserDataTag.JuptuneFiber:
            scope fiber = cast(JuptuneFiber*)c.userData;
            assert(fiber.isInWaitingState);

            loopThread.stats.cqeAwokeFiber++;
            fiber.lastCqe = c;

            // Naive attempt at giving each fiber a fair chance to run.
            if(fibersWaiting > 0)
                loopThread.fibersToWakeUpLast.put(fiber);
            else
            {
                fiber.state = JuptuneFiber.State.running;
                juptuneFiberSwap(fiber);
                loopThreadOnAfterFiberSwap(fiber);
            }
            break;

        case JuptuneUringUserDataTag.FAILSAFE:
            assert(false, "Unexpected tag value for CQE userdata");
    }
}

private void schedulerWakeUpFibers(scope LoopThread* loopThread) @nogc nothrow
{
    // TODO: This is poorly coded jank, make it better
    void handleFibers(bool ShrinkArray, alias ShouldCircuitBreak)(
        scope ref ArrayNonShrink!(JuptuneFiber*) array, 
    )
    {
        const yieldedFiberCount = array.length;
        foreach(i; 0..yieldedFiberCount)
        {
            if(ShouldCircuitBreak())
                break;

            scope fiber = array[i];
            fiber.state = JuptuneFiber.State.running;
            juptuneFiberSwap(fiber);
            loopThreadOnAfterFiberSwap(fiber);
            array[i] = null;
        }

        static if(ShrinkArray)
        {
            const yieldedFiberDiff = array.length - yieldedFiberCount;
            if(yieldedFiberDiff == 0)
                array.length = 0;
            else
            {
                array[0..yieldedFiberDiff] = array[yieldedFiberCount..$];
                array.length = yieldedFiberDiff;
            }
        }
    }

    // Handle fibers waiting for submit queue space (only if the queue isn't full)
    handleFibers!(true, () => loopThread.submitQueueIsFull)(loopThread.yieldedFibersSubmitQueueIsFull);

    // Handle non-io yielded fibers
    handleFibers!(true, () => false)(loopThread.yieldedFibers);

    // Handle fibers that had a CQE come through while other fibers are waiting
    handleFibers!(false, () => false)(loopThread.fibersToWakeUpLast);
    loopThread.fibersToWakeUpLast.length = 0;
}