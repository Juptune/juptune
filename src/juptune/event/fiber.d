/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.fiber;

import std.typecons : Nullable;
import juptune.core.util : Result, resultAssert;

private extern(C) void juptuneSwapFiberAsm(scope JuptuneRawFiber* from, scope JuptuneRawFiber* to) @nogc nothrow;
version(linux)
{
    version(X86_64)
    {
        private struct JuptuneRawFiber
        {
            void* ret;
            void* rbx;
            void* rbp;
            void* rsp;
            void* r12;
            void* r13;
            void* r14;
            void* r15;

            private this(void* entryPoint, ubyte[] stack) @nogc nothrow pure
            {
                this.ret = entryPoint;
                this.rsp = cast(void*)((cast(ulong)stack.ptr + stack.length - 8) & ~0x0F); // align to 16 bytes
                this.rsp -= 8; // Annoying to explain; but basically once we end up in usercode this keeps 16 byte alignment.
            }
        }
    }
    else static assert(false, "Unsupported architecture");
}
else static assert(false, "Unsupported OS");

private JuptuneFiber* g_currentFiberInThread;
private JuptuneFiber g_threadRootFiber;

package struct JuptuneFiber
{
    import juptune.event.iouring : JuptuneUringUserDataType, JuptuneUringUserDataTag;
    mixin JuptuneUringUserDataType!(JuptuneUringUserDataTag.JuptuneFiber);

    alias EntryPointNoGC = void function() @nogc nothrow;
    alias EntryPointGC   = void function() nothrow;

    @disable this(this);
    invariant(this.state != State.FAILSAFE, "Fiber is in a failsafe state.");

    enum State : ubyte
    {
        FAILSAFE,
        running,
        finished,
        isRoot, /// Used by the root "fiber".

        /*
            The fiber is waiting for an io_uring completion event to happen.

            `waitingForCompletionEventId` is the userdata that the io_uring completion event will have.
        */
        waitingForCompletionEvent = 0b1000_0000,

        /*
            The fiber has manually yielded, and is waiting for the scheduler to continue it.
        */
        waitingForReschedule,
    }

    JuptuneRawFiber rawFiber;
    State state;
    FiberAllocator.Block* block;

    TypeInfo contextType;
    void* contextPtr;
    void function(scope JuptuneFiber*) nothrow @nogc contextDtor;

    import juptune.event.iouring : IoUringCompletion;
    Nullable!IoUringCompletion lastCqe;

    union
    {
        EntryPointGC entryPointGC;
        EntryPointNoGC entryPointNoGC;
    }

    this(uint id, EntryPointGC entryPoint, ubyte[] stack) @nogc nothrow pure
    {
        // this.fiberId  = id;
        this.state    = State.running;
        this.rawFiber = JuptuneRawFiber(&juptuneFiberMain!"entryPointGC", stack);
        this.entryPointGC = entryPoint;
    }

    this(uint id, EntryPointNoGC entryPoint, ubyte[] stack) @nogc nothrow pure
    {
        // this.fiberId  = id;
        this.state    = State.running;
        this.rawFiber = JuptuneRawFiber(&juptuneFiberMain!"entryPointNoGC", stack);
        this.entryPointNoGC = entryPoint;
    }

    bool isInWaitingState() @nogc nothrow const
        => (cast(uint)this.state & 0b1000_0000) != 0;
}

package JuptuneFiber* juptuneFiberGetThis() @nogc nothrow
out(v; v !is null, "We are not in a fiber")
    => g_currentFiberInThread;

package JuptuneFiber* juptuneFiberGetRoot() @nogc nothrow
    => &g_threadRootFiber;

package void juptuneFiberSwap(scope JuptuneFiber* to) @nogc nothrow
in(to !is null, "Can't swap to a null fiber.")
in(!to.isInWaitingState, "Can't swap to a fiber that is waiting, did you forget to update its state?")
{
    enum WAIT_ERROR_MSG = 
        "Can't swap from a fiber that is not waiting. Because these fibers are specialised to be ran in our "
        ~"event loop; we need to always check that the fiber is in a waiting state; otherwise it'll likely "
        ~"end up in limbo due to a lack of rescheduling condition.";

    auto from = juptuneFiberGetThis();
    // assert(
    //     from.isInWaitingState 
    //     || from.state == JuptuneFiber.State.isRoot
    //     || from.state == JuptuneFiber.State.finished,
    //     WAIT_ERROR_MSG);
    if(from == to)
        return;

    g_currentFiberInThread = to;
    juptuneSwapFiberAsm(&from.rawFiber, &to.rawFiber);
}

package void juptuneFiberThreadInit() @nogc nothrow
{
    g_currentFiberInThread = &g_threadRootFiber;
    g_currentFiberInThread.state = JuptuneFiber.State.isRoot;
}

private noreturn juptuneFiberMain(string EntryPointFieldName)() nothrow
{
    scope thisFiber = juptuneFiberGetThis();
    assert(thisFiber.state == JuptuneFiber.State.running, "This fiber hasn't been marked as `running`; bug.");

    mixin("thisFiber."~EntryPointFieldName~"();");
    juptuneFiberOnEnd(thisFiber);
    juptuneFiberSwap(juptuneFiberGetRoot());
    assert(false);
}

package void juptuneFiberOnEnd(scope JuptuneFiber* fiber) @nogc nothrow
{
    if(fiber.contextDtor !is null)
        fiber.contextDtor(fiber);
    if(fiber.block !is null)
        fiber.block.uninformGC();
    fiber.state = JuptuneFiber.State.finished;
}

@("juptuneSwapFiberAsm")
unittest
{
    static JuptuneRawFiber a, b;

    static void f()
    {
        juptuneSwapFiberAsm(&b, &a);
    }

    b = JuptuneRawFiber(&f, new ubyte[4096]);
    juptuneSwapFiberAsm(&a, &b);
}

@("juptuneSwapFromRoot - success")
unittest
{
    import core.thread : Thread;

    auto thread = new Thread((){
        juptuneFiberThreadInit();

        auto f = JuptuneFiber(0, (){}, new ubyte[4096]);
        juptuneFiberSwap(&f);
    });
    thread.start();
    thread.join();
}

/// Configuration for a `FiberAllocator`.
struct FiberAllocatorConfig
{
    size_t blocksPerWall  = 64;       /// How many blocks to allocate at one time, per wall.
    size_t blockStackSize = 1024*128; /// The minimum amount of bytes to allocate for each blocks' stack.
    bool zeroBlocksOnFree = true;     /// Whether to zero-out the stack memory of a block during deallocation

    @safe @nogc nothrow pure:

    FiberAllocatorConfig withBlocksPerWall(size_t count) return { this.blocksPerWall = count; return this; }
    FiberAllocatorConfig withBlockStackSize(size_t bytes) return { this.blockStackSize = bytes; return this; }
    FiberAllocatorConfig shouldZeroOutBlocksOnFree(bool flag) return { this.zeroBlocksOnFree = flag; return this; }
}

package struct FiberAllocator
{
    enum POSIX_MIN_STACK_SIZE = 4096; // Otherwise the backtracer will usually crash.

    private
    {
        static struct Wall
        {
            void[] entireMappingRaw;
            Block[] blocks;
            Wall* nextWall;
        }

        static struct Block
        {
            enum Flags : ubyte
            {
                none,
                gcKnowsAboutBlock = 1 << 0
            }

            Block* nextFreeBlock;
            void[] fiberStack;
            Flags flags;
            JuptuneFiber fiber;
            void* preGuardPage;
            void* postGuardPage;

            void informGC() @nogc nothrow
            {
                import core.memory : GC;

                if((this.flags & Flags.gcKnowsAboutBlock) == 0)
                {
                    GC.addRange(this.fiberStack.ptr, this.fiberStack.length);
                    this.flags |= Flags.gcKnowsAboutBlock;
                }
            }

            void uninformGC() @nogc nothrow
            {
                import core.memory : GC;

                if((this.flags & Flags.gcKnowsAboutBlock) > 0)
                {
                    GC.removeRange(this.fiberStack.ptr);
                    this.flags &= ~Flags.gcKnowsAboutBlock;
                }
            }
        }

        Wall* _firstWall;
        Wall* _lastWall;
        Block* _nextFreeBlock;
        FiberAllocatorConfig _config;
        size_t _allocatedFibers;
    }

    @nogc nothrow:

    @disable this(this){}

    this(FiberAllocatorConfig config)
    {
        this._config = config;
        this.makeWall(config.blocksPerWall, config.blockStackSize, this._firstWall).resultAssert;
        this._lastWall = this._firstWall;
        this._nextFreeBlock = &this._firstWall.blocks[0];
    }

    ~this()
    {
        if(this._firstWall is null)
            return;

        auto wall = this._firstWall;
        while(wall !is null)
        {
            auto thisWall = wall;
            wall = wall.nextWall;

            version(Posix)
            {
                import core.sys.posix.sys.mman;
                const result = munmap(thisWall.entireMappingRaw.ptr, thisWall.entireMappingRaw.length);
                assert(result == 0, "munmap failed; this is a bug");
            }
            else static assert(false, "Unimplmented platform");
        }

        this._firstWall = null;
        this._lastWall = null;
        this._nextFreeBlock = null;
    }

    Result allocateFiber(FuncT)(uint id, FuncT entryPoint, out JuptuneFiber* fiber)
    {
        Block* block;
        auto blockResult = this.allocateBlock(block);
        if(blockResult.isError)
            return blockResult;

        block.fiber = JuptuneFiber(id, entryPoint, cast(ubyte[])block.fiberStack);
        fiber = &block.fiber;
        fiber.block = block;
        this._allocatedFibers++;
        return Result.noError;
    }

    void freeFiber(ref JuptuneFiber* fiber)
    in(fiber !is null)
    in(fiber.block !is null)
    {
        this.freeBlock(fiber.block);
        fiber = null;
        this._allocatedFibers--;
    }

    size_t allocatedFiberCount()
    {
        return this._allocatedFibers;
    }

    private Result allocateBlock(out Block* block)
    {
        if(this._nextFreeBlock is null)
        {
            Wall* newWall;
            auto newWallResult = this.makeWall(
                this._config.blocksPerWall,
                this._config.blockStackSize,
                newWall
            );
            if(newWallResult.isError)
                return newWallResult;

            this._lastWall.nextWall = newWall;
            this._lastWall = newWall;
            this._nextFreeBlock = &newWall.blocks[0];
        }

        block = this._nextFreeBlock;
        this._nextFreeBlock = this._nextFreeBlock.nextFreeBlock;
        block.nextFreeBlock = null;

        return Result.noError;
    }

    private void freeBlock(ref Block* block)
    in(block !is null)
    {
        scope(exit) block = null;

        debug
        {
            auto b = this._nextFreeBlock;
            while(b !is null)
            {
                assert(b !is block, "Attempted to free already freed block");
                b = b.nextFreeBlock;
            }
        }

        if(this._config.zeroBlocksOnFree)
            (cast(ubyte[])block.fiberStack)[0..$] = 0;

        if(this._nextFreeBlock is null)
        {
            this._nextFreeBlock = block;
            return;
        }

        block.nextFreeBlock = this._nextFreeBlock;
        this._nextFreeBlock = block;
    }

    /*
        A wall is a continuous block of memory that is a combination of:
            - Wall metadata
            - Block metadata
            - Block fiber stacks + guard pages

        The memory layout is as follows:

        -=============================================================-
            A `Wall` struct
        -=============================================================-
            `blockCount` amount of `Block` structs
        -=============================================================-
            [Any padding required to achieve page alignment]
        -=============================================================-
        [repeated `blockCount` times
            -=============================================================-
                A single guard page (the 'pre' guard page)
            -=============================================================-
                The page-aligned fiber stack that is at least 
                `fiberStackBytes` long
            -=============================================================-
                A single guard page (the 'post' guard page)
            -=============================================================-
        ]
    */
    private Result makeWall(size_t blockCount, size_t fiberStackBytes, out Wall* wall)
    {
        version(Posix)
        {
            import juptune.event.internal.linux;

            import core.sys.posix.sys.mman;
            import core.sys.posix.unistd : sysconf, _SC_PAGESIZE;

            if(fiberStackBytes < POSIX_MIN_STACK_SIZE)
                fiberStackBytes = POSIX_MIN_STACK_SIZE;

            // Calculate bytes needed for guard pages and fiber stacks
            const pageSizeBytes             = sysconf(_SC_PAGESIZE);
            const guardPageBytes            = 2 * pageSizeBytes;
            const fiberStackBytesAligned    = fiberStackBytes.alignTo(pageSizeBytes);
            const blockSize                 = guardPageBytes + fiberStackBytesAligned;
            const totalBlockSize            = blockSize * blockCount;

            // Calculate bytes needed for Wall metadata
            const metadataSize      = Wall.sizeof + (Block.sizeof * blockCount);
            const totalMetadataSize = (metadataSize).alignTo(pageSizeBytes);

            const totalSize = totalBlockSize + totalMetadataSize;
            assert(totalSize % pageSizeBytes == 0, "Calculations aren't page-aligned");

            // Map the memory and populate metadata
            auto mapFlags = MAP_ANON | MAP_PRIVATE;
            static if(__traits(compiles, MAP_STACK))
                mapFlags |= MAP_STACK;

            auto mapping = mmap(
                null,
                totalSize,
                PROT_READ | PROT_WRITE,
                mapFlags,
                -1,
                0
            );
            if(mapping is MAP_FAILED)
            {
                version(linux)
                {
                    import core.sys.linux.errno : errno;
                    return linuxErrorAsResult("Unable to allocate new wall", errno());
                }
                else
                {
                    static enum E { none, failed = int.max }
                    return Result.make(E.failed, "Unable to allocate new wall");
                }
            }

            bool assumeFailed = true;
            scope(exit)
            {
                if(assumeFailed)
                    munmap(mapping, totalSize);
            }

            wall = cast(Wall*)mapping;
            wall.blocks = (cast(Block*)(mapping + Wall.sizeof))[0..blockCount];
            wall.entireMappingRaw = mapping[0..totalSize];

            auto startOfBlockStacks = mapping + totalMetadataSize;
            assert(cast(size_t)startOfBlockStacks % pageSizeBytes == 0, "startOfBlockStacks is not page-aligned");
            assert(
                cast(void*)wall.blocks.ptr 
                + (wall.blocks.length * Block.sizeof) 
                <= startOfBlockStacks,
                "blocks is overlapping startOfBlockStacks - there is a calculation error somewhere"
            );

            foreach(i, ref block; wall.blocks)
            {
                block.preGuardPage  = startOfBlockStacks + (blockSize * i);
                block.fiberStack    = (startOfBlockStacks + (blockSize * i) + pageSizeBytes)[0..fiberStackBytesAligned];
                block.postGuardPage = startOfBlockStacks + (blockSize * (i + 1)) - pageSizeBytes;

                // import std.stdio : writefln;
                // debug writefln(
                //     "i: %s | pre: 0x%X | stack: 0x%X | post: 0x%X",
                //     i,
                //     block.preGuardPage,
                //     block.fiberStack.ptr,
                //     block.postGuardPage
                // );

                assert(cast(size_t)block.preGuardPage % pageSizeBytes == 0, "preGuardPage is not page-aligned");
                assert(cast(size_t)block.fiberStack.ptr % pageSizeBytes == 0, "fiberStack is not page-aligned");
                assert(cast(size_t)block.postGuardPage % pageSizeBytes == 0, "postGuardPage is not page-aligned");

                if(i != wall.blocks.length-1) // @suppress(dscanner.suspicious.length_subtraction)
                    block.nextFreeBlock = &wall.blocks[i+1];

                const preGuardResult = mprotect(block.preGuardPage, 1, PROT_NONE);
                if(preGuardResult < 0)
                {
                    version(linux)
                    {
                        import core.sys.linux.errno : errno;
                        return linuxErrorAsResult("Unable to set memory protection of the pre guard page", errno());
                    }
                    else
                    {
                        static enum E { none, failed = int.max }
                        return Result.make(E.failed, "Unable to set memory protection of the pre guard page");
                    }
                }

                const postGuardResult = mprotect(block.postGuardPage, 1, PROT_NONE);
                if(postGuardResult < 0)
                {
                    version(linux)
                    {
                        import core.sys.linux.errno : errno;
                        return linuxErrorAsResult("Unable to set memory protection of the post guard page", errno());
                    }
                    else
                    {
                        static enum E { none, failed = int.max }
                        return Result.make(E.failed, "Unable to set memory protection of the post guard page");
                    }
                }
            }

            assumeFailed = false; // Stop the call to `munmap` in the scope(exit) above.
        }
        else static assert(false, "Unimplemented platform");

        return Result.noError;
    }
}

@("FiberAllocator - block allocation behaviour")
unittest
{
    auto alloc = FiberAllocator(FiberAllocatorConfig().withBlocksPerWall(1));
    
    FiberAllocator.Block* b1, b2, b3;
    alloc.allocateBlock(b1).resultAssert;
    alloc.allocateBlock(b2).resultAssert;
    alloc.allocateBlock(b3).resultAssert;

    // Blocks should be unique
    assert(b1 !is b2);
    assert(b2 !is b3);

    // Walls should be allocated on demand
    assert(alloc._firstWall !is null);
    assert(alloc._firstWall.nextWall !is null);
    assert(alloc._firstWall.nextWall.nextWall !is null);
    
    // Blocks should be in wall order in this test case
    assert(b1 is &alloc._firstWall.blocks[0]);
    assert(b2 is &alloc._firstWall.nextWall.blocks[0]);
    assert(b3 is &alloc._firstWall.nextWall.nextWall.blocks[0]);

    // Deallocation case: No blocks available
    auto oldB2 = b2;
    alloc.freeBlock(b2);
    
    assert(b2 is null); // freeBlock tries to make things safe by nulling the original reference
    assert(alloc._nextFreeBlock is oldB2);
    alloc.allocateBlock(b2).resultAssert;
    assert(b2 is oldB2);

    // Deallocation case: at least 1 block is available during deallocation
    //              also: cross-wall blocks
    auto oldB3 = b3;
    alloc.freeBlock(b3); // Hits the "no blocks available" branch
    alloc.freeBlock(b2); // Hits the "at least one block available" branch

    assert(b2 is null);
    assert(b3 is null);

    assert(alloc._nextFreeBlock is oldB2); // Note: Newly freed blocks are put at the _front_ of the list
    assert(alloc._nextFreeBlock.nextFreeBlock is oldB3);

    alloc.allocateBlock(b2).resultAssert;
    alloc.allocateBlock(b3).resultAssert;

    assert(alloc._firstWall.nextWall.nextWall.nextWall is null); // No additional wall should've been allocated

    assert(b2 is oldB2);
    assert(b3 is oldB3);

    // Ensure dtor doesn't destroy the universe.
    alloc.__xdtor();
}

@("FiberAllocator - double free detection")
unittest
{
    import std.exception : assertThrown;

    auto alloc = FiberAllocator(FiberAllocatorConfig().withBlocksPerWall(1));
    
    FiberAllocator.Block* b;
    alloc.allocateBlock(b).resultAssert;

    auto bb = b;
    alloc.freeBlock(b);
    assertThrown!Error(alloc.freeBlock(bb));
}

@("FiberAllocator - zero out block config")
unittest
{
    // With zeroing out
    {
        import std.algorithm : all;

        auto alloc = FiberAllocator(FiberAllocatorConfig().withBlocksPerWall(1));

        FiberAllocator.Block* b, bb;
        alloc.allocateBlock(b).resultAssert;
        bb = b;

        (cast(ubyte[])b.fiberStack)[0..$] = ubyte.max;
        alloc.freeBlock(b);
        assert((cast(ubyte[])bb.fiberStack).all!(b => b == 0));
    }

    // Without
    {
        import std.algorithm : all;

        auto alloc = FiberAllocator(
            FiberAllocatorConfig()
                                .withBlocksPerWall(1)
                                .shouldZeroOutBlocksOnFree(false)
        );

        FiberAllocator.Block* b, bb;
        alloc.allocateBlock(b).resultAssert;
        bb = b;

        (cast(ubyte[])b.fiberStack)[0..$] = ubyte.max;
        alloc.freeBlock(b);
        assert((cast(ubyte[])bb.fiberStack).all!(b => b == ubyte.max));
    }
}

private T alignTo(T)(T value, T boundary)
{
    return (value + (boundary * (value % boundary > 0))) & ~(boundary-1);
}