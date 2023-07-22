module juptune.core.ds.block;

import juptune.core.util : Result, resultAssert;

private struct MemoryBlock
{
    MemoryBlock* next; // acyclic
    ubyte[] block;
    bool isAllocated;
}

/++ 
 + An allocation of blocks from a `MemoryBlockPool` where each block is the same size.
 +/
struct HomogenousMemoryBlockAllocation
{
    private
    {
        MemoryBlockPool* _pool;
        MemoryBlock* _head;
        MemoryBlock* _tail;
        size_t _powerOfTwo;
        size_t _blockCount;
    }

    @disable this(this){}

    @nogc nothrow:

    ~this() @safe
    {
        this.free();
    }

    /++
     + Frees the memory blocks back to its parent pool.
     +
     + Notes:
     +  This function is weakly safe as it assumes that the parent pool is still valid.
     + ++/
    void free() @safe
    {
        if(this._pool is null || this._head is null)
            return;

        assert(this._head.isAllocated, "head memory block is not marked as allocated. double free/double alloc?");
        this._head.isAllocated = false;

        this._pool.addFreeBlock(this._powerOfTwo, this._head);
        this._pool = null;
        this._head = null;
        this._tail = null;
    }

    /++ 
     + Returns:
     +  The sum of bytes across all allocated memory blocks.
     +/
    size_t totalBytes() @safe pure const
    {
        return this._blockCount * (1 << this._powerOfTwo);
    }
}

/++ 
 + A pool used to manage blocks of memory of varying sizes.
 +
 + Notes:
 +  This pool is not thread safe.
 +
 +  It is not safe to move this pool once any memory has been allocated from it.
 +
 +  This pool is not garbage collected. Once this pool's dtor is called, all memory allocated by this pool is freed.
 +  This also means that any allocations will become unsafe to use after the pool's dtor is called.
 +
 +  Additionally memory blocks are not made aware to the GC, so please do not store GC pointers into the blocks.
 +
 +  This pool is weakly safe in the sense that the user's management of memory is sane, and also trusted
 +  in the sense that calculations within the pool are correct.
 +
 +  Block sizes are powers of two, and are in the range [256, 1024 * 1024 * 4] inclusive.
 +
 + Usage:
 +  First you must preallocate blocks into the pool using `preallocateBlocks`.
 +
 +  You can then allocate blocks from the pool using `allocate`, and free the blocks by calling `.free` or `.__xdtor`
 +  on the resulting allocation object.
 +
 +  Due to the nature of the pool's memory model, it may be more efficient to allocate a larger number of blocks at once
 +  rather than allocating them one at a time.
 +
 + Memory model:
 +  "Preallocation" of blocks simply means that the pool will allocate a large chunk of memory from the system,
 +  where the size is dependent on the amount of blocks requested, and then split that memory up to form the resulting
 +  memory blocks.
 +
 +  Each preallocation contains blocks for a single power of two.
 +
 +  The layout of the memory is as follows, where the top is the start of the allocation:
 +
 +      [AllocationMetadata (internal struct)]
 +      [n MemoryBlocks (internal struct)]
 +      [n*(1 << powerOfTwo) bytes]
 +
 +  The `AllocationMetadata` struct is used to form a linked list of preallocation so that the pool can free all
 +  of its data when it is destroyed.
 +
 +  The `MemoryBlock` struct is used to form a linked list of free blocks; store the underlying ubyte slice from
 +  the preallocation, and other misc internal metadata.
 +
 +  The `n*(1 << powerOfTwo) bytes` is the unstructured chunk of memory that is split equally amongst each
 +  `MemoryBlock`. This is where your user data lives.
 +
 +  Additionally this pool only contains a linked list of free blocks, and does not keep track of allocated blocks.
 +
 +  Free block lists are stored within a static array of buckets, where each bucket represents a power of two,
 +  for easy and fast lookup.
 + ++/
struct MemoryBlockPool
{
    import core.bitop : bsf;

    enum MIN_BLOCK_SIZE  = 256; /// Minimum block size, in bytes
    enum MAX_BLOCK_SIZE  = 1024 * 1024 * 4; /// Maximum block size, in bytes
    enum MIN_BLOCK_POWER = bsf(MIN_BLOCK_SIZE); /// Minimum block size, in power of two
    enum MAX_BLOCK_POWER = bsf(MAX_BLOCK_SIZE); /// Maximum block size, in power of two
    enum BLOCK_BUCKETS   = (MAX_BLOCK_POWER - MIN_BLOCK_POWER) + 1;

    /// `Result`` error enum
    enum Errors
    {
        none,

        /// Returned whenever `preallocateBlocks` fails due to lack of system resources.
        outOfMemory,

        /++
         + Returned whenever `allocate` fails due to lack of free blocks.
         +
         + You can recover from this error by calling `preallocateBlocks` and trying again.
         + ++/
        notEnoughBlocks,
    }

    private
    {
        static struct Bucket
        {
            MemoryBlock* freeHead;
            MemoryBlock* freeTail;

            debug void printChain(string context) @safe
            {
                import std.stdio : writef, writefln;

                writefln("=======================\n%s", context);
                writefln("head: %X", this.freeHead);
                writefln("tail: %X", this.freeTail);

                writef("chain: ");
                auto block = this.freeHead;
                while(block !is null)
                {
                    writef("%X%s", block, block.next is null ? "" : " -> ");
                    block = block.next;
                }
                writefln("");
            }
        }

        // This is the structure for the first set of bytes in an overall allocation.
        static struct AllocationMetadata
        {
            AllocationMetadata* next;
            AllocationOffsets offsets;
        }

        static struct AllocationOffsets
        {
            size_t entireSizeInBytes;

            size_t memoryBlockOffset;
            size_t memoryBlockLengthInBytes;

            size_t rawDataOffset;
            size_t rawDataLengthInBytes;
        }

        Bucket[BLOCK_BUCKETS] _bucketByPower;
        AllocationMetadata*   _allocationList;
    }

    @disable this(this){}

    @nogc nothrow:

    ~this() @trusted
    {
        import core.stdc.stdlib : free;

        auto head = this._allocationList;
        while(head !is null)
        {
            auto oldHead = head;
            head = head.next;
            free(oldHead); // AllocationMetadata points to the start of the allocation, so is useable in `free`
        }
        this._allocationList = null;
        
        foreach(ref bucket; this._bucketByPower)
            bucket = Bucket.init;
    }

    Result allocate(size_t powerOfTwo, size_t blockCount, scope return out HomogenousMemoryBlockAllocation allocation) @trusted // @suppress(dscanner.style.long_line)
    in(blockCount != 0, "block count must be greater than zero")
    {
        scope bucket = this.bucketByPower(powerOfTwo);
        if(bucket.freeHead is null)
            return Result.make(Errors.notEnoughBlocks, "when allocating memory block");

        allocation._head = bucket.freeHead;
        auto block = bucket.freeHead;
        size_t count = 1;
        while(block.next !is null && count < blockCount)
        {
            block = block.next;
            count++;
        }

        if(count < blockCount)
            return Result.make(Errors.notEnoughBlocks, "when allocating memory block");

        allocation._pool = &this;
        allocation._tail = block;
        allocation._powerOfTwo = powerOfTwo;
        allocation._blockCount = blockCount;
        allocation._head.isAllocated = true;

        bucket.freeHead = block.next;
        if(bucket.freeHead is null)
            bucket.freeTail = null;
        allocation._tail.next = null;

        return Result.noError;
    }

    Result preallocateBlocks(size_t powerOfTwo, size_t blockCount) @trusted
    in(powerOfTwo >= MIN_BLOCK_POWER, "power is too small")
    in(powerOfTwo <= MAX_BLOCK_POWER, "power is too big")
    {
        import core.stdc.stdlib : calloc, free;

        const blockSize = 1 << powerOfTwo;
        const allocationOffsets = calculateAllocationOffsets(powerOfTwo, blockCount);

        void* memory = calloc(1, allocationOffsets.entireSizeInBytes);
        if(memory is null)
            return Result.make(Errors.outOfMemory, "when allocating memory for block pool");

        AllocationMetadata* allocationMetadata = cast(AllocationMetadata*)memory;
        allocationMetadata.next = this._allocationList;
        allocationMetadata.offsets = allocationOffsets;
        this._allocationList = allocationMetadata;

        auto memoryBlockListBytes = cast(ubyte[])(
            memory + allocationOffsets.memoryBlockOffset
        )[0..allocationOffsets.memoryBlockLengthInBytes];
        auto memoryBlockList = cast(MemoryBlock[])memoryBlockListBytes;

        auto rawDataPtr = cast(ubyte*)(memory + allocationOffsets.rawDataOffset);

        foreach(i, ref block; memoryBlockList)
        {
            block.block = rawDataPtr[i * blockSize .. (i + 1) * blockSize];
            if(i > 0)
                memoryBlockList[i-1].next = &memoryBlockList[i];
        }

        this.addFreeBlock(powerOfTwo, &memoryBlockList[0]);
        return Result.noError;
    }

    private void addFreeBlock(size_t powerOfTwo, MemoryBlock* block) @safe
    in(block !is null)
    in(powerOfTwo == bsf(block.block.length))
    {
        auto tail = block;
        while(tail.next !is null)
            tail = tail.next;

        scope bucket = this.bucketByPower(powerOfTwo);
        if(bucket.freeHead is null)
        {
            bucket.freeHead = block;
            bucket.freeTail = tail;
        }
        else
        {
            bucket.freeTail.next = block;
            bucket.freeTail = tail;
        }
    }

    private Bucket* bucketByPower(size_t power) @safe return
    in(power >= MIN_BLOCK_POWER, "power is too small")
    in(power <= MAX_BLOCK_POWER, "power is too big")
    {
        return &this._bucketByPower[power - MIN_BLOCK_POWER];
    }

    private static AllocationOffsets calculateAllocationOffsets(size_t powerOfTwo, size_t blockCount) @safe pure
    out(v; v.memoryBlockOffset + v.memoryBlockLengthInBytes < v.entireSizeInBytes)
    out(v; v.memoryBlockOffset > 0)
    out(v; v.rawDataOffset == v.memoryBlockOffset + v.memoryBlockLengthInBytes)
    out(v; v.rawDataOffset + v.rawDataLengthInBytes == v.entireSizeInBytes)
    {
        AllocationOffsets offsets;

        offsets.memoryBlockOffset = AllocationMetadata.sizeof;
        offsets.memoryBlockLengthInBytes = blockCount * MemoryBlock.sizeof;

        offsets.rawDataOffset = offsets.memoryBlockOffset + offsets.memoryBlockLengthInBytes;
        offsets.rawDataLengthInBytes = blockCount * (1 << powerOfTwo);

        offsets.entireSizeInBytes = offsets.rawDataOffset + offsets.rawDataLengthInBytes;

        return offsets;
    }
}

@("MemoryBlockPool - preallocateBlocks & ~this()")
@trusted
unittest
{
    MemoryBlockPool pool;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    pool.preallocateBlocks(MemoryBlockPool.MIN_BLOCK_POWER, 3).resultAssert;

    // Ensure the linked list is correct
    assert(bucket.freeHead !is null);
    assert(bucket.freeHead.next !is null);
    assert(bucket.freeHead.next.next !is null);
    assert(bucket.freeHead.next.next.next is null);
    assert(bucket.freeTail is bucket.freeHead.next.next);

    // Ensure that the blocks are the correct size
    assert(bucket.freeHead.block.length == MemoryBlockPool.MIN_BLOCK_SIZE);
    assert(bucket.freeHead.next.block.length == MemoryBlockPool.MIN_BLOCK_SIZE);
    assert(bucket.freeHead.next.next.block.length == MemoryBlockPool.MIN_BLOCK_SIZE);

    // Ensure that we didn't accidentally overlap the data blocks
    assert(bucket.freeHead.block.ptr + bucket.freeHead.block.length == bucket.freeHead.next.block.ptr);
    assert(bucket.freeHead.next.block.ptr + bucket.freeHead.next.block.length == bucket.freeHead.next.next.block.ptr);

    // Ensure that the allocation is being tracked
    assert(pool._allocationList !is null);

    // Ensure that the allocation metadata doesn't overlap the first MemoryBlock
    assert(cast(void*)pool._allocationList !is cast(void*)bucket.freeHead);
    assert(cast(size_t)pool._allocationList + MemoryBlockPool.AllocationMetadata.sizeof == cast(size_t)bucket.freeHead);

    // Ensure we're using the entire memory allocation
    assert(
        cast(size_t)(bucket.freeTail.block.ptr + bucket.freeTail.block.length) - cast(size_t)pool._allocationList
        == MemoryBlockPool.calculateAllocationOffsets(MemoryBlockPool.MIN_BLOCK_POWER, 3).entireSizeInBytes
    );

    // Explicitly call the dtor to make it clear we're testing that it doesn't crash
    pool.__xdtor();
    assert(pool == MemoryBlockPool.init);
}

@("MemoryBlockPool - addFreeBlock head&tail == single block")
@safe
unittest
{
    MemoryBlockPool pool;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    auto block = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block);

    assert(bucket.freeHead is block);
    assert(bucket.freeTail is block);
    assert(bucket.freeHead.next is null);
}

@("MemoryBlockPool - addFreeBlock head&tail == multiple separate blocks")
@safe
unittest
{
    MemoryBlockPool pool;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    auto block1 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    auto block2 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block1);
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block2);

    assert(bucket.freeHead is block1);
    assert(bucket.freeTail is block2);
    assert(bucket.freeHead.next is block2);
    assert(bucket.freeTail.next is null);
}

@("MemoryBlockPool - addFreeBlock head&tail == multiple linked blocks")
@safe
unittest
{
    MemoryBlockPool pool;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    auto block1 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    auto block2 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    block1.next = block2;
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block1);

    assert(bucket.freeHead is block1);
    assert(bucket.freeTail is block2);
    assert(bucket.freeHead.next is block2);
    assert(bucket.freeTail.next is null);
}

@("MemoryBlockPool - addFreeBlock - add chained blocks after head")
@safe
unittest
{
    MemoryBlockPool pool;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    auto block1 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    auto block2 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    auto block3 = new MemoryBlock(null, new ubyte[MemoryBlockPool.MIN_BLOCK_SIZE]);
    block2.next = block3;
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block1);
    pool.addFreeBlock(MemoryBlockPool.MIN_BLOCK_POWER, block2);

    assert(bucket.freeHead is block1);
    assert(bucket.freeTail is block3);
    assert(bucket.freeHead.next is block2);
    assert(bucket.freeTail.next is null);
}

@("MemoryBlockPool - allocate - no free blocks")
unittest
{
    MemoryBlockPool pool;
    HomogenousMemoryBlockAllocation alloc;

    auto result = pool.allocate(MemoryBlockPool.MIN_BLOCK_POWER, 1, alloc);
    assert(result.isError(MemoryBlockPool.Errors.notEnoughBlocks));
}

@("MemoryBlockPool - allocate - not enough free blocks")
unittest
{
    MemoryBlockPool pool;
    HomogenousMemoryBlockAllocation alloc;

    pool.preallocateBlocks(MemoryBlockPool.MIN_BLOCK_POWER, 4).resultAssert;
    auto result = pool.allocate(MemoryBlockPool.MIN_BLOCK_POWER, 5, alloc);
    assert(result.isError(MemoryBlockPool.Errors.notEnoughBlocks));
}

@("MemoryBlockPool - allocate - entire free blocks")
unittest
{
    MemoryBlockPool pool;
    HomogenousMemoryBlockAllocation alloc;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    pool.preallocateBlocks(MemoryBlockPool.MIN_BLOCK_POWER, 3).resultAssert;
    auto head = bucket.freeHead;
    auto tail = bucket.freeTail;
    pool.allocate(MemoryBlockPool.MIN_BLOCK_POWER, 3, alloc).resultAssert;

    assert(alloc._head is head);
    assert(alloc._tail is tail);
    assert(alloc._blockCount == 3);
    assert(alloc._pool is &pool);
    assert(alloc._powerOfTwo == MemoryBlockPool.MIN_BLOCK_POWER);
    assert(head.isAllocated);
    assert(tail.next is null);

    assert(bucket.freeHead is null);
    assert(bucket.freeTail is null);

    alloc.__xdtor();

    assert(bucket.freeHead is head);
    assert(bucket.freeTail is tail);
    assert(!head.isAllocated);
}

@("MemoryBlockPool - allocate - partial free blocks")
unittest
{
    MemoryBlockPool pool;
    HomogenousMemoryBlockAllocation alloc;
    scope bucket = pool.bucketByPower(MemoryBlockPool.MIN_BLOCK_POWER);

    pool.preallocateBlocks(MemoryBlockPool.MIN_BLOCK_POWER, 6).resultAssert;
    auto oldHead = bucket.freeHead;
    auto newHead = oldHead.next.next.next;

    pool.allocate(MemoryBlockPool.MIN_BLOCK_POWER, 3, alloc).resultAssert;
    assert(alloc._head is oldHead);
    assert(bucket.freeHead is newHead);

    alloc.__xdtor();

    assert(bucket.freeHead is newHead);
    assert(bucket.freeHead.next.next.next is oldHead);
    assert(bucket.freeTail is oldHead.next.next);
}
