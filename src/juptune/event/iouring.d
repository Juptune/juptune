/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.event.iouring;

import core.time         : Duration, seconds;
import std.typecons      : Flag;
import juptune.core.util : Result, resultAssert;

version(linux) private
{
    // Strangely the io_uring module is both outdated and also missing functions;
    // so we'll fill in the gaps.
    import core.sys.linux.errno;
    import core.sys.linux.io_uring      : io_uring_params, io_uring_cqe, io_uring_sqe, IOSQE_IO_LINK;
    import core.sys.posix.signal        : sigset_t;
    import core.sys.posix.sys.socket    : socklen_t, sockaddr;
    import core.sys.posix.unistd        : close;
    import core.sys.posix.sys.uio       : iovec;
    import core.stdc.config             : c_long, cpp_longlong;
    import juptune.event.internal.linux;
    
    // Implemented by our ASM since it's literally easier than trying to piss around
    // with Meson bugs.
    extern(C) int io_uring_setup(uint entries, io_uring_params* params) @nogc nothrow;
    extern(C) int io_uring_enter(int fd, uint to_submit, uint min_complete, uint flags, sigset_t* sig) @nogc nothrow;
    extern(C) int io_uring_register(int fd, uint opcode, void* arg, uint nr_args) @nogc nothrow;

    immutable _g_defaultDriver = IoUringDriver.native;

    alias FileDescriptor        = int;
    alias IoUringNativeDriver   = IoUringNativeLinuxDriver;
    alias IoUringEmulatedDriver = IoUringEmulatedPosixDriver;
    mixin IoUringTests!(IoUringDriver.native);

    struct timespec64 // @suppress(dscanner.style.phobos_naming_convention)
    {
        c_long tv_sec;
        c_long tv_nsec;
    }

    enum
    {
        IORING_SETUP_IOPOLL         = (1U << 0),
        IORING_SETUP_SQPOLL         = (1U << 1),
        IORING_SETUP_SQ_AFF         = (1U << 2),
        IORING_SETUP_CQSIZE         = (1U << 3),
        IORING_SETUP_CLAMP          = (1U << 4),
        IORING_SETUP_ATTACH_WQ      = (1U << 5),
        IORING_SETUP_R_DISABLED     = (1U << 6),
        IORING_SETUP_SUBMIT_ALL     = (1U << 7),
        IORING_SETUP_COOP_TASKRUN   = (1U << 8),
        IORING_SETUP_TASKRUN_FLAG   = (1U << 9),
        IORING_SETUP_SQE128         = (1U << 10),
        IORING_SETUP_CQE32          = (1U << 11),
        IORING_SETUP_SINGLE_ISSUER  = (1U << 12),
        IORING_SETUP_DEFER_TASKRUN  = (1U << 13),
    }

    enum
    {
        IORING_FEAT_SINGLE_MMAP     = (1U << 0),
        IORING_FEAT_NODROP          = (1U << 1),
        IORING_FEAT_SUBMIT_STABLE   = (1U << 2),
        IORING_FEAT_RW_CUR_POS      = (1U << 3),
        IORING_FEAT_CUR_PERSONALITY = (1U << 4),
        IORING_FEAT_FAST_POLL       = (1U << 5),
        IORING_FEAT_POLL_32BITS     = (1U << 6),
        IORING_FEAT_SQPOLL_NONFIXED = (1U << 7),
        IORING_FEAT_EXT_ARG         = (1U << 8),
        IORING_FEAT_NATIVE_WORKERS  = (1U << 9),
        IORING_FEAT_RSRC_TAGS       = (1U << 10),
        IORING_FEAT_CQE_SKIP        = (1U << 11),
        IORING_FEAT_LINKED_FILE     = (1U << 12),
        IORING_FEAT_REG_REG_RING    = (1U << 13),
    }

    enum
    {
        IORING_OFF_SQ_RING  = 0UL,
        IORING_OFF_CQ_RING  = 0x8000000UL,
        IORING_OFF_SQES     = 0x10000000UL,
    }

    enum
    {
        IORING_SQ_NEED_WAKEUP  = (1U << 0),
        IORING_SQ_CQ_OVERFLOW  = (1U << 1),
        IORING_SQ_TASKRUN      = (1U << 2),
    }

    enum
    {
        IORING_CQ_EVENTFD_DISABLED  = (1U << 0),
    }

    enum
    {
        IO_WQ_BOUND,
        IO_WQ_UNBOUND,
    }

    enum
    {
        IORING_ENTER_GETEVENTS          = (1U << 0),
        IORING_ENTER_SQ_WAKEUP          = (1U << 1),
        IORING_ENTER_SQ_WAIT            = (1U << 2),
        IORING_ENTER_EXT_ARG            = (1U << 3),
        IORING_ENTER_REGISTERED_RING    = (1U << 4),
    }

    enum 
    {
        IORING_REGISTER_BUFFERS             = 0,
        IORING_UNREGISTER_BUFFERS           = 1,
        IORING_REGISTER_FILES               = 2,
        IORING_UNREGISTER_FILES             = 3,
        IORING_REGISTER_EVENTFD             = 4,
        IORING_UNREGISTER_EVENTFD           = 5,
        IORING_REGISTER_FILES_UPDATE        = 6,
        IORING_REGISTER_EVENTFD_ASYNC       = 7,
        IORING_REGISTER_PROBE               = 8,
        IORING_REGISTER_PERSONALITY         = 9,
        IORING_UNREGISTER_PERSONALITY       = 10,
        IORING_REGISTER_RESTRICTIONS        = 11,
        IORING_REGISTER_ENABLE_RINGS        = 12,
        IORING_REGISTER_FILES2              = 13,
        IORING_REGISTER_FILES_UPDATE2       = 14,
        IORING_REGISTER_BUFFERS2            = 15,
        IORING_REGISTER_BUFFERS_UPDATE      = 16,
        IORING_REGISTER_IOWQ_AFF            = 17,
        IORING_UNREGISTER_IOWQ_AFF          = 18,
        IORING_REGISTER_IOWQ_MAX_WORKERS    = 19,
        IORING_REGISTER_RING_FDS            = 20,
        IORING_UNREGISTER_RING_FDS          = 21,
        IORING_REGISTER_PBUF_RING           = 22,
        IORING_UNREGISTER_PBUF_RING         = 23,
        IORING_REGISTER_SYNC_CANCEL         = 24,
        IORING_REGISTER_FILE_ALLOC_RANGE    = 25,
        IORING_REGISTER_USE_REGISTERED_RING = 1U << 31
    }

    enum
    {
        IORING_OP_NOP,
        IORING_OP_READV,
        IORING_OP_WRITEV,
        IORING_OP_FSYNC,
        IORING_OP_READ_FIXED,
        IORING_OP_WRITE_FIXED,
        IORING_OP_POLL_ADD,
        IORING_OP_POLL_REMOVE,
        IORING_OP_SYNC_FILE_RANGE,
        IORING_OP_SENDMSG,
        IORING_OP_RECVMSG,
        IORING_OP_TIMEOUT,
        IORING_OP_TIMEOUT_REMOVE,
        IORING_OP_ACCEPT,
        IORING_OP_ASYNC_CANCEL,
        IORING_OP_LINK_TIMEOUT,
        IORING_OP_CONNECT,
        IORING_OP_FALLOCATE,
        IORING_OP_OPENAT,
        IORING_OP_CLOSE,
        IORING_OP_FILES_UPDATE,
        IORING_OP_STATX,
        IORING_OP_READ,
        IORING_OP_WRITE,
        IORING_OP_FADVISE,
        IORING_OP_MADVISE,
        IORING_OP_SEND,
        IORING_OP_RECV,
        IORING_OP_OPENAT2,
        IORING_OP_EPOLL_CTL,
        IORING_OP_SPLICE,
        IORING_OP_PROVIDE_BUFFERS,
        IORING_OP_REMOVE_BUFFERS,
        IORING_OP_TEE,
        IORING_OP_SHUTDOWN,
        IORING_OP_RENAMEAT,
        IORING_OP_UNLINKAT,
        IORING_OP_MKDIRAT,
        IORING_OP_SYMLINKAT,
        IORING_OP_LINKAT,
        IORING_OP_MSG_RING,
        IORING_OP_FSETXATTR,
        IORING_OP_SETXATTR,
        IORING_OP_FGETXATTR,
        IORING_OP_GETXATTR,
        IORING_OP_SOCKET,
        IORING_OP_URING_CMD,
        IORING_OP_SEND_ZC,
        IORING_OP_SENDMSG_ZC,
    }
}

private struct MapField { string sqeFieldName; }
private struct MapFlag { string sqeFieldName; uint mask; }
private struct MapBuffer {}

private mixin template GenerateDriverFuncs(alias Opcode)
{
    @MapField("user_data") package void* userData;

    version(linux) void toSqe(scope out io_uring_sqe sqe) @nogc nothrow
    {
        import std.traits : isPointer;

        sqe.opcode = Opcode;

        static if(__traits(hasMember, typeof(this), "fd"))
            sqe.fd = this.fd;

        static foreach(memberName; __traits(allMembers, typeof(this)))
        {{
            alias Member = __traits(getMember, typeof(this), memberName);
            alias Udas   = __traits(getAttributes, Member);
            static if(Udas.length > 0)
            {
                static if(is(typeof(Udas[0]) == MapField))
                    mixin("sqe."~Udas[0].sqeFieldName~" = cast(typeof(sqe."~Udas[0].sqeFieldName~"))this."~memberName~";");
                else static if(is(typeof(Udas[0]) : MapFlag))
                    mixin("sqe."~Udas[0].sqeFieldName~" |= this."~memberName~" ? Udas[0].mask : 0;");
                else static if(is(Udas[0] : MapBuffer))
                {
                    static if(isPointer!(typeof(Member)))
                    {
                        sqe.addr = mixin("cast(ulong)this."~memberName);
                        sqe.len = 1;
                    }
                    else
                    {
                        sqe.addr = mixin("cast(ulong)&this."~memberName~"[0]");
                        mixin("assert(this."~memberName~".length <= uint.max, \"Buffer length is too large\");");
                        sqe.len = mixin("cast(uint)this."~memberName~".length");
                    }
                }
            }
        }}
    }
}

/++
 + In order to (slightly) more safely determine what type the user data of a CQE is,
 + we need the **very first byte** of each user data to be a `JuptuneUringUserDataTag` value.
 +
 + Small note: the naming scheme is sligtly different since we use the full name of the type, including
 +             the original casing.
 + ++/
package enum JuptuneUringUserDataTag : ubyte
{
    FAILSAFE,
    JuptuneFiber,
}

package mixin template JuptuneUringUserDataType(JuptuneUringUserDataTag tag)
{
    private JuptuneUringUserDataTag _juptune_tag = tag;
    static assert(typeof(this)._juptune_tag.offsetof == 0, "JuptuneUringUserDataType must be the first member of a struct"); // @suppress(dscanner.style.long_line)
}

/++ 
 + A `Result` error enum.
 + ++/
enum IoUringError
{
    none,

    /// Used whenever `mmap` fails when setting up the io_uring instance.
    /// This is likely due to hitting the mapping quota.
    mmapFailure,

    /// Used whenever memory fails to be allocated
    outOfMemory,
}

/++
 + All specified io_uring drivers.
 + ++/
enum IoUringDriver
{
    FAILSAFE,

    /++
     + The driver that implements the most native-like behaviour for io_uring.
     +
     + This is the performance driver.
     +
     + On Linux: ... this directly uses io_uring.
     + ++/
    native,

    /++
     + The driver that emulates io_uring using less efficient functionality.
     +
     + This is the "I want to develop outside of Linux" driver. It has no
     + focus on performance.
     +
     + This driver has no implementation currently, it's existence is here so that
     + I had the code already designed and ready to add it in when needed.
     +
     + On POSIX compatible systems (eventually): ... this will just use slow, standard syscalls with an
     + emulation of the submission and completion queues.
     + ++/
    emulated
}

/// A flag used to specify whether the submit queue is too full to submit anything else onto.
alias SubmitQueueIsFull = Flag!"submitQueueIsFull";

/++
 + Describes a completion event.
 + ++/
struct IoUringCompletion
{
    /// Ignore for now: still debating whether this is a good idea or not.
    enum JuptuneFlags : ubyte
    {
        none,
        threadWasCanceled = 1 << 0,
    }

    void* userData; /// The user data from the source SQE
    int result; /// The result of the command
    uint flags; /// Any additional flags relevant to the command.

    /// Ignore for now: still debating whether this is a good idea or not.
    JuptuneFlags juptuneFlags;

    /// A static completion who's intention is to be used when you have to accept a
    /// CQE, but don't really care about its result.
    static IoUringCompletion ignore;
}

/++
 + Configuration for the io_uring driver
 +
 + This configuration is tailored for the native Linux io_uring driver, as that's the main
 + target.
 + ++/
struct IoUringConfig
{
    IoUringDriver driver = _g_defaultDriver; /// Which driver to use.
    uint sqeEntryCount = 4096; /// How many SQEs to create. Note that for the Linux-native drive, 4096 is the max.

    @safe @nogc nothrow pure:

    IoUringConfig withDriver(IoUringDriver driver) return { this.driver = driver; return this; }
    IoUringConfig withSqeEntryCount(uint count) return { this.sqeEntryCount = count; return this; }
}

package struct IoUring
{
    import std.traits : isFunction;

    private static union Drivers
    {
        static if(__traits(compiles, IoUringNativeDriver))
        @(IoUringDriver.native) IoUringNativeDriver native;

        static if(__traits(compiles, IoUringEmulatedDriver))
        @(IoUringDriver.emulated) IoUringEmulatedDriver emulated;
    }
    private Drivers drivers;
    private IoUringDriver driver;

    @disable this(this){}

    this(IoUringConfig config) @nogc nothrow
    {
        this.driver = config.driver;
        opDispatch!"initDriver"(config).resultAssert;
    }

    ~this() @nogc nothrow
    {
        if(this != IoUring.init)
            opDispatch!"uninitDriver"();
    }

    // Note: It's recommended to call opDispatch directly instead of relying on
    //       the compiler's lowering; simply because the error messages are actually useful in the former case.
    auto opDispatch(string name, Params...)(auto ref Params params)
    {
        import std.traits : ReturnType;

        static foreach(memberName; __traits(allMembers, Drivers))
        {{
            alias Member        = __traits(getMember, Drivers, memberName);
            alias MemberFunc    = __traits(getMember, typeof(Member), name);
            enum DriverType     = __traits(getAttributes, Member)[0];

            if(DriverType == this.driver)
                return mixin("this.drivers."~memberName~"."~name~"(params)");
        }}

        assert(false, "No implementation for the selected driver is available");
    }
}

package struct IoUringLinkTimeout
{
    mixin GenerateDriverFuncs!(IORING_OP_LINK_TIMEOUT);

    @MapBuffer timespec64* timeout;
}

/// Performs no operation. Mostly useful just for testing, or I guess forcing the
/// fiber into a waiting state.
struct IoUringNop
{
    mixin GenerateDriverFuncs!(IORING_OP_NOP);
}

/// Linux `accept` syscall
struct IoUringAccept
{
    mixin GenerateDriverFuncs!(IORING_OP_ACCEPT);

    FileDescriptor fd;
    @MapField("addr") sockaddr* addr;
    @MapField("addr2") socklen_t* addrlen;
}

/// Linux `recv` syscall
struct IoUringRecv
{
    mixin GenerateDriverFuncs!(IORING_OP_RECV);

    FileDescriptor fd;
    @MapBuffer void[] buffer;
}

/// Linux `send` syscall
struct IoUringSend
{
    mixin GenerateDriverFuncs!(IORING_OP_SEND);

    FileDescriptor fd;
    @MapBuffer void[] buffer;
}

/// Linux `sendzc` syscall
struct IoUringSendZeroCopy
{
    mixin GenerateDriverFuncs!(IORING_OP_SEND_ZC);

    FileDescriptor fd;
    @MapBuffer void[] buffer;
}

/// Linux `close` syscall
struct IoUringClose
{
    mixin GenerateDriverFuncs!(IORING_OP_CLOSE);

    FileDescriptor fd;
}

/// Linux `readv` syscall
struct IoUringReadv
{
    mixin GenerateDriverFuncs!(IORING_OP_READV);

    FileDescriptor fd;
    @MapBuffer iovec[] iovecs;

    @MapField("off") ulong _offset = -1; // Do not change
}

/// Linux `writev` syscall
struct IoUringWritev
{
    mixin GenerateDriverFuncs!(IORING_OP_WRITEV);

    FileDescriptor fd;
    @MapBuffer iovec[] iovecs;

    @MapField("off") ulong _offset = -1; // Do not change
}

package struct IoUringTimeoutUserData
{
    timespec64 timeout;
}

version(linux)
private struct IoUringNativeLinuxDriver
{
    // Config data
    IoUringConfig config;
    io_uring_params ioUringParams;

    // Data from io_uring
    int ioUringFd;
    ubyte* sqPtr;
    ubyte* cqPtr;
    io_uring_sqe[] sqeSlice;
    io_uring_cqe[] cqeSlice;
    uint[] sqeIndexSlice;

    // Other data
    uint pendingSubmits;
    ulong[] sqeInUseMasks; // allocated with malloc
    IoUringTimeoutUserData[] timeoutUserData; // allocated with malloc

    @nogc nothrow:

    Result initDriver(const IoUringConfig config)
    {
        import core.stdc.stdlib : malloc;
        import core.sys.posix.signal : signal, SIG_IGN, SIGPIPE;
        import core.sys.linux.sys.mman;

        signal(SIGPIPE, SIG_IGN);

        this.config = config;
        this.enableFeatures();

        const setupResult = io_uring_setup(config.sqeEntryCount, &this.ioUringParams);
        if(setupResult < 0)
            return linuxErrorAsResult("io_ring_setup failed", setupResult);
        this.ioUringFd = setupResult;
        
        this.sqPtr = cast(ubyte*)mmap(
            null, 
            this.ioUringParams.sq_off.array + this.ioUringParams.sq_entries * uint.sizeof,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            this.ioUringFd,
            IORING_OFF_SQ_RING
        );
        if(this.sqPtr is MAP_FAILED)
        {
            this.uninitDriver();
            return linuxErrorAsResult("Failed to mmap io_uring submission queue", errno());
        }

        auto sqEntriesPtr = cast(io_uring_sqe*)mmap(
            null, 
            this.ioUringParams.sq_entries * io_uring_sqe.sizeof,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            this.ioUringFd,
            IORING_OFF_SQES
        );
        if(sqEntriesPtr is MAP_FAILED)
        {
            this.uninitDriver();
            return Result.make(IoUringError.mmapFailure, "Failed to mmap io_uring submission queue entries");
        }

        this.cqPtr = cast(ubyte*)mmap(
            null, 
            this.ioUringParams.cq_off.cqes + this.ioUringParams.cq_entries * io_uring_cqe.sizeof,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            this.ioUringFd,
            IORING_OFF_CQ_RING
        );
        if(this.cqPtr is MAP_FAILED)
        {
            this.uninitDriver();
            return Result.make(IoUringError.mmapFailure, "Failed to mmap io_uring completion queue");
        }

        auto cqEntriesPtr = cast(io_uring_cqe*)(this.cqPtr + this.ioUringParams.cq_off.cqes);
        this.sqeIndexSlice = (cast(uint*)(this.sqPtr + this.ioUringParams.sq_off.array))[0..this.ioUringParams.sq_entries];
        this.sqeSlice = sqEntriesPtr[0..this.ioUringParams.sq_entries];
        this.cqeSlice = cqEntriesPtr[0..this.ioUringParams.cq_entries];

        const maskCount = (this.ioUringParams.sq_entries / 64) + 1;
        auto maskPtr = cast(ulong*)malloc(ulong.sizeof * maskCount);
        if(maskPtr is null)
        {
            this.uninitDriver();
            return Result.make(IoUringError.outOfMemory, "Unable to allocate SQE mask array");
        }
        this.sqeInUseMasks = maskPtr[0..maskCount];
        this.sqeInUseMasks[] = ulong.max;

        auto timeoutPtr = cast(IoUringTimeoutUserData*)malloc(IoUringTimeoutUserData.sizeof * this.ioUringParams.sq_entries);
        if(timeoutPtr is null)
        {
            this.uninitDriver();
            return Result.make(IoUringError.outOfMemory, "Unable to allocate timeout user data array");
        }
        this.timeoutUserData = timeoutPtr[0..this.ioUringParams.sq_entries];

        return Result.noError;
    }

    void uninitDriver()
    {
        import core.stdc.stdlib : free;

        if(this.ioUringFd > 0)
        {
            close(this.ioUringFd);
            this.ioUringFd = 0;
        }

        if(this.sqeInUseMasks !is null)
        {
            free(this.sqeInUseMasks.ptr);
            this.sqeInUseMasks = null;
        }

        if(this.timeoutUserData !is null)
        {
            free(this.timeoutUserData.ptr);
            this.timeoutUserData = null;
        }
    }

    private alias _submitTest = submit!IoUringNop;
    SubmitQueueIsFull submit(Command)(Command command)
    {
        return this.submitImpl(command, (_, __){});
    }

    private alias _submitTimeoutTest = submitTimeout!IoUringNop;
    SubmitQueueIsFull submitTimeout(Command)(Command command, Duration timeout)
    {
        if(timeout == Duration.zero)
            return this.submitImpl(command, (_, __){});

        if(this.ioUringParams.sq_entries - this.pendingSubmits < 2)
            return SubmitQueueIsFull.yes;

        const result = this.submitImpl(command, (sqe, sqeIndex){
            sqe.flags |= IOSQE_IO_LINK;
        });
        assert(result == SubmitQueueIsFull.no, "Bug: submitImpl should never return SubmitQueueIsFull.yes here");

        return this.submitImpl(IoUringLinkTimeout(), (sqe, sqeIndex){
            const totalSeconds = timeout.total!"seconds";
            const totalNanos   = (timeout - totalSeconds.seconds).total!"nsecs";
            scope userData     = &this.timeoutUserData[sqeIndex];

            userData.timeout.tv_sec   = totalSeconds;
            userData.timeout.tv_nsec  = totalNanos;

            sqe.addr = cast(ulong)&userData.timeout;
            sqe.len  = 1;
        });
    }

    void processCompletions(scope void delegate(IoUringCompletion) nothrow @nogc handler) nothrow @nogc
    {
        import core.atomic : atomicStore, atomicLoad, MemoryOrder;

        auto head     = *cast(uint*)(this.cqPtr + this.ioUringParams.cq_off.head);
        scope tailPtr = cast(uint*)(this.cqPtr + this.ioUringParams.cq_off.tail);
        const cqMask  = *cast(uint*)(this.cqPtr + this.ioUringParams.cq_off.ring_mask);
        while(head != atomicLoad!(MemoryOrder.acq)(*tailPtr))
        {
            const headIndex = head & cqMask;
            const cqe = cqeSlice[headIndex];
            handler(IoUringCompletion(cast(void*)cqe.user_data, cqe.res, cqe.flags));
            head++;
        }

        atomicStore!(MemoryOrder.rel)(*cast(uint*)(this.cqPtr + this.ioUringParams.cq_off.head), head);
    }

    void enter(uint minCompletes = 0)
    {
        uint flags = 0;
        if(minCompletes > 0)
            flags |= IORING_ENTER_GETEVENTS;

        const result = io_uring_enter(this.ioUringFd, this.pendingSubmits, minCompletes, flags, null);

        const oldPendingSubmits = this.pendingSubmits;
        if(result < 0)
        {
            switch(result)
            {
                case EAGAIN:
                    return; // Docs suggest no sqes were submitted

                case EBUSY:
                    return; // Docs suggest no sqes were submitted

                case EINTR: // Interrupted; but docs suggest all sqes are still submitted
                    this.pendingSubmits = 0;
                    break;

                default:
                    import juptune.event.internal.linux : linuxErrorAsResult;
                    linuxErrorAsResult("io_uring_enter failed", result).resultAssert;
                    assert(false);
            }
        }
        else
            this.pendingSubmits -= result;

        // Free submitted SQEs
        const submitted = oldPendingSubmits - this.pendingSubmits;
        const sqeTail   = *cast(uint*)(sqPtr + this.ioUringParams.sq_off.tail) - oldPendingSubmits;
        const sqeMask   = *cast(uint*)(sqPtr + this.ioUringParams.sq_off.ring_mask);

        foreach(i; 0..submitted)
        {
            const index = (sqeTail + i) & sqeMask;
            this.freeSqe(this.sqeIndexSlice[index]);
        }
    }

    alias _submitImplTest = submitImpl!(IoUringNop);
    private SubmitQueueIsFull submitImpl(Command)(Command command, scope void delegate(io_uring_sqe*, uint) @nogc nothrow modifyFunc)
    in(this.pendingSubmits <= this.ioUringParams.sq_entries, "Bug: pendingSubmits is larger than the SQE count")
    {
        import core.atomic : atomicStore, MemoryOrder;

        if(this.pendingSubmits >= this.ioUringParams.sq_entries)
            return SubmitQueueIsFull.yes;

        const sqeIndex = this.allocateNextSqe();
        assert(sqeIndex < this.ioUringParams.sq_entries);

        scope sqe = &this.sqeSlice[sqeIndex];
        command.toSqe(*sqe);
        
        const sqOff  = this.ioUringParams.sq_off;
        auto sqTail  = *cast(uint*)(sqPtr + sqOff.tail);
        auto sqMask  = *cast(uint*)(sqPtr + sqOff.ring_mask);
        auto index   = sqTail & sqMask;
        
        modifyFunc(sqe, sqeIndex);
        
        this.sqeIndexSlice[index] = sqeIndex;
        atomicStore!(MemoryOrder.rel)(*cast(uint*)(sqPtr + sqOff.tail), sqTail + 1);
        this.pendingSubmits++;

        return SubmitQueueIsFull.no;
    }

    private uint allocateNextSqe()
    {
        import core.bitop : bsf;

        size_t i;
        while(this.sqeInUseMasks[i] == 0)
            i++;
        assert(i < this.sqeInUseMasks.length, "Bug: allocateNextSqe shouldn't have been called, since there's none left.");

        const index = bsf(this.sqeInUseMasks[i]);
        this.sqeInUseMasks[i] &= ~(1UL << index);

        enum BitsPerLong = ulong.sizeof * 8;
        const result = (BitsPerLong * i) + index;
        assert(result <= uint.max, "Result is too large?");

        return cast(uint)result;
    }

    private void freeSqe(uint index)
    {
        enum BitsPerLong = ulong.sizeof * 8;
        const maskLong = index / BitsPerLong;
        const maskBit  = index % BitsPerLong;

        this.sqeInUseMasks[maskLong] |= 1UL << maskBit;
    }

    private void enableFeatures()
    {
        if(g_linuxKernal.major > 5 || (g_linuxKernal.major == 5 && g_linuxKernal.minor >= 18))
            this.ioUringParams.flags |= IORING_SETUP_SUBMIT_ALL;
        if(g_linuxKernal.major > 5 || (g_linuxKernal.major == 5 && g_linuxKernal.minor >= 19))
            this.ioUringParams.flags |= IORING_SETUP_COOP_TASKRUN;
        if(g_linuxKernal.major >= 6)
            this.ioUringParams.flags |= IORING_SETUP_SINGLE_ISSUER;
    }
}

version(Posix)
private struct IoUringEmulatedPosixDriver
{
    @nogc nothrow:

    Result initDriver(const IoUringConfig config){ assert(false, "Not implemented"); }
    void uninitDriver(){ assert(false, "Not implemented"); }
    void enter(uint minCompletes = 0){ assert(false, "Not implemented"); }
    SubmitQueueIsFull submit(Command)(Command command){ assert(false, "Not implemented"); }
    SubmitQueueIsFull submitTimeout(Command)(Command command, Duration timeout = Duration.zero){ assert(false, "Not implemented"); }
    void processCompletions(scope void delegate(IoUringCompletion) nothrow @nogc handler) nothrow @nogc{ assert(false, "Not implemented"); }
}

private mixin template IoUringTests(IoUringDriver driver)
{
    import std.conv : to;
    private immutable _t = driver.to!string~" - ";

    @(_t~"init")
    unittest
    {
        auto uring = IoUring(IoUringConfig().withDriver(driver));
        uring.__xdtor();
    }

    version(linux)
    static if(driver == IoUringDriver.native)
    {
        @(_t~"allocateNextSqe")
        unittest
        {
            import std.exception : assertThrown;

            auto uring = IoUring(IoUringConfig().withDriver(driver));
            scope driver = &uring.drivers.native;

            assert(driver.sqeInUseMasks.length > 0);
            assert(driver.allocateNextSqe() == 0);
            assert(driver.allocateNextSqe() == 1);
            assert(driver.allocateNextSqe() == 2);
            assert(driver.allocateNextSqe() == 3);
            assert(driver.sqeInUseMasks[0] == ~0b1111);
            
            driver.freeSqe(1);
            assert(driver.sqeInUseMasks[0] == ~0b1101);
            assert(driver.allocateNextSqe() == 1);

            driver.sqeInUseMasks[0] = 0;
            assert(driver.sqeInUseMasks.length > 1);
            assert(driver.allocateNextSqe() == 64);
            assert(driver.allocateNextSqe() == 65);
            assert(driver.sqeInUseMasks[1] == ~0b11);
            
            driver.freeSqe(64);
            assert(driver.sqeInUseMasks[1] == ~0b10);
            assert(driver.allocateNextSqe() == 64);

            driver.sqeInUseMasks[] = ulong.max;
            foreach(i; 0..driver.sqeInUseMasks.length * 64)
            {
                import std.format : format;
                const got = driver.allocateNextSqe();
                assert(got == i, format("got: %s | wanted: %s"));
            }

            assertThrown!Error(driver.allocateNextSqe());
        }

        @(_t~"submit pending check")
        unittest
        {
            auto uring = IoUring(IoUringConfig().withDriver(driver));
            scope driver = &uring.drivers.native;
            
            assert(driver.sqeIndexSlice.length == driver.ioUringParams.sq_entries);
            assert(driver.sqeSlice.length == driver.ioUringParams.sq_entries);

            foreach(ref sqe; driver.sqeSlice)
                sqe.opcode = ubyte.max; // OP_NOP is `0`, so to ensure we're actually setting the SQE, set them to something else for now.

            foreach(i; 0..driver.ioUringParams.sq_entries)
                assert(driver.submit(IoUringNop()) == SubmitQueueIsFull.no);
            assert(driver.submit(IoUringNop()) == SubmitQueueIsFull.yes);

            foreach(i, sqe; driver.sqeSlice)
            {
                import std.format : format;
                assert(sqe.opcode == IORING_OP_NOP, format("i: %s | sqe: %s", i, sqe));
            }

            assert(driver.pendingSubmits == driver.ioUringParams.sq_entries);
        }

        @(_t~"enter")
        unittest
        {
            auto uring = IoUring(IoUringConfig().withDriver(driver));
            scope driver = &uring.drivers.native;

            assert(driver.cqeSlice.length == driver.ioUringParams.cq_entries);
            foreach(i; 0..driver.ioUringParams.sq_entries)
            {
                auto nop = IoUringNop();
                nop.userData = cast(void*)i;
                assert(driver.submit(nop) == SubmitQueueIsFull.no);
            }

            foreach(i, ref cqe; driver.cqeSlice)
            {
                cqe.res = -1;
                cqe.user_data = cast(void*)ulong.max;
            }

            assert(driver.pendingSubmits == driver.ioUringParams.sq_entries);
            driver.enter();
            assert(driver.pendingSubmits == 0);

            size_t completed;
            driver.processCompletions((cqe){
                import std.format : format;

                debug const msg = format("completed: %s | cqe: %s", completed, cqe);

                assert(cqe.result == 0);
                debug assert(cqe.userData == cast(void*)completed, msg);

                completed++;
            });
            assert(completed == driver.ioUringParams.sq_entries);
        }

        @(_t~"enter full CQE queue")
        unittest
        {
            auto uring = IoUring(IoUringConfig().withDriver(driver));
            scope driver = &uring.drivers.native;

            foreach(_; 0..2)
            {
                foreach(i; 0..driver.ioUringParams.sq_entries)
                    assert(driver.submit(IoUringNop()) == SubmitQueueIsFull.no);

                assert(driver.pendingSubmits == driver.ioUringParams.sq_entries);
                driver.enter();
                assert(driver.pendingSubmits == 0);
            }

            assert(driver.submit(IoUringNop()) == SubmitQueueIsFull.no);
            driver.enter();

            size_t completed;
            driver.processCompletions((_){ completed++; });
            assert(completed == driver.ioUringParams.cq_entries);

            // NOTE: I think extra OP_NOPs get completely dropped by the kernal,
            //       which is why I can't get this extra `+ 1` CQE to occur.
            //
            // driver.enter();
            // driver.processCompletions((_){ completed++; });
            // assert(completed == driver.ioUringParams.cq_entries + 1);
        }

        @(_t~"basic timeout behaviour")
        unittest
        {
            auto uring = IoUring(IoUringConfig().withDriver(driver));
            scope driver = &uring.drivers.native;

            // NOTE: NOP completes instantly, so the timeout shouldn't take affect.
            auto op = IoUringNop();
            op.userData = cast(void*)1;
            
            assert(driver.submitTimeout(op, 10.seconds) == SubmitQueueIsFull.no);
            assert(driver.pendingSubmits == 2);
            driver.enter();
            assert(driver.pendingSubmits == 0);

            IoUringCompletion[2] completions;
            size_t completed;
            driver.processCompletions((cqe){ 
                completions[completed++] = cqe;
            });
            assert(completed == 2);
            assert(completions[0].result == 0);
            assert(completions[1].result == -ECANCELED);
        }
    }
}