/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.ds.pointer;

import juptune.core.util : Result;

/++
 + A shared ref counted pointer.
 +
 + Notes:
 +  Memory management is only handled by stdc's calloc & friends.
 +
 +  Because I don't want to complicate things too much right now, `ValueT` must be a zero-init type.
 + ++/
shared struct SharedRefCount(alias ValueT)
{
    static assert(__traits(isZeroInit, ValueT), "Value type must be a zero-init type (for now!)");

    private
    {
        static struct Payload
        {
            ValueT    _value;
            ptrdiff_t _count;
        }

        shared(Payload*) _payload;
    }

    this(scope ref return shared typeof(this) refCount) @trusted @nogc nothrow shared
    {
        import core.atomic : atomicFetchAdd;

        this.__xdtor();

        if(refCount.isNull)
            return;

        this._payload = refCount._payload;
        const oldValue = atomicFetchAdd(this._payload._count, 1);
        assert(oldValue > 0, "bug: previous value of ref count was <= 0 (on acquire) - crashing to prevent other spurious bugs"); // @suppress(dscanner.style.long_line)
    }

    ~this() @trusted @nogc nothrow shared
    {
        import core.atomic      : atomicFetchSub;
        import core.stdc.stdlib : free;
        
        if(this._payload is null)
            return;

        const oldValue = atomicFetchSub(this._payload._count, 1);
        assert(oldValue > 0, "bug: previous value of ref count was <= 0 (on free) - crashing to prevent other spurious bugs"); // @suppress(dscanner.style.long_line)
        if(oldValue == 1)
            free(cast(void*)this._payload);
        this._payload = null;
    }

    /// Returns: Whether this SharedRefCount has a value or not.
    bool isNull() @safe @nogc nothrow => this._payload is null;

    /++
     + Safely accesses the underlying shared value.
     +
     + Notes:
     +  This is the safest way to access the underlying value, as it contains a null check &
     +  it shouldn't be possible for the ref count to reach 0 while `func` is executing.
     +
     + Params:
     +  func = The accessor function.
     +
     + Throws:
     +  Anything that `func` throws.
     +
     + Returns:
     +  Whatever `func` returns.
     + ++/
    alias access = accessImpl!(Result delegate(scope ref shared ValueT) @nogc nothrow);
    
    /// ditto.
    alias accessGC = accessImpl!(Result delegate(scope ref shared ValueT));

    private Result accessImpl(DelegateT)(scope DelegateT func)
    in(!this.isNull, "bug: this shared ref count is null")
    {
        return func(this._payload._value);
    }

    /++
     + Instantiates this SharedRefCount, using the provided init function to setup
     + the underlying value.
     +
     + Notes:
     +  The value isn't passed as `shared` into `initFunc` as - at this point in time - there
     +  is only a single reference to it.
     +
     +  The `makeGC` override **does not allocate the payload using the GC**, it's there for when
     +  the `initFunc` can't be marked as @nogc.
     +
     + Params:
     +  initFunc = The function responsible for setting up the initial value of the payload.
     +
     + Throws:
     +  Anything that `initFunc` throws.
     +
     + Returns:
     +  Whatever `initFunc` returns.
     + ++/
    alias make = makeImpl!(Result delegate(scope out ValueT) @nogc nothrow);
    
    /// ditto.
    alias makeGC = makeImpl!(Result delegate(scope out ValueT));

    private Result makeImpl(DelegateT)(scope DelegateT initFunc)
    in(this.isNull, "bug: this shared ref count is not null")
    {
        import core.stdc.stdlib : calloc, free;
        import core.exception   : onOutOfMemoryErrorNoGC;

        auto ptr = cast(Payload*)calloc(1, Payload.sizeof);
        if(ptr is null)
            onOutOfMemoryErrorNoGC();

        auto result = initFunc(ptr._value);
        if(result.isError)
        {
            free(ptr);
            return result;
        }

        ptr._count = 1;
        this._payload = cast(shared)ptr;
        return Result.noError;
    }
}
///
@("SharedRefCount - very basic test")
unittest
{
    import juptune.core.util : resultAssert;

    SharedRefCount!int rc;
    assert(rc.isNull);
    rc.__xdtor(); // Making sure we don't crash on null dtor

    // Making sure null copies are safe.
    {
        auto copy = rc;
    }

    // Making sure basic init + dtor works.
    rc.make((scope out value){ value = 67; return Result.noError; }).resultAssert;
    assert(!rc.isNull);
    assert(rc._payload._count == 1);
    rc.access((scope ref value){ assert(value == 67); return Result.noError; }).resultAssert;
    rc.__xdtor();
    assert(rc.isNull);

    // Making sure basic copy ctor works.
    rc.make((scope out value){ value = 67; return Result.noError; }).resultAssert;
    {
        auto copy = rc;
        assert(rc._payload is copy._payload);
        assert(rc._payload._count == 2);
        {
            auto copy2 = copy;
            assert(rc._payload is copy2._payload);
            assert(rc._payload._count == 3);
        }
        assert(rc._payload._count == 2);
    }
    assert(rc._payload._count == 1);
}