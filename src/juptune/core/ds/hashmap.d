/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.ds.hashmap;

import juptune.core.ds.alloc, juptune.core.ds.array, std.digest.murmurhash, std.digest.crc;
import std.traits : hasElaborateDestructor, hasElaborateCopyConstructor;
import std.algorithm : move;

struct RobinHoodHashMapBase(
    alias Alloc,
    size_t DefaultInitSize,
    alias GetGrowSize,
    alias GetLoadFactor,
    alias Hasher,
    alias KeyT_,
    alias ValueT_
)
{
    alias KeyT   = KeyT_;
    alias ValueT = ValueT_;

    static struct Kvp
    {
        KeyT key;
        ValueT value;
        private ushort psl;
        private bool isSet;

        @nogc nothrow:

        static if(hasElaborateCopyConstructor!KeyT || hasElaborateCopyConstructor!ValueT)
        this(ref return scope Kvp kvp)
        {
            this.key = kvp.key;
            this.value = kvp.value;
        }
    }

    private static struct Map
    {
        alias Grow = (len, cap) => len;
        alias Shrink = (len, cap) => cap / 2;
        alias ShouldShrink = (len, cap) => len <= cap / 3;
        ArrayBase!(
            Alloc,
            DefaultInitSize,
            Grow,
            Shrink,
            ShouldShrink,
            Kvp
        ) array;
        size_t length;

        @nogc nothrow:

        this(ref return scope Map map)
        {
            this.array = map.array;
            this.length = map.length;
        }
    }

    private
    {
        Map _map;
        size_t _loadFactor;
    }

    @nogc nothrow:

    static if(Alloc.CtorParams.length)
    this(Alloc.CtorParams params)
    {
        this._array = ArrayT(params);
    }

    this(ref return scope typeof(this) src)
    {
        this._map = src._map;
        this._loadFactor = src._loadFactor;
    }

    void put(VT : ValueT)(KeyT key, VT value)
    {
        if(this._map.array.length == 0)
        {
            this._map.array.length = DefaultInitSize;
            this._loadFactor = GetLoadFactor(this._map.length, this._map.array.length);
        }

        this._put(key, value, this._map);

        if(this._map.length >= this._loadFactor)
        {
            while(!this.moveToNewMap(GetGrowSize(this._map.length, this._map.array.length)))
            {}
            this._loadFactor = GetLoadFactor(this._map.length, this._map.array.length);
        }
    }

    ValueT tryRemove(KeyT key, out bool wasFound)
    {
        uint index;
        scope ptr = this._getPtr(key, index, this._map);
        if(!ptr)
        {
            ValueT init;
            wasFound = false;
            return init;
        }

        ValueT value;
        value = ptr.value;

        const startIndex = index;
        auto prevIndex = index;
        index = (index + 1) % this._map.array.length;
        
        this._map.array[startIndex].isSet = false;
        static if(hasElaborateDestructor!ValueT)
            this._map.array[startIndex].value.__xdtor;
        static if(hasElaborateDestructor!KeyT)
            this._map.array[startIndex].key.__xdtor;

        while(index != startIndex && this._map.array[index].isSet && this._map.array[index].psl != 0)
        {
            this._map.array.move!"key"(prevIndex, this._map.array[index].key);
            this._map.array.move!"value"(prevIndex, this._map.array[index].value);
            this._map.array[prevIndex].psl = cast(ushort)(this._map.array[index].psl - 1);
            this._map.array[prevIndex].isSet = true;
            this._map.array[index].isSet = false;
            static if(hasElaborateDestructor!ValueT)
                this._map.array[index].value.__xdtor;
            static if(hasElaborateDestructor!KeyT)
                this._map.array[index].key.__xdtor;

            prevIndex = index;
            index = (index + 1) % this._map.array.length;
        }

        this._map.length--;
        wasFound = true;
        return value;
    }

    ValueT tryGet(KeyT key, out bool wasFound)
    {
        uint _1;
        scope ptr = this._getPtr(key, _1, this._map);
        if(!ptr)
        {
            ValueT init; // Sometimes the compiler thinks SomeType.init needs TypeInfo, sometimes it doesn't, so we'll just be safe.
            wasFound = false;
            return init;
        }

        wasFound = true;
        return ptr.value;
    }

    ValueT remove(KeyT key, ValueT default_ = ValueT.init)
    {
        bool b;
        auto value = this.tryRemove(key, b);
        return b ? value : default_;
    }

    ValueT get(KeyT key, ValueT default_ = ValueT.init)
    {
        bool b;
        auto value = this.tryGet(key, b);
        return b ? value : default_;
    }

    ValueT* getPtr(KeyT key)
    {
        uint _1;
        scope ptr = this._getPtr(key, _1, this._map);
        return ptr ? &ptr.value : null;
    }

    @property @safe
    size_t length() const
    {
        return this._map.length;
    }

    ref ValueT opIndex(KeyT key)
    {
        scope ptr = this.getPtr(key);
        assert(ptr, "Key does not exist.");
        return *ptr;
    }

    void opIndexAssign(ValueT value, KeyT key)
    {
        this.put(key, value);
    }

    void opIndexOpAssign(string op, T)(T value, KeyT key)
    {
        mixin("this.opIndex(key) "~op~"= value;");
    }

    ValueT* opBinaryRight(string op)(KeyT key)
    if(op == "in")
    {
        return this.getPtr(key);
    }

    auto byKeyValue()
    {
        static struct R
        {
            Map* map;
            Kvp* front;
            bool empty;
            size_t cursor;

            this(Map* map)
            {
                this.map = map;
                this.popFront();
            }

            void popFront()
            {
                if(this.cursor >= this.map.array.length)
                {
                    this.empty = true;
                    return;
                }

                while(this.cursor < this.map.array.length && !this.map.array[this.cursor++].isSet) {}
                if(this.cursor > this.map.array.length)
                {
                    this.empty = true;
                    return;
                }

                this.front = &this.map.array[this.cursor-1];
            }
        }

        return R(&this._map);
    }

    private:

    Kvp* _getPtr(KeyT key, out uint index, ref typeof(_map) map)
    {
        if(map.array.length == 0)
            return null;

        // My brain isn't working and I can't get it to think about how to abuse
        // the properties of Robin Hood hashing to make this faster, so for now
        // we'll have O(n) worst case lookup times.
        // p sure it's supposed to have O(log n) worst case?
        const hash = this.getHash!Hasher(key);
        index = hash % map.array.length;
        const startIndex = index;

        if(map.array[index].isSet && map.array[index].key == key)
            return &map.array[index];
        
        index = (index + 1) % map.array.length;
        while(!(map.array[index].key == key && map.array[index].isSet) && index != startIndex)
            index = (index + 1) % map.array.length;

        if(index == startIndex)
            return null;
        else
        {
            assert(map.array[index].key == key);
            return &map.array[index];
        }
    }

    bool moveToNewMap(size_t newMapSize)
    {
        Map map;
        map.array.length = newMapSize;
        assert(map.array.length >= this._map.length, "New map size is too small");

        foreach(i; 0..this._map.array.length)
        {
            if(this._map.array[i].isSet)
                this._put(this._map.array[i].key, this._map.array[i].value, map);
        }
        if(map.length != this._map.length)
            return false;

        move(map, this._map);
        return true;
    }

    uint getHash(alias Hasher)(KeyT key)
    {
        uint hash;
        static if(__traits(hasMember, KeyT, "toHash"))
            hash = key.toHash();
        else
        {
            Hasher hasher;
            hasher.start();
            static if(is(KeyT : Key[], Key))
                hasher.put(cast(ubyte[])(&key[0])[0..Key.sizeof*key.length]);
            else
                hasher.put(cast(ubyte[])(&key)[0..1]);
            const bytes = hasher.finish();
            hash = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
        }
        return hash;
    }

    void _put(VT : ValueT)(KeyT initKey, VT initValue, ref typeof(_map) map)
    {
        assert(map.length != map.array.length, "The array should've grown by now.");

        auto key   = initKey;
        auto value = initValue;
        const hash = this.getHash!Hasher(key);
        auto index = hash % map.array.length;
        ushort psl = 0;

        while(true)
        {
            scope ptr = &map.array[index];
            if(!ptr.isSet)
            {
                ptr.isSet = true;
                ptr.psl = psl;
                map.array.move!"key"(index, key);
                map.array.move!"value"(index, value);
                map.length++;
                return;
            }
            else if(ptr.key == key)
            {
                map.array.move!"value"(index, value);
                return;
            }
            else if(ptr.psl < psl)
            {
                auto tempKey = ptr.key;
                auto tempValue = ptr.value;
                auto tempPsl = ptr.psl;
                map.array.move!"key"(index, key);
                map.array.move!"value"(index, value);
                ptr.psl = psl;
                key = tempKey;
                value = tempValue;
                psl = tempPsl;
                continue;
            }
            else
            {
                psl++;
                index = (index + 1) % map.array.length;
            }
        }
    }
}

alias RobinHoodHashMapDefault(alias Alloc, alias KeyT, alias ValueT) = RobinHoodHashMapBase!(
    Alloc,
    8,
    (len, cap) => cap * 2,
    (len, cap) => cast(size_t)(cast(float)cap * 0.8),
    MurmurHash3!32,
    KeyT,
    ValueT
);

alias RobinHoodHashMap(alias KeyT, alias ValueT) = RobinHoodHashMapDefault!(Malloc, KeyT, ValueT);
alias HashMap(alias KeyT, alias ValueT) = RobinHoodHashMap!(KeyT, ValueT);

@("basic")
@nogc nothrow
unittest
{
    HashMap!(string, int) map;
    map.put("a", 1); map.put("a", 2); 
    map.put("b", 2); map.put("b", 4); 
    map.put("c", 3); map.put("c", 6); 
    map.put("d", 4); map.put("d", 4); 
    assert(map.length == 4);

    assert(map["a"] == 2);
    map["b"] = 8;
    assert(map["b"] == 8);
    map["b"] /= 2;
    assert(map["b"] == 4);
    assert("b" in map);
    
    bool wasRemoved;
    assert(map.tryRemove("a", wasRemoved) == 2 && wasRemoved && map.length == 3);
    assert(map.tryRemove("b", wasRemoved) == 4 && wasRemoved && map.length == 2);
    assert(map.tryRemove("c", wasRemoved) == 6 && wasRemoved && map.length == 1);
    assert(map.tryRemove("d", wasRemoved) == 4 && wasRemoved && map.length == 0);
    assert(map.tryRemove("d", wasRemoved) == 0 && !wasRemoved);
}

@("stress")
@nogc nothrow
unittest
{
    HashMap!(int, int) map;

    // If this test is failing, compile with LDC2
    // I think I'm hitting a super strange DMD codegen bug
    foreach(i; 0..100_000)
    {
        map.put(i, i);
    }

    foreach(i; 0..100_000)
    {
        bool b;
        assert(map.tryGet(i, b) == i);
        assert(b);
    }
        
    foreach(i; 0..100_000)
    {
        bool b;
        map.tryRemove(i, b);
        assert(b);
    }
}

@("copyable types")
@nogc nothrow
unittest
{
    int i;

    static struct S
    {
        @nogc nothrow:

        int* i;
        this(int* i)
        {
            this.i = i;
            (*i)++;
        }

        this(scope return ref S s)
        {
            this.i = s.i;
            (*this.i)++;
        }

        ~this()
        {
            if(this.i)
            {
                (*i)--;
                this.i = null;
            }
        }
    }

    HashMap!(int, S) map;

    map.put(0, S(&i));
    map.put(1, S(&i));
    map.put(2, S(&i));
    map.put(3, S(&i));
    map.put(4, S(&i));
    assert(i == 5);
    assert(map.length == 5);

    bool b;
    map.tryRemove(0, b); assert(b); assert(i == 4); assert(map.length == 4);
    map.tryRemove(1, b); assert(b); assert(i == 3); assert(map.length == 3);
    map.tryRemove(2, b); assert(b); assert(i == 2); assert(map.length == 2);
    map.tryRemove(3, b); assert(b); assert(i == 1); assert(map.length == 1);
    map.tryRemove(4, b); assert(b); assert(i == 0); assert(map.length == 0);

    foreach(n; 0..1000)
        map.put(n, S(&i));
    assert(map.length == 1000);
    assert(i == 1000);

    foreach(n; 0..1000)
        map.remove(n);
    assert(map.length == 0);
    assert(i == 0);
}

@("tryGet - missing")
@nogc nothrow
unittest
{
    HashMap!(int, bool) map;
    bool b;
    assert(!map.tryGet(0, b) && !b);

    map.put(0, true);
    map.tryRemove(0, b);
    assert(!map.tryGet(0, b) && !b);
}

@("remove")
@nogc nothrow
unittest
{
    HashMap!(int, bool) map;
    map.put(1, true);
    assert(!map.remove(0));
    assert(map.remove(2, true));
    assert(map.remove(1));
}

@("get")
@nogc nothrow
unittest
{
    HashMap!(int, bool) map;
    map.put(1, true);
    assert(!map.get(0));
    assert(map.get(2, true));
    assert(map.get(1));
}

@("byKeyValue")
@nogc nothrow
unittest
{
    HashMap!(string, int) map;
    map.put("abc", 123);

    assert(map.byKeyValue.front.key == "abc");
}

@("String key and value")
@nogc nothrow
unittest
{
    import juptune.core.ds.string;

    HashMap!(String, String) map;
    map.put(String("abc"), String("123"));
    assert(map.get(String("abc"), String.init) == String("123"));
    assert(map.get(String("doe ray me"), String.init) == String.init);
    map.put(String("abc"), String("321"));
    assert(map.get(String("abc"), String.init) == String("321"));
}