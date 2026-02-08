/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

/// Contains misc types that are common throughout the entire package without having a distinct place to exist in.
module juptune.asn1.lang.common;

import std.experimental.allocator.mallocator                        : Mallocator;
import std.experimental.allocator.building_blocks.allocator_list    : AllocatorList;
import std.experimental.allocator.building_blocks.region            : Region;
import std.experimental.allocator.building_blocks.stats_collector   : StatsCollector, Stats = Options;

private alias NodeAllocator = StatsCollector!(
    AllocatorList!(
        (n) => Region!Mallocator(1024 * 1024),
        Mallocator
    ),
    Stats.bytesAllocated
);

struct Asn1Location
{
    size_t start;
    size_t end;

    const(char)[] sourceName;
    uint line;

    // Unittests don't really give a damn about line and sourceName.
    version(unittest) bool opEquals()(auto ref const Asn1Location loc) const
        => loc.start == this.start && loc.end == this.end;
}

struct Asn1ParserContext
{
    import juptune.asn1.lang.ast : Asn1BaseNode;
    import juptune.asn1.lang.ir  : Asn1BaseIr;
    import juptune.core.ds            : Array, String, HashMap;
    import juptune.core.util          : Result;

    @disable this(this){}

    NodeAllocator allocator;
    Array!Asn1BaseNode nodesToDtor;
    Array!Asn1BaseIr irToDtor;
    Array!String strings;

    @nogc nothrow:

    ~this()
    {
        foreach(node; this.nodesToDtor)
            node.dispose(); // Allows things like List nodes to free their Array resources.
        foreach(ir; this.irToDtor)
            ir.dispose(); // Allows things like List nodes to free their Array resources.

        this.allocator.__xdtor();
        this.nodesToDtor.__xdtor();
        this.irToDtor.__xdtor();
        this.strings.__xdtor();
    }

    /++
     + Creates a copy of the given string, and ties its lifetime with this context instance.
     +
     + This is helpful for @nogc use cases, since you can: Load in a string; call this function
     + to ensure it has the correct lifetime; free the previously loaded string, and finally
     + use the copied version of the string for any actual parsing.
     +
     + The alternative is that @nogc user code would have to guarentee that source code strings
     + do not get freed before a context instance.
     +
     + Notes:
     +  The returned value should never outlive this context instance's lifetime.
     +
     + Params:
     +  slice = The slice to make a copy of.
     +
     + Returns:
     +  The copied slice, in the form of a `String`.
     + ++/
    String preserveString(scope const(char)[] slice)
    {
        this.strings.put(String(slice));
        return this.strings[$-1];
    }

    /++
     + An overload of `preserveString` that doesn't create a copy, but instead
     + preserves a living instance of `str`, so that its ref count doesn't reach 0 until
     + sometime after this context instance is destroyed.
     + ++/
    void preserveString(ref String str)
    {
        this.strings.put(str);
    }

    NodeT allocNode(NodeT : Asn1BaseNode, CtorArgs...)(auto ref CtorArgs args)
    {
        import std.experimental.allocator : make;
        auto node = make!NodeT(this.allocator, args);

        static if(__traits(hasMember, NodeT, "_MustBeDtored"))
            this.nodesToDtor.put(node);

        return node;
    }

    NodeT allocNode(NodeT : Asn1BaseIr, CtorArgs...)(auto ref CtorArgs args)
    {
        import std.experimental.allocator : make;
        auto node = make!NodeT(this.allocator, args);
        this.irToDtor.put(node);
        return node;
    }

    // Just for monitoring memory (mis)usage
    size_t bytesAllocated() => this.allocator.bytesAllocated;
}


/++++ Error Handling ++++/

abstract class Asn1ErrorHandler
{
    import juptune.core.ds : Array, String;

    @nogc nothrow:

    abstract void startLine(Asn1Location location);
    abstract void putInLine(scope const(char)[] slice);
    abstract void endLine();
    abstract void indent();
    abstract void dedent();

    String errorAndString(Args...)(Asn1Location location, scope auto ref Args args)
    {
        import juptune.core.util : toStringSink;

        Array!char buffer;

        static struct Putter
        {
            Asn1ErrorHandler handler;
            Array!char* buffer;
            void put(scope const(char)[] slice) @nogc nothrow
            {
                this.handler.putInLine(slice);
                buffer.put(slice);
            }
        }
        scope putter = Putter(this, &buffer);

        this.startLine(location);
        scope(exit) this.endLine();

        foreach(ref arg; args)
        {
            static if(!__traits(compiles, putInLine(arg)))
                toStringSink(arg, putter);
            else
            {
                this.putInLine(arg);
                buffer.put(arg);
            }
        }

        return String.fromDestroyingArray(buffer);
    }
}

final class Asn1NullErrorHandler : Asn1ErrorHandler
{
    __gshared instance = new Asn1NullErrorHandler();
    
    @nogc nothrow:

    override void startLine(Asn1Location location) {}
    override void putInLine(scope const(char)[] slice) {}
    override void endLine() {}
    override void indent() {}
    override void dedent() {}
}