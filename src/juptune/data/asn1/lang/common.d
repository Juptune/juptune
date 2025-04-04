/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.lang.common;

import std.experimental.allocator.mallocator                        : Mallocator;
import std.experimental.allocator.building_blocks.allocator_list    : AllocatorList;
import std.experimental.allocator.building_blocks.region            : Region;

private alias NodeAllocator = AllocatorList!(
    (n) => Region!Mallocator(1024 * 1024),
    Mallocator
);

struct Asn1Location
{
    size_t start;
    size_t end;
}

struct Asn1ParserContext
{
    import juptune.data.asn1.lang.ast : Asn1BaseNode;
    import juptune.data.asn1.lang.ir  : Asn1BaseIr;
    import juptune.core.ds            : Array, String2, HashMap;
    import juptune.core.util          : Result;

    @disable this(this){}

    NodeAllocator allocator;
    Array!Asn1BaseNode nodesToDtor;
    Array!Asn1BaseIr irToDtor;

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
}