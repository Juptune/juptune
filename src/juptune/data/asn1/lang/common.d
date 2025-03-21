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

struct Asn1ParserContext
{
    import juptune.data.asn1.lang.ast : Asn1BaseNode;

    @disable this(this){}

    NodeAllocator allocator;

    NodeT allocNode(NodeT : Asn1BaseNode, CtorArgs...)(auto ref CtorArgs args)
    {
        import std.experimental.allocator : make;
        return make!NodeT(this.allocator, args);
    }
}