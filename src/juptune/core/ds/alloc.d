/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.ds.alloc;

import std.meta : AliasSeq;

struct Malloc
{
    alias CtorParams = AliasSeq!();
    enum  IsCopyable = true;

    mixin template InjectState()
    {
        import core.stdc.stdlib;

        @nogc
        void* calloc(size_t amount)
        {
            return core.stdc.stdlib.calloc(amount, 1);
        }

        @nogc
        void free(void* ptr)
        {
            core.stdc.stdlib.free(ptr);
        }

        @nogc
        void* realloc(void* ptr, size_t size)
        {
            return core.stdc.stdlib.realloc(ptr, size);
        }

        void allocCtor(Alloc.CtorParams _){}
        void allocDtor(){}
    }
}