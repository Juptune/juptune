/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.rng;

void cryptoFillBuffer(scope ubyte[] buffer) @trusted @nogc nothrow // @trusted: as long as the user doesn't do something stupid
in(buffer.length > 0, "Buffer length must be greater than 0 - it's likely a bug otherwise")
{
    version(Juptune_LibSodium)
    {
        import juptune.crypto.libsodium : randombytes_buf;
        randombytes_buf(buffer.ptr, buffer.length);
    } else assert(false, "No implmentation for cryptoFillBuffer");
}

/++++ Unittests ++++/

@("cryptoFillBuffer - making sure it doesn't crash")
unittest
{
    auto buffer = new ubyte[16];
    cryptoFillBuffer(buffer);
}