/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto;

public import
    juptune.crypto.aead,
    juptune.crypto.ecdsa,
    juptune.crypto.hkdf,
    juptune.crypto.keyexchange,
    juptune.crypto.memory,
    juptune.crypto.rng,
    juptune.crypto.rsa
;

shared static this()
{
    version(Juptune_LibSodium)
    {
        import juptune.crypto.libsodium;
        const result = sodium_init();
        assert(result == 0, "Failed to initialize libsodium");
    }
}