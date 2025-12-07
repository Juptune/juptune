/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.hkdf;

import juptune.core.util : Result;

enum HkdfError
{
    none,
    expandFailed,
    extractFailed,
}

version(Juptune_LibSodium) Result hkdfExpandSha256(
    scope ubyte[] outKey, 
    scope const(ubyte)[] context, 
    scope ref const ubyte[32] masterKey
) @nogc nothrow
{
    import juptune.crypto.libsodium : crypto_kdf_hkdf_sha256_expand;

    auto ret = crypto_kdf_hkdf_sha256_expand(
        &outKey[0], outKey.length,
        cast(const(char)*)&context[0], context.length,
        masterKey
    );
    return ret == 0 ? Result.noError : Result.make(HkdfError.expandFailed, "Expand failed (libsodium doesn't provide further information)"); // @suppress(dscanner.style.long_line)
}

version(Juptune_LibSodium) Result hkdfExtractSha256(
    scope ref ubyte[32] outKey,
    scope const(ubyte)[] salt,
    scope const(ubyte)[][] keyingMaterials...
) @nogc nothrow
in(salt.length > 0, "salt must not be empty")
{
    import juptune.crypto.libsodium 
        :
            crypto_kdf_hkdf_sha256_extract_init,
            crypto_kdf_hkdf_sha256_extract_update,
            crypto_kdf_hkdf_sha256_extract_final,
            crypto_kdf_hkdf_sha256_state
        ;

    crypto_kdf_hkdf_sha256_state state;

    auto ret = crypto_kdf_hkdf_sha256_extract_init(&state, &salt[0], salt.length);
    if(ret != 0)
        return Result.make(HkdfError.extractFailed, "crypto_kdf_hkdf_sha256_extract_init failed (libsodium doesn't provide further information)"); // @suppress(dscanner.style.long_line)

    foreach(material; keyingMaterials)
    {
        ret = crypto_kdf_hkdf_sha256_extract_update(&state, &material[0], material.length);
        if(ret != 0)
            return Result.make(HkdfError.extractFailed, "crypto_kdf_hkdf_sha256_extract_update failed (libsodium doesn't provide further information)"); // @suppress(dscanner.style.long_line)
    }

    ret = crypto_kdf_hkdf_sha256_extract_final(&state, outKey);
    if(ret != 0)
        return Result.make(HkdfError.extractFailed, "crypto_kdf_hkdf_sha256_extract_update failed (libsodium doesn't provide further information)"); // @suppress(dscanner.style.long_line)

    return Result.noError;
}