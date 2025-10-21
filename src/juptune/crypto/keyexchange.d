/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.crypto.keyexchange;

import juptune.core.util : Result;

version(Juptune_OpenSSL)
{
    import juptune.crypto.openssl; // Intentionally everything

    struct X25519PrivateKey
    {
        private
        {
            EVP_PKEY* _pkey;
        }

        @disable this(this);

        ~this() @nogc nothrow
        {
            if(this._pkey !is null)
            {
                EVP_PKEY_free(this._pkey);
                this._pkey = null;
            }
        }

        static Result generate(ref X25519PrivateKey key) @nogc nothrow
        {
            key = typeof(key).init;

            auto ctx = EVP_PKEY_CTX_new_from_name(null, "X25519", null);
            scope(exit) EVP_PKEY_CTX_free(ctx);

            auto ret = EVP_PKEY_keygen_init(ctx);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_keygen_init for X25519 private key");

            ret = EVP_PKEY_keygen(ctx, &key._pkey);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_keygen for X25519 private key");

            return Result.noError;
        }

        Result getPublicKey(scope ubyte[] keyBytes) @nogc nothrow
        in(keyBytes.length == 32, "keyBytes must be 32 bytes in length")
        {
            auto length = keyBytes.length;
            auto ret = EVP_PKEY_get_raw_public_key(this._pkey, &keyBytes[0], &length);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_get_raw_public_key for X25519 private key");
            return Result.noError;
        }
    }

    struct X25519PublicKey
    {
        private
        {
            EVP_PKEY* _pkey;
        }

        @disable this(this);

        ~this() @nogc nothrow
        {
            if(this._pkey !is null)
            {
                EVP_PKEY_free(this._pkey);
                this._pkey = null;
            }
        }

        static Result fromBytes(scope const(ubyte)[] bytes, ref X25519PublicKey key) @nogc nothrow
        {
            key = typeof(key).init;

            key._pkey = EVP_PKEY_new_raw_public_key_ex(null, "X25519", null, &bytes[0], bytes.length);
            if(key._pkey is null)
                return opensslErrorToResult("when calling EVP_PKEY_new_raw_public_key_ex for X25519 public key");

            return Result.noError;
        }
    }
}