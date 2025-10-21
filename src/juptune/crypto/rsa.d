/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.rsa;

import juptune.core.util : Result;
import juptune.crypto.memory : SecureMemory;

enum RsaPadding
{
    FAILSAFE,
    none,
    pkcs1,
    pkcs1Oaep,
    pkcs1Pss,
    pkcs1WithTls,
    x931,
}

enum RsaSignatureAlgorithm
{
    FAILSAFE,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
}

version(Juptune_OpenSSL)
{
    import juptune.crypto.openssl; // Intentionally everything

    struct RsaPublicKey
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

        static Result fromBigEndianBytes(
            scope const(ubyte)[] modulus,
            scope const(ubyte)[] exponent,
            scope ref RsaPublicKey result,
        ) @nogc nothrow
        {
            result = RsaPublicKey.init;

            auto mod = opensslBigEndianFromBytes!false(modulus);
            auto exp = opensslBigEndianFromBytes!false(exponent);
            auto builder = OSSL_PARAM_BLD_new();

            scope(exit)
            {
                BN_free(mod);
                BN_free(exp);
                OSSL_PARAM_BLD_free(builder);
            }

            auto ret = OSSL_PARAM_BLD_push_BN(builder, "n", mod);
            if(ret != 1)
                return opensslErrorToResult("when calling OSSL_PARAM_BLD_push_BN");
            ret = OSSL_PARAM_BLD_push_BN(builder, "e", exp);
            if(ret != 1)
                return opensslErrorToResult("when calling OSSL_PARAM_BLD_push_BN");

            auto params = OSSL_PARAM_BLD_to_param(builder);
            auto pkeyCtx = EVP_PKEY_CTX_new_from_name(null, "RSA", null);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_CTX_new_from_name");
            scope(exit) EVP_PKEY_CTX_free(pkeyCtx);

            ret = EVP_PKEY_fromdata_init(pkeyCtx);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_fromdata_init");

            ret = EVP_PKEY_fromdata(pkeyCtx, &result._pkey, EVP_PKEY_PUBLIC_KEY, params);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_fromdata");

            return Result.noError;
        }

        Result verifySignature(
            scope const(ubyte)[] signature,
            scope const(ubyte)[] originalData,
            RsaPadding padding,
            RsaSignatureAlgorithm signatureAlgorithm,
            scope out bool success,
        ) @nogc nothrow
        in(this._pkey !is null, "RsaPublicKey is not initialised")
        {
            auto ctx = EVP_PKEY_CTX_new(this._pkey, null);
            scope(exit) EVP_PKEY_CTX_free(ctx);

            auto ret = EVP_PKEY_verify_init(ctx);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_verify_init");

            ret = EVP_PKEY_CTX_set_rsa_padding(ctx, toPadMode(padding));
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_CTX_set_rsa_padding");

            ret = EVP_PKEY_CTX_set_signature_md(ctx, toEvpMd(signatureAlgorithm));
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_CTX_set_signature_md");

            ret = EVP_PKEY_verify(ctx, signature.ptr, signature.length, originalData.ptr, originalData.length);
            if(ret < 0)
                return opensslErrorToResult("when calling EVP_PKEY_verify");
            success = (ret == 1);

            return Result.noError;
        }

        Result encryptedLength(
            scope const(ubyte)[] plaintext, 
            RsaPadding padding,
            out size_t length,
        ) @nogc nothrow
        in(this._pkey !is null, "RsaPublicKey is not initialised")
        {
            return this.encryptImpl(plaintext, padding, null, length);
        }

        Result encrypt(
            scope const(ubyte)[] plaintext,
            RsaPadding padding,
            scope ref ubyte[] ciphertext,
            scope ref ubyte[] usedCiphertextSlice,
        ) @nogc nothrow
        in(this._pkey !is null, "RsaPublicKey is not initialised")
        {
            size_t length = ciphertext.length;
            auto result = this.encryptImpl(plaintext, padding, ciphertext, length);
            if(result.isError)
                return result;
            usedCiphertextSlice = ciphertext[0..length];
            return Result.noError;
        }

        private Result encryptImpl(
            scope const(ubyte)[] plaintext,
            RsaPadding padding,
            scope ubyte[] outCiphertext,
            scope ref size_t length,
        ) @nogc nothrow
        in(this._pkey !is null, "RsaPublicKey is not initialised")
        {
            auto ctx = EVP_PKEY_CTX_new(this._pkey, null);
            scope(exit) EVP_PKEY_CTX_free(ctx);

            auto ret = EVP_PKEY_encrypt_init(ctx);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_encrypt_init");

            ret = EVP_PKEY_CTX_set_rsa_padding(ctx, toPadMode(padding));
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_CTX_set_rsa_padding");

            ret = EVP_PKEY_encrypt(ctx, outCiphertext.ptr, &length, plaintext.ptr, plaintext.length);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_encrypt");

            return Result.noError;
        }
    }

    private int toPadMode(RsaPadding padding) @nogc nothrow pure
    {
        final switch(padding) with(RsaPadding)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");

            case none: return 3;
            case pkcs1: return 1;
            case pkcs1Oaep: return 4;
            case pkcs1Pss: return 6;
            case pkcs1WithTls: return 7;
            case x931: return 5;
        }
    }

    private const(EVP_MD)* toEvpMd(RsaSignatureAlgorithm algorithm) @nogc nothrow
    {
        final switch(algorithm) with(RsaSignatureAlgorithm)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");

            case sha1: return EVP_sha1();
            case sha224: return EVP_sha224();
            case sha256: return EVP_sha256();
            case sha384: return EVP_sha384();
            case sha512: return EVP_sha512();
        }
    }
}