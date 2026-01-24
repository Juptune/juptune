/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.ecdsa;

import juptune.core.util : Result;

enum EcdsaGroupName
{
    FAILSAFE,
    secp256r1,
    secp384r1,
}

enum EcdsaSignatureAlgorithm
{
    FAILSAFE,
    sha256,
    sha384,
    sha512,
}

version(Juptune_OpenSSL)
{
    import juptune.crypto.openssl; // Intentionally everything

    struct EcdsaPublicKey
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

        static Result fromBytes(
            EcdsaGroupName namedCurve,
            scope const(ubyte)[] sec1PublicKey,
            scope ref EcdsaPublicKey result,
        ) @nogc nothrow
        {
            result = EcdsaPublicKey.init;

            const groupName = toEvpGroupName(namedCurve);

            auto builder = OSSL_PARAM_BLD_new();
            scope(exit) OSSL_PARAM_BLD_free(builder);

            auto ret = OSSL_PARAM_BLD_push_utf8_string(builder, "group", groupName.ptr, groupName.length);
            if(ret != 1)
                return opensslErrorToResult("when calling OSSL_PARAM_BLD_push_utf8_string");
            ret = OSSL_PARAM_BLD_push_octet_string(builder, "pub", sec1PublicKey.ptr, sec1PublicKey.length);
            if(ret != 1)
                return opensslErrorToResult("when calling OSSL_PARAM_BLD_push_octet_string");

            auto params = OSSL_PARAM_BLD_to_param(builder);
            auto pkeyCtx = EVP_PKEY_CTX_new_from_name(null, "EC", null);
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
            EcdsaSignatureAlgorithm signatureAlgorithm,
            scope out bool success,
        ) @nogc nothrow
        in(this._pkey !is null, "EcdasPublicKey is not initialised")
        {
            auto ctx = EVP_PKEY_CTX_new(this._pkey, null);
            scope(exit) EVP_PKEY_CTX_free(ctx);

            auto ret = EVP_PKEY_verify_init(ctx);
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_verify_init");

            ret = EVP_PKEY_CTX_set_signature_md(ctx, toEvpMd(signatureAlgorithm));
            if(ret != 1)
                return opensslErrorToResult("when calling EVP_PKEY_CTX_set_signature_md");

            ret = EVP_PKEY_verify(ctx, signature.ptr, signature.length, originalData.ptr, originalData.length);
            if(ret < 0)
                return opensslErrorToResult("when calling EVP_PKEY_verify");
            success = (ret == 1);

            return Result.noError;
        }
    }

    private const(EVP_MD)* toEvpMd(EcdsaSignatureAlgorithm algorithm) @nogc nothrow
    {
        final switch(algorithm) with(EcdsaSignatureAlgorithm)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");

            case sha256: return EVP_sha256();
            case sha384: return EVP_sha384();
            case sha512: return EVP_sha512();
        }
    }

    private string toEvpGroupName(EcdsaGroupName algorithm) @nogc nothrow
    {
        final switch(algorithm) with(EcdsaGroupName)
        {
            case FAILSAFE: assert(false, "bug: FAILSAFE");

            case secp256r1: return "prime256v1"; // Just OpenSSL things
            case secp384r1: return "secp384r1";
        }
    }
}