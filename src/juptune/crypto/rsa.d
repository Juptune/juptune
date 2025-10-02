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
    extern(C) @nogc nothrow
    {
        struct BIGNUM {}

        // For public keys
        BIGNUM* BN_new();
        void BN_free(BIGNUM *a);

        // For private keys
        BIGNUM* BN_secure_new();
        void BN_clear_free(BIGNUM* a);

        int BN_hex2bn(BIGNUM** a, const(char)* str);



        struct OSSL_PARAM_BLD {}
        struct OSSL_PARAM {}

        OSSL_PARAM_BLD* OSSL_PARAM_BLD_new();
        void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD* bld);
        OSSL_PARAM* OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD* bld);
        int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD* bld, const(char)* key, const(BIGNUM)* bn);



        struct EVP_PKEY_CTX {}
        struct EVP_PKEY {}
        struct EVP_MD {}

        enum EVP_PKEY_PUBLIC_KEY = 0x04 | 0x80 | 0x02;

        EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, void* e);
        EVP_PKEY_CTX* EVP_PKEY_CTX_new_from_name(void* libctx, const(char)* name, const(char)* propquery);
        void EVP_PKEY_CTX_free(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
        int EVP_PKEY_fromdata(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey, int selection, OSSL_PARAM* param);
        void EVP_PKEY_free(EVP_PKEY* pkey);
        int EVP_PKEY_get_bits(const(EVP_PKEY)* pkey);

        int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX* ctx, int pad_mode);
        int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX* ctx, const(EVP_MD)* md);
        const(EVP_MD)* EVP_sha1();
        const(EVP_MD)* EVP_sha224();
        const(EVP_MD)* EVP_sha256();
        const(EVP_MD)* EVP_sha384();
        const(EVP_MD)* EVP_sha512();

        int EVP_PKEY_encrypt_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_encrypt(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);

        int EVP_PKEY_decrypt_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_decrypt(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);

        int EVP_PKEY_verify_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_verify(EVP_PKEY_CTX* ctx, const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);

        int EVP_PKEY_sign_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_sign(EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);




        ulong ERR_get_error();
        void ERR_error_string_n(ulong e, char* buf, size_t len);
    }

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

            auto mod = .fromBigEndianBytes!false(modulus);
            auto exp = .fromBigEndianBytes!false(exponent);
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

        uint keySizeInBytes() @nogc nothrow const
        in(this._pkey !is null, "RsaPublicKey is not initialised")
        {
            return (EVP_PKEY_get_bits(this._pkey) + 7) / 8; // + 7 to round up in bytes.
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

    private BIGNUM* fromBigEndianBytes(bool isPrivate)(scope const(ubyte)[] bytes)
    out(r; r !is null, "bug: result is null?")
    {
        import core.stdc.stdlib : malloc, free;
        import juptune.core.util.conv : toBase16, IntToHexCharBuffer;

        static if(isPrivate)
            alias newBn = BN_secure_new;
        else
            alias newBn = BN_new;

        static if(isPrivate)
            static assert(false, "TODO");
        else
        {
            alias allocHexBuffer = malloc;
            alias freeHexBuffer = free;
        }

        if(bytes.length == 0)
            return BN_new();

        IntToHexCharBuffer buffer;
        char[] hexBuffer = (cast(char*)allocHexBuffer((bytes.length * 2) + 1))[0..(bytes.length * 2) + 1];
        scope(exit) freeHexBuffer(hexBuffer.ptr);

        foreach(i, byte_; bytes)
        {
            const slice = toBase16(byte_, buffer);
            if(byte_ < 0x10)
            {
                hexBuffer[i*2] = '0';
                hexBuffer[(i*2)+1] = slice[$-1];
            }
            else
                hexBuffer[i*2..(i*2)+2] = slice[$-2..$];
        }
        hexBuffer[$-1] = '\0';

        auto result = newBn();
        const length = BN_hex2bn(&result, hexBuffer.ptr);
        assert(length != 0, "bug: BN_hex2bin somehow failed?");

        return result;
    }
    ///
    unittest
    {
        auto zero = fromBigEndianBytes!false([0]);
        auto deadbeef = fromBigEndianBytes!false([0xDE, 0xAD, 0xBE, 0xEF]);
        auto manyBytes = fromBigEndianBytes!false([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]); // @suppress(dscanner.style.long_line)

        scope(exit)
        {
            BN_free(zero);
            BN_free(deadbeef);
            BN_free(manyBytes);
        }
    }

    private Result opensslErrorToResult(string context) @nogc nothrow
    {
        import core.stdc.string : strlen;
        import juptune.core.ds : String2;

        enum OpenSslError { error }
        char[128] buffer;

        ERR_error_string_n(ERR_get_error(), &buffer[0], buffer.length);

        return Result.make(
            OpenSslError.error,
            context,
            String2(buffer[0..strlen(&buffer[0])])
        );
    }
}