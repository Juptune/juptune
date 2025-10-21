module juptune.crypto.openssl;

import juptune.core.util : Result;

Result opensslErrorToResult(string context) @nogc nothrow
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

BIGNUM* opensslBigEndianFromBytes(bool isPrivate)(scope const(ubyte)[] bytes)
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
    auto zero = opensslBigEndianFromBytes!false([0]);
    auto deadbeef = opensslBigEndianFromBytes!false([0xDE, 0xAD, 0xBE, 0xEF]);
    auto manyBytes = opensslBigEndianFromBytes!false([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]); // @suppress(dscanner.style.long_line)

    scope(exit)
    {
        BN_free(zero);
        BN_free(deadbeef);
        BN_free(manyBytes);
    }
}

extern(C) @nogc nothrow:
        
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
EVP_PKEY* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const(ubyte)* key, size_t keylen);
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

int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);

int EVP_PKEY_get_raw_public_key(const EVP_PKEY* pkey, ubyte* pub, size_t* len);

ulong ERR_get_error();
void ERR_error_string_n(ulong e, char* buf, size_t len);