/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.crypto.aead;

import juptune.core.util : Result;

// A `Result` error enum
enum AeadError
{
    none,

    /// The decryption of a ciphertext failed
    decryptionFailed,
}

/++
 + Provides a generic interface for AEAD encryption and decryption.
 +
 + To understand what `AeadAlgorithmT` is, see the `AeadIetfChacha20Poly1305` struct as an example.
 +
 + This struct makes extensive use of the `SecureMemory` struct to help encourage secure storage
 + of sensitive memory.
 +
 + This struct is weakly safe as there are certain behaviours and access patterns that are not
 + possible to prevent at compile time.
 + ++/
struct AeadEncryptionContext(AeadAlgorithmT)
{
    import juptune.crypto.memory : SecureMemory;

    private
    {
        SecureMemory.Slice!ubyte _nonce;
        SecureMemory.Slice!ubyte _key;
    }

    @nogc nothrow:

    @disable this(this);

    /++
     + Constructs a new `AeadEncryptionContext` with the given `nonce` and `key`.
     +
     + Assertions:
     +  `nonce` must be of length `AeadAlgorithmT.NONCE_LENGTH`
     +
     +  `key` must be of length `AeadAlgorithmT.KEY_LENGTH`
     +
     +  `nonce` and `key` must not overlap the same memory range
     +
     + Notes:
     +  On dtor, this struct will zero out the memory inside of `nonce`.
     +
     +  This ctor will overwrite the data within `nonce` with the underlying AEAD's nonce initialisation.
     +
     +  It goes without saying, but the `SecureMemory` that the buffers are sourced from must not be freed
     +  until this struct is destroyed.
     +
     + Params:
     +  nonce = The memory buffer to store the nonce in.
     +  key   = The memory buffer where the key is stored. This must be filled outside of this struct.
     + ++/
    this(return SecureMemory.Slice!ubyte nonce, return const SecureMemory.Slice!ubyte key) @trusted
    in(nonce.memory.length == AeadAlgorithmT.NONCE_LENGTH, "bug: nonce length is not correct - use NONCE_LENGTH")
    in(key.memory.length == AeadAlgorithmT.KEY_LENGTH, "bug: key length is not correct - use KEY_LENGTH")
    in(nonce.mustNotOverlap(key))
    {
        this._nonce = nonce;
        this._key   = cast()key; // Cast away const since D structs cannot sanely have const members... *sigh*
        AeadAlgorithmT.initNonce(this._nonce);
    }

    ~this() @safe
    {
        if(this._nonce != typeof(_nonce).init)
        {
            this._nonce.memory[0..$] = 0;
            this._nonce = typeof(_nonce).init;
        }

        this._key = typeof(_key).init;
    }

    /++
     + Encrypts the given `plaintext` into the `outCipherText` buffer, using the given `additionalData`
     + to calculate the authentication tag, and returns a slice `outCipherText` which contains the final
     + encrypted ciphertext + authentication tag.
     +
     + Assertions:
     +  `plaintext` must not be empty, it makes no sense to encrypt an empty buffer.
     +
     +  `outCipherText` must be at least `plaintext.length + AeadAlgorithmT.ABYTES` in length. Where
     +   ABYTES is typically the length of the authentication tag.
     +
     + Notes:
     +  This is a "combined" AEAD encryption, where the authentication tag is appended to the ciphertext.
     +  You can retrieve the tag by taking the last `AeadAlgorithmT.ABYTES` bytes of `outCipherTextSlice`.
     +
     + Params:
     +  plaintext          = The plaintext to encrypt.
     +  additionalData     = The additional data to use when calculating the authentication tag.
     +  outCipherText      = The buffer to store the encrypted ciphertext + authentication tag in.
     +  outCipherTextSlice = The slice of `outCipherText` that contains the encrypted ciphertext + authentication tag.
     +
     + Throws:
     +  Anything that `AeadAlgorithmT.encrypt` throws.
     +
     + Returns:
     +  A `Result` that indicates if the encryption was successful or not.
     + ++/
    Result encrypt(
        scope const SecureMemory.Slice!ubyte plaintext,
        scope const ubyte[] additionalData,
        scope ubyte[] outCipherText,
        scope out ubyte[] outCipherTextSlice
    ) @safe
    in(plaintext.memory.length > 0, "bug: plaintext length must not be 0")
    in(outCipherText.length >= plaintext.memory.length + AeadAlgorithmT.ABYTES, "bug: outCipherText is not large enough - use ABYTES") // @suppress(dscanner.style.long_line)
    {
        return AeadAlgorithmT.encrypt(
            outCipherText,
            plaintext.memory,
            additionalData,
            this._nonce,
            this._key,
            outCipherTextSlice
        );
    }

    /++
     + Decrypts the given `cipherText` into the `outPlainText` buffer, using the given `additionalData`
     + to calculate the authentication tag, and returns a slice `outPlainText` which contains the final
     + decrypted plaintext.
     +
     + Assertions:
     +  `cipherText` must be at least `AeadAlgorithmT.ABYTES` in length. Where ABYTES is typically the
     +  length of the authentication tag.
     +
     +  `outPlainText` must be at least `cipherText.length - AeadAlgorithmT.ABYTES` in length.
     +
     + Notes:
     +  This is a "combined" AEAD decryption, where the authentication tag is assumed to be appended to
     +  the ciphertext.
     +
     + Params:
     +  cipherText        = The ciphertext to decrypt.
     +  additionalData    = The additional data to use when calculating the authentication tag.
     +  outPlainText      = The buffer to store the decrypted plaintext in.
     +  outPlainTextSlice = The slice of `outPlainText` that contains the decrypted plaintext.
     +
     + Throws:
     +  Anything that `AeadAlgorithmT.decrypt` throws.
     +
     + Returns:
     +  A `Result` that indicates if the decryption was successful or not.
     + ++/
    Result decrypt(
        scope const ubyte[] cipherText,
        scope const ubyte[] additionalData,
        scope SecureMemory.Slice!ubyte outPlainText,
        scope out SecureMemory.Slice!ubyte outPlainTextSlice,
    ) @trusted
    in(cipherText.length > AeadAlgorithmT.ABYTES, "bug: cipherText length must be larger than ABYTES")
    in(outPlainText.memory.length >= cipherText.length - AeadAlgorithmT.ABYTES, "bug: outPlainText is not large enough") // @suppress(dscanner.style.long_line)
    {
        ubyte[] slice;
        auto result = AeadAlgorithmT.decrypt(
            outPlainText.memory,
            cipherText,
            additionalData,
            this._nonce,
            this._key,
            slice
        );
        if(result.isError)
            return result;

        outPlainTextSlice = outPlainText.opSlice!0(0, slice.length); // For some reason the actual slice syntax doesn't work, lmfao
        return Result.noError;
    }
}

version(Juptune_LibSodium)
struct AeadIetfChacha20Poly1305
{
    import juptune.crypto.memory : SecureMemory;

    alias EncryptionContext = AeadEncryptionContext!AeadIetfChacha20Poly1305;

    enum NONCE_LENGTH = 12;
    enum KEY_LENGTH   = 32;
    enum ABYTES       = 16;

    shared static this()
    {
        import juptune.crypto.libsodium : 
            crypto_aead_chacha20poly1305_ietf_npubbytes, 
            crypto_aead_chacha20poly1305_ietf_abytes, 
            crypto_aead_chacha20poly1305_ietf_keybytes;
        assert(
            crypto_aead_chacha20poly1305_ietf_npubbytes() == NONCE_LENGTH,
            "bug: crypto_aead_chacha20poly1305_ietf_npubbytes() is hard assumed to be 12"
        );
        assert(
            crypto_aead_chacha20poly1305_ietf_keybytes() == KEY_LENGTH,
            "bug: crypto_aead_chacha20poly1305_ietf_keybytes() is hard assumed to be 32"
        );
        assert(
            crypto_aead_chacha20poly1305_ietf_abytes() == ABYTES,
            "bug: crypto_aead_chacha20poly1305_ietf_abytes() is hard assumed to be 16"
        );
    }

    private static @nogc nothrow:

    Result encrypt(
        scope return ubyte[] c, 
        scope const ubyte[] m, 
        scope const ubyte[] ad, 
        scope SecureMemory.Slice!ubyte n, 
        scope const SecureMemory.Slice!ubyte k,
        scope out ubyte[] outC
    ) @trusted
    {
        import juptune.crypto.libsodium : crypto_aead_chacha20poly1305_ietf_encrypt;

        ulong clen = c.length;
        const result = crypto_aead_chacha20poly1305_ietf_encrypt(
            c.ptr, &clen,
            m.ptr, m.length,
            (ad.length == 0) ? null : ad.ptr, ad.length,
            null,
            n.memory.ptr,
            k.memory.ptr
        );
        assert(result == 0, "bug: somehow this failed - the docs suggest this can't happen");
        nextNonce(n);
        outC = c[0..clen];

        return Result.noError;
    }

    Result decrypt(
        scope return ubyte[] m, 
        scope const ubyte[] c, 
        scope const ubyte[] ad, 
        scope SecureMemory.Slice!ubyte n, 
        scope const SecureMemory.Slice!ubyte k,
        scope out ubyte[] outSlice
    ) @trusted
    {
        import juptune.crypto.libsodium : crypto_aead_chacha20poly1305_ietf_decrypt;

        ulong mlen = m.length;
        const result = crypto_aead_chacha20poly1305_ietf_decrypt(
            m.ptr, &mlen,
            null,
            c.ptr, c.length,
            (ad.length == 0) ? null : ad.ptr, ad.length,
            n.memory.ptr,
            k.memory.ptr
        );
        if(result != 0)
            return Result.make(AeadError.decryptionFailed, "decryption failed");

        outSlice = m[0..mlen];
        nextNonce(n);
        return Result.noError;
    }

    void initNonce(scope SecureMemory.Slice!ubyte nonce) @trusted
    in(nonce.memory.length == NONCE_LENGTH, "bug: nonce length is not correct")
    {
        import juptune.crypto.libsodium : randombytes_buf;
        randombytes_buf(nonce.memory.ptr, NONCE_LENGTH);
    }

    void nextNonce(scope SecureMemory.Slice!ubyte nonce) @trusted
    in(nonce.memory.length == NONCE_LENGTH, "bug: nonce length is not correct")
    {
        // sodium_add always expects little endian
        ubyte[NONCE_LENGTH] one;
        one[0] = 1;

        import juptune.crypto.libsodium : sodium_add;
        sodium_add(nonce.memory.ptr, one.ptr, NONCE_LENGTH);
    }
}

/++++ Unittests ++++/

version(unittest) import juptune.core.util : resultAssert;

@("AeadIetfChacha20Poly1305 - basic")
@nogc unittest
{
    import std.algorithm         : all;
    import juptune.crypto.memory : SecureMemory;
    import juptune.crypto.rng    : cryptoFillBuffer;

    SecureMemory mem;
    SecureMemory.allocate(mem, 4096).resultAssert;

    SecureMemory.Slice!ubyte key, nonce, nonceBefore, plain, plainDecrypt, cipher;
    mem.contigiousSlice!ubyte([
        AeadIetfChacha20Poly1305.KEY_LENGTH,
        AeadIetfChacha20Poly1305.NONCE_LENGTH,
        AeadIetfChacha20Poly1305.NONCE_LENGTH,
        50,
        50,
        50 + AeadIetfChacha20Poly1305.ABYTES
    ], [
        &key,
        &nonce,
        &nonceBefore,
        &plain,
        &plainDecrypt,
        &cipher
    ]);

    cryptoFillBuffer(key.memory);
    foreach(i, ref b; plain.memory)
        b = cast(ubyte)i;

    auto ctx = AeadIetfChacha20Poly1305.EncryptionContext(nonce, key);
    nonceBefore.memory[0..$] = nonce.memory[0..$];

    ubyte[5] ad = [0, 1, 2, 3, 4];
    ubyte[] cipherSlice;
    ctx.encrypt(
        plain, 
        ad[], 
        cipher.memory, 
        cipherSlice
    ).resultAssert;
    assert(cipherSlice.length == 50 + AeadIetfChacha20Poly1305.ABYTES, "bug: cipherSlice length is not correct");
    assert(!cipherSlice.all!(a => a == 0), "bug: cipherSlice is all 0");
    assert(cipherSlice[0..50] != plain.memory[0..50], "bug: cipherSlice is not encrypted");
    assert(nonce.memory[0..$] != nonceBefore.memory[0..$], "bug: nonce was not incremented");

    nonce.memory[0..$] = nonceBefore.memory[0..$];
    SecureMemory.Slice!ubyte plainSlice;
    ctx.decrypt(
        cipherSlice, 
        ad[], 
        plainDecrypt, 
        plainSlice
    ).resultAssert;
    assert(plainSlice.memory[0..50] == plain.memory[0..50], "bug: plainSlice is not decrypted");
    assert(nonce.memory[0..$] != nonceBefore.memory[0..$], "bug: nonce was not incremented");
}