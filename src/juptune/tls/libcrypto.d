module juptune.tls.libcrypto;


/**** Bindings ****/
extern (C) @nogc nothrow:

struct EVP_MD_CTX {}
struct EVP_MD {}

EVP_MD_CTX* EVP_MD_CTX_new(); // @suppress(dscanner.style.phobos_naming_convention)
void EVP_MD_CTX_free(EVP_MD_CTX* ctx); // @suppress(dscanner.style.phobos_naming_convention)

unittest { auto ctx = EVP_MD_CTX_new(); assert(ctx !is null); EVP_MD_CTX_free(ctx); } // Make sure we don't crash