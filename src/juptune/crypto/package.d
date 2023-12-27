module juptune.crypto;

shared static this()
{
    import juptune.crypto.libsodium;
    
    const result = sodium_init();
    assert(result == 0, "Failed to initialize libsodium");
}