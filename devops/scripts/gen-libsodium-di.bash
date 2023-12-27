# Must be ran from the root of the juptune repository
# $> bash devops/scripts/gen-libsodium-di.bash

LIBSODIUM_DIR=/tmp/juptune-libsodium/
LIBSODIUM_TAG='1.0.18'
JUPTUNE_DIR=$(pwd)

set -exuo pipefail

# Logic is stored in a function so that we can use `pushd` and `popd` to
# change directories without affecting the caller's working directory.
main() {
    # Ensure we have all the required tools
    git version
    ldc2 --version
    clang --version

    # Fetch libsodium
    if [[ ! -d "${LIBSODIUM_DIR}" ]]; then
        git clone https://github.com/jedisct1/libsodium ${LIBSODIUM_DIR}
    fi
    git checkout tags/${LIBSODIUM_TAG} > /dev/null 2>&1

    # Expand main header file
    cd src/libsodium/include/
    clang -E -P sodium.h > sodium.c

    # Remove extensions and things that D doesn't like
    sed -i 's/__endptr//g'      sodium.c
    sed -i 's/__nptr//g'        sodium.c
    sed -i 's/__extension__//g' sodium.c
    sed -i 's/__inline//g'      sodium.c
    sed -i 's/__restrict//g'    sodium.c
    sed -i 's/.*__asm__.*//g'   sodium.c

    # Generate .di file
    ldc2 -c sodium.c --Hf sodium.di

    # Clean up the file
    sed -i 's/const struct//g'  sodium.di # e.g. alias a = const struct b
    sed -i 's/= struct/= /g'    sodium.di # e.g. alias a = struct b
    sed -i 's/, struct/, /g'    sodium.di # e.g. (int _, struct a* b)
    sed -i 's/(struct/(/g'      sodium.di # e.g. (struct a* b)
    sed -i 's/out,/out_,/g'     sodium.di # e.g. (int out, int _)
    sed -i 's/out)/out_)/g'     sodium.di # e.g. (int _, int out)
    sed -i 's/in,/in_,/g'       sodium.di # e.g. (int in, int _)
    sed -i 's/in)/in_)/g'       sodium.di # e.g. (int _, int in)

    ldc2 ${JUPTUNE_DIR}/devops/scripts/clean-libsodium-di.d --of clean-libsodium-di
    ./clean-libsodium-di

    # Make sure it compiles, then move it to the right place
    ldc2 -c libsodium.di
    mv libsodium.di ${JUPTUNE_DIR}/src/juptune/crypto/libsodium.di
}

pushd ${LIBSODIUM_DIR}; main; popd