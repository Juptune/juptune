# Must be ran from the root of the juptune repository
# $> bash devops/scripts/gen-libsodium-di.bash

LIBSODIUM_DIR=/tmp/juptune-libsodium/
LIBSODIUM_TAG='1.0.20-RELEASE'
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
    if [[ ! -f "${LIBSODIUM_DIR}/.gitignore" ]]; then
        git clone https://github.com/jedisct1/libsodium ${LIBSODIUM_DIR}
    fi
    git checkout ${LIBSODIUM_TAG} > /dev/null 2>&1

    # Expand main header file
    cd src/libsodium/include/
    clang -E -P sodium.h > sodium_preformat.c
    clang-format sodium_preformat.c --style="{AlignAfterOpenBracket: DontAlign, ColumnLimit: 10000}" > sodium.c

    # Remove extensions and things that D doesn't like
    sed -i 's/__endptr//g'      sodium.c
    sed -i 's/__nptr//g'        sodium.c
    sed -i 's/__extension__//g' sodium.c
    sed -i 's/__inline//g'      sodium.c
    sed -i 's/__restrict//g'    sodium.c
    sed -i 's/.*__asm__.*//g'   sodium.c
    sed -i 's/__attribute__((visibility("default"))) //g'   sodium.c
    sed -i 's/__attribute__((nonnull))//g'   sodium.c
    sed -i 's/__attribute__((warn_unused_result))//g'   sodium.c
    sed -i 's/__attribute__((deprecated))//g'   sodium.c
    sed -i 's/__attribute__((nonnull(/\;\/\//g'   sodium.c

    # For some reason clang chokes on these lines
    sed -i 's/typedef __float128 _Float128;//g'   sodium.c
    sed -i 's/typedef float _Float32;//g'   sodium.c
    sed -i 's/typedef double _Float64;//g'   sodium.c
    sed -i 's/typedef double _Float32x;//g'   sodium.c
    sed -i 's/typedef long double _Float64x;//g'   sodium.c

    # And then there's also these weird lines
    sed -i 's/"__isoc99_/\/\//g'   sodium.c

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

    # Manually tweak a few declarations
    sed -i 's/, ubyte\[/, ref ubyte\[/g' sodium.di
    sed -i 's/(ubyte\[/(ref ubyte\[/g' sodium.di
    sed -i 's/, const(ubyte)\[/, ref const(ubyte)\[/g' sodium.di
    sed -i 's/(const(ubyte)\[/(ref const(ubyte)\[/g' sodium.di

    ldc2 ${JUPTUNE_DIR}/devops/scripts/clean-libsodium-di.d --of clean-libsodium-di
    ./clean-libsodium-di

    # Make sure it compiles, then move it to the right place
    ldc2 -c libsodium.di
    mv libsodium.di ${JUPTUNE_DIR}/src/juptune/crypto/libsodium.di
}

mkdir -p ${LIBSODIUM_DIR} || true
pushd ${LIBSODIUM_DIR}; main; popd