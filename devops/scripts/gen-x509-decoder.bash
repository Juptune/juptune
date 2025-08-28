# Must be ran from the root of the juptune repository
# $> bash devops/scripts/gen-x509-decoder.bash

JUPTUNE_DIR=$(pwd)
MAIN_BUIlD_DIR="build"
TEMP_BUILD_DIR="temp-juptune-build"

set -exuo pipefail

# Ensure we have all the required tools
ldc2 --version
meson --version

# Setup a build dir if one doesn't exist
if [ ! -d $MAIN_BUIlD_DIR ]; then
    BUILD_DIR=$TEMP_BUILD_DIR
    meson setup $TEMP_BUILD_DIR -Ddefault_library=static
else
    BUILD_DIR=$MAIN_BUIlD_DIR
fi

# Ensure dasn1 is compiled, and use it to generate the decoder model
meson compile -C $BUILD_DIR dasn1
$BUILD_DIR/tools/dasn1/dasn1 compile dlang-raw \
    --out-dir $JUPTUNE_DIR/src/juptune/data/asn1/generated/raw/ \
    --base-module juptune.data.asn1.generated \
    $JUPTUNE_DIR/tools/dasn1/tests/x509/models/

if [ "$BUILD_DIR" = "$TEMP_BUILD_DIR" ]; then
    rm -rf $TEMP_BUILD_DIR
fi