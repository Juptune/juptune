#### Project configuration ####

project(
    'juptune', 
    'd',
    license: 'MPL-2.0',
    version: '0.0.1',
)

# Meson has crappy bugs for its basic functionality that will take 200 years to be addressed:
# https://github.com/mesonbuild/meson/issues/11999

#### Dependencies ####

juptune_d_versions = []

libsodium_dep = dependency('libsodium', version: '>=1.0.18')
if libsodium_dep.found() # Currently not optional, but just in case in the future.
    message('Found libsodium, enabling Juptune_LibSodium.')
    juptune_d_versions += ['Juptune_LibSodium']
else
    error('No cryptography library found.')
endif

summary({
    'D Versions': juptune_d_versions,
}, section: 'Dependencies')

#### Sources ####

core_srcs = files(
    './src/juptune/core/ds/alloc.d',
    './src/juptune/core/ds/array.d',
    './src/juptune/core/ds/block.d',
    './src/juptune/core/ds/hashmap.d',
    './src/juptune/core/ds/package.d',
    './src/juptune/core/ds/string.d',
    './src/juptune/core/ds/string2.d',

    './src/juptune/core/util/ansi.d',
    './src/juptune/core/util/conv.d',
    './src/juptune/core/util/maths.d',
    './src/juptune/core/util/package.d',
    './src/juptune/core/util/result.d',
    './src/juptune/core/util/statemachine.d',

    './src/juptune/core/internal/linux.d',
)

crypto_srcs = files(
    './src/juptune/crypto/aead.d',
    './src/juptune/crypto/libsodium.di',
    './src/juptune/crypto/memory.d',
    './src/juptune/crypto/package.d',
    './src/juptune/crypto/rng.d',
)

data_srcs = files(
    './src/juptune/data/alphabet.d',
    './src/juptune/data/base.d',
    './src/juptune/data/buffer.d',
    './src/juptune/data/package.d',
    './src/juptune/data/utf8.d',

    './src/juptune/data/asn1/decode/bcd/encoding.d',
    './src/juptune/data/asn1/generated/PKIX1Explicit88_1_3_6_1_5_5_7_0_18.d',
    './src/juptune/data/asn1/lang/ast.d',
    './src/juptune/data/asn1/lang/ast2ir.d',
    './src/juptune/data/asn1/lang/common.d',
    './src/juptune/data/asn1/lang/ir.d',
    './src/juptune/data/asn1/lang/lexer.d',
    './src/juptune/data/asn1/lang/operations.d',
    './src/juptune/data/asn1/lang/package.d',
    './src/juptune/data/asn1/lang/parser.d',
    './src/juptune/data/asn1/lang/printer.d',
    './src/juptune/data/asn1/lang/tooling.d',
    './src/juptune/data/asn1/lang/typecheck.d',

    './src/juptune/data/json/builder.d',
    './src/juptune/data/json/package.d',
)

event_srcs = files(
    './src/juptune/event/fiber.d',
    './src/juptune/event/io.d',
    './src/juptune/event/iouring.d',
    './src/juptune/event/loop.d',
    './src/juptune/event/package.d',
)

http_srcs = files(
    './src/juptune/http/common.d',
    './src/juptune/http/client.d',
    './src/juptune/http/package.d',
    './src/juptune/http/tls13.d',
    './src/juptune/http/uri.d',
    './src/juptune/http/v1.d',
)

#### Dependencies ####

juptune_core_dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: core_srcs,
    d_module_versions: juptune_d_versions,
)

juptune_data_dep = declare_dependency(
    sources: data_srcs,
    dependencies: [juptune_core_dep],
)

juptune_crypto_dep = declare_dependency(
    sources: crypto_srcs,
    dependencies: [juptune_core_dep, juptune_data_dep, libsodium_dep],
)

juptune_event_dep = declare_dependency(
    sources: event_srcs,
    dependencies: [juptune_core_dep],
)

juptune_http_dep = declare_dependency(
    sources: http_srcs,
    dependencies: [juptune_core_dep, juptune_crypto_dep, juptune_event_dep],
)

juptune_all_dep = declare_dependency(
    dependencies: [juptune_core_dep, juptune_crypto_dep, juptune_data_dep, juptune_event_dep, juptune_http_dep],
)

juptune_test_dep = declare_dependency(
    sources: './src/dummy_main.d',
    dependencies: [juptune_all_dep],
)

#### Executables ####

examples = {
    'http-hello-world-hardcoded': ['./examples/http-hello-world-hardcoded/main.d'],
    'http-echo-low-level': ['./examples/http-echo-low-level/main.d'],
    'http-client-curl': ['./examples/http-client-curl/main.d'],
}

example_exes = []
foreach example_name, example_srcs : examples
    example_exes += executable(
        'juptune-'+example_name, 
        example_srcs,
        dependencies: [juptune_all_dep],
        build_by_default: false,
    )
endforeach
alias_target('examples', example_exes)

juptune_all_unittest_exe = executable(
    'juptune-unittest', 
    dependencies: [juptune_test_dep],
    d_unittest: true,
)

#### Subdirs ####

subdir('tools/dasn1')

#### Install ####

install_subdir('src/juptune', install_dir: 'include/d/juptune/')
juptune_lib = library(
    meson.project_name(), 
    dependencies: juptune_all_dep,
    install: true,
    version: meson.project_version(),
)

pkgc = import('pkgconfig')
pkgc.generate(
    name: meson.project_name(),
    description: 'High-performance iouring-based I/O framework for D.',
    version: meson.project_version(),
    subdirs: 'd/juptune',
    url: 'https://www.github.com/Juptune/juptune',
    libraries: [juptune_lib],
)

#### Tests ####

test('juptune-unittest', juptune_all_unittest_exe)