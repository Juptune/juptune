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

libsodium_dep = dependency('libsodium', version: '>=1.0.20')
if libsodium_dep.found() # Currently not optional, but just in case in the future.
    message('Found libsodium, enabling Juptune_LibSodium.')
    juptune_d_versions += ['Juptune_LibSodium']
else
    error('No cryptography library found.')
endif

openssl_dep = dependency('openssl', version: '>=3.5.0') # libsodium doesn't support everything unfortunately (e.g. RSA)
if openssl_dep.found() # Currently not optional, but just in case in the future.
    message('Found OpenSSL, enabling Juptune_OpenSSL.')
    juptune_d_versions += ['Juptune_OpenSSL']
else
    error('No secondary cryptography library found.')
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
    './src/juptune/core/ds/pointer.d',
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
    './src/juptune/crypto/ecdsa.d',
    './src/juptune/crypto/libsodium.di',
    './src/juptune/crypto/memory.d',
    './src/juptune/crypto/hkdf.d',
    './src/juptune/crypto/keyexchange.d',
    './src/juptune/crypto/openssl.d',
    './src/juptune/crypto/package.d',
    './src/juptune/crypto/rng.d',
    './src/juptune/crypto/rsa.d',
)

data_srcs = files(
    './src/juptune/data/alphabet.d',
    './src/juptune/data/base.d',
    './src/juptune/data/buffer.d',
    './src/juptune/data/package.d',
    './src/juptune/data/pem.d',
    './src/juptune/data/utf8.d',

    './src/juptune/data/asn1/decode/bcd/encoding.d',
    './src/juptune/data/asn1/generated/raw/AttributeCertificateVersion1_1_2_840_113549_1_9_16_0_15.d',
    './src/juptune/data/asn1/generated/raw/CryptographicMessageSyntax_1_2_840_113549_1_9_16_0_14.d',
    './src/juptune/data/asn1/generated/raw/CryptographicMessageSyntaxAlgorithms_1_2_840_113549_1_9_16_0_16.d',
    './src/juptune/data/asn1/generated/raw/PKIX1_PSS_OAEP_Algorithms_1_3_6_1_5_5_7_0_33.d',
    './src/juptune/data/asn1/generated/raw/PKIX1Algorithms88_1_3_6_1_5_5_7_0_17.d',
    './src/juptune/data/asn1/generated/raw/PKIX1Explicit88_1_3_6_1_5_5_7_0_18.d',
    './src/juptune/data/asn1/generated/raw/PKIX1Implicit88_1_3_6_1_5_5_7_0_19.d',
    './src/juptune/data/asn1/generated/raw/PKIXAttributeCertificate_1_3_6_1_5_5_7_0_12.d',
    './src/juptune/data/asn1/generated/raw/SecureMimeMessageV3dot1_1_2_840_113549_1_9_16_0_21.d',
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
    
    './src/juptune/data/x509/asn1convert.d',
    './src/juptune/data/x509/package.d',
    './src/juptune/data/x509/store.d',
    './src/juptune/data/x509/validation.d',
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
    './src/juptune/http/uri.d',
    './src/juptune/http/v1.d',

    './src/juptune/http/tls/client_messages.d',
    './src/juptune/http/tls/common.d',
    './src/juptune/http/tls/decode.d',
    './src/juptune/http/tls/encode.d',
    './src/juptune/http/tls/models.d',
    './src/juptune/http/tls/package.d',
    './src/juptune/http/tls/server_messages.d',
    './src/juptune/http/tls/tls13.d',
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
    dependencies: [juptune_core_dep, juptune_data_dep, libsodium_dep, openssl_dep],
)

juptune_event_dep = declare_dependency(
    sources: event_srcs,
    dependencies: [juptune_core_dep],
)

juptune_http_dep = declare_dependency(
    sources: http_srcs,
    dependencies: [juptune_core_dep, juptune_crypto_dep, juptune_data_dep, juptune_event_dep],
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