#### Project configuration ####

project(
    'juptune', 
    'd',
    license: 'MPL-2.0',
    version: '0.0.1',
)

# Meson has crappy bugs for its basic functionality that will take 200 years to be addressed:
# https://github.com/mesonbuild/meson/issues/11999

libsodium_dep = dependency('libsodium', version: '>=1.0.18')

#### Sources ####

core_srcs = files(
    './src/juptune/core/ds/alloc.d',
    './src/juptune/core/ds/array.d',
    './src/juptune/core/ds/block.d',
    './src/juptune/core/ds/hashmap.d',
    './src/juptune/core/ds/package.d',
    './src/juptune/core/ds/string.d',

    './src/juptune/core/util/ansi.d',
    './src/juptune/core/util/conv.d',
    './src/juptune/core/util/package.d',
    './src/juptune/core/util/result.d',
    './src/juptune/core/util/statemachine.d',
    './src/juptune/core/util/utf.d',
)

crypto_srcs = files(
    './src/juptune/crypto/libsodium.di',
    './src/juptune/crypto/package.d',
)

event_srcs = files(
    './src/juptune/event/fiber.d',
    './src/juptune/event/io.d',
    './src/juptune/event/iouring.d',
    './src/juptune/event/loop.d',
    './src/juptune/event/package.d',

    './src/juptune/event/internal/linux.d',
)

http_srcs = files(
    './src/juptune/http/common.d',
    './src/juptune/http/client.d',
    './src/juptune/http/package.d',
    './src/juptune/http/uri.d',
    './src/juptune/http/v1.d',
)

#### Dependencies ####

juptune_core_dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: core_srcs,
)

juptune_crypto_dep = declare_dependency(
    sources: crypto_srcs,
    dependencies: [juptune_core_dep, libsodium_dep],
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
    dependencies: [juptune_core_dep, juptune_crypto_dep, juptune_event_dep, juptune_http_dep],
)

#### Executables ####

examples = {
    'http-hello-world-hardcoded': ['./examples/http-hello-world-hardcoded/main.d'],
    'http-echo-low-level': ['./examples/http-echo-low-level/main.d'],
    'http-client-curl': ['./examples/http-client-curl/main.d'],
}

foreach example_name, example_srcs : examples
    executable(
        'juptune-'+example_name, 
        example_srcs,
        dependencies: [juptune_all_dep],
    )
endforeach

juptune_all_unittest_exe = executable(
    'juptune-unittest', 
    './src/dummy_main.d',
    dependencies: [juptune_all_dep],
    d_unittest: true,
)

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

#### Subdirs ####

subdir('./devops/pkg/opensuse-rpm')