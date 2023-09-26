#### Project configuration ####

project('juptune', 'd')

# Tl;dr Meson has crappy bugs for its basic functionality that will take 200 years to be addressed:
# https://github.com/mesonbuild/meson/issues/11999

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
    './src/juptune/core/util/utf.d',
)

event_asm_srcs = files() # Conditionally set by platform
event_srcs = files(
    './src/juptune/event/fiber.d',
    './src/juptune/event/io.d',
    './src/juptune/event/iouring.d',
    './src/juptune/event/loop.d',
    './src/juptune/event/package.d',

    './src/juptune/event/internal/linux.d',
)

tls_srcs = files(
    './src/juptune/tls/libcrypto.d',
    './src/juptune/tls/package.d',
    './src/juptune/tls/tls13.d',
)

http_srcs = files(
    './src/juptune/http/package.d',
    './src/juptune/http/uri.d',
    './src/juptune/http/v1.d',
)

#### Asm configuration ####

if target_machine.cpu() == 'x86_64' and target_machine.system() == 'linux'
    add_languages('nasm')
    add_project_arguments('-Dlinux_amd64_sysv', language: 'nasm')
    event_asm_srcs = files(
        './src/juptune/event/asm/amd64/fiber.asm',
        './src/juptune/event/asm/amd64/iouring.asm',
    )
else
    error('Unsupported architecture')
endif

#### Dependencies ####

juptune_core_dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: core_srcs,
)

juptune_event_dep = declare_dependency(
    sources: [event_srcs, event_asm_srcs],
    dependencies: [juptune_core_dep],
)

juptune_tls_dep = declare_dependency(
    sources: tls_srcs,
    dependencies: [juptune_core_dep, juptune_event_dep],
)

juptune_http_dep = declare_dependency(
    sources: http_srcs,
    dependencies: [juptune_core_dep, juptune_event_dep, juptune_tls_dep],
)

juptune_all_dep = declare_dependency(
    dependencies: [juptune_core_dep, juptune_event_dep, juptune_http_dep, juptune_tls_dep],
)

#### Executables ####

examples = {
    'http-hello-world-hardcoded': ['./examples/http-hello-world-hardcoded/main.d'],
}

foreach example_name, example_srcs : examples
    executable(
        'juptune-'+example_name, 
        example_srcs,
        dependencies: [juptune_all_dep],
        link_args: ['-lcrypto']
    )
endforeach

juptune_all_unittest_exe = executable(
    'juptune-unittest', 
    './src/dummy_main.d',
    dependencies: [juptune_all_dep],
    d_unittest: true,
    link_args: ['-lcrypto']
)

#### Install ####

event_asm_lib = library(
    'juptune-event-asm',
    event_asm_srcs,
    install: true,
    link_args: ['-lcrypto']
)

install_subdir('src/juptune', install_dir: 'include/d/')

pkgc = import('pkgconfig')
pkgc.generate(
    name: 'juptune-dev',
    description: 'High-performance iouring-based I/O framework for D - development files.',
    version: meson.project_version(),
    subdirs: 'd/juptune',
    url: 'https://www.github.com/Juptune/juptune',
    libraries: [event_asm_lib],
)

#### Tests ####

test('juptune-unittest', juptune_all_unittest_exe)