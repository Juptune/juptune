#### Project configuration ####

project(
    'juptune', 
    'd',
    license: 'MPL-2.0',
    version: '0.0.1'
)

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

juptune_http_dep = declare_dependency(
    sources: http_srcs,
    dependencies: [juptune_core_dep, juptune_event_dep],
)

juptune_all_dep = declare_dependency(
    dependencies: [juptune_core_dep, juptune_event_dep, juptune_http_dep],
)

#### Executables ####

examples = {
    'http-hello-world-hardcoded': ['./examples/http-hello-world-hardcoded/main.d'],
    'http-echo-manual': ['./examples/http-echo-manual/main.d'],
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

pkgc = import('pkgconfig')
pkgc.generate(
    name: meson.project_name(),
    description: 'High-performance iouring-based I/O framework for D - development files.',
    version: meson.project_version(),
    subdirs: 'd/juptune',
    url: 'https://www.github.com/Juptune/juptune',
)

#### Tests ####

test('juptune-unittest', juptune_all_unittest_exe)