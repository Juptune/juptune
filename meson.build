#### Project configuration ####

project('juptune', 'd')

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

event_asm_srcs = files(
    './src/juptune/event/fiber.asm',
    './src/juptune/event/iouring.asm',
)
event_srcs = files(
    './src/juptune/event/fiber.d',
    './src/juptune/event/io.d',
    './src/juptune/event/iouring.d',
    './src/juptune/event/loop.d',
    './src/juptune/event/package.d',

    './src/juptune/event/internal/linux.d',
)

#### Asm configuration ####

if target_machine.cpu() == 'x86_64' and target_machine.system() == 'linux'
    add_languages('nasm')
    add_project_arguments('-Dlinux_amd64_sysv', language: 'nasm')
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

juptune_all_dep = declare_dependency(
    dependencies: [juptune_core_dep, juptune_event_dep],
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
    )
endforeach

juptune_all_unittest_exe = executable(
    'juptune-unittest', 
    './src/dummy_main.d',
    dependencies: [juptune_all_dep],
    d_unittest: true
)

#### Install ####

event_asm_lib = library(
    'juptune-event-asm',
    event_asm_srcs,
    install: true,
)

install_subdir('src/juptune', install_dir: 'include/d/juptune/')

pkgc = import('pkgconfig')
pkgc.generate(
    name: 'juptune-dev',
    description: 'High-performance iouring-based I/O framework for D - development files.',
    subdirs: 'd/juptune',
    url: 'https://www.github.com/Juptune/juptune',
    libraries: [event_asm_lib],
)

#### Tests ####

test('juptune-unittest', juptune_all_unittest_exe)