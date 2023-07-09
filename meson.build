#### Project configuration ####

project('juptune-event', ['d', 'nasm'])

#### Sources ####

core_srcs = [
    './src/juptune/core/ds/alloc.d',
    './src/juptune/core/ds/array.d',
    './src/juptune/core/ds/hashmap.d',
    './src/juptune/core/ds/package.d',
    './src/juptune/core/ds/string.d',

    './src/juptune/core/util/ansi.d',
    './src/juptune/core/util/conv.d',
    './src/juptune/core/util/package.d',
    './src/juptune/core/util/result.d',
    './src/juptune/core/util/utf.d',
]

event_srcs = [
    './src/juptune/event/fiber.d',
    './src/juptune/event/io.d',
    './src/juptune/event/iouring.d',
    './src/juptune/event/loop.d',
    './src/juptune/event/package.d',

    './src/juptune/event/internal/linux.d',
]

nasm_srcs = [
    './src/juptune/event/fiber.asm',
    './src/juptune/event/iouring.asm',
]

#### Nasm configuration ####

if host_machine.cpu() == 'x86_64' and host_machine.system() == 'linux'
    add_project_arguments('-Dlinux_amd64_sysv', language: 'nasm')
else
    error('Unsupported architecture')
endif


#### Dependencies ####

juptune_nasm_dep = declare_dependency(
    sources: nasm_srcs,
)

juptune_core_dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: core_srcs,
    dependencies: [juptune_nasm_dep],
)

juptune_event_dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: event_srcs,
    dependencies: [juptune_core_dep],
)

juptune_all_dep = declare_dependency(
    include_directories: include_directories('src'),
    dependencies: [juptune_core_dep, juptune_event_dep],
)

#### Executables ####

juptune_all_unittest_exe = executable(
    'juptune-unittest', 
    './src/dummy_main.d',
    dependencies: [juptune_all_dep],
    d_unittest: true
)

juptune_http_hello_world_hardcoded_exe = executable(
    'juptune-http-hello-world-hardcoded',
    './examples/http-hello-world-hardcoded/main.d',
    dependencies: [juptune_all_dep]
)

#### Tests ####

test('juptune-unittest', juptune_all_unittest_exe)