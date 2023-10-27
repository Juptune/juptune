#### Project configuration ####

project('basic-meson-project', 'd')

#### Sources ####

srcs = files(
    './src/main.d',
)

#### Dependencies ####

juptune_dep = dependency('juptune')

dep = declare_dependency(
    include_directories: include_directories('src'),
    sources: srcs,
    dependencies: [juptune_dep],
)

#### Executables ####

main_exe = executable('basic-meson-project', dependencies: [dep], install: true)
test_exe = executable('unittests', dependencies: [dep], d_unittest: true)

#### Tests ####

test('unittests', test_exe)