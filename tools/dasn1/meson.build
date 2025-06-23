#### Imports from the parent meson.build file ####

juptune_data_dep = juptune_data_dep

#### Sources ####

dasn1_srcs = files(
    './src/dasn1/context.d',
    './src/dasn1/errors.d',
    './src/dasn1/print.d',
    
    './src/main.d',
)

#### Dependencies ####

dasn1_all_dep = declare_dependency(
    sources: dasn1_srcs,
    dependencies: [juptune_data_dep],
    include_directories: include_directories('src')
)

#### Binaries ####

dasn1_exe = executable(
    'dasn1',
    dependencies: dasn1_all_dep,
)

dasn1_unittest_exe = executable(
    'dasn1-unittest',
    dependencies: dasn1_all_dep,
    d_unittest: true
)

#### Tests ####

test('dasn1-unittest', dasn1_unittest_exe)