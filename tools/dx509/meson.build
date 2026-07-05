#### Imports from the parent meson.build file ####

juptune_all_dep = juptune_all_dep

#### Sources ####

dx509_srcs = files(
    './src/dx509/x509_hexdump.d',
    './src/dx509/x509_print.d',

    './src/main.d',
)

#### Dependencies ####

dx509_all_dep = declare_dependency(
    sources: dx509_srcs,
    dependencies: [juptune_all_dep],
    include_directories: include_directories('src')
)

#### Binaries ####

dx509_exe = executable(
    'dx509',
    dependencies: dx509_all_dep,
)

dx509_unittest_exe = executable(
    'dx509-unittest',
    dependencies: dx509_all_dep,
    d_unittest: true
)

#### Tests ####

# test('dasn1-unittest', dasn1_unittest_exe)