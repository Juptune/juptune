#### Imports from the parent meson.build file ####

juptune_all_dep = juptune_all_dep

#### Test ####

integration_test_postgres_exe = executable(
    'integration-test-postgres',
    dependencies: [juptune_all_dep],
    sources: files(
        './client_tests/general.d',
        './client_tests/querying.d',

        './protocol_tests/errors.d',
        './protocol_tests/general.d',
        './protocol_tests/querying.d',

        './config.d',
        './main.d',
        './testlib.d',
    ),
    include_directories: include_directories('.'),
    d_unittest: false # We use a custom test harness
)

test('integration-postgres', integration_test_postgres_exe, suite: 'integration', protocol: 'tap')