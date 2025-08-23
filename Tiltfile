load('ext://uibutton', 'cmd_button', 'text_input', 'choice_input')

#### Setup ####

local('''
    if [ ! -d build ]; then
        meson setup build
    fi
''')

#### Development ####

local_resource(
    'test',
    cmd='meson test -C build juptune-unittest || cat build/meson-logs/testlog.txt',
    deps=['meson.build', 'src/'],
    labels=['development']
)
cmd_button(
    'test:open-logs',
    resource='test',
    text='Open logs',
    argv=['bash', '-c', '$GUI_EDITOR build/meson-logs/testlog.txt'],
    inputs=[text_input('GUI_EDITOR', 'Editor', default='code')]
)

local_resource(
    'compile examples',
    cmd='meson compile examples -C build',
    deps=['meson.build', 'examples/'],
    labels=['development'],
    auto_init=False,
    trigger_mode=TRIGGER_MODE_MANUAL
)

local_resource(
    'compile dasn1',
    cmd='meson compile dasn1 -C build',
    deps=['meson.build', 'tools/dasn1/src'],
    labels=['development'],
    auto_init=False
)

#### Refresh ASN.1 Models ####

refresh_resources = []

def refreshModelsForTest(testName):
    base_dir = 'tools/dasn1/tests/'+testName

    resource_name = 'Refresh test-'+testName
    refresh_resources.append(resource_name)
    
    local_resource(
        resource_name,
        dir=base_dir,
        cmd='bash refresh.sh',
        deps=[base_dir+'/models/'],
        resource_deps=['compile dasn1'],
        labels=["zzz_asn1"],
        allow_parallel=True
    )

refreshModelsForTest('adhoc')
refreshModelsForTest('x509')

local_resource(
    'test dasn1',
    cmd='meson test -C build dasn1* || cat build/meson-logs/testlog.txt',
    deps=['meson.build', 'src/', 'tools/'],
    resource_deps=refresh_resources,
    labels=['development'],
)

#### Manual Actions ####

local_resource(
    '[DevOps]',
    cmd='echo "Please use the buttons provided to perform different operations."',
    labels=['zzz_manual'],
)
cmd_button(
    'devops:gen-libsodium-di',
    resource='[DevOps]',
    text='Generate libsodium .di file',
    argv=['bash', 'devops/scripts/gen-libsodium-di.bash']
)
cmd_button(
    'devops:test-github-action',
    resource='[DevOps]',
    text='Test GitHub Action',
    argv=[
        'bash',
        '-c',
        'act -W $WORKFLOW_FILE --artifact-server-path /tmp/ --detect-event; echo "Exit code: $?"'
    ],
    inputs=[
        choice_input(
            'WORKFLOW_FILE',
            'Workflow file',
            choices=listdir('.github/workflows/')
        )
    ]
)