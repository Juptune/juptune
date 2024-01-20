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
    cmd='meson test -C build',
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