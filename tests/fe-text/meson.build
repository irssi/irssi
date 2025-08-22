test_test_paste_join_multiline = executable('test-paste-join-multiline',
  files(
    '../../src/fe-text/gui-entry.c',
    '../../src/fe-text/gui-printtext.c',
    '../../src/fe-text/gui-windows.c',
    '../../src/fe-text/mainwindows.c',
    '../../src/fe-text/term-terminfo.c',
    '../../src/fe-text/term.c',
    '../../src/fe-text/terminfo-core.c',
    '../../src/fe-text/sidepanels.c',
    '../../src/fe-text/textbuffer-formats.c',
    '../../src/fe-text/textbuffer-view.c',
    '../../src/fe-text/textbuffer.c',
    'mock-irssi.c',
    'test-paste-join-multiline.c',
  ),
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
  ],
  c_args : [
    '-D' + 'PACKAGE_STRING' + '="' + 'fe-text' + '"',
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep + textui_dep,
)

test('test-paste-join-multiline test', test_test_paste_join_multiline,
  args : ['--tap'],
  protocol : 'tap')

