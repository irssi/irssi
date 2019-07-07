test_test_796 = executable('test-796',
  files(
    'test-796.c',
  ),
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
    libirc_a,
    libfe_common_irc_a,
    libfe_irc_dcc_a,
    libfe_irc_notifylist_a,
  ],
  c_args : [
    '-D' + 'PACKAGE_STRING' + '="' + 'irc/flood' + '"',
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep
)
test('test-796 test', test_test_796,
  args : [
    '--tap',
  ],
  protocol : 'tap')
