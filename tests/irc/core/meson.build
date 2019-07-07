test_test_irc = executable('test-irc',
  files(
    'test-irc.c',
  ),
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
    libirc_core_a,
  ],
  c_args : [
    '-D' + 'PACKAGE_STRING' + '="' + 'irc/core' + '"',
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep
)
test('test-irc test', test_test_irc,
  args : [
    '--tap',
  ],
  protocol : 'tap')

test_test_channel_events = executable('test-channel-events',
  files(
    'test-channel-events.c',
  ),
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
    libirc_core_a,
  ],
  c_args : [
    '-D' + 'PACKAGE_STRING' + '="' + 'irc/core' + '"',
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep
)
test('test-channel-events test', test_test_channel_events,
  args : [
    '--tap',
  ],
  protocol : 'tap')
