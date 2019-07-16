test_test_formats = executable('test-formats',
  files(
    'test-formats.c',
  ),
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
  ],
  c_args : [
    '-D' + 'PACKAGE_STRING' + '="' + 'fe-common/core' + '"',
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep
)
test('test-formats test', test_test_formats,
  args : ['--tap'],
  protocol : 'tap')
