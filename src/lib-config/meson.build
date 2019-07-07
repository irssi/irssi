# this file is part of irssi

libconfig_a = static_library('irssi_config',
  files(
    'get.c',
    'parse.c',
    'set.c',
    'write.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep)

install_headers(
  files(
    'iconfig.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'lib-config')
