# this file is part of irssi

libirc_flood_a = shared_module('irc_flood',
  files(
    'autoignore.c',
    'flood.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  install : true,
  install_dir : moduledir,
  dependencies : dep)

install_headers(
  files('module.h'),
  subdir : incdir / 'src' / 'irc' / 'flood')
