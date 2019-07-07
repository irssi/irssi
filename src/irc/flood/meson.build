# this file is part of irssi

libirc_flood_a = static_library('irc_flood',
  files(
    'autoignore.c',
    'flood.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep)

install_headers(
  files('module.h'),
  subdir : incdir / 'src' / 'irc' / 'flood')
