# this file is part of irssi

libirc_flood_a = static_library('irc_flood',
  files(
    'autoignore.c',
    'flood.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep)
shared_module('irc_flood',
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  link_with : dl_cross_irc_core,
  link_whole : libirc_flood_a)

install_headers(
  files('module.h'),
  subdir : incdir / 'src' / 'irc' / 'flood')
