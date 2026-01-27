# this file is part of irssi

libirc_flood_a = static_library(
  'irc_flood',
  files(
    'autoignore.c',
    'flood.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep,
)
shared_library(
  'irc_flood',
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  link_with : dl_cross_irc_core + dl_cross_irssi_main,
  link_whole : libirc_flood_a,
  override_options : [ 'b_lundef=false' ],
)

install_headers(
  files('module.h'),
  subdir : incdir / 'src' / 'irc' / 'flood',
)
