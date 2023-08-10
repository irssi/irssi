# this file is part of irssi

shared_module('irc_proxy',
  files(
    'dump.c',
    'listen.c',
    'proxy.c',
  )
  + [ irssi_version_h ],
  include_directories : rootinc,
  implicit_include_directories : false,
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  dependencies : dep,
)

# noinst_headers = files(
#   'module.h',
#   'proxy.h',
# )
