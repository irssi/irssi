# this file is part of irssi

shared_module('otr_core',
  files(
    'key.c',
    'otr-fe.c',
    'otr-formats.c',
    'otr-module.c',
    'otr-ops.c',
    'otr.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  dependencies : dep,
)

# noinst_headers = files(
#   'irssi-otr.h',
#   'key.h',
#   'module.h',
#   'otr-fe.h',
#   'otr-formats.h',
#   'otr.h',
# )
