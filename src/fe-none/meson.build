# this file is part of irssi

executable('botti',
  files(
    'irssi.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  export_dynamic : true,
  link_with : [
    libconfig_a,
    libcore_a,
    libirc_a,
  ],
  install : true,
  dependencies : dep
)

# noinst_headers = files(
#   'module.h',
# )
