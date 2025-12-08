# this file is part of irssi

fe_none_irssi = executable('botti',
  files(
    'irssi.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  export_dynamic : true,
  implib : true,
  link_with : [
    libconfig_a,
    libcore_a,
  ],
  install : true,
  dependencies : dep
)
if need_dl_cross_link_main
  dl_cross_irssi_main = [ fe_none_irssi ]
endif

# noinst_headers = files(
#   'module.h',
# )
