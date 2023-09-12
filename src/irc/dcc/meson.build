# this file is part of irssi

libirc_dcc_sm = shared_module('irc_dcc',
  files(
    'dcc-autoget.c',
    'dcc-chat.c',
    'dcc-get.c',
    'dcc-queue.c',
    'dcc-resume.c',
    'dcc-send.c',
    'dcc-server.c',
    'dcc.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  link_with : dl_cross_irc_core,
  dependencies : dep)

dl_cross_irc_dcc = []
if need_dl_cross_link
  dl_cross_irc_dcc += libirc_dcc_sm
endif

install_headers(
  files(
    'dcc-chat.h',
    'dcc-file-rec.h',
    'dcc-file.h',
    'dcc-get.h',
    'dcc-queue.h',
    'dcc-rec.h',
    'dcc-send.h',
    'dcc-server.h',
    'dcc.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'irc' / 'dcc')
