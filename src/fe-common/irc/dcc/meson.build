# this file is part of irssi

libfe_irc_dcc_a = static_library('fe_irc_dcc',
  files(
    'fe-dcc-chat-messages.c',
    'fe-dcc-chat.c',
    'fe-dcc-get.c',
    'fe-dcc-send.c',
    'fe-dcc-server.c',
    'fe-dcc.c',
    'module-formats.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  c_args : [
    def_helpdir,
    def_sysconfdir,
  ],
  dependencies : dep)
shared_module('fe_irc_dcc',
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  link_with : dl_cross_irc_dcc,
  link_whole : libfe_irc_dcc_a)

install_headers(
  files(
    'fe-dcc.h',
    'module-formats.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'fe-common' / 'irc' / 'dcc')
