# this file is part of irssi

libfe_irc_notifylist_a = static_library('fe_irc_notifylist',
  files(
    'fe-notifylist.c',
    'module-formats.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  c_args : [
    def_helpdir,
    def_sysconfdir,
  ],
  dependencies : dep)

install_headers(
  files(
    'module-formats.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'fe-common' / 'irc' / 'notifylist')
