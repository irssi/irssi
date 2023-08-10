# this file is part of irssi

libirc_notifylist_sm = shared_module('irc_notifylist',
  files(
    'notify-commands.c',
    'notify-ison.c',
    'notify-setup.c',
    'notify-whois.c',
    'notifylist.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  name_suffix : module_suffix,
  install : true,
  install_dir : moduledir,
  link_with : dl_cross_irc_core,
  dependencies : dep)

dl_cross_irc_notifylist = []
if need_dl_cross_link
  dl_cross_irc_notifylist += libirc_notifylist_sm
endif

install_headers(
  files(
    'module.h',
    'notify-setup.h',
    'notifylist.h',
  ),
  subdir : incdir / 'src' / 'irc' / 'notifylist')
