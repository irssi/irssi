# this file is part of irssi

shared_module('irc_notifylist',
  files(
    'notify-commands.c',
    'notify-ison.c',
    'notify-setup.c',
    'notify-whois.c',
    'notifylist.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  install : true,
  install_dir : moduledir,
  dependencies : dep)

install_headers(
  files(
    'module.h',
    'notify-setup.h',
    'notifylist.h',
  ),
  subdir : incdir / 'src' / 'irc' / 'notifylist')
