# this file is part of irssi

libirc_notifylist_a = static_library('irc_notifylist',
  files(
    'notify-commands.c',
    'notify-ison.c',
    'notify-setup.c',
    'notify-whois.c',
    'notifylist.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep)

install_headers(
  files(
    'module.h',
    'notify-setup.h',
    'notifylist.h',
  ),
  subdir : incdir / 'src' / 'irc' / 'notifylist')
