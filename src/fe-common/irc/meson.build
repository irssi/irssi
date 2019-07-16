# this file is part of irssi

libfe_common_irc_a = static_library('fe_common_irc',
  files(
    'fe-cap.c',
    'fe-common-irc.c',
    'fe-ctcp.c',
    'fe-events-numeric.c',
    'fe-events.c',
    'fe-irc-channels.c',
    'fe-irc-commands.c',
    'fe-irc-messages.c',
    'fe-irc-queries.c',
    'fe-irc-server.c',
    'fe-ircnet.c',
    'fe-modes.c',
    'fe-netjoin.c',
    'fe-netsplit.c',
    'fe-sasl.c',
    'fe-whois.c',
    'irc-completion.c',
    'module-formats.c',

    'irc-modules.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  c_args : [
    def_helpdir,
    def_themesdir,
  ],
  dependencies : dep)

install_headers(
  files(
    'fe-irc-channels.h',
    'fe-irc-server.h',
    'module-formats.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'fe-common' / 'irc')

subdir('dcc')
subdir('notifylist')
