libperl_irc_a = shared_module('Irc',
  [ xsubpp.process(
    files(
      'Channel.xs',
      'Client.xs',
      'Ctcp.xs',
      'Dcc.xs',
      'Irc.xs',
      'Modes.xs',
      'Netsplit.xs',
      'Notifylist.xs',
      'Query.xs',
      'Server.xs',
    ),
    extra_args : [
      '-typemap',
      '../common/typemap',
    ],
  ) ]
  + files(
    'module.h',
  ),
  name_prefix : '',
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'Irc',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
)

install_headers(
  files(
    'Irc.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)
  
# 'Makefile.PL.in',
# 'typemap',
