shared_library('Irc',
  [ xsubpp.process(
    files(
      'Channel.xs',
      'Client.xs',
      'Ctcp.xs',
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
  name_suffix : perl_module_suffix,
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'Irc',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
  link_with : dl_cross_perl_core + dl_cross_irc_notifylist + dl_cross_irc_core + dl_cross_irssi_main,
  override_options : ['b_lundef=false'],
)

install_headers(
  files(
    'Irc.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)

shared_library('Dcc',
  [ xsubpp.process(
    files(
      'Dcc.xs',
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
  name_suffix : perl_module_suffix,
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'Irc' / 'Dcc',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
  link_with : dl_cross_perl_core + dl_cross_irc_dcc + dl_cross_irc_core + dl_cross_irssi_main,
  override_options : ['b_lundef=false'],
)

install_headers(
  files(
    'Irc/Dcc.pm',
  ),
  install_dir : perlmoddir / 'Irssi' / 'Irc',
)
  
# 'Makefile.PL.in',
# 'typemap',
