libperl_common_a = shared_module('Irssi',
  [ xsubpp.process(
    files(
      'Channel.xs',
      'Core.xs',
      'Expando.xs',
      'Ignore.xs',
      'Irssi.xs',
      'Log.xs',
      'Masks.xs',
      'Query.xs',
      'Rawlog.xs',
      'Server.xs',
      'Settings.xs',
    )
  ) ]
  + files(
    'module.h',
  )
  + [ irssi_version_h ],
  name_prefix : '',
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
)

install_headers(
  files(
    'Irssi.pm',
  ),
  install_dir : perlmoddir,
)
  
# 'Makefile.PL.in',
# 'typemap',
