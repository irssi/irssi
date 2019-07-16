libperl_ui_a = shared_module('UI',
  [ xsubpp.process(
    files(
      'Formats.xs',
      'Themes.xs',
      'UI.xs',
      'Window.xs',
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
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'UI',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
)

install_headers(
  files(
    'UI.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)
  
# 'Makefile.PL.in',
# 'typemap',
