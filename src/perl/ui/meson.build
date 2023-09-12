libperl_Irssi_UI_a = shared_module('UI',
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
  name_suffix : perl_module_suffix,
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'UI',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
  link_with : dl_cross_perl_core,
)

install_headers(
  files(
    'UI.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)
  
# 'Makefile.PL.in',
# 'typemap',
