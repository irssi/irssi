libperl_Irssi_TextUI_a = shared_module('TextUI',
  [ xsubpp.process(
    files(
      'Statusbar.xs',
      'TextBufferView.xs',
      'TextBuffer.xs',
      'TextUI.xs',
    ),
    extra_args : [
      '-typemap',
      '../common/typemap',
      '-typemap',
      '../ui/typemap',
    ],
  ) ]
  + files(
    'module.h',
  ),
  name_prefix : '',
  name_suffix : perl_module_suffix,
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'TextUI',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
  link_with : dl_cross_perl_core,
)

install_headers(
  files(
    'TextUI.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)
  
# 'Makefile.PL.in',
# 'typemap',
