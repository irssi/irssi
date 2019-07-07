libperl_textui_a = shared_module('TextUI',
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
  install : true,
  install_dir : perlmoddir / 'auto' / 'Irssi' / 'TextUI',
  include_directories : rootinc,
  implicit_include_directories : true,
  dependencies : dep + [ perl_dep ],
)

install_headers(
  files(
    'TextUI.pm',
  ),
  install_dir : perlmoddir / 'Irssi',
)
  
# 'Makefile.PL.in',
# 'typemap',
