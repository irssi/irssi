
perl_signals_list_h = custom_target('perl-signals-list.h',
  input : files('../../docs/signals.txt'),
  output : 'perl-signals-list.h',
  capture : true,
  depend_files : files('get-signals.pl'),
  command : [perl, files('get-signals.pl'), '@INPUT@'],
)

irssi_core_pl_h = custom_target('irssi-core.pl.h',
  input : files('irssi-core.pl'),
  output : 'irssi-core.pl.h',
  capture : true,
  command : [file2header, '@INPUT@', 'irssi_core_code'],
)

shared_module('perl_core',
  files(
    'perl-common.c',
    'perl-core.c',
    'perl-signals.c',
    'perl-sources.c',
  ) + [
    irssi_core_pl_h,
    perl_signals_list_h,
  ],
  c_args : [
    def_scriptdir,
    def_perl_use_lib,
    '-D' + 'PERL_STATIC_LIBS' + '=' + 0.to_string(),
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  install : true,
  install_dir : moduledir,
  install_rpath : perl_rpath,
  build_rpath : perl_rpath,
  dependencies : dep + [ perl_dep ],
)

shared_module('fe_perl',
  files(
    'module-formats.c',
    'perl-fe.c',
  ),
  c_args : [
    def_scriptdir,
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  install : true,
  install_dir : moduledir,
  dependencies : dep,
)

subdir('common')
foreach s : chat_modules
  subdir(s)
endforeach
subdir('ui')
if want_textui
  subdir('textui')
endif

# noinst_headers = files(
#   'module-fe.h',
#   'module-formats.h',
#   'module.h',
#   'perl-common.h',
#   'perl-core.h',
#   'perl-signals.h',
#   'perl-sources.h',
# )
