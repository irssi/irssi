# this file is part of irssi

if have_capsicum
  fe_common_core_capsicum_source = files('fe-capsicum.c')
else
  fe_common_core_capsicum_source = []
endif

fe_common_core_sources = [
  files(
    'chat-completion.c',
    'command-history.c',
    'completion.c',
    'fe-channels.c',
    'fe-common-core.c',
    'fe-core-commands.c',
    'fe-exec.c',
    'fe-expandos.c',
    'fe-help.c',
    'fe-ignore-messages.c',
    'fe-ignore.c',
    'fe-log.c',
    'fe-messages.c',
    'fe-modules.c',
    'fe-queries.c',
    'fe-recode.c',
    'fe-server.c',
    'fe-settings.c',
    'fe-tls.c',
    'fe-windows.c',
    'formats.c',
    'hilight-text.c',
    'keyboard.c',
    'module-formats.c',
    'printtext.c',
    'themes.c',
    'window-activity.c',
    'window-commands.c',
    'window-items.c',
    'windows-layout.c',
  )
  + fe_common_core_capsicum_source
  + [
    default_theme_h,
    irssi_version_h,
  ]
]

libfe_common_core_a = static_library('fe_common_core',
  fe_common_core_sources,
  include_directories : rootinc,
  implicit_include_directories : false,
  c_args : [
    def_helpdir,
    def_themesdir,
  ],
  dependencies : dep)

if want_fuzzer
  libfuzzer_fe_common_core_a = static_library('fuzzer_fe_common_core',
    fe_common_core_sources,
    include_directories : rootinc,
    implicit_include_directories : false,
    c_args : [
      def_helpdir,
      def_themesdir,
      def_suppress_printf_fallback,
    ],
    dependencies : dep)
endif

install_headers(
  files(
    'chat-completion.h',
    'command-history.h',
    'completion.h',
    'fe-capsicum.h',
    'fe-channels.h',
    'fe-common-core.h',
    'fe-core-commands.h',
    'fe-exec.h',
    'fe-messages.h',
    'fe-queries.h',
    'fe-recode.h',
    'fe-settings.h',
    'fe-tls.h',
    'fe-windows.h',
    'formats.h',
    'hilight-text.h',
    'keyboard.h',
    'module-formats.h',
    'module.h',
    'printtext.h',
    'themes.h',
    'window-activity.h',
    'window-items.h',
    'windows-layout.h',
  ),
  subdir : incdir / 'src' / 'fe-common' / 'core')
