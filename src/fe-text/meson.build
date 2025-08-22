# this file is part of irssi

executable('irssi',
  files(
    #### terminfo_sources ####
    'term-terminfo.c',
    'terminfo-core.c',

    #### irssi sources ####
    'gui-entry.c',
    'gui-expandos.c',
    'gui-printtext.c',
    'gui-readline.c',
    'gui-windows.c',
    'irssi.c',
    'lastlog.c',
    'mainwindow-activity.c',
    'mainwindows-layout.c',
    'mainwindows.c',
    'module-formats.c',
    'sidepanels.c',
    'statusbar-config.c',
    'statusbar-items.c',
    'statusbar.c',
    'term.c',
    'textbuffer-commands.c',
    'textbuffer-formats.c',
    'textbuffer-view.c',
    'textbuffer.c',
  )
  + [
    irssi_version_h,
    default_config_h,
    default_theme_h,
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  export_dynamic : true,
  link_with : [
    libconfig_a,
    libcore_a,
    libfe_common_core_a,
    ],
  install : true,
  dependencies : dep
  + textui_dep
)

install_headers(
  files(
    'gui-printtext.h',
    'gui-windows.h',
    'mainwindows.h',
    'sidepanels.h',
    'statusbar-item.h',
    'statusbar.h',
    'term.h',
    'textbuffer-formats.h',
    'textbuffer-view.h',
    'textbuffer.h',
  ),
  subdir : incdir / 'src' / 'fe-text')

# noinst_headers = files(
#   'gui-entry.h',
#   'gui-readline.h',
#   'module-formats.h'
#   'module.h',
#   'statusbar-config.h',
#   'terminfo-core.h',
# )
