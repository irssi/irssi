# this file is part of irssi

libirc_dcc_a = static_library('irc_dcc',
  files(
    'dcc-autoget.c',
    'dcc-chat.c',
    'dcc-get.c',
    'dcc-queue.c',
    'dcc-resume.c',
    'dcc-send.c',
    'dcc-server.c',
    'dcc.c',
  ),
  include_directories : rootinc,
  implicit_include_directories : false,
  dependencies : dep)

install_headers(
  files(
    'dcc-chat.h',
    'dcc-file-rec.h',
    'dcc-file.h',
    'dcc-get.h',
    'dcc-queue.h',
    'dcc-rec.h',
    'dcc-send.h',
    'dcc-server.h',
    'dcc.h',
    'module.h',
  ),
  subdir : incdir / 'src' / 'irc' / 'dcc')
