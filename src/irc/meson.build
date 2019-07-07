# this file is part of irssi

subdir('core')
subdir('dcc')
subdir('flood')
subdir('notifylist')

libirc_a = static_library('irc',
  files(
    'irc.c',
  ),
  link_with : [
    libirc_core_a,
    libirc_dcc_a,
    libirc_flood_a,
    libirc_notifylist_a,
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
)

if want_proxy
  subdir('proxy')
endif
