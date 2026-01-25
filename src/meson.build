# this file is part of irssi

subdir('lib-config')
subdir('core')
subdir('fe-common' / 'core')
if want_bot
  subdir('fe-none')
endif
if want_textui
  subdir('fe-text')
endif
foreach s : chat_modules
  subdir(s)
  subdir('fe-common' / s)
endforeach
if have_perl
  subdir('perl')
endif
if have_otr
  subdir('otr')
endif
if want_fuzzer
  subdir('fe-fuzz')
endif

install_headers(
  files('common.h'),
  subdir : incdir / 'src',
)
