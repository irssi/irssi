# this file is part of irssi

if want_gregex
  regex_impl = files('iregex-gregex.c')
else
  regex_impl = files('iregex-regexh.c')
endif

if have_capsicum
  core_capsicum_source = files('capsicum.c')
else
  core_capsicum_source = []
endif

libcore_a = static_library('core',
  files(
    'args.c',
    'channels-setup.c',
    'channels.c',
    'chat-commands.c',
    'chat-protocols.c',
    'chatnets.c',
    'commands.c',
    'core.c',
    'expandos.c',
    'ignore.c',
    'levels.c',
    'line-split.c',
    'log-away.c',
    'log.c',
    'masks.c',
    'misc.c',
    'modules-load.c',
    'modules.c',
    'net-disconnect.c',
    'net-nonblock.c',
    'net-sendbuffer.c',
    'network-openssl.c',
    'network.c',
    'nicklist.c',
    'nickmatch-cache.c',
    'pidwait.c',
    'queries.c',
    'rawlog.c',
    'recode.c',
    'refstrings.c',
    'servers-reconnect.c',
    'servers-setup.c',
    'servers.c',
    'session.c',
    'settings.c',
    'signals.c',
    'special-vars.c',
    'tls.c',
    'utf8.c',
    'wcwidth-wrapper.c',
    'wcwidth.c',
    'write-buffer.c',
  )
  + core_capsicum_source
  + regex_impl
  + [
    default_config_h,
    irssi_version_h,
  ],
  include_directories : rootinc,
  implicit_include_directories : false,
  c_args : [
    def_moduledir,
    def_sysconfdir,
  ],
  dependencies : dep)

install_headers(
  files(
    #### structure_headers ####
    'channel-rec.h',
    'channel-setup-rec.h',
    'chatnet-rec.h',
    'query-rec.h',
    'server-connect-rec.h',
    'server-rec.h',
    'server-setup-rec.h',
    'window-item-rec.h',

    ####
    'args.h',
    'capsicum.h',
    'channels-setup.h',
    'channels.h',
    'chat-protocols.h',
    'chatnets.h',
    'commands.h',
    'core.h',
    'expandos.h',
    'ignore.h',
    'iregex.h',
    'levels.h',
    'line-split.h',
    'log.h',
    'masks.h',
    'misc.h',
    'module.h',
    'modules-load.h',
    'modules.h',
    'net-disconnect.h',
    'net-nonblock.h',
    'net-sendbuffer.h',
    'network-openssl.h',
    'network.h',
    'nick-rec.h',
    'nicklist.h',
    'nickmatch-cache.h',
    'pidwait.h',
    'queries.h',
    'rawlog.h',
    'recode.h',
    'refstrings.h',
    'servers-reconnect.h',
    'servers-setup.h',
    'servers.h',
    'session.h',
    'settings.h',
    'signals.h',
    'special-vars.h',
    'tls.h',
    'utf8.h',
    'window-item-def.h',
    'write-buffer.h',
  ),
  subdir : incdir / 'src' / 'core')
