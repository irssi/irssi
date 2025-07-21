project('irssi', 'c',
  version : '1.5-head',
  meson_version : '>=0.53',
  default_options : ['warning_level=1'])

############################
############################

glib_internal_version = 'glib-2.74.3' # keep this in sync with subprojects/glib.wrap
glib_pcre2_internal_version = 'pcre2-10.40'
cc = meson.get_compiler('c')
rootinc = include_directories('.')
dep = []
textui_dep = []
need_dl_cross_link = false
# The Android environment requires that all modules are linked to each other.
# See https://github.com/android/ndk/issues/201
if host_machine.system() == 'android'
  need_dl_cross_link = true
endif

includedir          = get_option('includedir')
incdir              = 'irssi'
moduledir           = get_option('libdir') / incdir / 'modules'
helpdir             = get_option('datadir') / incdir / 'help'
themedir            = get_option('datadir') / incdir / 'themes'
scriptdir           = get_option('datadir') / incdir / 'scripts'
docdir              = get_option('docdir') != '' ? get_option('docdir') : (get_option('datadir') / 'doc' / incdir)

want_textui         = get_option('without-textui') != 'yes'
want_bot            = get_option('with-bot') == 'yes'
want_fuzzer         = get_option('with-fuzzer') == 'yes'
fuzzer_lib          = get_option('with-fuzzer-lib')
fuzzer_link_language = get_option('fuzzer-link-language')
want_proxy          = get_option('with-proxy') == 'yes'

require_capsicum    = get_option('with-capsicum') == 'yes'
want_capsicum       = get_option('with-capsicum') != 'no'

require_libutf8proc = get_option('disable-utf8proc') == 'no'
want_libutf8proc    = get_option('disable-utf8proc') != 'yes'

require_perl        = get_option('with-perl') == 'yes'
want_perl           = get_option('with-perl') != 'no'
with_perl_lib       = get_option('with-perl-lib')

require_otr         = get_option('with-otr') == 'yes'
want_otr            = get_option('with-otr') != 'no'

want_glib_internal  = get_option('install-glib') != 'no'
require_glib_internal = get_option('install-glib') == 'force'

want_static_dependency = get_option('static-dependency') == 'yes'

package_version     = get_option('PACKAGE_VERSION') != '' ? get_option('PACKAGE_VERSION') : meson.project_version()

fs = import('fs')
if fs.exists('config.status') or fs.exists('irssi-version.h') or fs.exists('default-config.h') or fs.exists('default-theme.h') or fs.exists('src/perl/irssi-core.pl.h') or fs.exists('src/perl/perl-signals-list.h') or fs.exists('irssi-config.h')
  error('this tree has been configured with autotools, cannot proceed')
endif

UNSET = '=INVALID='
UNSET_ARR = [UNSET]

chat_modules = ['irc']

run_command('mkdir', meson.current_build_dir() / incdir, check : false)
run_command('ln', '-s', meson.current_source_dir() / 'src', meson.current_build_dir() / incdir, check : false)
run_command('ln', '-s', meson.current_build_dir() / 'irssi-config.h', meson.current_build_dir() / incdir, check : false)
run_command('ln', '-s', meson.current_build_dir() / 'irssi-version.h', meson.current_build_dir() / incdir, check : false)

def_moduledir  = '-D' + 'MODULEDIR'  + '="' + (get_option('prefix') / moduledir) + '"'
def_sysconfdir = '-D' + 'SYSCONFDIR' + '="' + (get_option('prefix') / get_option('sysconfdir')) + '"'
def_helpdir    = '-D' + 'HELPDIR'    + '="' + (get_option('prefix') / helpdir) + '"'
def_themesdir  = '-D' + 'THEMESDIR'  + '="' + (get_option('prefix') / themedir) + '"'
def_scriptdir  = '-D' + 'SCRIPTDIR'  + '="' + (get_option('prefix') / scriptdir) + '"'

def_suppress_printf_fallback = '-D' + 'SUPPRESS_PRINTF_FALLBACK'


module_suffix = []
perl_module_suffix = []
# Meson uses the wrong module extensions on Mac.
# https://gitlab.gnome.org/GNOME/glib/issues/520
if ['darwin', 'ios'].contains(host_machine.system())
  module_suffix = 'so'
  perl_module_suffix = 'bundle'
endif

##############
# Help files #
##############

build_perl = find_program('perl', native : true)
if meson.is_cross_build()
  cross_perl = find_program('perl')
else
  cross_perl = build_perl
endif
run_command(build_perl, files('utils/syntax.pl'), check : true)

###################
# irssi-version.h #
###################

env = find_program('env')
irssi_version_sh = find_program('utils/irssi-version.sh')
irssi_version_h = custom_target('irssi-version.h',
  build_by_default : true,
  build_always_stale : true,
  capture : true,
  command : [env, 'VERSION=' + meson.project_version(),
    irssi_version_sh, meson.current_source_dir()],
  output : 'irssi-version.h',
  install : true,
  install_dir : includedir / incdir,
)

####################
# default-config.h #
####################

file2header = find_program('utils/file2header.sh')
default_config_h = custom_target('default-config.h',
  input : files('irssi.conf'),
  output : 'default-config.h',
  capture : true,
  command : [file2header, '@INPUT@', 'default_config'],
)

###################
# default-theme.h #
###################

default_theme_h = custom_target('default-theme.h',
  input : files('themes/default.theme'),
  output : 'default-theme.h',
  capture : true,
  command : [file2header, '@INPUT@', 'default_theme'],
)

################
# Dependencies #
################

#### inet_addr ####
inet_addr_found = false
foreach inet_addr_provider : ['', 'nsl']
  prov_lib = []
  if inet_addr_provider != ''
    prov_lib += cc.find_library(inet_addr_provider, required : false)
  endif
  if (prov_lib.length() == 0 or prov_lib[0].found()) and cc.has_function('inet_addr', dependencies : prov_lib)
    dep += prov_lib
    inet_addr_found = true
    break
  endif
endforeach
if not inet_addr_found
  error('inet_addr not found')
endif

#### socket ####
socket_found = false
foreach socket_provider : ['', 'socket', 'network']
  prov_lib = []
  if socket_provider != ''
    prov_lib += cc.find_library(socket_provider, required : false)
  endif
  if (prov_lib.length() == 0 or prov_lib[0].found()) and cc.has_function('socket', dependencies : prov_lib)
    dep += prov_lib
    socket_found = true
    break
  endif
endforeach
if not socket_found
  error('socket not found')
endif

built_src = []
glib_internal = false
message('*** If you don\'t have GLib, you can run meson ... -Dinstall-glib=yes')
message('*** to download and build it automatically')
message('*** Or alternatively install your distribution\'s package')
message('*** On Debian: sudo apt-get install libglib2.0-dev')
message('*** On Redhat: dnf install glib2-devel')
if not require_glib_internal
  glib_dep = dependency('glib-2.0', version : '>=2.32', required : not want_glib_internal, static : want_static_dependency, include_type : 'system')
else
  glib_dep = dependency('', required : false)
endif
if not glib_dep.found()
  glib_internal = true
  meson_cmd = find_program('meson')
  ninja = find_program('ninja')

  glib_internal_download_t = custom_target('glib-internal-download',
    command : [ meson_cmd, 'subprojects', 'download', 'glib', '--sourcedir', meson.current_source_dir() ],
    console : true,
    output : ['glib-internal-download'],
  )

  glib_internal_dependencies = [
    dependency('threads'),
  ]
  glib_internal_configure_args = []

  glib_internal_usr_local = false
  if not cc.has_function('iconv_open')
    prov_lib = cc.find_library('iconv', required : false)
    if not prov_lib.found()
      prov_lib = cc.find_library('iconv', dirs : '/usr/local/lib')
      glib_internal_usr_local = true
    endif
    if cc.has_function('libiconv_open', dependencies : prov_lib)
      glib_internal_configure_args += '-Diconv=gnu'
    else
      glib_internal_configure_args += '-Diconv=native'
    endif
    glib_internal_dependencies += prov_lib
  endif

  if not cc.has_function('ngettext')
    prov_lib = cc.find_library('intl', required : false)
    if not prov_lib.found()
      prov_lib = cc.find_library('intl', dirs : '/usr/local/lib')
      glib_internal_usr_local = true
    endif
    glib_internal_dependencies += prov_lib
  endif

  if glib_internal_usr_local
    glib_internal_configure_args += ['-Dc_args=-I/usr/local/include', '-Dc_link_args=-L/usr/local/lib']
  endif

  if not cc.has_function('getxattr') or not cc.has_header('sys/xattr.h')
    if cc.has_header_symbol('attr/xattr.h', 'getxattr')
      prov_lib = cc.find_library('xattr', required : false)
    else
      prov_lib = dependency('', required : false)
    endif
    if prov_lib.found()
      glib_internal_dependencies += prov_lib
    else
      glib_internal_configure_args += '-Dxattr=false'
    endif
  endif

  glib_internal_configure_t = custom_target('glib-internal-configure',
    command : [ meson_cmd, 'setup', '--prefix=/irssi-glib-internal',
      '--buildtype=' + get_option('buildtype'),
      '-Dlibmount=disabled', '-Dselinux=disabled', '-Ddefault_library=static', '-Dforce_fallback_for=pcre2',
      glib_internal_configure_args,
      (meson.current_build_dir() / 'build-subprojects' / 'glib'),
      (meson.current_source_dir() / 'subprojects' / glib_internal_version) ],
    console : true,
    output : ['glib-internal-configure'],
    depends : glib_internal_download_t,)
  glib_internal_build_t = custom_target('glib-internal-build',
    command : [ ninja, '-C', meson.current_build_dir() / 'build-subprojects' / 'glib',
      'subprojects' / glib_pcre2_internal_version / 'libpcre2-8.a',
      'glib' / 'libglib-2.0.a',
      'gmodule' / 'libgmodule-2.0.a'],
    console : true,
    output : ['glib-internal-build'],
    depends : glib_internal_configure_t,)
  glib_dep = declare_dependency(
    dependencies : glib_internal_dependencies,
    sources : glib_internal_build_t,
    compile_args : [
      '-isystem' + (meson.current_source_dir() / 'subprojects' / glib_internal_version / 'glib'),
      '-isystem' + (meson.current_source_dir() / 'subprojects' / glib_internal_version),
      '-isystem' + (meson.current_build_dir() / 'build-subprojects' / 'glib' / 'glib'),
    ],
    link_args : [
      meson.current_build_dir() / 'build-subprojects' / 'glib' / 'subprojects' / glib_pcre2_internal_version / 'libpcre2-8.a',
      meson.current_build_dir() / 'build-subprojects' / 'glib' / 'glib' / 'libglib-2.0.a',
    ],
  )
  built_src += glib_internal_build_t
  libdl_dep = []
  prov_lib = cc.find_library('dl', required : false)
  if prov_lib.found() and cc.has_function('dlopen', dependencies : prov_lib)
    libdl_dep += prov_lib
  endif
  gmodule_dep = declare_dependency(sources : glib_internal_build_t,
    dependencies : libdl_dep,
    compile_args : [
      '-isystem' + (meson.current_source_dir() / 'subprojects' / glib_internal_version / 'gmodule'),
    ],
    link_args : [ meson.current_build_dir() / 'build-subprojects' / 'glib' / 'gmodule' / 'libgmodule-2.0.a' ],
  )
else
  gmodule_dep = dependency('gmodule-2.0', static : want_static_dependency, include_type : 'system')
endif
dep += glib_dep
dep += gmodule_dep

if glib_internal and want_static_dependency and want_fuzzer
  openssl_proj = subproject('openssl', default_options : ['default_library=static', 'asm=disabled'])
  openssl_dep = openssl_proj.get_variable('openssl_dep')
else
  openssl_dep = dependency('openssl', static : want_static_dependency, include_type : 'system')
endif
dep += openssl_dep

############
# utf8proc #
############

have_libutf8proc = false
libutf8proc = []
if want_libutf8proc
  libutf8proc = cc.find_library('utf8proc', required : require_libutf8proc)
  have_libutf8proc = cc.has_function('utf8proc_version', dependencies : libutf8proc)
  if have_libutf8proc
    dep += libutf8proc
  endif
endif

############################
############################

############
# terminfo #
############

if want_textui
  setupterm_found = false
  foreach setupterm_provider : ['tinfo', 'ncursesw', 'ncurses', 'terminfo']
    prov_lib = cc.find_library(setupterm_provider, required : false)
    if prov_lib.found() and cc.has_function('setupterm', dependencies : prov_lib)
      textui_dep += prov_lib
      setupterm_found = true
      break
    endif
  endforeach
  if not setupterm_found
    error('Terminfo not found')
  endif
endif

########
# perl #
########

have_perl = false
if want_perl
  perl_cflags = []
  perl_ldflags = []
  perl_rpath_flags = []
  perl_rpath = ''

  #### ccopts ####
  perl_ccopts = meson.get_cross_property('perl_ccopts', UNSET_ARR)
  if perl_ccopts == UNSET_ARR
    res = run_command(cross_perl, '-MExtUtils::Embed', '-e', 'ccopts', check : true)
    perl_ccopts = res.stdout().strip().split()
  endif
  foreach fl : perl_ccopts
    if fl.startswith('-D') or fl.startswith('-U') or fl.startswith('-I') or fl.startswith('-i') or fl.startswith('-f') or fl.startswith('-m')
      if fl.startswith('-I')
        fl = '-isystem' + fl.split('-I')[1]
      endif
      perl_cflags += fl
    endif
  endforeach

  perl_cflags += cc.get_supported_arguments('-fPIC')

  #### ldopts ####
  perl_ldopts = meson.get_cross_property('perl_ldopts', UNSET_ARR)
  if perl_ldopts == UNSET_ARR
    res = run_command(cross_perl, '-MExtUtils::Embed', '-e', 'ldopts', check : true)
    perl_ldopts = res.stdout().strip().split()
  endif
  skip_libs = ['-ldb', '-ldbm', '-lndbm', '-lgdbm', '-lc', '-lposix', '-rdynamic']
  foreach fl : perl_ldopts
    if not fl.startswith('-A') and not skip_libs.contains(fl)
      if fl.startswith('-Wl,-rpath,')
        perl_rpath = fl.split(',')[2]
        perl_rpath_flags += fl
      else
        perl_ldflags += fl
      endif
    endif
  endforeach

  perl_version = meson.get_cross_property('perl_version', UNSET)
  if perl_version == UNSET
    perl_version = run_command(cross_perl, '-V::version:', check : true).stdout().split('\'')[1]
  endif

  # disable clang warning
  if perl_version.version_compare('<5.35.2')
    perl_cflags += cc.get_supported_arguments('-Wno-compound-token-split-by-macro')
  endif
  perl_dep = declare_dependency(compile_args : perl_cflags, link_args : perl_ldflags,
    version : perl_version)

  ####
  if not cc.links('''
#include <EXTERN.h>
#include <perl.h>
int main()
{
  perl_alloc();
  return 0;
}
''', args : perl_cflags + perl_ldflags + perl_rpath_flags,
     name : 'working Perl support')
    if require_perl
      error('error linking with perl libraries')
    else
      warning('error linking with perl libraries')
    endif
  else
    xsubpp_file_c = meson.get_cross_property('perl_xsubpp', UNSET)
    if xsubpp_file_c == UNSET
      xsubpp_file_c = run_command(build_perl, '-MExtUtils::ParseXS', '-e($r = $INC{"ExtUtils/ParseXS.pm"}) =~ s{ParseXS\\.pm$}{xsubpp}; print $r', check : true).stdout()
    endif
    xsubpp = generator(build_perl,
      output : '@BASENAME@.c',
      capture : true,
      arguments : [ xsubpp_file_c, '@EXTRA_ARGS@', '@INPUT@' ],
    )
    xsubpp_file = files(xsubpp_file_c)

    if with_perl_lib == 'module'
      perl_install_base = run_command(build_perl, '-MText::ParseWords=shellwords', '-e', 'grep { s/^INSTALL_BASE=// && print && exit } shellwords $ENV{PERL_MM_OPT}', check : true).stdout()
      if perl_install_base == ''
        with_perl_lib = ''
      endif
    endif
    if with_perl_lib == ''
      if get_option('prefix') in ['/usr/local', 'C:/']
        with_perl_lib = 'site'
      elif get_option('prefix') in ['/usr']
        with_perl_lib = 'vendor'
      endif
    endif
    perlmoddir = ''
    if with_perl_lib in ['site', 'vendor', 'module']
      set_perl_use_lib = false
      perl_library_dir = with_perl_lib + ' default'
      if with_perl_lib in ['site', 'vendor']
        perlmoddir = meson.get_cross_property('perl_install' + with_perl_lib + 'arch', UNSET)
        if perlmoddir == UNSET
          perlmoddir = run_command(cross_perl, '-V::install' + with_perl_lib + 'arch:', check : true).stdout().split('\'')[1]
        endif
      elif with_perl_lib == 'module'
        perl_archname = meson.get_cross_property('perl_archname', UNSET)
        if perl_archname == UNSET
          perl_archname = run_command(cross_perl, '-V::archname:', check : true).stdout().split('\'')[1]
        endif
        perlmoddir = perl_install_base / 'lib' / 'perl5' / perl_archname
      endif
    elif with_perl_lib == ''
      set_perl_use_lib = true
      perl_library_dir = 'in prefix'
      perlmoddir = get_option('libdir') / incdir / 'perl'
    elif with_perl_lib.startswith('/')
      set_perl_use_lib = true
      perl_library_dir = 'custom'
      perlmoddir = with_perl_lib
    endif
    if perlmoddir == ''
      error('Unrecognised with-perl-lib value: ' + with_perl_lib)
    endif

    perl_use_lib = get_option('prefix') / perlmoddir
    if set_perl_use_lib
      perl_inc = meson.get_cross_property('perl_inc', UNSET_ARR)
      if perl_inc == UNSET_ARR
        set_perl_use_lib = run_command(cross_perl, '-e', 'exit ! grep $_ eq $ARGV[0], grep /^\\//, @INC', perl_use_lib, check : false).returncode() != 0
      else
        set_perl_use_lib = not perl_inc.contains(perl_use_lib)
      endif
      if not set_perl_use_lib
        perl_library_dir += ' - other path in @INC'
      else
        perl_library_dir += ' - prepends to @INC with /set perl_use_lib'
      endif
    endif
    def_perl_use_lib = '-D' + 'PERL_USE_LIB' + '="'
    if set_perl_use_lib
      def_perl_use_lib += perl_use_lib
    endif
    def_perl_use_lib += '"'

    have_perl = true
  endif
endif

#######
# OTR #
#######

have_otr = false
if want_otr
  libgcrypt = dependency('libgcrypt', version : '>=1.2.0', required : require_otr, static : want_static_dependency, include_type : 'system')
  libotr = dependency('libotr', version : '>=4.1.0', required : require_otr, static : want_static_dependency, include_type : 'system')
  if libgcrypt.found() and libotr.found()
    dep += libgcrypt
    dep += libotr
    have_otr = true
  endif
endif

############
# capsicum #
############

have_capsicum = false
if want_capsicum
  if cc.has_function('cap_enter', dependencies : cc.find_library('c'))
    libnv = cc.find_library('nv', required : require_capsicum)
    nvlist_create_found = libnv.found() and cc.has_function('nvlist_create', dependencies : libnv, prefix : '#include <sys/nv.h>')
    if nvlist_create_found
      dep += libnv
      have_capsicum = true
    else
      if require_capsicum
        error('nvlist_create not found')
      endif
    endif
  else
    if require_capsicum
      error('cap_enter not found')
    endif
  endif
endif

# dependency helper sets
dep_cflagsonly = []
foreach d : dep
  dep_cflagsonly += d.partial_dependency(includes : true, compile_args : true)
endforeach
dl_cross_dep = []
if need_dl_cross_link
  dl_cross_dep = dep
endif

##################
# irssi-config.h #
##################

conf = configuration_data()

conf.set('HAVE_CAPSICUM', have_capsicum, description : 'Build with Capsicum support')
conf.set('HAVE_GMODULE', true)
conf.set('TERM_TRUECOLOR', true)
conf.set('USE_GREGEX', true)
conf.set10('_DARWIN_USE_64_BIT_INODE', true, description : 'Enable large inode numbers on Mac OS X 10.5.')
conf.set_quoted('FHS_PREFIX', get_option('fhs-prefix'))

headers = [
  'sys/ioctl.h',
  'sys/resource.h',
  'sys/time.h',
  'sys/utsname.h',
  'dirent.h',
  'term.h',
  'unistd.h',
]
foreach h : headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1, description : 'Define to 1 if you have the <' + h + '> header file.')
  endif
endforeach

if want_textui and conf.get('HAVE_TERM_H', 0) == 1
  if cc.links('''
#include <stdio.h>
#include <term.h>
int main (void) {
  return tputs("x", 1, putchar);
}
''', args : '-pedantic-errors', dependencies : textui_dep, name : 'Curses working')
    # ok
  else
    has_curses_h = cc.has_header('curses.h')
    if has_curses_h and cc.links('''
#include <curses.h>
#include <term.h>
int main (void) {
  return tputs("x", 1, putchar);
}
''', args : '-pedantic-errors', dependencies : textui_dep, name : 'Curses working with curses.h')
      conf.set('NEED_CURSES_H', 1, description : 'tputs needs curses.h')
    else
      if has_curses_h and cc.links('''
#include <curses.h>
#include <term.h>
int char_putchar (char c) {
  return putchar(c);
}
int main (void) {
  return tputs("x", 1, char_putchar);
}
''', args : '-pedantic-errors', dependencies : textui_dep, name : 'Curses with tputs third argument arg char')
        conf.set('NEED_CURSES_H', 1, description : 'tputs needs curses.h')
        conf.set('TPUTS_SVR4', 1, description : 'third argument of tputs has the type int (*)(char)')
      else
        error('could not link terminfo')
      endif
    endif
  endif
endif

conf.set('HAVE_LIBUTF8PROC', have_libutf8proc)
conf.set_quoted('PACKAGE_VERSION', package_version)
conf.set_quoted('PACKAGE_TARNAME', meson.project_name())

configure_file(output : 'irssi-config.h',
  configuration : conf,
  install_dir : includedir / incdir)

##########
# CFLAGS #
##########

#### warnings ####
add_project_arguments(cc.get_supported_arguments('-Werror=declaration-after-statement'), language : 'c')

#### personality ####
add_project_arguments(cc.get_supported_arguments('-fno-strict-aliasing'), language : 'c')
if get_option('buildtype').contains('debug')
  add_project_arguments(cc.get_supported_arguments('-fno-omit-frame-pointer'), language : 'c')
endif

if want_fuzzer
  if fuzzer_lib.startswith('-fsanitize=fuzzer')
    if not cc.has_argument('-fsanitize=fuzzer-no-link')
      error('compiler does not support -fsanitize=fuzzer-no-link, try clang?')
    endif
    add_project_arguments('-fsanitize=fuzzer-no-link', language : 'c')
  endif
  if fuzzer_link_language != 'c'
    add_languages(fuzzer_link_language)
  endif
endif

##############
# irssi-1.pc #
##############

pc = import('pkgconfig')
pc_requires = []
if not glib_internal
  pc_requires += glib_dep
endif
signalsfile = docdir / 'signals.txt'
if signalsfile.startswith('/')
  signalsfile = signalsfile.split(get_option('prefix'))
  if signalsfile[0] == ''
    signalsfile = '${prefix}' + signalsfile[1]
  else
    signalsfile = signalsfile[0]
  endif
else
  signalsfile = '${prefix}' / signalsfile
endif
pc.generate(filebase : 'irssi-1',
  name : 'Irssi',
  description : 'Irssi chat client',
  version : package_version,
  requires : pc_requires,
  variables : [
    'irssimoduledir=${libdir}' / incdir / 'modules',
    'signalsfile=' + signalsfile
  ])

###########
# irssi.1 #
###########

install_man('docs/irssi.1')

###########
# subdirs #
###########

subdir('src')
subdir('tests')
subdir('docs')
subdir('scripts')
subdir('themes')
# subdir('utils')

############################
############################

message('*** Irssi configured ***')
message('')
message('Building text frontend ........... : ' + want_textui.to_string('yes', 'no'))
message('Building irssi bot ............... : ' + want_bot.to_string('yes', 'no'))
message('Building irssi proxy ............. : ' + want_proxy.to_string('yes', 'no'))
if want_perl and not have_perl
  message('Building with Perl support ....... : NO!')
  message(' - Try: sudo apt-get install libperl-dev')
  message(' -  Or: dnf install perl-devel')
else
  message('Building with Perl support ....... : ' + have_perl.to_string('yes', 'no'))
endif
if have_perl
  message('Perl library directory ........... : ' + perl_use_lib)
  message('                                     ' + perl_library_dir)
endif
message('Install prefix ................... : ' + get_option('prefix'))
message('')
message('Building with Capsicum ........... : ' + have_capsicum.to_string('yes', 'no'))
message('Building with utf8proc ........... : ' + have_libutf8proc.to_string('yes', 'no'))
message('Building with OTR support ........ : ' + have_otr.to_string('yes', 'no'))
message('')
message('If there are any problems, read the INSTALL file.')
message('Now type ninja -C ' + meson.current_build_dir() + ' to build Irssi')
message('')

############################
############################
