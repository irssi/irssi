project('irssi', 'c',
  version : '1.3-head',
  meson_version : '>=0.49',
  default_options : ['warning_level=1'])

############################
############################

glib_internal_version = 'glib-2.58.3' # keep this in sync with subprojects/glib.wrap
cc = meson.get_compiler('c')
rootinc = include_directories('.')
dep = []
textui_dep = []

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
want_truecolor      = get_option('enable-true-color') == 'yes'
want_gregex         = get_option('disable-gregex') != 'yes'

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

chat_modules = ['irc']

run_command('mkdir', meson.current_build_dir() / incdir)
run_command('ln', '-s', meson.current_source_dir() / 'src', meson.current_build_dir() / incdir)
run_command('ln', '-s', meson.current_build_dir() / 'irssi-config.h', meson.current_build_dir() / incdir)
run_command('ln', '-s', meson.current_build_dir() / 'irssi-version.h', meson.current_build_dir() / incdir)

def_moduledir  = '-D' + 'MODULEDIR'  + '="' + (get_option('prefix') / moduledir) + '"'
def_sysconfdir = '-D' + 'SYSCONFDIR' + '="' + (get_option('prefix') / get_option('sysconfdir')) + '"'
def_helpdir    = '-D' + 'HELPDIR'    + '="' + (get_option('prefix') / helpdir) + '"'
def_themesdir  = '-D' + 'THEMESDIR'  + '="' + (get_option('prefix') / themedir) + '"'
def_scriptdir  = '-D' + 'SCRIPTDIR'  + '="' + (get_option('prefix') / scriptdir) + '"'

def_suppress_printf_fallback = '-D' + 'SUPPRESS_PRINTF_FALLBACK'

##############
# Help files #
##############

perl = find_program('perl')
run_command(perl, files('utils/syntax.pl'))

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

glib_internal = false
message('*** If you don\'t have GLib, you can run meson ... -Dinstall-glib=yes')
message('*** to download and build it automatically')
message('*** Or alternatively install your distribution\'s package')
message('*** On Debian: sudo apt-get install libglib2.0-dev')
message('*** On Redhat: dnf install glib2-devel')
if not require_glib_internal
  glib_dep = dependency('glib-2.0', version : '>=2.28', required : not want_glib_internal, static : want_static_dependency)
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
  glib_internal_configure_t = custom_target('glib-internal-configure',
    command : [ meson_cmd, 'setup', '--prefix=/irssi-glib-internal',
      '--buildtype=' + get_option('buildtype'),
      '-Dlibmount=false', '-Dselinux=false', '-Ddefault_library=static', '-Dinternal_pcre=true',
      (meson.current_build_dir() / 'build-subprojects' / 'glib'),
      (meson.current_source_dir() / 'subprojects' / glib_internal_version) ],
    console : true,
    output : ['glib-internal-configure'],
    depends : glib_internal_download_t,)
  glib_internal_build_t = custom_target('glib-internal-build',
    command : [ ninja, '-C', meson.current_build_dir() / 'build-subprojects' / 'glib',
      'glib' / 'libglib-2.0.a',
      'gmodule' / 'libgmodule-2.0.a'],
    console : true,
    output : ['glib-internal-build'],
    depends : glib_internal_configure_t,)
  glib_dep = declare_dependency(
    dependencies : [
      dependency('threads'),
    ],
    sources : glib_internal_build_t,
    compile_args : [
      '-I' + (meson.current_source_dir() / 'subprojects' / glib_internal_version / 'glib'),
      '-I' + (meson.current_source_dir() / 'subprojects' / glib_internal_version),
      '-I' + (meson.current_build_dir() / 'build-subprojects' / 'glib' / 'glib'),
    ],
    link_args : [ meson.current_build_dir() / 'build-subprojects' / 'glib' / 'glib' / 'libglib-2.0.a' ],
  )
  libdl_dep = []
  prov_lib = cc.find_library('dl', required : false)
  if prov_lib.found() and cc.has_function('dlopen', dependencies : prov_lib)
    libdl_dep += prov_lib
  endif
  gmodule_dep = declare_dependency(sources : glib_internal_build_t,
    dependencies : libdl_dep,
    compile_args : [
      '-I' + (meson.current_source_dir() / 'subprojects' / glib_internal_version / 'gmodule'),
    ],
    link_args : [ meson.current_build_dir() / 'build-subprojects' / 'glib' / 'gmodule' / 'libgmodule-2.0.a' ],
  )
else
  gmodule_dep = dependency('gmodule-2.0', static : want_static_dependency)
endif
dep += glib_dep
dep += gmodule_dep

openssl_dep = dependency('openssl', static : want_static_dependency)
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
  res = run_command(perl, '-MExtUtils::Embed', '-e', 'ccopts')
  foreach fl : res.stdout().strip().split()
   if fl.startswith('-D') or fl.startswith('-U') or fl.startswith('-I') or fl.startswith('-i') or fl.startswith('-f') or fl.startswith('-m')
     perl_cflags += fl
   endif
  endforeach

  perl_cflags += cc.get_supported_arguments('-fPIC')

  #### ldopts ####
  res = run_command(perl, '-MExtUtils::Embed', '-e', 'ldopts')
  skip_libs = ['-ldb', '-ldbm', '-lndbm', '-lgdbm', '-lc', '-lposix', '-rdynamic']
  foreach fl : res.stdout().strip().split()
   if not fl.startswith('-A') and not skip_libs.contains(fl)
     if fl.startswith('-Wl,-rpath,')
       perl_rpath = fl.split(',')[2]
       perl_rpath_flags += fl
     else
       perl_ldflags += fl
     endif
   endif
  endforeach

  perl_dep = declare_dependency(compile_args : perl_cflags, link_args : perl_ldflags,
    version : run_command(perl, '-V::version:').stdout().split('\'')[1])

  ####
  if not cc.run('''
#include <EXTERN.h>
#include <perl.h>
int main()
{
  perl_alloc();
  return 0;
}
''', args : perl_cflags + perl_ldflags + perl_rpath_flags,
     name : 'working Perl support').compiled()
    if require_perl
      error('error linking with perl libraries')
    else
      warning('error linking with perl libraries')
    endif
  else
    xsubpp_file_c = run_command(perl, '-MExtUtils::ParseXS', '-Eprint $INC{"ExtUtils/ParseXS.pm"} =~ s{ParseXS\\.pm$}{xsubpp}r').stdout()
    xsubpp = generator(perl,
      output : '@BASENAME@.c',
      capture : true,
      arguments : [ xsubpp_file_c, '@EXTRA_ARGS@', '@INPUT@' ],
    )
    xsubpp_file = files(xsubpp_file_c)

    if with_perl_lib == 'module'
      perl_install_base = run_command(perl, '-MText::ParseWords=shellwords', '-e', 'grep { s/^INSTALL_BASE=// && print && exit } shellwords $ENV{PERL_MM_OPT}').stdout()
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
    if with_perl_lib in ['site', 'vendor', 'module']
      set_perl_use_lib = false
      perl_library_dir = with_perl_lib + ' default'
      if with_perl_lib in ['site', 'vendor']
        perlmoddir = run_command(perl, '-V::install' + with_perl_lib + 'arch:').stdout().split('\'')[1]
      elif with_perl_lib == 'module'
        perlmoddir = perl_install_base / 'lib' / 'perl5' / run_command(perl, '-V::archname:').stdout().split('\'')[1]
      endif
    elif with_perl_lib == ''
      set_perl_use_lib = true
      perl_library_dir = 'in prefix'
      perlmoddir = get_option('libdir') / incdir / 'perl'
    elif with_perl_lib.startswith('/')
      set_perl_use_lib = true
      perl_library_dir = 'custom'
      perlmoddir = with_perl_lib
    else
      error('Unrecognised with-perl-lib value: ' + with_perl_lib)
    endif

    perl_use_lib = get_option('prefix') / perlmoddir
    if set_perl_use_lib
      set_perl_use_lib = run_command(perl, '-e', 'exit ! grep $_ eq $ARGV[0], grep /^\\//, @INC', perl_use_lib).returncode() != 0
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
  libgcrypt = dependency('libgcrypt', version : '>=1.2.0', required : require_otr, static : want_static_dependency)
  libotr = dependency('libotr', version : '>=4.1.0', required : require_otr, static : want_static_dependency)
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
    nvlist_create_found = libnv.found() and cc.has_function('nvlist_create_found', dependencies : libnv)
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

##################
# irssi-config.h #
##################

conf = configuration_data()

conf.set('HAVE_CAPSICUM', have_capsicum, description : 'Build with Capsicum support')
conf.set('HAVE_GMODULE', true)
conf.set('HAVE_SOCKS', false, description : 'Build with socks support')
conf.set('TERM_TRUECOLOR', want_truecolor, description : 'true color support in terminal')
conf.set('USE_GREGEX', want_gregex, description : 'use GRegex for regular expressions')
conf.set10('_DARWIN_USE_64_BIT_INODE', true, description : 'Enable large inode numbers on Mac OS X 10.5.')

headers = [
  'sys/ioctl.h',
  'sys/resource.h',
  'sys/time.h',
  'sys/utsname.h',
  'dirent.h',
  'unistd.h',
]
foreach h : headers
  if cc.has_header(h)
    conf.set('HAVE_' + h.underscorify().to_upper(), 1, description : 'Define to 1 if you have the <' + h + '> header file.')
  endif
endforeach

conf.set('HAVE_LIBUTF8PROC', have_libutf8proc)
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_TARNAME', meson.project_name())

configure_file(output : 'irssi-config.h',
  configuration : conf,
  install_dir : includedir / incdir)

##########
# CFLAGS #
##########

#### warnings ####
add_project_arguments('-Wall', language : 'c')
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
pc.generate(filebase : 'irssi-1', name : 'Irssi', description : 'Irssi chat client', requires : pc_requires)

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
message('Building with true color support.. : ' + want_truecolor.to_string('yes', 'no'))
message('Building with GRegex ............. : ' + want_gregex.to_string('yes', 'no'))
message('Building with Capsicum ........... : ' + have_capsicum.to_string('yes', 'no'))
message('Building with utf8proc ........... : ' + have_libutf8proc.to_string('yes', 'no'))
message('Building with OTR support ........ : ' + have_otr.to_string('yes', 'no'))
message('')
message('If there are any problems, read the INSTALL file.')
message('Now type ninja -C ' + meson.current_build_dir() + ' to build Irssi')
message('')

############################
############################
