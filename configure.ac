AC_INIT(irssi, 0.8.21-head)
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR(build-aux)
AC_PREREQ(2.50)

AC_CONFIG_HEADERS([irssi-config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.9 no-define foreign])

AM_SILENT_RULES([yes])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CPP
AM_PROG_LIBTOOL

AC_PATH_PROG(sedpath, sed)
AC_PATH_PROG(perlpath, perl)

AC_CHECK_HEADERS(unistd.h dirent.h sys/ioctl.h sys/resource.h)

# check posix headers..
AC_CHECK_HEADERS(sys/socket.h sys/time.h sys/utsname.h regex.h)

AC_SYS_LARGEFILE

AC_ARG_WITH(socks,
[  --with-socks            Build with socks support],
	if test x$withval = xno; then
		want_socks=no
	else
		want_socks=yes
	fi,
	want_socks=no)

AC_ARG_WITH(textui,
[  --without-textui        Build without text frontend],
	if test x$withval = xno; then
		want_textui=no
	else
		want_textui=yes
	fi,
	want_textui=yes)

AC_ARG_WITH(bot,
[  --with-bot              Build irssi-bot],
	if test x$withval = xno; then
		want_irssibot=no
	else
		want_irssibot=yes
	fi,
	want_irssibot=no)

AC_ARG_WITH(proxy,
[  --with-proxy            Build irssi-proxy],
	if test x$withval = xno; then
		want_irssiproxy=no
	else
		want_irssiproxy=yes
	fi,
	want_irssiproxy=no)

AC_ARG_WITH(modules,
[  --with-modules          Specify what modules to build in binary],
	if test x$withval != xyes -a x$withval != xno; then
		build_modules="$withval"
	fi)

if test "x$prefix" != "xNONE"; then
	prefix=`eval echo $prefix`
	PERL_MM_PARAMS="INSTALLDIRS=perl INSTALL_BASE=$prefix"
	perl_set_use_lib=yes

	perl_prefix_note=yes
fi

AC_ARG_WITH(perl-staticlib,
[  --with-perl-staticlib   Specify that we want to link perl libraries
                          statically in irssi, default is no],
	if test x$withval = xno; then
		want_staticperllib=no
	else
		want_staticperllib=yes
	fi,
	want_staticperllib=no)


AC_ARG_WITH(perl-lib,
[  --with-perl-lib=[perl|site|vendor|DIR]  Specify where to install the
                          Perl libraries for irssi, default is site],
	if test "x$withval" = xyes; then
		want_perl=yes
	elif test "x$withval" = xno; then
		want_perl=no
	elif test "x$withval" = xperl; then
		want_perl=yes
		perl_prefix_note=no
		PERL_MM_PARAMS="INSTALLDIRS=perl"
		perl_set_use_lib=no
	elif test "x$withval" = xsite; then
		want_perl=yes
		perl_prefix_note=no
		PERL_MM_PARAMS=""
		perl_set_use_lib=no
	elif test "x$withval" = xvendor; then
		want_perl=yes
		perl_prefix_note=no
		if test -z "`$perlpath -v|grep '5\.0'`"; then
			PERL_MM_PARAMS="INSTALLDIRS=vendor"
		else
			PERL_MM_PARAMS="INSTALLDIRS=perl PREFIX=`$perlpath -e 'use Config; print $Config{prefix}'`"
		fi
		perl_set_use_lib=no
	else
		want_perl=yes
		perl_prefix_note=no
		PERL_MM_PARAMS="INSTALLDIRS=perl LIB=$withval"
		perl_set_use_lib=yes
	fi,
	want_perl=yes)

AC_ARG_WITH(perl,
[  --with-perl[=yes|no|module]  Build with Perl support - also specifies
                          if it should be built into main irssi binary
                          (static, default) or as module],
	if test x$withval = xyes; then
		want_perl=static
	elif test x$withval = xstatic; then
		want_perl=static
	elif test x$withval = xmodule; then
		want_perl=module
	else
		want_perl=no
	fi,
	want_perl=static)

AC_ARG_ENABLE(true-color,
[  --enable-true-color     Build with true color support in terminal],
	if test x$enableval = xno ; then
		want_truecolor=no
	else
		want_truecolor=yes
	fi,
	want_truecolor=no)

dnl **
dnl ** just some generic stuff...
dnl **

dnl * OS specific options
case "$host_os" in
  hpux*)
    CFLAGS="$CFLAGS -D_XOPEN_SOURCE_EXTENDED"
    ;;
  *)
    ;;
esac


AC_SEARCH_LIBS([socket], [socket])

AC_SEARCH_LIBS([inet_addr], [nsl])

dnl * gcc specific options
if test "x$ac_cv_prog_gcc" = "xyes"; then
  CFLAGS="$CFLAGS -Wall"
fi

AC_CHECK_TYPE(socklen_t, ,
	[AC_DEFINE([socklen_t], [int], [Define to 'int' if <sys/socket.h> doesn't define.])], [
AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(off_t)

if test $ac_cv_sizeof_off_t = 8; then
  offt_64bit=yes
else
  offt_64bit=no
fi

if test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_long; then
  # try to use unsigned long always first
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "lu")
  AC_DEFINE(UOFF_T_LONG)
elif test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_int; then
  # next try int
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "u")
  AC_DEFINE(UOFF_T_INT)
elif test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_long_long; then
  # and finally long long
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "llu")
  AC_DEFINE(UOFF_T_LONG_LONG)
else
  AC_ERROR([Couldn't find integer type for off_t])
fi

dnl **
dnl ** check for socks
dnl **

if test "x$want_socks" = "xyes"; then
	AC_CHECK_LIB(socks, connect, [
		AC_DEFINE(HAVE_SOCKS,, Build with socks support)
		LIBS="$LIBS -lsocks"
		AC_CHECK_HEADER(socks.h, [
			AC_DEFINE(HAVE_SOCKS_H)
			CFLAGS="$CFLAGS -DSOCKS"
			AC_MSG_RESULT(["socks5 library found, building with it"])
		], [
			AC_MSG_RESULT(["socks4 library found, building with it"])
			CFLAGS="$CFLAGS -Dconnect=Rconnect -Dgetsockname=Rgetsockname -Dgetpeername=Rgetpeername -Dbind=Rbind -Daccept=Raccept -Dlisten=Rlisten -Dselect=Rselect"
		])
	])
fi

dnl **
dnl ** OpenSSL checks
dnl **
AC_CHECK_LIB([ssl], [SSL_library_init])

dnl **
dnl ** fe-text checks
dnl **

for try in 1 2; do
  if test $try = 1; then
    glib_modules=gmodule
  else
    echo "*** trying without -lgmodule"
    glib_modules=
  fi
  AM_PATH_GLIB_2_0(2.16.0,,, $glib_modules)
  if test "$GLIB_LIBS"; then
    if test $glib_modules = gmodule; then
      AC_DEFINE(HAVE_GMODULE)
      have_gmodule=yes
    fi
    break
  fi
done

if test -z "$GLIB_LIBS"; then
  echo
  echo "*** If you don't have GLIB, you can get it from ftp://ftp.gtk.org/pub/glib/"
  echo "*** We recommend you get the latest stable GLIB 2 version."
  echo "*** Compile and install it, and make sure pkg-config finds it,"
  echo "*** by adding the path where the .pc file is located to PKG_CONFIG_PATH"
  echo -n "*** Or alternatively install your distribution's package"
  if test -f /etc/debian_version; then
    echo :
    echo "*** sudo apt-get install libglib2.0-dev"
  elif test -f /etc/redhat-release; then
    echo " (glib2-devel)"
  else
    echo .
  fi
  echo

  AC_ERROR([GLIB is required to build irssi.])
fi

LIBS="$LIBS $GLIB_LIBS -lssl -lcrypto"

dnl **
dnl ** curses checks
dnl **

if test "x$want_textui" != "xno"; then

	TEXTUI_NO_LIBS="$LIBS"
	LIBS=
	AC_SEARCH_LIBS([setupterm], [tinfo ncursesw ncurses], [want_textui=yes], [
		AC_ERROR(Terminfo not found - install libncurses-dev or ncurses-devel package)
		want_textui="no, Terminfo not found"
	])

	TEXTUI_LIBS="$LIBS"
	AC_SUBST(TEXTUI_LIBS)
	LIBS="$TEXTUI_NO_LIBS"

fi

dnl **
dnl ** perl checks
dnl **

if test "$want_perl" != "no"; then
	AC_MSG_CHECKING(for working Perl support)

	if test -z "$perlpath"; then
		perl_check_error="perl binary not found"
	else
		PERL_CFLAGS=`$perlpath -MExtUtils::Embed -e ccopts 2>/dev/null`
	fi

	if test "x$ac_cv_prog_gcc" = "xyes" -a -z "`echo $host_os|grep 'bsd\|linux'`"; then
		dnl * several systems have Perl compiled with native compiler
		dnl * but irssi is being compiled with GCC. Here we try to
		dnl * fix those command line options a bit so GCC won't
		dnl * complain about them. Normally there's only few options
		dnl * that we want to keep:
		dnl * -Ddefine -Uundef -I/path -fopt -mopt
		PERL_CFLAGS=`echo $PERL_CFLAGS | $perlpath -pe 's/^(.* )?-@<:@^DUIfm@:>@@<:@^ @:>@+/\1/g; s/^(.* )?\+@<:@^ @:>@+/\1/g'`

		PERL_EXTRA_OPTS="CCCDLFLAGS=\"-fPIC\""
		AC_SUBST(PERL_EXTRA_OPTS)
	fi

	if test -z "$PERL_CFLAGS"; then
		if test -n "$perl_check_error"; then
			perl_check_error="Error getting perl CFLAGS"
		fi
		AC_MSG_RESULT([not found, building without Perl])
		want_perl=no
	else
		PERL_LDFLAGS=`$perlpath -MExtUtils::Embed -e ldopts 2>/dev/null`

		dnl * remove all database stuffs
		dnl * nsl is already in ldflags
		dnl * libc is of course linked without needing -lc
		dnl * -rdynamic must not be in LIBADD line
		for word in -ldb -ldbm -lndbm -lgdbm -lc -rdynamic; do
		  PERL_LDFLAGS=`echo $PERL_LDFLAGS | $sedpath -e "s/$word //" -e "s/$word$//"`
		done

		case "$host_os" in
		  linux*)
		    PERL_LDFLAGS=`echo $PERL_LDFLAGS | $sedpath -e 's/-lposix //' -e 's/-lposix$//'`
		    ;;
		  hpux*)
		    if test "x$ac_cv_prog_gcc" = "xyes"; then
		      PERL_CFLAGS=`echo $PERL_CFLAGS | $sedpath -e 's/-Ae //' -e 's/-Ae$//'`
		      PERL_LDFLAGS=`echo $PERL_LDFLAGS | $sedpath -e 's/-Ae //' -e 's/-Ae$//'`
		    fi
		    ;;
		  *)
		    ;;
		esac

		dnl * check that perl's ldflags actually work
		echo "#include <EXTERN.h>" > conftest.c
		echo "#include <perl.h>" >> conftest.c
		echo "int main(){perl_alloc(); return 0;}" >> conftest.c
		$CC $CFLAGS $PERL_CFLAGS conftest.c -o conftest $LDFLAGS $PERL_LDFLAGS 2> perl.error.tmp > /dev/null
		if test ! -s conftest -a "x$ignore_perl_errors" = "x"; then
			perl_check_error="Error linking with perl libraries: $PERL_LDFLAGS: `cat perl.error.tmp`"
			AC_MSG_RESULT([error linking with perl libraries, building without Perl])
			want_perl=no
		fi

		rm -f perl.error.tmp
	fi

	if test "x$want_perl" != "xno"; then
		AC_MSG_RESULT(ok)

		if test "x$want_perl" = "xstatic"; then
			dnl * building with static perl support
			dnl * all PERL_LDFLAGS linking is done in fe-text
			PERL_LINK_FLAGS="$PERL_LDFLAGS"
			PERL_LINK_LIBS="../perl/libperl_core_static.la"
			PERL_FE_LINK_LIBS="../perl/libfe_perl_static.la"
			PERL_LDFLAGS=
			AC_DEFINE(HAVE_STATIC_PERL)

			dnl * build only static library of perl module
			perl_module_lib=
			perl_module_fe_lib=
			perl_static_lib=libperl_core_static.la
			perl_static_fe_lib=libfe_perl_static.la
		else
			dnl * build dynamic library of perl module
			perl_module_lib=libperl_core.la
			perl_module_fe_lib=libfe_perl.la
			perl_static_lib=
			perl_static_fe_lib=
		fi

		if test "x$want_staticperllib" = "xyes"; then
			PERL_MM_PARAMS="$PERL_MM_PARAMS LINKTYPE=static"
			PERL_LINK_LIBS="$PERL_LINK_LIBS ../perl/common/blib/arch/auto/Irssi/Irssi.a ../perl/irc/blib/arch/auto/Irssi/Irc/Irc.a ../perl/ui/blib/arch/auto/Irssi/UI/UI.a ../perl/textui/blib/arch/auto/Irssi/TextUI/TextUI.a"
			PERL_STATIC_LIBS=1
		else
			PERL_STATIC_LIBS=0
		fi

		# remove any prefix from PERL_MM_OPT
		PERL_MM_OPT=`perl -MText::ParseWords -e 'sub qu{$_=shift;s{^(.*?)=(.*)$}{($a,$b)=($1,$2);$b=~s/"/\\\\"/g;qq{$a="$b"}}ge if /@<:@\s"@:>@/;$_} local $,=" "; print map qu($_), grep !/^(INSTALL_BASE|PREFIX)=/, shellwords(@ARGV)' "$PERL_MM_OPT"`
		# figure out the correct @INC path - we'll need to do this
		# through MakeMaker since it's difficult to get it right
		# otherwise.
		$perlpath -MExtUtils::MakeMaker -e 'WriteMakefile(NAME => "test", MAKEFILE => "Makefile.test", FIRST_MAKEFILE => "/dev/null", NO_META => 1, NO_MYMETA => 1);' $PERL_MM_PARAMS >/dev/null
		echo 'show-INSTALLDIRS:' >> Makefile.test
		echo '	@echo $(INSTALLDIRS)' >> Makefile.test
		perl_INSTALLDIRS=`$am_make -s -f Makefile.test show-INSTALLDIRS`
		if test "x$perl_INSTALLDIRS" = "xsite"; then
			perl_library_dir="site default"
			perl_INSTALL_VAR=INSTALLSITEARCH
		elif test "x$perl_INSTALLDIRS" = "xvendor"; then
			perl_library_dir="vendor default"
			perl_INSTALL_VAR=INSTALLVENDORARCH
		else
			perl_library_dir="module default"
			perl_INSTALL_VAR=INSTALLARCHLIB
		fi
		echo 'show-ARCHLIB:' >> Makefile.test
		echo '	@echo $('"$perl_INSTALL_VAR"')' >> Makefile.test
		perl_use_lib=`$am_make -s -f Makefile.test show-ARCHLIB`
		rm -f Makefile.test
		if test "x$perl_set_use_lib" = "xyes"; then
			if $perlpath -e 'exit ! grep $_ eq $ARGV@<:@0@:>@, grep /^\//, @INC' "$perl_use_lib"; then
				perl_library_dir="other path in @INC"
				perl_set_use_lib=no
			else
				perl_library_dir="prepends to @INC with /set perl_use_lib"
				PERL_USE_LIB="$perl_use_lib"
			fi
		fi

		AC_SUBST(perl_module_lib)
		AC_SUBST(perl_static_lib)
		AC_SUBST(perl_module_fe_lib)
		AC_SUBST(perl_static_fe_lib)

		AC_SUBST(PERL_LINK_FLAGS)
		AC_SUBST(PERL_LINK_LIBS)
		AC_SUBST(PERL_FE_LINK_LIBS)

		AC_SUBST(PERL_LDFLAGS)
		AC_SUBST(PERL_CFLAGS)

		AC_SUBST(PERL_USE_LIB)
		AC_SUBST(PERL_MM_OPT)
		AC_SUBST(PERL_MM_PARAMS)
		AC_SUBST(PERL_STATIC_LIBS)
	fi
fi

dnl ** check what we want to build
AM_CONDITIONAL(BUILD_TEXTUI, test "$want_textui" = "yes")
AM_CONDITIONAL(BUILD_IRSSIBOT, test "$want_irssibot" = "yes")
AM_CONDITIONAL(BUILD_IRSSIPROXY, test "$want_irssiproxy" = "yes")
AM_CONDITIONAL(HAVE_PERL, test "$want_perl" != "no")

# move LIBS to PROG_LIBS so they're not tried to be used when linking eg. perl libraries
PROG_LIBS=$LIBS
LIBS=
AC_SUBST(PROG_LIBS)

dnl **
dnl ** Keep all the libraries here so each frontend doesn't need to
dnl ** keep track of them all
dnl **
dnl ** (these could be made configurable)

CHAT_MODULES="irc"
irc_MODULES="dcc flood notifylist"
if test -n "$build_modules"; then
	irc_MODULES="$irc_MODULES $build_modules"
fi

dnl ****************************************

AC_SUBST(CHAT_MODULES)
AC_SUBST(irc_MODULES)

CORE_LIBS="../core/libcore.a ../lib-config/libirssi_config.a"
FE_COMMON_LIBS=""

CHAT_LIBS=""
for c in $CHAT_MODULES; do
	module_inits=""
	module_deinits=""
	fe_module_inits=""
	fe_module_deinits=""
	CHAT_LIBS="$CHAT_LIBS ../$c/lib$c.a ../$c/core/lib${c}_core.a"
	if test -f $srcdir/src/fe-common/$c/module.h; then
		FE_COMMON_LIBS="$FE_COMMON_LIBS../fe-common/$c/libfe_common_$c.a "
	fi
	for s in `eval echo \\$${c}_MODULES`; do
		CHAT_LIBS="$CHAT_LIBS ../$c/$s/lib${c}_$s.a"
		module_inits="$module_inits ${c}_${s}_init();"
		module_deinits="${c}_${s}_deinit(); $module_deinits"
		if test -f $srcdir/src/fe-common/$c/$s/module.h; then
			FE_COMMON_LIBS="$FE_COMMON_LIBS../fe-common/$c/$s/libfe_${c}_$s.a "
			fe_module_inits="$fe_module_inits fe_${c}_${s}_init();"
			fe_module_deinits="fe_${c}_${s}_deinit(); $fe_module_deinits"
		fi
	done

	mkdir -p src/$c
	file="src/$c/$c.c"
	echo "/* this file is automatically generated by configure - don't change */" > $file
	echo "void ${c}_core_init(void); void ${c}_core_deinit(void);" >> $file
	if test -n "$module_inits"; then
		echo "$module_inits" | $sedpath -e 's/()/(void)/g' -e 's/ /void /g' >> $file
		echo "$module_deinits" | $sedpath -e 's/ *$//' -e 's/()/(void)/g' -e 's/ /void /g' -e 's/^/void /' >> $file
	fi
	echo "void ${c}_init(void) { ${c}_core_init(); $module_inits }" >> $file
	echo "void ${c}_deinit(void) { $module_deinits ${c}_core_deinit(); }" >> $file

	if test -f $srcdir/src/fe-common/$c/module.h; then
		mkdir -p src/fe-common/$c
		file="src/fe-common/$c/${c}-modules.c"
		echo "/* this file is automatically generated by configure - don't change */" > $file
		if test -n "$fe_module_inits"; then
			echo "$fe_module_inits" | $sedpath -e 's/()/(void)/g' -e 's/ /void /g' >> $file
			echo "$fe_module_deinits" | $sedpath -e 's/ *$//' -e 's/()/(void)/g' -e 's/ /void /g' -e 's/^/void /' >> $file
		fi
		echo "void fe_${c}_modules_init(void) { $fe_module_inits }" >> $file
		echo "void fe_${c}_modules_deinit(void) { $fe_module_deinits }" >> $file
	fi
done

FE_COMMON_LIBS="$FE_COMMON_LIBS../fe-common/core/libfe_common_core.a"

dnl ** common libraries needed by frontends
COMMON_NOUI_LIBS="$CHAT_LIBS $CORE_LIBS"
COMMON_LIBS="$FE_COMMON_LIBS $COMMON_NOUI_LIBS"
AC_SUBST(COMMON_NOUI_LIBS)
AC_SUBST(COMMON_LIBS)

if test "x$want_truecolor" = "xyes"; then
	AC_DEFINE([TERM_TRUECOLOR], [], [true color support in terminal])
else
	want_truecolor=no
fi

AH_TEMPLATE(HAVE_GMODULE)
AH_TEMPLATE(HAVE_SOCKS_H, [misc..])
AH_TEMPLATE(HAVE_STATIC_PERL)
AH_TEMPLATE(PRIuUOFF_T, [printf()-format for uoff_t, eg. "u" or "lu" or "llu"])
AH_TEMPLATE(UOFF_T_INT, [What type should be used for uoff_t])
AH_TEMPLATE(UOFF_T_LONG)
AH_TEMPLATE(UOFF_T_LONG_LONG)

AC_CONFIG_FILES([
Makefile
src/Makefile
src/core/Makefile
src/irc/Makefile
src/irc/core/Makefile
src/irc/dcc/Makefile
src/irc/notifylist/Makefile
src/irc/proxy/Makefile
src/irc/flood/Makefile
src/fe-common/Makefile
src/fe-common/core/Makefile
src/fe-common/irc/Makefile
src/fe-common/irc/dcc/Makefile
src/fe-common/irc/notifylist/Makefile
src/fe-none/Makefile
src/fe-text/Makefile
src/lib-config/Makefile
src/perl/Makefile
src/perl/common/Makefile.PL
src/perl/irc/Makefile.PL
src/perl/ui/Makefile.PL
src/perl/textui/Makefile.PL
scripts/Makefile
scripts/examples/Makefile
docs/Makefile
docs/help/Makefile
docs/help/in/Makefile
irssi-config
])

AC_OUTPUT

dnl ** for building from objdir
old_dir=`pwd` && cd $srcdir && whole_dir=`pwd` && cd $old_dir
if test "x$old_dir" != "x$whole_dir"; then
	$LN_S $srcdir/irssi-version.h irssi-version.h
	if test "x$want_perl" != "xno"; then
		subdirfiles=""
		for i in $whole_dir/src/perl/common $whole_dir/src/perl/irc $whole_dir/src/perl/ui $whole_dir/src/perl/textui; do
			subdirfiles=`echo $subdirfiles $i/typemap $i/module.h $i/*.pm $i/*.xs`
		done
		for file in $whole_dir/src/perl/module.h $subdirfiles; do
			link=`echo $file|$sedpath "s?$whole_dir/??"`
			rm -f $link
			$LN_S $file $link
		done
	fi
fi

echo

echo "Building text frontend ........... : $want_textui"
echo "Building irssi bot ............... : $want_irssibot"
echo "Building irssi proxy ............. : $want_irssiproxy"
if test "x$have_gmodule" = "xyes"; then
	echo "Building with module support ..... : yes"
else
	echo "Building with module support : NO!! /LOAD will not work!"
	echo " - You're missing gmodule (comes with glib) for some reason,"
	echo "   or it doesn't work in your system."
fi

if test "x$want_perl" = "xstatic"; then
	echo "Building with Perl support ....... : static (in irssi binary)"
elif test "x$want_perl" = "xmodule"; then
	echo "Building with Perl support ....... : module"
else
	if test -z "$perl_check_error"; then
		echo "Building with Perl support ....... : no"
	else
		echo "Building with Perl support ....... : NO!"
		echo " - $perl_check_error"
                if test -f /etc/debian_version; then
                  echo " - Try: sudo apt-get install libperl-dev"
                elif test -f /etc/redhat-release; then
                  echo " - Try installing perl-devel"
                fi
	fi
fi

if test "x$want_perl" != "xno" -a "x$perl_mod_error" != "x"; then
	echo " - NOTE: Perl support will be compiled statically to irssi, not as"
	echo "   a module as requested. Reason:"
	echo "   $perl_mod_error"

	if test -f /etc/debian_version; then
		echo " - Try: sudo apt-get install libperl-dev"
	fi
fi

if test "x$want_perl" != "xno"; then
	echo "Perl library directory ........... : ($perl_library_dir - $perl_use_lib)"
	if test "x$perl_prefix_note" = "xyes"; then
		echo "  - NOTE: This was automatically set to the same directory you gave with"
		echo "  --prefix. If you want the perl libraries to install to their 'correct'"
		echo "  path, you'll need to give --with-perl-lib=site option to configure."
		echo "  Anyway, installing perl to this directory should work just as well."
	fi
fi
echo "Install prefix ................... : $prefix"

echo

echo "Building with 64bit DCC support .. : $offt_64bit"
echo "Building with true color support.. : $want_truecolor"

echo
echo "If there are any problems, read the INSTALL file."
