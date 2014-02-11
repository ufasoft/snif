dnl configure.ac -- Process this file with autoconf to produce configure

AC_PREREQ([2.67])

AC_INIT(ufasoft_sniffer, 4.170, support@ufasoft.com,, http://ufasoft.com/sniffer)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([subdir-objects dist-xz])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([msgan/icqdump.cpp])
AC_CONFIG_HEADER([config.h])

AC_PROG_CXX
AM_PROG_CC_C_O
AC_LANG([C++])

AC_PATH_PROG([COMPILER], [$CXX])
if ! test -x "${COMPILER}"; then
	AC_MSG_ERROR([No C++ compiler found. Please install a C++ compiler.])
fi


case "$CC" in
*clang*)
    CLANG=yes
    ;;
*)
    CLANG=no
    ;;
esac

if test "x$GCC" = xyes -a "x$CLANG" = xno; then
AC_MSG_CHECKING([for gcc 4.4])
AC_RUN_IFELSE([AC_LANG_PROGRAM([],[
        if( ! ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 4 ) ) ) return 1;])],
    [AC_MSG_RESULT(yes)],
	[AC_MSG_ERROR([requires gcc 4.4 or later])
]) # end AC_RUN_IFELSE
fi

AX_CHECK_COMPILE_FLAG([-std=c++1y], [CXXFLAGS="$CXXFLAGS -std=c++1y"], [CXXFLAGS="$CXXFLAGS -std=c++0x"])

AC_CHECK_FUNCS([pthread_setname_np])


case "${host_os}" in
freebsd*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include -I/usr/local/include/libxml2"
	LDFLAGS="$LDFLAGS -L/usr/local/lib"
	;;
esac

AC_CHECK_LIB([pcap], 	[pcap_open_live],		, [AC_MSG_ERROR([Library not found, install pcap-dev])				])
AC_CHECK_LIB([xml2], 	[xmlTextReaderDepth],	, [AC_MSG_ERROR([Library not found, install libxml2-dev])			])
AC_CHECK_LIB([z], 		[deflate],				, [AC_MSG_ERROR([Library not found, install libz-dev])				])
AC_CHECK_LIB([pcre], 	[pcre_compile],			, [AC_MSG_ERROR([Library not found, install libpcre-dev])			])
AC_CHECK_LIB([pthread], [pthread_create],		, [AC_MSG_ERROR([Library not found])								])
AC_CHECK_LIB([curl], 	[curl_global_init],		, [AC_MSG_ERROR([Library libcurl not found, install libcurl-dev])	])
AC_CHECK_LIB([rt], 		[clock_gettime],		, [AC_MSG_ERROR([Library not found])								])
AC_SEARCH_LIBS([dlopen], [dl dld], []			, [AC_MSG_ERROR([unable to find the dlopen() function])				])
AC_SEARCH_LIBS([iconv],  [iconv], []			, [AC_MSG_ERROR([unable to find the iconv() function])				])
AC_CHECK_LIB([sqlite3], [sqlite3_open16],		, [AC_MSG_WARN([SQLite not found. Install sqlite3-dev package for saving messages to database])])

PKG_PROG_PKG_CONFIG()

PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.21], ,[AC_MSG_ERROR([Missing required libcurl-devel >= 7.21])])
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(LIBCURL_LIBS)


AC_MSG_CHECKING([if compiling with clang])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[
#ifndef __clang__
       not clang
#endif
]])], [CLANGCC="yes"], [CLANGCC="no"])
AC_MSG_RESULT([$CLANGCC])

AM_CONDITIONAL(CLANG, test "$CLANGCC" = "yes" )

AC_OUTPUT(Makefile)

echo
echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo


echo
echo "Compilation............: make (gmake on FreeBSD)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS $LIBCURL_CFLAGS $JANSSON_CFLAGS"
echo "  CXXFLAGS.............. $CXXFLAGS"
echo "  LDFLAGS..............: $LDFLAGS $PTHREAD_FLAGS $USB_FLAGS"
echo "  LDADD................: $LIBCURL_LIBS$JANSSON_LIBS$OPENCL_LIBS$NCURSES_LIBS$PDCURSES_LIBS$UDEV_LIBS$USB_LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo
