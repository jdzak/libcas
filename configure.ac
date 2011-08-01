#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([libcas],[1.0.0],[matt@forsetti.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign color-tests])
AC_SUBST([PACKAGE_DESCRIPTION],["Library implementing the cas1 and cas2 protocols, and a command-line binary to validate tickets"])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	tests/Makefile
	Doxyfile
])

AC_CONFIG_SRCDIR([src/cas.c])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Checks for libraries.
LIBCURL_CHECK_CONFIG([yes],7.21.0,[],[AC_MSG_ERROR([libcurl not found])])
AM_PATH_XML2(2.7.8,[AC_DEFINE([HAVE_LIBXML2], [1], [Define to 1 if you have a functional libxml2 library.])],[AC_MSG_ERROR([libxml2 not found])])

#PKG_CHECK_MODULES([CHECK], [check >= 0.9.4],,[AC_MSG_WARN([libcheck not found -- check unit tests will not be run])])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Check for doxygen
AC_PATH_PROG([DOXYGEN],["doxygen"])
AM_CONDITIONAL([DOXYGEN],[ test "x$DOXYGEN" != "x" ])

AC_OUTPUT
