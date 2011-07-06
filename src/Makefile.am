ACLOCAL_AMFLAGS = -I m4 --install

#Public header
include_HEADERS = cas.h
#The primary library, libcas
lib_LTLIBRARIES = libcas.la
libcas_la_SOURCES = cas.c cas.h cas-int.h cas1.c cas2.c


libcas_la_CPPFLAGS=${XML_CPPFLAGS} ${LIBCURL_CPPFLAGS}
libcas_la_LIBADD=${XML_LIBS} ${LIBCURL}

bin_PROGRAMS=cascli loop


cascli_SOURCES = main.c
cascli_LDADD=libcas.la

loop_sources = loop.c
loop_LDADD=libcas.la
