ACLOCAL_AMFLAGS = -I m4 --install

lib_LTLIBRARIES = libcas.la
libcas_la_SOURCES = cas.c cas.h cas-int.h cas1.c cas2.c
include_HEADERS = cas.h
cascli_SOURCES = main.c
bin_PROGRAMS=cascli


libcas_la_CPPFLAGS=${XML_CPPFLAGS} ${LIBCURL_CPPFLAGS}
libcas_la_LIBADD=${XML_LIBS} ${LIBCURL}

cascli_LDADD=libcas.la
