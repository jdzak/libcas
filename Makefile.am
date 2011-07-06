ACLOCAL_AMFLAGS = -I m4 --install
SUBDIRS = src . tests
#check_SCRIPTS=$(srcdir)/tests/test000-cas1-no.sh $(srcdir)/tests/test001-cas1-myprinc.sh $(srcdir)/tests/test002-cas1-garbage.sh $(srcdir)/tests/test003-cas2-no.sh $(srcdir)/tests/test004-cas2-myprinc.sh $(srcdir)/tests/test005-cas2-garbage.sh
#check_SCRIPTS=$(shell find $(srcdir)/tests/ -type f | sort )
#TESTS=${check_SCRIPTS}
#EXTRA_DIST=${TESTS}

distclean-local:
	rm -rf autom4te.cache
	
autoclean: distclean
	rm -f configure aclocal.m4 config.h.in config.sub depcomp install-sh missing config.guess Makefile.in src/Makefile.in ltmain.sh ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.gz
	
	if [ -d "${PACKAGE_NAME}-${PACKAGE_VERSION}" ]; then \
		chmod -R +w ${PACKAGE_NAME}-${PACKAGE_VERSION}; \
		rm -rf ${PACKAGE_NAME}-${PACKAGE_VERSION}; \
	fi
	
