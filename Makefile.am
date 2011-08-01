ACLOCAL_AMFLAGS = -I m4 --install
SUBDIRS = src . tests

EXTRA_DIST=$(shell ls $(srcdir)/examples/* ) Doxyfile.in

if DOXYGEN
html-local:	
	doxygen Doxyfile
endif
	
distclean-local:
	rm -rf autom4te.cache Doxyfile
	
clean-local:
	rm -rf docs
	
autoclean: distclean
	rm -f configure aclocal.m4 config.h.in config.sub depcomp install-sh missing config.guess Makefile.in src/Makefile.in ltmain.sh ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.gz
	
	if [ -d "${PACKAGE_NAME}-${PACKAGE_VERSION}" ]; then \
		chmod -R +w ${PACKAGE_NAME}-${PACKAGE_VERSION}; \
		rm -rf ${PACKAGE_NAME}-${PACKAGE_VERSION}; \
	fi
	
