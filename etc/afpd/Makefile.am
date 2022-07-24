# Makefile.am for etc/afpd/

pkgconfdir = @PKGCONFDIR@

sbin_PROGRAMS = afpd
noinst_PROGRAMS = hash

afpd_SOURCES = \
	afp_asp.c \
	afp_config.c \
	afp_options.c \
	afp_util.c \
	appl.c \
	auth.c \
	catsearch.c \
	desktop.c \
	dircache.c \
	directory.c \
	enumerate.c \
	file.c \
	filedir.c \
	fork.c \
	gettok.c \
	hash.c \
	main.c \
	mangle.c \
	messages.c  \
	ofork.c \
	status.c \
	switch.c \
	uam.c \
	unix.c \
	volume.c

afpd_LDADD =  \
	$(top_builddir)/libatalk/cnid/libcnid.la \
	$(top_builddir)/libatalk/libatalk.la \
	@LIBADD_DL@ @PTHREAD_LIBS@

afpd_LDFLAGS = -export-dynamic 

afpd_CFLAGS = \
	-Wno-use-after-free \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/sys \
	-DAPPLCNAME \
	-DSERVERTEXT=\"$(SERVERTEXT)/\" \
	-D_PATH_AFPDDEFVOL=\"$(pkgconfdir)/AppleVolumes.default\" \
	-D_PATH_AFPDSYSVOL=\"$(pkgconfdir)/AppleVolumes.system\" \
	-D_PATH_AFPDPWFILE=\"$(pkgconfdir)/afppasswd\" \
	-D_PATH_AFPDCONF=\"$(pkgconfdir)/afpd.conf\" \
	-D_PATH_AFPDSIGCONF=\"$(pkgconfdir)/afp_signature.conf\" \
	-D_PATH_AFPDUAMPATH=\"$(UAMS_PATH)/\" \
	-D_PATH_ACL_LDAPCONF=\"$(pkgconfdir)/afp_ldap.conf\" \
	-D_PATH_AFPDUUIDCONF=\"$(pkgconfdir)/afp_voluuid.conf\"

noinst_HEADERS = auth.h afp_config.h desktop.h directory.h file.h \
	 filedir.h fork.h icon.h mangle.h misc.h status.h switch.h \
	 uam_auth.h unix.h volume.h hash.h dircache.h

hash_SOURCES = hash.c
hash_CFLAGS = -DKAZLIB_TEST_MAIN -I$(top_srcdir)/include
