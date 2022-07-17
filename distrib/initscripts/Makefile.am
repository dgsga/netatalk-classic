## Makefile for distrib/initscripts/

SUFFIXES = .tmpl .

pkgconfdir = @PKGCONFDIR@

#
# Template Generation
#

.tmpl:
	sed -e s@:BINDIR:@${bindir}@ \
	    -e s@:SBINDIR:@${sbindir}@ \
	    -e s@:ETCDIR:@${pkgconfdir}@ \
	    -e s@:PKGLIBEXECDIR:@${pkglibexecdir}@ \
	    -e s@:VERSION:@${VERSION}@ \
	    <$< >$@

GENERATED_FILES = \
	rc.a2boot.netbsd	\
	rc.afpd.netbsd		\
	rc.atalkd.netbsd	\
	rc.cnid_metad.netbsd	\
	rc.papd.netbsd		\
	rc.timelord.netbsd	\
	a2boot.service		\
	afpd.service		\
	atalkd.service		\
	cnid.service		\
	papd.service		\
	timelord.service

TEMPLATES = \
	rc.a2boot.netbsd.tmpl		\
	rc.afpd.netbsd.tmpl		\
	rc.atalkd.netbsd.tmpl		\
	rc.cnid_metad.netbsd.tmpl	\
	rc.papd.netbsd.tmpl		\
	rc.timelord.netbsd.tmpl		\
	a2boot.service.tmpl		\
	afpd.service.tmpl		\
	atalkd.service.tmpl		\
	cnid.service.tmpl		\
	papd.service.tmpl		\
	timelord.service.tmpl

CLEANFILES = $(GENERATED_FILES) $(sysv_SCRIPTS) $(service_DATA) afpd atalkd cnid_metad papd timelord
EXTRA_DIST = $(TEMPLATES)

# overwrite automake uninstall
# not beautiful, but this way we can call the OS specific init script
# tools, like chkconfig, insserv or rc-update

uninstall: uninstall-startup

#
# checking for general systemd scripts:
#

if USE_SYSTEMD

servicedir	= /lib/systemd/system

service_DATA	= a2boot.service afpd.service atalkd.service cnid.service papd.service timelord.service

install-data-hook:
	-systemctl daemon-reload
if SYSTEMD_START
	-systemctl enable $(service_DATA)
	-systemctl start $(service_DATA)
endif

uninstall-startup:
	-systemctl disable $(service_DATA)
	rm -f $(addprefix $(DESTDIR)$(servicedir)/, $(service_DATA))
	-systemctl daemon-reload

endif

#
# checking for NetBSD init scripts
#

if USE_NETBSD

sysvdir = /etc/rc.d
sysv_SCRIPTS = a2boot afpd atalkd cnid_metad papd timelord

afpd: rc.afpd.netbsd
	cp -f $? $@
	chmod a+x $@

atalkd: rc.atalkd.netbsd
	cp -f $? $@
	chmod a+x $@

cnid_metad: rc.cnid_metad.netbsd
	cp -f $? $@
	chmod a+x $@

papd: rc.papd.netbsd
	cp -f $? $@
	chmod a+x $@

timelord: rc.timelord.netbsd
	cp -f $? $@
	chmod a+x $@

a2boot: rc.a2boot.netbsd
	cp -f $? $@
	chmod a+x $@

install-data-hook:

uninstall-hook:

uninstall-startup: uninstall-am

endif

#
# defaults, no init scripts installed
#

if USE_UNDEF

install-data-hook:

uninstall-hook:

uninstall-startup: uninstall-am

endif

