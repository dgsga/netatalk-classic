# Makefile.am for bin/psorder

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/sys -Wno-use-after-free

bin_PROGRAMS = psorder

psorder_SOURCES = psorder.c pa.c
psorder_LDADD = $(top_builddir)/libatalk/libatalk.la

noinst_HEADERS = psorder.h pa.h
