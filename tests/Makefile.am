AM_CFLAGS = -I$(top_srcdir)/src/
TESTS = check_helper

check_PROGRAMS = check_helper

check_helper_SOURCES = check_helper.c
check_helper_CFLAGS = @CHECK_CFLAGS@ -DRUNNING_CHECK
check_helper_LDADD = @CHECK_LIBS@
