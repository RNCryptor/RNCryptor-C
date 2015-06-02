#!/bin/sh
#
# muquit@muquit.com May-24-2015 
VALGRIND_LOG=/tmp/vg.log
/bin/rm -f VALGRIND_LOG
VALGRIND="valgrind -v --track-origins=yes --tool=memcheck --leak-check=yes --error-limit=yes --log-file=$VALGRIND_LOG"
$VALGRIND ${1+"$@"}
