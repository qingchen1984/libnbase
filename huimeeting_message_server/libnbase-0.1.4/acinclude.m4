AC_DEFUN([AC_CHECK_EXTRA_OPTIONS],[
        AC_MSG_CHECKING(for debugging)
        AC_ARG_ENABLE(debug, [  --enable-debug		compile for debugging])
        if test -z "$enable_debug" ; then
                enable_debug="no"
        elif test $enable_debug = "yes" ; then
                CPPFLAGS="${CPPFLAGS} -g -D_DEBUG"
        fi
        AC_MSG_RESULT([$enable_debug])
	AC_MSG_CHECKING(for supporting mmap)
        AC_ARG_ENABLE(mmap, [  --enable-mmap	compile for supporting mmap])
        if test -z "$enable_mmap" ; then
                enable_mmap="no"
        elif test $enable_mmap = "yes" ; then
                CPPFLAGS="${CPPFLAGS}  -D_USE_MMAP"
        fi
        AC_MSG_RESULT([$enable_mmap])
])

