AC_INIT([dnslicing], [1.0], [])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_PROG_CXX([gcc])
LT_INIT
PKG_CHECK_MODULES([PROTOBUF], [protobuf >= 3.0.0])
dnl Not necessary for recent autoconf versions but I think it makes things more
dnl readable
AC_SUBST([PROTOBUF_CFLAGS])
AC_SUBST([PROTOBUF_LIBS])

dnl we need >= 1.3.0 so that binary error details (libgrpc++_error_details) are
dnl available
PKG_CHECK_MODULES([GRPC], [grpc++ >= 1.3.0 grpc >= 3.0.0])
AC_SUBST([GRPC_CFLAGS])
AC_SUBST([GRPC_LIBS])
AC_CONFIG_FILES([
 Makefile
 NoSlicingController/Makefile
])
AC_OUTPUT
