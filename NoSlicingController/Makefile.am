AM_CXXFLAGS = -std=c++11 -Wall -lstdc++ -lboost_system

AM_CPPFLAGS = \
-I../../PI/include \
-I../../PI/proto/frontend \
-I../../PI/proto/server \
-I../../PI/proto/cpp_out \
-I../../PI/grpc_out \
-I../../PI/p4info

noinst_PROGRAMS = controller

controller_SOURCES = \
routerController.cpp \
routerController.h \
controllerMain.cpp

COMMON_SERVER_LIBS = \
../../PI/proto/server/libpigrpcserver.la \
../../PI/proto/frontend/libpifeproto.la \
../../PI/proto/libpiprotogrpc.la \
../../PI/proto/libpiprotobuf.la \
../../PI/src/libpiall.la

controller_LDADD = \
../../PI/src/libpip4info.la \
../..//PI/proto/libpiprotogrpc.la \
../../PI/src/libpip4info.la \
../../PI/proto/libpiprotobuf.la \
../../PI/proto/p4info/libpiconvertproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
