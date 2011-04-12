# $Id: Makefile 22130 2007-03-12 14:08:02Z chris $

CBUILD = ../build
include $(CBUILD)/Makefile.pre

PACKAGES += RESIP RUTIL ARES PTHREAD OPENSSL

CXXFLAGS += -I..
ifeq ($(VOCAL_COMPILE_TYPE),debug)
CXXFLAGS += -DDEBUG
endif

ifneq (${DEBUG_SPIRIT},)
CXXFLAGS += -DBOOST_SPIRIT_DEBUG=1
endif

CXXFLAGS += -DMSRP_REENTRANT

TARGET_LIBRARY = libmsrp

SRC = \
	AuthTuple.cxx \
	Buffer.cxx \
	ByteRange.cxx \
	ConnectionPool.cxx \
	Connection.cxx \
	Demultiplex.cxx \
	Exception.cxx \
	Header.cxx \
	IncomingMessage.cxx \
	MessageBuffer.cxx \
	MessagePool.cxx \
	Message.cxx \
	MessageSessionBase.cxx \
	Mime.cxx \
	OutgoingMessage.cxx \
	ParserFactory.cxx \
	Scheduler.cxx \
	Session.cxx \
	SessionFactory.cxx \
	Status.cxx \
	StreamContext.cxx \
	TargetSelector.cxx \
	Uri.cxx

CXXFLAGS += -I/usr/local/include

LDLIBS_LAST += -L/usr/local/lib -lboost_signals-gcc-mt-d -lboost_thread-gcc-mt-d

include $(CBUILD)/Makefile.post

INSTALL_INCDIR := $(INSTALL_PREFIX)/include/msrp
