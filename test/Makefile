# $Id: Makefile 22130 2007-03-12 14:08:02Z chris $

CBUILD = ../../build
include $(CBUILD)/Makefile.pre

PACKAGES += MSRP RESIP RUTIL ARES PTHREAD OPENSSL

TESTPROGRAMS = \
	testUri.cxx \
	testSessionFactory.cxx \
	testMessage.cxx \
	testMessageBuffer.cxx
#	testDns.cxx \
#	testMessagePool.cxx \

LDLIBS_LAST += -L/usr/local/lib \
	-lboost_date_time-gcc-mt-d \
	-lboost_signals-gcc-mt-d \
	-lboost_thread-gcc-mt-d \
	-lboost_filesystem-gcc-mt-d \
	-lssl \
	-lcrypto

ifeq (${VOCAL_COMPILE_TYPE},debug)
CXXFLAGS += -DDEBUG
endif

ifneq (${DEBUG_SPIRIT},)
CXXFLAGS += -DBOOST_SPIRIT_DEBUG=1
endif

CXXFLAGS += -DMSRP_REENTRANT

include $(CBUILD)/Makefile.post
