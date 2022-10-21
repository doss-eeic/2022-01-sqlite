ifndef builddir
$(error builddir must be defined by the build-directory Makefile)
endif
ifndef libdir
libdir = $(builddir)/lib
endif
ifndef bindir
bindir = $(builddir)/bin
endif
ifndef libtool
$(error libtool must be defined by the build-directory Makefile)
endif
ifndef CC
CC = gcc
endif
ifndef CXX
CXX = g++
endif

INSTALL = install
CXXFLAGS = -Iinclude $(CFLAGS)
LIBSRC := src/aes.cpp src/rsa.cpp src/hybrid.cpp src/cryption_api.cpp
BUILDDIR := $(builddir)
LIBTOOL := $(libtool)
LIBOBJ := $(patsubst src/%.cpp, $(BUILDDIR)/%.lo, $(LIBSRC))
LIBS := -lcrypto $(LIBS)
HDR := include/cryption.hpp
TESTSRC := src/test/aes_test.cpp src/test/rsa_test.cpp src/test/hybrid_test.cpp src/test/api_test.c
TESTPROGS := $(BUILDDIR)/aes_test $(BUILDDIR)/rsa_test $(BUILDDIR)/hybrid_test $(BUILDDIR)/api_test

$(BUILDDIR)/libcryption.la: $(LIBOBJ)
	$(LIBTOOL) --mode=link $(CXX) $(LIBOBJ) $(LIBS) -rpath "$(libdir)" -o $@

$(BUILDDIR)/aes.lo: src/aes.cpp $(HDR)
	$(LIBTOOL) --mode=compile $(CXX) $< $(CXXFLAGS) -c -o $@

$(BUILDDIR)/rsa.lo: src/rsa.cpp $(HDR)
	$(LIBTOOL) --mode=compile $(CXX) $< $(CXXFLAGS) -c -o $@

$(BUILDDIR)/hybrid.lo: src/hybrid.cpp $(HDR)
	$(LIBTOOL) --mode=compile $(CXX) $< $(CXXFLAGS) -c -o $@

$(BUILDDIR)/cryption_api.lo: src/cryption_api.cpp $(HDR)
	$(LIBTOOL) --mode=compile $(CXX) $< $(CXXFLAGS) -c -o $@

$(BUILDDIR)/aes_test: src/test/aes_test.cpp $(HDR) $(BUILDDIR)/libcryption.la
	$(LIBTOOL) --mode=link $(CXX) $< $(CXXFLAGS) $(LIBS) $(BUILDDIR)/libcryption.la -o $@

$(BUILDDIR)/rsa_test: src/test/rsa_test.cpp $(HDR) $(BUILDDIR)/libcryption.la
	$(LIBTOOL) --mode=link $(CXX) $< $(CXXFLAGS) $(LIBS) $(BUILDDIR)/libcryption.la -o $@

$(BUILDDIR)/hybrid_test: src/test/hybrid_test.cpp $(HDR) $(BUILDDIR)/libcryption.la
	$(LIBTOOL) --mode=link $(CXX) $< $(CXXFLAGS) $(LIBS) $(BUILDDIR)/libcryption.la -o $@

$(BUILDDIR)/api_test: src/test/api_test.c $(HDR) $(BUILDDIR)/libcryption.la
	$(LIBTOOL) --mode=link --tag=CC $(CC) $< $(CXXFLAGS) $(LIBS) $(BUILDDIR)/libcryption.la -o $@

.PHONY: all_test install clean

all_test: $(TESTPROGS)
	$(INSTALL) -d $(bindir)
	$(LIBTOOL) --mode=install $(INSTALL) $(TESTPROGS) $(bindir)

install: $(BUILDDIR)/libcryption.la
	$(INSTALL) -d $(libdir)
	$(LIBTOOL) --mode=install $(INSTALL) $(BUILDDIR)/libcryption.la $(libdir)

clean:
	rm -f $(TESTPROGS)
	rm -f $(BUILDDIR)/libcryption.la
	rm -f $(LIBOBJ)
