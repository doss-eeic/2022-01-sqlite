CXX := g++
LIBSRCS := src/aes.cpp src/rsa.cpp src/hybrid.cpp
LIBOBJS := $(patsubst src/%.cpp, build/%.o, $(LIBSRCS))
HDR := src/cipher.hpp
TEST := aes_test rsa_test hybrid_test
LIBS := -lcrypto
CFLAGS := -O0 -g

lib/libcipher.so: $(LIBOBJS)
	$(CXX) $(LIBOBJS) $(LIBS) -fPIC -shared -o $@

# $(LIBOBJS): build/%.o : src/%.cpp $(HDR) build
# 	$(CXX) $< -c -fPIC -o $@

build/aes.o: src/aes.cpp $(HDR)
	$(CXX) $< $(CFLAGS) -c -fPIC -o $@

build/rsa.o: src/rsa.cpp $(HDR)
	$(CXX) $< $(CFLAGS) -c -fPIC -o $@

build/hybrid.o: src/hybrid.cpp $(HDR)
	$(CXX) $< $(CFLAGS) -c -fPIC -o $@
# $(TEST): %: src/test/%.cpp $(HDR) lib/libcipher.so
# 	$(CXX) $< -Isrc $(LIBS) -Llib -lcipher -o $@

aes_test: src/test/aes_test.cpp $(HDR) lib/libcipher.so
	$(CXX) $< $(CFLAGS) -Isrc $(LIBS) -Llib -lcipher -o $@

rsa_test: src/test/rsa_test.cpp $(HDR) lib/libcipher.so
	$(CXX) $< $(CFLAGS) -Isrc $(LIBS) -Llib -lcipher -o $@

hybrid_test: src/test/hybrid_test.cpp $(HDR) lib/libcipher.so
	$(CXX) $< $(CFLAGS) -Isrc $(LIBS) -Llib -lcipher -o $@

all_test: $(TEST)

clean:
	rm -f $(TEST)
	rm -f lib/*
	rm -f build/*
