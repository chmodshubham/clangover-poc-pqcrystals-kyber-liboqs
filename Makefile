CURRENT_DIR := $(shell pwd)
LIBOQS_SRC := liboqs/src/kem/kyber/pqcrystals-kyber_kyber512_ref
LIBOQS_SHIMS := liboqs/src/common/pqclean_shims
LIBOQS_INC := liboqs/build/include
LIBOQS_LIB_DIR := liboqs/build/lib

# --- PQ-Crystals Kyber (b628ba7) ---

attack-pqcrystal-kyber: .ref_built
	clang -O3 -o clangover-pqcrystal-kyber attack.c kyber/ref/randombytes.c -Lkyber/ref/lib \
	-l:libpqcrystals_kyber512_ref.so -l:libpqcrystals_fips202_ref.so \
	-Ikyber/ref/ -Wl,-rpath,$(CURRENT_DIR)/kyber/ref/lib -DKYBER_K=2 -Wall
	clang -O3 -DJSON_LOG -o clangover-pqcrystal-kyber-ui attack.c kyber/ref/randombytes.c -Lkyber/ref/lib \
	-l:libpqcrystals_kyber512_ref.so -l:libpqcrystals_fips202_ref.so \
	-Ikyber/ref/ -Wl,-rpath,$(CURRENT_DIR)/kyber/ref/lib -DKYBER_K=2 -Wall

.ref_built:
	@grep -q '\-Os' kyber/ref/Makefile || sed -i 's/-O3/-Os/g' kyber/ref/Makefile
	CC=clang make -C kyber/ref shared
	@touch .ref_built

# --- LibOQS v0.10.0 ---

LIBOQS_KYBER_SRCS := $(wildcard $(LIBOQS_SRC)/*.c)

attack-liboqs: .liboqs_built
	clang -O3 -o clangover-liboqs attack.c \
	-I$(LIBOQS_SRC) -I$(LIBOQS_SHIMS) -I$(LIBOQS_INC) \
	-L$(LIBOQS_LIB_DIR) -l:libkyber512_liboqs.so \
	-Wl,-rpath,$(CURRENT_DIR)/$(LIBOQS_LIB_DIR) -DKYBER_K=2 -Wall -lm
	clang -O3 -DJSON_LOG -o clangover-liboqs-ui attack.c \
	-I$(LIBOQS_SRC) -I$(LIBOQS_SHIMS) -I$(LIBOQS_INC) \
	-L$(LIBOQS_LIB_DIR) -l:libkyber512_liboqs.so \
	-Wl,-rpath,$(CURRENT_DIR)/$(LIBOQS_LIB_DIR) -DKYBER_K=2 -Wall -lm

.liboqs_built:
	@mkdir -p liboqs/build
	@cd liboqs/build && \
	[ -f build.ninja ] || CC=clang cmake -GNinja \
		-DBUILD_SHARED_LIBS=OFF \
		-DOQS_BUILD_ONLY_LIB=ON \
		-DOQS_MINIMAL_BUILD="KEM_kyber_512" \
		-DOQS_USE_OPENSSL=OFF \
		-DOQS_DIST_BUILD=ON \
		-DOQS_ENABLE_KEM_kyber_512_avx2=OFF \
		..
	@cd liboqs/build && ninja
	@# Disable AVX2 SHA3 dispatch to keep timing measurements stable
	@sed -i 's/^#define OQS_ENABLE_SHA3_xkcp_low_avx2 1/\/\/ disabled: OQS_ENABLE_SHA3_xkcp_low_avx2/' \
		liboqs/build/include/oqs/oqsconfig.h
	clang -c -fPIC -Os \
		-I$(LIBOQS_INC) -Iliboqs/src/common -Iliboqs/src/common/sha3/xkcp_low \
		liboqs/src/common/sha3/xkcp_sha3.c -o liboqs/build/xkcp_sha3_noavx2.o
	@# Compile Kyber sources as a single translation unit with -Os to reproduce the vulnerable branch
	clang -shared -fPIC -Os -DKYBER_K=2 \
		-I$(LIBOQS_SRC) -I$(LIBOQS_SHIMS) -I$(LIBOQS_INC) \
		$(LIBOQS_KYBER_SRCS) \
		liboqs/build/xkcp_sha3_noavx2.o \
		liboqs/build/src/common/CMakeFiles/common.dir/rand/rand.c.o \
		liboqs/build/src/common/CMakeFiles/common.dir/pqclean_shims/fips202.c.o \
		liboqs/build/src/common/CMakeFiles/common.dir/common.c.o \
		liboqs/build/src/common/sha3/xkcp_low/CMakeFiles/xkcp_low_keccakp_1600_plain64.dir/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c.o \
		-o $(LIBOQS_LIB_DIR)/libkyber512_liboqs.so
	@touch .liboqs_built

# --- common ---

clean:
	-$(RM) -f clangover-pqcrystal-kyber clangover-pqcrystal-kyber-ui clangover-liboqs clangover-liboqs-ui \
		attack_log.jsonl .ref_built .liboqs_built
	@make -C kyber/ref clean 2>/dev/null || true
	@rm -rf liboqs/build 2>/dev/null || true