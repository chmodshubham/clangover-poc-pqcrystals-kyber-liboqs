CURRENT_DIR := $(shell pwd)

attack: .ref_built
	clang -O3 -o clangover attack.c kyber/ref/randombytes.c -Lkyber/ref/lib \
	-l:libpqcrystals_kyber512_ref.so -l:libpqcrystals_fips202_ref.so \
	-Ikyber/ref/ -Wl,-rpath,$(CURRENT_DIR)/kyber/ref/lib -DKYBER_K=2 -Wall

.ref_built:
	sed -i 's/-O3/-Os/g' kyber/ref/Makefile && \
	CC=clang make -C kyber/ref shared && \
	touch .ref_built

ui: .ref_built
	clang -O3 -DJSON_LOG -o clangover-ui attack.c kyber/ref/randombytes.c -Lkyber/ref/lib \
	-l:libpqcrystals_kyber512_ref.so -l:libpqcrystals_fips202_ref.so \
	-Ikyber/ref/ -Wl,-rpath,$(CURRENT_DIR)/kyber/ref/lib -DKYBER_K=2 -Wall

run:
	./clangover

clean:
	-$(RM) -f clangover clangover-ui attack_log.jsonl .ref_built
	@make -C kyber/ref clean
