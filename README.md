# Clangover — ML-KEM 512 Timing Side-Channel Attack

Proof-of-concept key recovery attack exploiting a secret-dependent branch emitted by Clang (v15–18) when compiling the [PQCrystals Kyber](https://github.com/pq-crystals/kyber) reference implementation with `-Os`. Uses end-to-end decapsulation timing via `rdtscp` to leak the full secret key in ~5–10 minutes.

## Prerequisites

- **x86-64 Linux** (bare-metal or VM with `rdtscp` support)
- **Clang 15–18**
- **GNU Make**
- **Python 3** with Flask (`pip install flask`)

## Quick Start

### Build Kyber shared library

```
git submodule init && git submodule update
sed -i 's/-O3/-Os/g' kyber/ref/Makefile
CC=clang make -C kyber/ref shared
```

### CLI attack

```
make
./clangover
```

### Web dashboard

```
make ui
cd ui && python3 server.py
```

Open `http://localhost:5000` in your browser.

## Troubleshooting

- Ensure you're using `clang` (not `gcc`) version 15+
- Tweak `CONFIDENCE_HIGH` and `OUTLIER_THRESHOLD` in `attack.c` for your hardware
- Disable CPU frequency scaling for more stable timing measurements
