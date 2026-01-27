# Building Irssi with Nix

This project includes a Nix flake for reproducible builds and development environments.

## Prerequisites

- [Nix](https://nixos.org/download.html) with flakes enabled

To enable flakes, add to `~/.config/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

## Quick Start

```bash
# Build irssi
nix build

# Run irssi
./result/bin/irssi

# Enter development shell
nix develop
```

## Available Packages

| Package | Description |
|---------|-------------|
| `irssi` (default) | Full build with Perl scripting and proxy support |
| `irssi-minimal` | Build without Perl scripting support |
| `fuzz` | Fuzz targets with AddressSanitizer + UndefinedBehaviorSanitizer |
| `fuzz-asan` | Fuzz targets with AddressSanitizer only |
| `fuzz-ubsan` | Fuzz targets with UndefinedBehaviorSanitizer only |

### Building Packages

```bash
# Build default (full irssi)
nix build

# Build minimal variant
nix build .#irssi-minimal

# Build fuzzers (recommended: ASan + UBSan)
nix build .#fuzz

# Build fuzzers with only ASan (faster)
nix build .#fuzz-asan
```

## Development Shells

| Shell | Description |
|-------|-------------|
| `default` | Standard development with gcc, gdb, valgrind |
| `fuzz` | Fuzzing development with clang + libFuzzer |

### Using Development Shells

```bash
# Standard development
nix develop
meson setup Build
ninja -C Build
ninja -C Build test

# Fuzzing development
nix develop .#fuzz
meson setup Build-fuzz -Dwith-perl=no -Dwithout-textui=yes -Dwith-fuzzer=yes
ninja -C Build-fuzz
```

## Fuzzing

The project includes five fuzz targets built with [libFuzzer](https://llvm.org/docs/LibFuzzer.html):

| Fuzzer | Tests |
|--------|-------|
| `irssi-fuzz` | Text formatting (`printtext_string()`) |
| `server-fuzz` | IRC protocol message parsing |
| `dcc-fuzz` | DCC protocol message parsing (SEND, CHAT, RESUME, ACCEPT) |
| `event-get-params-fuzz` | IRC event parameter parsing |
| `theme-load-fuzz` | Theme file loading |

### Building Fuzzers

```bash
# Build with ASan + UBSan (recommended for finding bugs)
nix build .#fuzz

# Build with ASan only (faster execution)
nix build .#fuzz-asan
```

### Running Fuzzers

```bash
# Basic fuzzing (creates corpus automatically)
./result/bin/irssi-fuzz corpus/irssi-fuzz/

# With dictionary (recommended for server-fuzz and dcc-fuzz)
./result/bin/server-fuzz -dict=src/fe-fuzz/tokens.txt corpus/server-fuzz/
./result/bin/dcc-fuzz -dict=src/fe-fuzz/dcc-tokens.txt corpus/dcc-fuzz/

# Limit number of runs
./result/bin/irssi-fuzz -runs=10000 corpus/irssi-fuzz/

# Parallel fuzzing (use multiple cores)
./result/bin/server-fuzz -fork=4 -dict=src/fe-fuzz/tokens.txt corpus/server-fuzz/

# Ignore memory leaks to focus on crashes
./result/bin/server-fuzz -detect_leaks=0 corpus/server-fuzz/
```

### Seed Corpus

Initial seed inputs are provided in `fuzz-corpora/`:

```bash
# Copy seeds to corpus directories
mkdir -p corpus/irssi-fuzz corpus/server-fuzz corpus/dcc-fuzz corpus/event-get-params-fuzz corpus/theme-load-fuzz
cp fuzz-corpora/irssi-fuzz/* corpus/irssi-fuzz/
cp fuzz-corpora/server-fuzz/* corpus/server-fuzz/
cp fuzz-corpora/dcc-fuzz/* corpus/dcc-fuzz/
cp fuzz-corpora/event-get-params-fuzz/* corpus/event-get-params-fuzz/
cp fuzz-corpora/theme-load-fuzz/* corpus/theme-load-fuzz/
```

### Reproducing Crashes

When a fuzzer finds a crash, it saves the input to a file:

```bash
# Reproduce a crash
./result/bin/server-fuzz crash-<hash>

# Get more details with symbolized stack trace
ASAN_OPTIONS=symbolize=1 ./result/bin/server-fuzz crash-<hash>
```

### Fuzzer Input Formats

- **irssi-fuzz**: Arbitrary text, may contain irssi format codes (`%B`, `%U`, etc.)
- **server-fuzz**: Byte 0 selects prefix mode, remaining bytes are `\r\n`-separated IRC messages
- **dcc-fuzz**: Byte 0 selects DCC type (0=SEND, 1=CHAT, 2=RESUME, 3=ACCEPT, 4=GET cmd, 5=CLOSE cmd, 6=raw), remaining bytes are DCC message content
- **event-get-params-fuzz**: Byte 0 selects parsing mode (0-7), remaining bytes are parameters
- **theme-load-fuzz**: irssi theme file format

## Continuous Integration

To check that everything builds:

```bash
nix flake check
```

## Troubleshooting

### UBSan warnings about function pointer types

The warning about `signals.c` function pointer types is expected:
```
runtime error: call to function through pointer to incorrect function type
```

This is due to irssi's dynamic signal dispatch system and is a known pattern in the codebase.

### Fuzzer stops immediately

Ensure the corpus directory exists:
```bash
mkdir -p corpus/irssi-fuzz
```

### Build fails with "perl not found"

Perl is required even for minimal/fuzzer builds (for generating help files). The Nix flake handles this automatically.
