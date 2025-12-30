{
  description = "Irssi - A modular text mode chat client with IRC support";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Common build inputs for both the package and dev shell
        buildInputs = with pkgs; [
          glib
          openssl
          ncurses
          perl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
          utf8proc
        ];

        # Native build inputs (tools needed at build time)
        nativeBuildInputs = with pkgs; [
          meson
          ninja
          pkg-config
          perl
        ];

        # Build fuzzers with clang and libfuzzer
        # sanitizers: list of sanitizers to enable (e.g., ["address" "undefined"])
        mkFuzzerPackage = { sanitizers ? [ "address" "undefined" ] }:
          let
            # Use clang's stdenv for libfuzzer support
            clangStdenv = pkgs.llvmPackages.stdenv;

            # Build sanitizer flags for linking (includes fuzzer)
            sanitizerFlags = pkgs.lib.concatMapStringsSep "," (s: s) sanitizers;
            fullSanitizerFlags =
              if sanitizers == [] then "-fsanitize=fuzzer"
              else "-fsanitize=fuzzer,${sanitizerFlags}";

            # Compile-time sanitizer flags (without fuzzer - meson adds fuzzer-no-link)
            compileSanitizerFlags =
              if sanitizers == [] then ""
              else "-fsanitize=${sanitizerFlags}";
          in
          clangStdenv.mkDerivation {
            pname = "irssi-fuzz";
            version = "1.5-head";

            src = ./.;

            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
              perl  # Needed at build time for generating help files
            ];

            buildInputs = with pkgs; [
              glib
              openssl
              ncurses
            ];

            # Use preConfigure to set CFLAGS/LDFLAGS since meson's -Dc_args
            # breaks the initial compiler test when sanitizers are involved
            preConfigure = pkgs.lib.optionalString (sanitizers != []) ''
              export CFLAGS="-g -O1 -fno-omit-frame-pointer ${compileSanitizerFlags}"
              export LDFLAGS="${compileSanitizerFlags}"
            '';

            mesonFlags = [
              "-Dwith-perl=no"
              "-Dwithout-textui=yes"
              "-Dwith-fuzzer=yes"
              "-Dwith-fuzzer-lib=${fullSanitizerFlags}"
              "-Dfuzzer-link-language=c"
            ];

            # Only install the fuzzer binaries
            postInstall = ''
              # Remove non-fuzzer files if any were installed
              rm -rf $out/share $out/include $out/lib/pkgconfig || true
            '';

            meta = with pkgs.lib; {
              description = "Irssi fuzz testing targets built with libFuzzer";
              homepage = "https://irssi.org/";
              license = licenses.gpl2Plus;
              platforms = platforms.unix;
            };
          };

      in
      {
        packages = {
          default = self.packages.${system}.irssi;

          irssi = pkgs.stdenv.mkDerivation {
            pname = "irssi";
            version = "1.5-head";

            src = ./.;

            inherit nativeBuildInputs buildInputs;

            mesonFlags = [
              "-Dwith-perl=yes"
              "-Dwith-proxy=yes"
            ];

            meta = with pkgs.lib; {
              description = "A modular text mode chat client with IRC support";
              homepage = "https://irssi.org/";
              license = licenses.gpl2Plus;
              maintainers = [];
              platforms = platforms.unix;
            };
          };

          # Variant without Perl scripting support
          irssi-minimal = pkgs.stdenv.mkDerivation {
            pname = "irssi-minimal";
            version = "1.5-head";

            src = ./.;

            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
              perl  # Perl is needed at build time for generating help files
            ];

            buildInputs = with pkgs; [
              glib
              openssl
              ncurses
            ];

            mesonFlags = [
              "-Dwith-perl=no"
            ];

            meta = with pkgs.lib; {
              description = "A modular text mode chat client with IRC support (minimal build)";
              homepage = "https://irssi.org/";
              license = licenses.gpl2Plus;
              platforms = platforms.unix;
            };
          };

          # Fuzzers with AddressSanitizer + UndefinedBehaviorSanitizer (recommended)
          fuzz = mkFuzzerPackage {
            sanitizers = [ "address" "undefined" ];
          };

          # Fuzzers with only AddressSanitizer (faster, catches memory errors)
          fuzz-asan = mkFuzzerPackage {
            sanitizers = [ "address" ];
          };

          # Fuzzers with only UndefinedBehaviorSanitizer
          fuzz-ubsan = mkFuzzerPackage {
            sanitizers = [ "undefined" ];
          };
        };

        devShells = {
          default = pkgs.mkShell {
            name = "irssi-dev";

            inherit buildInputs;

            nativeBuildInputs = nativeBuildInputs ++ (with pkgs; [
              # Additional development tools
              gdb
              valgrind
            ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              strace
            ]);

            shellHook = ''
              echo "Irssi development environment"
              echo ""
              echo "Build commands:"
              echo "  meson setup Build"
              echo "  ninja -C Build"
              echo ""
              echo "Run tests:"
              echo "  ninja -C Build test"
              echo ""
            '';
          };

          # Development shell for fuzzing
          fuzz = pkgs.mkShell.override { stdenv = pkgs.llvmPackages.stdenv; } {
            name = "irssi-fuzz-dev";

            buildInputs = with pkgs; [
              glib
              openssl
              ncurses
            ];

            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
              perl
              # Fuzzing tools
              llvmPackages.llvm  # For llvm-symbolizer, llvm-cov, etc.
            ];

            shellHook = ''
              echo "Irssi fuzzing development environment (clang + libFuzzer)"
              echo ""
              echo "Build fuzzers:"
              echo "  meson setup Build-fuzz -Dwith-perl=no -Dwithout-textui=yes -Dwith-fuzzer=yes"
              echo "  ninja -C Build-fuzz"
              echo ""
              echo "Fuzz targets will be in Build-fuzz/src/fe-fuzz/:"
              echo "  - irssi-fuzz"
              echo "  - server-fuzz"
              echo "  - event-get-params-fuzz (in irc/core/)"
              echo "  - theme-load-fuzz (in fe-common/core/)"
              echo ""
              echo "Run a fuzzer:"
              echo "  ./Build-fuzz/src/fe-fuzz/irssi-fuzz corpus/"
              echo ""
            '';
          };
        };
      }
    );
}
