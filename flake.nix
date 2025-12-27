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
        };

        devShells.default = pkgs.mkShell {
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
      }
    );
}
