{
  description = "spine -- high-speed poller for Cacti";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        buildInputs = with pkgs; [
          net-snmp
          mariadb-connector-c
          openssl
          zlib
        ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
          systemd
        ];
        nativeBuildInputs = with pkgs; [ cmake pkg-config ];
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "spine";
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
          src = self;
          inherit nativeBuildInputs buildInputs;
          cmakeFlags = [
            "-DSPINE_BUILD_MAIN=ON"
            "-DBUILD_TESTING=OFF"
            "-DCMAKE_BUILD_TYPE=Release"
          ];
        };

        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs;
          buildInputs = buildInputs ++ (with pkgs; [
            gcc
            clang
            gdb
            cppcheck
            clang-tools
            git
            gh
            shellcheck
            python3
            ninja
          ]);
          shellHook = ''
            echo "spine dev shell (nix)"
            echo "Configure: cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=ON"
            echo "Build:     cmake --build build -j"
          '';
        };
      });
}
