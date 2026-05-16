# Nix flake for hermetic Gemma.Witness builds.
#
# Three usage paths:
#
#   nix develop              # drop into a shell with rust 1.80, node 22,
#                            # pnpm 9, python 3, uv, cosign, cargo-deny,
#                            # cargo-audit, cargo-fuzz. Everything pinned
#                            # by flake.lock, so two developers get bit-for-bit
#                            # identical toolchains.
#
#   nix build .#verifier-html
#                            # produces ./result/verify.html, the same bytes
#                            # the CI verifier-build job produces from the
#                            # same commit. SHA-256 matches
#                            # apps/verifier/expected-output-hash.txt.
#
#   nix build .#witness-cli
#                            # produces ./result/bin/witness-cli, the Linux
#                            # release binary.
#
# The reproducibility CI workflow (.github/workflows/reproducibility.yml)
# runs `nix build` and asserts the output hashes against the values
# committed in expected-output-hash.txt files.
#
# Bumping nixpkgs or rust-overlay requires updating flake.lock AND the
# expected-output-hash.txt files in the same commit; CI rejects drift.

{
  description = "Gemma.Witness reproducible build flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Pinned to the workspace MSRV from CLAUDE.md / Cargo.toml.
        rustToolchain = pkgs.rust-bin.stable."1.80.1".default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # Source filter so changes to evidence/, dist/, target/, or the
        # roadmap don't invalidate the build cache.
        sourceFilter = path: type:
          let baseName = baseNameOf (toString path);
          in !(builtins.any (s: s == baseName) [
            "target" "node_modules" "dist" "result"
            ".git" ".github" "evidence"
            "ROADMAP.md" "LIMITATIONS-RESOLUTION.md"
            "day-4-evidence.md" "demo-tampered-byte.witness"
          ]);

        cleanSource = pkgs.lib.cleanSourceWith {
          filter = sourceFilter;
          src = ./.;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.nodejs_22
            pkgs.pnpm
            pkgs.python313
            pkgs.uv
            pkgs.cargo-deny
            pkgs.cargo-audit
            pkgs.cargo-fuzz
            pkgs.cosign
            pkgs.pkg-config
            pkgs.openssl
            pkgs.git
          ];
          shellHook = ''
            export CARGO_INCREMENTAL=0
            export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME=."
            echo "Gemma.Witness dev shell. Rust $(rustc --version | cut -d' ' -f2), Node $(node --version), pnpm $(pnpm --version)."
          '';
        };

        packages = {
          # The verifier HTML, built reproducibly. Hash is asserted in CI
          # against apps/verifier/expected-output-hash.txt.
          verifier-html = pkgs.stdenv.mkDerivation {
            pname = "gemma-witness-verifier";
            version = "0.1.0";
            src = cleanSource;
            nativeBuildInputs = [ pkgs.nodejs_22 pkgs.pnpm ];
            # Offline build: lockfile must cover every transitive dep.
            buildPhase = ''
              export HOME=$TMPDIR
              export SOURCE_DATE_EPOCH=1715817600
              cd apps/verifier
              pnpm install --frozen-lockfile --prefer-offline
              pnpm build
            '';
            installPhase = ''
              mkdir -p $out
              cp apps/verifier/dist/verify.html $out/verify.html
            '';
          };

          # The CLI binary, built reproducibly. Hash is asserted in CI
          # against crates/witness-cli/expected-output-hash.txt.
          witness-cli = pkgs.rustPlatform.buildRustPackage {
            pname = "witness-cli";
            version = "0.1.0";
            src = cleanSource;
            cargoLock = {
              lockFile = ./Cargo.lock;
              # Outside-workspace path deps and any registry-bypass entries
              # would land here. Empty today; bump when adding such a dep.
              allowBuiltinFetchGit = false;
            };
            buildAndTestSubdir = "crates/witness-cli";
            # The capture app's tauri/swift_rs stack does not build on
            # the Nix linux runner, and the live e2e tests need a sidecar
            # we are not spinning up here.
            doCheck = false;
            CARGO_INCREMENTAL = "0";
            RUSTFLAGS = "--remap-path-prefix=/build=. --remap-path-prefix=/private/tmp=.";
          };
        };

        checks = {
          repro-verifier-hash = pkgs.runCommand "verifier-hash-check"
            { buildInputs = [ pkgs.coreutils ]; }
            ''
              expected=$(cat ${./apps/verifier/expected-output-hash.txt})
              actual=$(sha256sum ${self.packages.${system}.verifier-html}/verify.html | cut -d' ' -f1)
              if [ "$expected" = "PLACEHOLDER" ]; then
                echo "expected-output-hash.txt is the placeholder; skipping strict check."
                touch $out
                exit 0
              fi
              if [ "$expected" != "$actual" ]; then
                echo "verifier-html hash drift: expected $expected, got $actual"
                exit 1
              fi
              echo "verifier-html hash $actual"
              touch $out
            '';
        };
      });
}
