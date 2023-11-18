{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    flake-utils.url = "github:poscat0x04/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , nix-filter
    }:
  flake-utils.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; overlays = [ self.overlay ]; };
    in {
      packages = rec {
        inherit (pkgs) wgcf-teams;
        default = wgcf-teams;
      };
    }) // {
      overlay = final: prev: {
        wgcf-teams = let
          cargo-toml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        in with final.rustPlatform; buildRustPackage {
          pname = cargo-toml.package.name;
          version = cargo-toml.package.version;

          src = nix-filter.lib {
            root = ./.;
            include = [
              ./src
              ./Cargo.toml
              ./Cargo.lock
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ final.pkg-config ];
          buildInputs = [ final.openssl ];
        };
      };
    };
}
