{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
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
        wgcf-teams = with final.rustPlatform; buildRustPackage {
          pname = "wgcf-teams";
          version = "0.1.0";

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
