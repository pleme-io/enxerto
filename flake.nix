{
  description = "enxerto — pleme-io mesh sidecar-injector";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    forge = {
      url = "github:pleme-io/forge";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
      inputs.crate2nix.follows = "crate2nix";
      inputs.substrate.follows = "substrate";
    };
  };

  outputs =
    { self, nixpkgs, crate2nix, fenix, substrate, forge, ... }:
    (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix fenix substrate forge;
    }) {
      toolName = "enxerto";
      src = self;
    };
}
