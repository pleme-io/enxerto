{
  description = "enxerto — pleme-io mesh sidecar-injector";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crate2nix, flake-utils, substrate, devenv, ... }: let
    releaseOutputs = (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils devenv;
    }) {
      toolName = "enxerto";
      src = self;
      repo = "pleme-io/enxerto";
    };

    imageSystem = "x86_64-linux";
    pkgsLinux = import nixpkgs { system = imageSystem; };
    cargoNix = pkgsLinux.callPackage ./Cargo.nix {};
    enxertoBin = cargoNix.workspaceMembers."enxerto".build;

    fakeNss = pkgsLinux.runCommand "enxerto-fake-nss" { } ''
      mkdir -p $out/etc
      cat > $out/etc/passwd <<'EOF'
      root:x:0:0:root:/root:/bin/sh
      enxerto:x:1738:1738:enxerto webhook:/var/lib/enxerto:/bin/sh
      nobody:x:65534:65534:nobody:/var/empty:/bin/sh
      EOF
      cat > $out/etc/group <<'EOF'
      root:x:0:
      enxerto:x:1738:
      nobody:x:65534:
      EOF
    '';

    dockerImage = pkgsLinux.dockerTools.buildLayeredImage {
      name = "ghcr.io/pleme-io/enxerto";
      tag = "amd64-${if (self ? rev) then builtins.substring 0 8 self.rev else "dev"}";
      contents = [
        enxertoBin
        pkgsLinux.cacert
        pkgsLinux.coreutils
        fakeNss
      ];
      config = {
        Entrypoint = [ "${enxertoBin}/bin/enxerto" ];
        Env = [
          "PATH=/bin"
          "SSL_CERT_FILE=${pkgsLinux.cacert}/etc/ssl/certs/ca-bundle.crt"
          "RUST_LOG=info,enxerto=debug"
        ];
        User = "1738";
        ExposedPorts = { "8443/tcp" = {}; };
      };
    };

    pushImageApp = system: let
      pkgs = import nixpkgs { inherit system; };
    in {
      type = "app";
      program = toString (pkgs.writeShellScript "enxerto-push-image" ''
        set -euo pipefail
        IMAGE_PATH="$(nix build --no-link --print-out-paths .#dockerImage)"
        TAG="''${TAG:-amd64-latest}"
        echo "Pushing $IMAGE_PATH → docker://ghcr.io/pleme-io/enxerto:$TAG"
        ${pkgs.skopeo}/bin/skopeo copy \
          --insecure-policy \
          docker-archive:"$IMAGE_PATH" \
          docker://ghcr.io/pleme-io/enxerto:"$TAG"
      '');
    };

    imageOutputs = {
      packages.${imageSystem}.dockerImage = dockerImage;
      apps.${imageSystem}.push-image = pushImageApp imageSystem;
      apps."aarch64-darwin".push-image = pushImageApp "aarch64-darwin";
      apps."x86_64-darwin".push-image = pushImageApp "x86_64-darwin";
    };
  in
    nixpkgs.lib.recursiveUpdate releaseOutputs imageOutputs;
}
