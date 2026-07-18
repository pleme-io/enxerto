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

    hardened = import "${substrate}/lib/build/oci/hardened-base.nix" { pkgs = pkgsLinux; };

    # Named uid/gid entry (vs. hardened-base's own generic "nonroot" 65532
    # stub) — preserved from the pre-hardening image so anything keying off
    # the literal "enxerto" username in /etc/passwd still resolves. Layered
    # on top of the base image, so it overwrites (not collides with) the
    # base's own /etc/passwd + /etc/group at the final layer (rsync -a
    # last-writer-wins semantics in dockerTools' layer builder).
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

    dockerImage = hardened.mkPackageImage {
      service = "enxerto";
      # enxerto is dynamically linked against glibc (crate2nix buildRustCrate,
      # no musl target) — distroless-glibc, not -static.
      base = hardened.bases.distroless-glibc;
      package = enxertoBin;
      publishName = "ghcr.io/pleme-io/enxerto";
      publishTag = "amd64-${if (self ? rev) then builtins.substring 0 8 self.rev else "dev"}";
      entrypoint = [ "${enxertoBin}/bin/enxerto" ];
      # coreutils + fakeNss carried over from the old hand-rolled image even
      # though nothing in enxerto's own runtime (a pure axum/tokio HTTP
      # admission webhook — no subprocess/shell-out in src/) appears to need
      # them; the /bin/sh usage in src/patch.rs is JSON emitted for the
      # INJECTED aresta/iptables-init sidecars, not enxerto's own process.
      # Preserved defensively — this is a hardening swap, not a behavior
      # change.
      extraContents = [ pkgsLinux.coreutils fakeNss ];
      env = [
        "PATH=/bin"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
        "RUST_LOG=info,enxerto=debug"
      ];
      # Named uid:gid (matches the fakeNss "enxerto" entry above) — overrides
      # mkPackageImage's own 65532:65532 nonroot default. Distinct from
      # aresta's own 1737:1737 (the sidecar it injects); no relation between
      # the two numbers beyond both being dedicated non-root uids.
      user = "1738:1738";
      exposedPorts = { "8443/tcp" = {}; };
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
