{
  description = "Build teos (The Eye of Satoshi) server and plugin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-analyzer-src.follows = "";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, fenix, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        inherit (pkgs) lib;

        craneLib = crane.mkLib pkgs;
        src = craneLib.cleanCargoSource ./.;

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          inherit src;
          strictDeps = true;
 
	  nativeBuildInputs = [ 
            pkgs.pkg-config 
            pkgs.openssl 
            pkgs.rustfmt # needed for tonic build
          ];

          buildInputs = [
            # Add additional build inputs here
            pkgs.pkg-config
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            # Additional darwin specific inputs can be set here
            pkgs.libiconv
          ];

          # TODO: hack but without there are warnings and I can't make other method work 
          pname = "teos";
          version = "0.2.0";

          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };

        craneLibLLvmTools = craneLib.overrideToolchain
          (fenix.packages.${system}.complete.withComponents [
            "cargo"
            "llvm-tools"
            "rustc"
          ]);

        # Build *just* the cargo dependencies (of the entire workspace),
        # so we can reuse all of that work (e.g. via cachix) when running in CI
        # It is *highly* recommended to use something like cargo-hakari to avoid
        # cache misses when building individual top-level-crates
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        individualCrateArgs = commonArgs // {
          inherit cargoArtifacts;
          inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;
          # NB: we disable tests since we'll run them all via cargo-nextest
          doCheck = false;
        };

        fileSetForCrate = crate: lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./teos-common
            ./watchtower-plugin
            ./teos
            crate
          ];
        };

        # Build the top-level crates of the workspace as individual derivations.
        # This allows consumers to only depend on (and build) only what they need.
        # Though it is possible to build the entire workspace as a single derivation,
        # so this is left up to you on how to organize things
        plugin = craneLib.buildPackage (individualCrateArgs // {
          pname = "watchtower-plugin";
          version = "0.2.0"; # TODO: hack but without there are warnings and I can't make other method work 
          cargoExtraArgs = "-p watchtower-plugin";
          src = fileSetForCrate ./watchtower-plugin;
        });
        teos = craneLib.buildPackage (individualCrateArgs // {
          pname = "teos";
          version = "0.2.0"; # TODO: hack but without there are warnings and I can't make other method work 
          cargoExtraArgs = "-p teos";
          src = fileSetForCrate ./teos;
        });
      in
      {
        packages = {
          inherit plugin teos;
          default = teos;
        };

        apps = {
          plugin = flake-utils.lib.mkApp {
            drv = plugin;
          };
          teos = flake-utils.lib.mkApp {
            drv = teos;
          };
        };

      });
}

