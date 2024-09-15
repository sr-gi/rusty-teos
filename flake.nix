{
  description = "Build teos (The Eye of Satoshi) server and plugin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        inherit (pkgs) lib;

        craneLib = (crane.mkLib pkgs).overrideToolchain fenix.packages.${system}.stable.minimalToolchain;

        commonArgs = {
          strictDeps = true;

          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.openssl
            pkgs.rustfmt # needed for tonic build
          ];

          buildInputs =
            [ ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              # Additional darwin specific inputs can be set here
              pkgs.libiconv
            ];

          PROTOC = "${pkgs.protobuf}/bin/protoc";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };

        fileSetForCrate =
          crate:
          lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./teos-common
              ./teos
              ./watchtower-plugin
              crate
            ];
          };

        plugin = craneLib.buildPackage (
          commonArgs
          // {
            pname = "watchtower-plugin";
            cargoExtraArgs = "-p watchtower-plugin";
            src = fileSetForCrate ./watchtower-plugin;
            inherit (craneLib.crateNameFromCargoToml { cargoToml = ./watchtower-plugin/Cargo.toml; }) version;
          }
        );
        teos = craneLib.buildPackage (
          commonArgs
          // {
            pname = "teos";
            cargoExtraArgs = "-p teos";
            src = fileSetForCrate ./teos;
            inherit (craneLib.crateNameFromCargoToml { cargoToml = ./teos/Cargo.toml; }) version;
          }
        );
      in
      {
        packages = {
          inherit plugin teos;
          default = teos;
        };

        apps = {
          plugin = flake-utils.lib.mkApp { drv = plugin; };
          teos = flake-utils.lib.mkApp { drv = teos; };
        };

        formatter = pkgs.nixfmt-rfc-style;

        checks = {
          inherit teos plugin;
        };

        devShells.default = craneLib.devShell {
          packages = commonArgs.buildInputs ++ commonArgs.nativeBuildInputs;
        };
      }
    );
}
