{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    nci.url = "github:yusdacra/nix-cargo-integration";
    nci.inputs.nixpkgs.follows = "nixpkgs";
    parts.url = "github:hercules-ci/flake-parts";
    parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  };
  outputs = inputs @ { nci, ... }: let
    crateName = "jwtinfo";
  in  inputs.parts.lib.mkFlake { inherit inputs; } {
      systems = ["x86_64-linux"];
      imports = [
        nci.flakeModule
        ({ ... }: {
          perSystem = { pkgs, ... }: {
            nci.projects.${crateName}.path = ./;
            nci.crates.${crateName}.profiles.release.runTests = false;
          };
        })
      ];
      perSystem = { pkgs, config, ... }: let
        crateOutputs = config.nci.outputs."${crateName}";
      in {
        devShells.default = crateOutputs.devShell;
        packages.default = crateOutputs.packages.release;
      };
    };
}
