{
  description = "Heimdall Admin Service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python311
            uv
            ruff
            just
            docker
            docker-compose
            postgresql
            git
          ];

          shellHook = ''
            echo "Heimdall development environment loaded"
            echo "Python: $(python --version)"
            echo "uv: $(uv --version)"
            echo "ruff: $(ruff --version)"
            echo "just: $(just --version)"
          '';
        };
      });
}