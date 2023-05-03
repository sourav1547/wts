# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    foundry.url = "github:shazow/foundry.nix/monthly"; # Use monthly branch for permanent releases
  };

  outputs = { self, nixpkgs, utils, foundry }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ foundry.overlay ];
        };
      in {

        devShell = with pkgs; mkShell {
          buildInputs = [
            # From the foundry overlay
            # Note: Can also be referenced without overlaying as: foundry.defaultPackage.${system}
            foundry-bin

            # ... any other dependencies we need
            solc

            bash
            nodejs-18_x
            nodePackages.pnpm
            nix-prefetch-scripts
            glibc
            python310

          ];

          # Decorative prompt override so we know when we're in a dev shell
          shellHook = ''
              export PS1="[dev] $PS1"
              export PIP_PREFIX="$(pwd)/_build/pip_packages"
              export PYTHONPATH="$(pwd)/_build/pip_packages/local/lib/python3.10/dist-packages/:$PYTHONPATH"
              export PYTHONPATH="$(pwd)/trade_executor:$PYTHONPATH"
              export PATH="$PATH:$(pwd)/_build/pip_packages/local/bin:$(pwd)/node_modules/.bin:$(pwd)/scripts"
              export ROOT="$(pwd)"
              rm -Rf _build
              pip install eth-brownie==1.19.3
              pip install py_ecc==6.0.0
              pip install black==22.10.0
              pnpm i
              alias ganache-cli=ganache
          '';
        };
      });
}