{
  description = "WireGuard mesh daemon development environment";

  # Pin the nixos-unstable revision without inventing lock-file metadata.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b1b875982b17dabde9b4a37f3e229e74913e6db3";

  outputs =
    { nixpkgs, ... }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs
          [
            "aarch64-linux"
            "x86_64-linux"
            "aarch64-darwin"
            "x86_64-darwin"
          ]
          (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # Development only: no VM tests, implicit checks, or unverified vendor hash.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go_1_26
            pkgs.gopls
          ];
          GOTOOLCHAIN = "local";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
