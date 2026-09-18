{
  description = "WireGuard mesh daemon and isolated NixOS integration tests";

  # Pin the nixos-unstable revision without inventing lock-file metadata.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b1b875982b17dabde9b4a37f3e229e74913e6db3";

  outputs =
    { self, nixpkgs, ... }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs [
          "aarch64-linux"
          "x86_64-linux"
          "aarch64-darwin"
          "x86_64-darwin"
        ] (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.buildGo126Module {
          pname = "wireguard-meshd";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              type == "regular"
              && (
                pkgs.lib.hasSuffix ".go" path
                || builtins.elem (baseNameOf path) [
                  "go.mod"
                  "go.sum"
                ]
              );
          };
          vendorHash = "sha256-2BLFPdWkemykGEcCQGb704+PQJh+0+cARsISvq/9H6Y=";
          postInstall = ''
            mv "$out/bin/wireguard-mesh" "$out/bin/wireguard-meshd"
          '';
          meta.platforms = pkgs.lib.platforms.linux;
        };
      });

      checks = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
        system:
        import ./tests {
          pkgs = nixpkgs.legacyPackages.${system};
          mesh = self.packages.${system}.default;
        }
      );

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
