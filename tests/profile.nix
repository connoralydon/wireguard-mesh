{
  pkgs,
  mesh,
  baseline ? mesh,
  mode ? "same-lan",
}:
let
  withProfile =
    package:
    package.overrideAttrs (old: {
      postPatch = (old.postPatch or "") + ''
        cp ${./profile-server.go.txt} cpu_profile.go
      '';
    });
in
(import ./default.nix {
  inherit pkgs;
  mesh = withProfile mesh;
  baseline = withProfile baseline;
  profile = true;
}).${mode}
