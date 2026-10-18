{ pkgs, mesh }:
let
  transportTest = mesh.overrideAttrs (old: {
    postInstall = (old.postInstall or "") + ''
      go test -trimpath -c -o $out/bin/mesh-network-tests .
    '';
  });
in
pkgs.testers.runNixOSTest {
  name = "wireguard-mesh-ipv6-transport";
  qemu.forceAccel = true;
  nodes.node = {
    virtualisation.memorySize = 512;
    virtualisation.cores = 2;
    virtualisation.interfaces.lan.vlan = 1;
    networking.firewall.enable = false;
    networking.useDHCP = false;
    networking.interfaces.lan.ipv4.addresses = [
      {
        address = "192.0.2.2";
        prefixLength = 24;
      }
    ];
    environment.systemPackages = [ transportTest ];
  };
  testScript = ''
    start_all()
    node.wait_for_unit("multi-user.target")
    node.wait_until_succeeds(
        "${pkgs.iproute2}/bin/ip -6 -o address show dev lan scope link | grep -v -e tentative -e dadfailed",
        timeout=30,
    )
    node.succeed(
        "${pkgs.coreutils}/bin/env WGMESH_IPV6_TEST_INTERFACE=lan "
        "${transportTest}/bin/mesh-network-tests "
        "-test.run='^(TestNetworkIPv6ZoneValidation|TestNetworkScopedIPv6LAN)$' "
        "-test.v -test.timeout=30s",
        timeout=45,
    )
  '';
}
