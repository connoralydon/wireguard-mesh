{ pkgs, mesh }:
let
  inherit (pkgs) lib;
  unit = pkgs.runCommand "mesh-direct-test-unit" { } ''
    mkdir -p $out/lib/systemd/system
    cp ${
      pkgs.writeText "wireguard-meshd@.service" (
        lib.replaceStrings [ "wireguard-meshd -" ] [ "${mesh}/bin/wireguard-meshd -" ] (
          builtins.readFile (../. + "/wireguard-meshd@.service")
        )
      )
    } $out/lib/systemd/system/wireguard-meshd@.service
  '';
  guest = pkgs.writeScriptBin "mesh-direct-test" ''
    #!${pkgs.python3}/bin/python3
    import os
    os.environ["PATH"] = "${
      lib.makeBinPath [
        pkgs.iproute2
        pkgs.wireguard-tools
        pkgs.iptables
        pkgs.systemd
        pkgs.coreutils
        pkgs.conntrack-tools
      ]
    }"
    ${builtins.readFile ./direct_guest.py}
  '';
  address = ip: [
    {
      address = ip;
      prefixLength = 24;
    }
  ];
  router = n: {
    virtualisation.interfaces = {
      wan.vlan = 1;
      lan.vlan = n;
    };
    networking.interfaces = {
      wan.ipv4.addresses = address "192.0.2.1${toString n}";
      lan.ipv4.addresses = address "172.20.${toString n}.1";
    };
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    boot.kernel.sysctl."net.netfilter.nf_conntrack_acct" = 1;
  };
  make =
    mode:
    let
      isNat = lib.hasPrefix "nat-traversal" mode;
      isLan = !isNat;
      oneNat = mode == "nat-traversal-one-nat";
    in
    pkgs.testers.runNixOSTest {
      name = "wireguard-mesh-${mode}";
      qemu.forceAccel = true;
      defaults = {
        virtualisation.memorySize = 768;
        virtualisation.cores = 2;
        networking.firewall.enable = false;
        networking.useDHCP = false;
        boot.kernelModules = [
          "wireguard"
          "sch_netem"
          "nf_conntrack"
        ];
        environment.systemPackages = [
          mesh
          guest
          pkgs.wireguard-tools
          pkgs.iproute2
          pkgs.iptables
          pkgs.python3
          pkgs.conntrack-tools
          pkgs.tcpdump
        ];
        # The stable and direct interfaces share the tunnel source address.
        boot.kernel.sysctl = {
          "net.ipv4.conf.all.rp_filter" = 2;
          "net.ipv4.conf.default.rp_filter" = 2;
        };
        systemd.packages = [ unit ];
        systemd.services."wireguard-meshd@wg0" = {
          overrideStrategy = "asDropin";
          serviceConfig = {
            RestartSec = "15s";
          }
          // lib.optionalAttrs (isNat || mode == "same-lan-stun-down") {
            CapabilityBoundingSet = lib.mkForce [
              "CAP_NET_ADMIN"
              "CAP_NET_RAW"
            ];
            AmbientCapabilities = lib.mkForce [
              "CAP_NET_ADMIN"
              "CAP_NET_RAW"
            ];
          };
        };
      };
      nodes = {
        a = {
          virtualisation.interfaces.wan.vlan = 1;
          networking.interfaces.wan.ipv4.addresses = address "192.0.2.1";
          boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
        };
        b = {
          virtualisation.interfaces = {
            lan.vlan = 2;
          }
          // lib.optionalAttrs isLan { wan.vlan = 1; };
          networking.interfaces = {
            lan.ipv4.addresses = address "172.20.2.2";
          }
          // lib.optionalAttrs isLan { wan.ipv4.addresses = address "192.0.2.2"; };
        };
        c = {
          virtualisation.interfaces = {
            lan.vlan = if isNat then 3 else 2;
          }
          // lib.optionalAttrs (isLan || oneNat) { wan.vlan = 1; };
          networking.interfaces = {
            lan.ipv4.addresses = address (if isNat then "172.20.3.3" else "172.20.2.3");
          }
          // lib.optionalAttrs (isLan || oneNat) { wan.ipv4.addresses = address "192.0.2.3"; };
        };
      }
      // lib.optionalAttrs isNat {
        nb = router 2;
      }
      // lib.optionalAttrs (isNat && !oneNat) {
        nc = router 3;
      };
      testScript = ''
        mode = "${mode}"
        turnserver = "${pkgs.coturn}/bin/turnserver"
        guest_helper = "${guest}/bin/mesh-direct-test"
        tcpdump = "${pkgs.tcpdump}/bin/tcpdump"
        ${builtins.readFile ./direct.py}
      '';
    };
in
lib.genAttrs [
  "same-lan-routes"
  "same-lan-auto"
  "same-lan-stun-down"
  "nat-traversal"
  "nat-traversal-port-preserving"
  "nat-traversal-blocked"
  "nat-traversal-wg-blocked"
  "nat-traversal-symmetric"
  "nat-traversal-stun-failover"
  "nat-traversal-one-nat"
  "nat-traversal-long-outage"
] make
