{ pkgs, mesh }:
let
  inherit (pkgs) lib;
  observer = pkgs.buildGo126Module {
    pname = "mesh-kernel-observer";
    version = "0.1.0";
    src = lib.cleanSourceWith {
      src = ../.;
      filter =
        path: type:
        type == "directory"
        || (
          type == "regular"
          && (
            lib.hasSuffix ".go" path
            || builtins.elem (baseNameOf path) [
              "go.mod"
              "go.sum"
            ]
          )
        );
    };
    vendorHash = "sha256-tMVVz858VrtYThmTdafY/HEmpWWfYFSe/T6VqK+HnOU=";
    subPackages = [ "tests/observer" ];
    postInstall = ''
      mv "$out/bin/observer" "$out/bin/mesh-kernel-observer"
    '';
  };
  unit = pkgs.runCommand "mesh-direct-test-unit" { } ''
    mkdir -p $out/lib/systemd/system
    cp ${
      pkgs.writeText "wireguard-meshd@.service" (
        lib.replaceStrings [ "wireguard-meshd -" ] [ "${mesh}/bin/wireguard-meshd -" ] (
          builtins.readFile (../. + "/wireguard-meshd@.service")
        )
      )
    } $out/lib/systemd/system/wireguard-meshd@.service
    cp ${
      pkgs.writeText "wireguard-mesh-rosenpass@.service" (
        lib.replaceStrings
          [ "wireguard-meshd -" "ExecStartPre=install " ]
          [ "${mesh}/bin/wireguard-meshd -" "ExecStartPre=${pkgs.coreutils}/bin/install " ]
          (builtins.readFile (../. + "/wireguard-mesh-rosenpass@.service"))
      )
    } $out/lib/systemd/system/wireguard-mesh-rosenpass@.service
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
        pkgs.util-linux
        pkgs.rosenpass
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
      isNat = lib.hasPrefix "nat-traversal" mode || lib.hasPrefix "lan-first-" mode;
      isLan = !isNat;
      oneNat = mode == "nat-traversal-one-nat";
      pairLan = lib.hasPrefix "lan-first-" mode;
      isRosenpass = lib.hasSuffix "rosenpass-routes" mode || mode == "nat-traversal-rosenpass";
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
          observer
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
        users.groups = lib.mkIf isRosenpass {
          mesh-wg0 = { };
          mesh-psk-wg0 = { };
        };
        users.users = lib.mkIf isRosenpass {
          mesh-wg0 = {
            isSystemUser = true;
            uid = 991;
            group = "mesh-wg0";
            extraGroups = [ "mesh-psk-wg0" ];
          };
          mesh-rosenpass-wg0 = {
            isSystemUser = true;
            group = "mesh-psk-wg0";
          };
        };
        systemd.services."wireguard-mesh-rosenpass@wg0" = lib.mkIf isRosenpass {
          overrideStrategy = "asDropin";
          serviceConfig.Restart = "no";
        };
        systemd.services."wireguard-meshd@wg0" = {
          overrideStrategy = "asDropin";
          serviceConfig = {
            RestartSec = "15s";
          }
          // lib.optionalAttrs isRosenpass {
            DynamicUser = lib.mkForce false;
            User = "mesh-wg0";
            SupplementaryGroups = [ "mesh-psk-wg0" ];
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
          // lib.optionalAttrs pairLan { pairlan.vlan = 4; }
          // lib.optionalAttrs isLan { wan.vlan = 1; };
          networking.interfaces = {
            lan.ipv4.addresses = address "172.20.2.2";
          }
          // lib.optionalAttrs pairLan { pairlan.ipv4.addresses = address "172.21.4.2"; }
          // lib.optionalAttrs isLan { wan.ipv4.addresses = address "192.0.2.2"; };
        };
        c = {
          virtualisation.interfaces = {
            lan.vlan = if isNat then 3 else 2;
          }
          // lib.optionalAttrs pairLan { pairlan.vlan = 4; }
          // lib.optionalAttrs (isLan || oneNat) { wan.vlan = 1; };
          networking.interfaces = {
            lan.ipv4.addresses = address (if isNat then "172.20.3.3" else "172.20.2.3");
          }
          // lib.optionalAttrs pairLan { pairlan.ipv4.addresses = address "172.21.4.3"; }
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
        kernel_observer = "${observer}/bin/mesh-kernel-observer"
        tcpdump = "${pkgs.tcpdump}/bin/tcpdump"
        rosenpass = "${pkgs.rosenpass}/bin/rosenpass"
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
  "lan-first-nat-fallback"
  "lan-first-wg-blocked"
  "same-lan-rosenpass-routes"
  "nat-traversal-rosenpass"
] make
