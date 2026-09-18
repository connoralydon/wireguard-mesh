{ pkgs, mesh }:
let
  inherit (pkgs) lib;
  template = pkgs.runCommand "wireguard-mesh-test-unit" { } ''
    mkdir -p $out/lib/systemd/system
    cp ${
      pkgs.writeText "wireguard-meshd@.service" (
        lib.replaceStrings [ "wireguard-meshd -" ] [ "${mesh}/bin/wireguard-meshd -" ] (
          builtins.readFile (../. + "/wireguard-meshd@.service")
        )
      )
    } $out/lib/systemd/system/wireguard-meshd@.service
  '';
  guest = pkgs.writeScriptBin "mesh-test" ''
    #!${pkgs.python3}/bin/python3
    ${builtins.readFile ./guest.py}
  '';
  recoveryGuest = pkgs.writeScriptBin "mesh-recovery-test" ''
    #!${pkgs.python3}/bin/python3
    ${builtins.readFile ./recovery_guest.py}
  '';
  privacyGuest = pkgs.writeScriptBin "mesh-privacy-test" ''
    #!${pkgs.python3}/bin/python3
    ${builtins.readFile ./privacy_guest.py}
  '';
  adapterGuest = pkgs.writeScriptBin "mesh-adapter-test" ''
    #!${pkgs.python3}/bin/python3
    ${builtins.readFile ./adapter_guest.py}
  '';
  adapterTemplate = pkgs.runCommand "wireguard-mesh-adapter-test-unit" { } ''
    mkdir -p $out/lib/systemd/system
    cp ${
      pkgs.writeText "wireguard-mesh-rosenpass@.service" (
        lib.replaceStrings
          [ "wireguard-meshd -" "ExecStartPre=install " ]
          [ "${mesh}/bin/wireguard-meshd -" "ExecStartPre=${pkgs.coreutils}/bin/install " ]
          (builtins.readFile (../. + "/wireguard-mesh-rosenpass@.service"))
      )
    } $out/lib/systemd/system/wireguard-mesh-rosenpass@.service
  '';
  adapter = {
    environment.systemPackages = [ pkgs.rosenpass ];
    systemd.packages = [ adapterTemplate ];
    users.groups.mesh-wg0 = { };
    users.groups.mesh-psk-wg0 = { };
    users.users.mesh-wg0 = {
      isSystemUser = true;
      uid = 991;
      group = "mesh-wg0";
      extraGroups = [ "mesh-psk-wg0" ];
    };
    users.users.mesh-rosenpass-wg0 = {
      isSystemUser = true;
      group = "mesh-psk-wg0";
    };
    # This account can open the socket but must fail its SO_PEERCRED check.
    users.users.mesh-intruder = {
      isSystemUser = true;
      group = "mesh-psk-wg0";
    };
    systemd.services."wireguard-meshd@wg0".serviceConfig = {
      DynamicUser = lib.mkForce false;
      User = "mesh-wg0";
      SupplementaryGroups = [ "mesh-psk-wg0" ];
    };
    # Keep mesh running when the adapter stops so its own fallback is tested.
    # These cases test IPv4 endpoint changes, not IPv6 address selection.
    boot.kernel.sysctl."net.ipv6.conf.all.disable_ipv6" = 1;
    boot.kernel.sysctl."net.ipv6.conf.default.disable_ipv6" = 1;
    boot.kernelModules = [
      "sch_ingress"
      "cls_u32"
      "act_gact"
    ];
  };
  rosenpass = {
    environment.systemPackages = [ pkgs.rosenpass ];
    users.groups.mesh-psk = { };
    users.users.rosenpass = {
      isSystemUser = true;
      group = "mesh-psk";
    };
    systemd.services."wireguard-meshd@wg0".serviceConfig.SupplementaryGroups = [ "mesh-psk" ];
    # Rosenpass can write only its output directory, not WireGuard state.
    systemd.services.rosenpass = {
      serviceConfig = {
        ExecStart = "${pkgs.rosenpass}/bin/rosenpass exchange-config /etc/rosenpass.toml";
        User = "rosenpass";
        Group = "mesh-psk";
        RuntimeDirectory = "rosenpass";
        RuntimeDirectoryMode = "0750";
        RuntimeDirectoryPreserve = "yes";
        UMask = "0027";
        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        LimitCORE = 0;
      };
    };
  };
  makeTest =
    mode:
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
        ];
        environment.systemPackages = with pkgs; [
          mesh
          guest
          recoveryGuest
          privacyGuest
          adapterGuest
          wireguard-tools
          iproute2
          iptables
          tcpdump
        ];
        systemd.packages = [ template ];
        # Keep crash recovery observable before the normal automatic restart.
        systemd.services."wireguard-meshd@wg0" = {
          overrideStrategy = "asDropin";
          serviceConfig.RestartSec = "15s";
        };
      };
      nodes = {
        a = {
          virtualisation.interfaces.wan.vlan = 1;
          networking.interfaces.wan.ipv4.addresses = [
            {
              address = "192.0.2.1";
              prefixLength = 24;
            }
          ];
          boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
        };
        b = {
          imports =
            lib.optional (mode == "rosenpass") rosenpass
            ++ lib.optional (lib.hasPrefix "rosenpass-" mode) adapter;
          virtualisation.interfaces =
            if mode == "nat" then
              { lan.vlan = 2; }
            else
              { wan.vlan = 1; } // lib.optionalAttrs (mode != "relay-only") { lan.vlan = 2; };
          networking.interfaces =
            if mode == "nat" then
              {
                lan.ipv4.addresses = [
                  {
                    address = "172.20.2.2";
                    prefixLength = 24;
                  }
                ];
              }
            else
              {
                wan.ipv4.addresses = [
                  {
                    address = "192.0.2.2";
                    prefixLength = 24;
                  }
                ];
              }
              // lib.optionalAttrs (mode != "relay-only") {
                lan.ipv4.addresses = [
                  {
                    address = "172.20.2.2";
                    prefixLength = 24;
                  }
                ];
              };
        };
        c = {
          imports =
            lib.optional (mode == "rosenpass") rosenpass
            ++ lib.optional (lib.hasPrefix "rosenpass-" mode) adapter;
          virtualisation.interfaces =
            if mode == "nat" then
              { lan.vlan = 3; }
            else
              { wan.vlan = 1; } // lib.optionalAttrs (mode != "relay-only") { lan.vlan = 2; };
          networking.interfaces =
            if mode == "nat" then
              {
                lan.ipv4.addresses = [
                  {
                    address = "172.20.3.3";
                    prefixLength = 24;
                  }
                ];
              }
            else
              {
                wan.ipv4.addresses = [
                  {
                    address = "192.0.2.3";
                    prefixLength = 24;
                  }
                ];
              }
              // lib.optionalAttrs (mode != "relay-only") {
                lan.ipv4.addresses = [
                  {
                    address = "172.20.2.3";
                    prefixLength = 24;
                  }
                ];
              };
        };
      }
      // lib.optionalAttrs (mode == "nat") {
        nb = {
          virtualisation.interfaces = {
            wan.vlan = 1;
            lan.vlan = 2;
          };
          networking.interfaces = {
            wan.ipv4.addresses = [
              {
                address = "192.0.2.12";
                prefixLength = 24;
              }
            ];
            lan.ipv4.addresses = [
              {
                address = "172.20.2.1";
                prefixLength = 24;
              }
            ];
          };
          boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
        };
        nc = {
          virtualisation.interfaces = {
            wan.vlan = 1;
            lan.vlan = 3;
          };
          networking.interfaces = {
            wan.ipv4.addresses = [
              {
                address = "192.0.2.13";
                prefixLength = 24;
              }
            ];
            lan.ipv4.addresses = [
              {
                address = "172.20.3.1";
                prefixLength = 24;
              }
            ];
          };
          boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
        };
      };
      testScript = ''
        mode = "${mode}"
        ${builtins.readFile ./rosenpass.py}
        ${builtins.readFile ./adapter.py}
        ${builtins.readFile ./recovery.py}
        ${builtins.readFile ./base.py}
      '';
    };
in
lib.genAttrs [
  "relay-only"
  "same-lan"
  "nat"
  "rosenpass"
  "rosenpass-adapter"
  "rosenpass-rekey"
] makeTest
