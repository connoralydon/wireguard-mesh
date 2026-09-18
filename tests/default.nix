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
          imports = lib.optional (mode == "rosenpass") rosenpass;
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
          imports = lib.optional (mode == "rosenpass") rosenpass;
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
        ${builtins.readFile ./base.py}
      '';
    };
in
lib.genAttrs [ "relay-only" "same-lan" "nat" "rosenpass" ] makeTest
