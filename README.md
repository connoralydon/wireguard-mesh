# wireguard-mesh

Wireguard is an incredible VPN. One issue is that peers and routes are statically defined.

You CAN create a mesh, but the routes all need to be predefined. 

This service allows you to statically set a meshing configuration so already authenticated peers will be able to discover each other.

---
## Problem

Here's a concrete example on inter-LAN routing.
```
You have three nodes: A, B & C.
Node A is a cloud node with a public IP, ie an ingress point.
Nodes B and C are on the same LAN.

For the sake of simplicity Nodes B and C are routed to each other via A. B might be a laptop that roams and C might be a persistent server. Or, B & C might be servers and you'd like to reach them via the WAN through A.

The problem is that if B & C want to pass data over the wireguard VPN, they need to route through A. This introduces extra latency and extra bandwidth quota consumption on your A node.
```

That example can extend to another scenario where B and C are on separate LANs.

This would need hole punching similar to what Tailscale's DERP currently does. This isn't supported ATM.

---
## Usage
The `wireguard-meshd` service assumes that your initial Wireguard configuration defines *stable* routes. It will attempt to find *unstable* non-defined routes by encrypted broadcast via multicast or broadcast. You need one of these for it to work. Make sure your network supports this.

Multicast is preferred so it doesn't over-advertise its presence to the network.

Auto-failover to broadcast is not supported. It is hard because these nodes are separate.


--- 
## Architecture
The daemon is simple. It changes the Wireguard configuration at runtime. No guarantees on packet/network drops. I'm sure there's some optimization possible for faster failover.
