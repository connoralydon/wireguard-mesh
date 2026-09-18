package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

const (
	rosenpassLifetime = 3 * time.Minute
	rosenpassTimeout  = 2 * time.Second
	rosenpassRPCSize  = 4096
)

type rosenpassRequest struct {
	Peer    string
	Address netip.Addr // Invalid (zero) withdraws the endpoint.
	Link    linkAddr
}

type rosenpassResponse struct {
	Instance      string
	Generation    uint64   // Process counter; unchanged by rekeys.
	KeyGeneration uint64   // Successful new-key publications within this instance.
	Hash          [32]byte // SHA-256 of the decoded 32-byte PSK, not its base64 text.
	Expires       time.Time
	Valid         bool
}

// Each connection carries one newline-terminated JSON request and response.
// Call before reading the PSK, then compare its hash and query again. Require
// both responses to be valid with the same instance, both generations, and hash.
// A direct WireGuard trial must still confirm the key with the remote peer.
func queryRosenpass(socket string, request rosenpassRequest) (rosenpassResponse, error) {
	var response rosenpassResponse
	deadline := time.Now().Add(rosenpassTimeout)
	conn, err := net.DialTimeout("unix", socket, rosenpassTimeout)
	if err != nil {
		return response, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return response, err
	}
	data, err := json.Marshal(request)
	if err != nil || len(data)+1 > rosenpassRPCSize {
		return response, errors.New("invalid Rosenpass request")
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return response, err
	}
	if err := readRosenpassJSON(conn, &response); err != nil {
		return rosenpassResponse{}, err
	}
	if response.Instance == "" || (response.Valid && (response.Generation == 0 || response.KeyGeneration == 0 ||
		response.Hash == [32]byte{} || !time.Now().Before(response.Expires) ||
		response.Expires.After(time.Now().Add(rosenpassLifetime)))) {
		return rosenpassResponse{}, errors.New("invalid Rosenpass status")
	}
	return response, nil
}

func readRosenpassJSON(r io.Reader, value any) error {
	line, err := bufio.NewReaderSize(r, rosenpassRPCSize).ReadSlice('\n')
	if err != nil {
		return errors.New("incomplete or oversized Rosenpass RPC")
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid Rosenpass RPC JSON")
	}
	return nil
}
