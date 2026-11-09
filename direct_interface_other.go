//go:build !linux

package main

import "errors"

type ownedDirectInterface struct{ Name string }

func (o *ownedDirectInterface) Close() error {
	return errors.New("automatic direct interface requires Linux")
}
func ensureDirectInterface(wgClient, string, string, uint16, uint16) (*ownedDirectInterface, error) {
	return nil, errors.New("automatic direct interface requires Linux")
}
func recoverDirectInterface(wgClient, string, string) error { return nil }
