//go:build !linux

package main

import (
	"context"
	"errors"
)

func runRosenpassAdapter(context.Context, string) error {
	return errors.New("Rosenpass adapter requires Linux SO_PEERCRED")
}
