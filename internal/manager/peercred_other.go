//go:build !linux

package manager

import "errors"

func peerUID(fd int) (int, error) { return -1, errors.New("unsupported") }
