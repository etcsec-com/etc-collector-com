//go:build !windows

package main

import "errors"

func installWindowsSCMService(binPath, mode string) error {
	return errors.New("Windows service installation not supported on this platform")
}

func startWindowsSCMService() error {
	return errors.New("Windows service not supported on this platform")
}

func stopWindowsSCMService() error {
	return errors.New("Windows service not supported on this platform")
}

func removeWindowsSCMService() error {
	return errors.New("Windows service not supported on this platform")
}
