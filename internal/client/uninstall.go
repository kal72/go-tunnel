package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func UninstallClient() error {
	fmt.Println("Uninstalling gotunnel...")

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("could not resolve symlinks for executable: %w", err)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		configDir := filepath.Join(home, ".gotunnel")
		if err := os.RemoveAll(configDir); err == nil {
			fmt.Println("Removed configuration directory:", configDir)
		}
	}

	if runtime.GOOS == "windows" {
		// On Windows, we cannot delete the running executable.
		// We spawn a detached command to delete it after a short delay.
		cmd := exec.Command("cmd", "/C", "ping 127.0.0.1 -n 2 > nul & del /F /Q", fmt.Sprintf("\"%s\"", exePath))
		err = cmd.Start()
		if err != nil {
			fmt.Printf("⚠️  Could not auto-delete executable. Please delete it manually: %s\n", exePath)
		} else {
			fmt.Println("Removed executable:", exePath)
		}
	} else {
		err = os.Remove(exePath)
		if err != nil {
			return fmt.Errorf("failed to remove executable (try running with sudo): %w", err)
		}
		fmt.Println("Removed executable:", exePath)
	}

	fmt.Println("✅ gotunnel has been successfully uninstalled.")
	return nil
}
