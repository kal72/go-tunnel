package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func UpdateClient(serverURL string, currentVersion string) error {
	fmt.Println("Checking for updates...")

	resp, err := http.Get(fmt.Sprintf("%s/api/cli/version", serverURL))
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %s", resp.Status)
	}

	var verResp struct {
		Version     string `json:"version"`
		DownloadURL string `json:"download_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&verResp); err != nil {
		return fmt.Errorf("failed to decode version response: %w", err)
	}

	if verResp.Version == currentVersion {
		fmt.Printf("You are already using the latest version (%s).\n", currentVersion)
		return nil
	}

	fmt.Printf("New version available: %s (current: %s)\n", verResp.Version, currentVersion)

	dlPath := verResp.DownloadURL
	dlPath = strings.ReplaceAll(dlPath, "{os}", runtime.GOOS)
	dlPath = strings.ReplaceAll(dlPath, "{arch}", runtime.GOARCH)

	if runtime.GOOS == "windows" {
		dlPath += ".exe"
	}

	fullURL := fmt.Sprintf("%s%s", serverURL, dlPath)
	fmt.Printf("Downloading %s...\n", fullURL)

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	// resolve symlinks if any
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("could not resolve symlinks for executable: %w", err)
	}

	exeDir := filepath.Dir(exePath)
	tmpPath := filepath.Join(exeDir, fmt.Sprintf(".gotunnel-update-%s", verResp.Version))

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("could not create temporary file %s: %w", tmpPath, err)
	}

	dlResp, err := http.Get(fullURL)
	if err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode != http.StatusOK {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("download failed with status: %s", dlResp.Status)
	}

	if _, err := io.Copy(out, dlResp.Body); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write update: %w", err)
	}
	out.Close()

	oldPath := exePath + ".old"
	os.Remove(oldPath)

	err = os.Rename(exePath, oldPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename current executable (try running as administrator/root): %w", err)
	}

	err = os.Rename(tmpPath, exePath)
	if err != nil {
		os.Rename(oldPath, exePath) // rollback
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	os.Remove(oldPath)

	fmt.Println("✅ Successfully updated to", verResp.Version)
	return nil
}
