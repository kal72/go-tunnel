package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func CheckForNewVersion(serverURL, currentVersion string) {
	if currentVersion == "dev" || currentVersion == "v0.0" {
		return
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/api/cli/version", http.NoBody)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var verResp struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verResp); err != nil {
		return
	}

	if verResp.Version != "" && verResp.Version != currentVersion {
		yellow := "\033[1;33m"
		cyan := "\033[1;36m"
		green := "\033[1;32m"
		reset := "\033[0m"
		gray := "\033[90m"
		bold := "\033[1m"

		fmt.Printf("\n  %s╭─────────────────────────────────────────────────╮%s\n", yellow, reset)
		fmt.Printf("  %s│%s                                                 %s│%s\n", yellow, reset, yellow, reset)
		fmt.Printf("  %s│%s  🚀  %sUpdate Available:%s %s%s%s (current: %s%s%s) %s│%s\n", yellow, reset, bold, reset, green, verResp.Version, reset, gray, currentVersion, reset, yellow, reset)
		fmt.Printf("  %s│%s  👉  Run %sgotunnel update%s to upgrade now         %s│%s\n", yellow, reset, cyan, reset, yellow, reset)
		fmt.Printf("  %s│%s                                                 %s│%s\n", yellow, reset, yellow, reset)
		fmt.Printf("  %s╰─────────────────────────────────────────────────╯%s\n\n", yellow, reset)
	}
}

func UpdateClient(serverURL, currentVersion string) error {
	fmt.Println("Checking for updates...")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/api/cli/version", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	tmpPath := filepath.Join(exeDir, ".gotunnel-update-"+verResp.Version)

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("could not create temporary file %s: %w", tmpPath, err)
	}

	dlReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fullURL, http.NoBody) // #nosec G107
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to create update request: %w", err)
	}
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer func() { _ = dlResp.Body.Close() }()

	if dlResp.StatusCode != http.StatusOK {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download failed with status: %s", dlResp.Status)
	}

	if _, err := io.Copy(out, dlResp.Body); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write update: %w", err)
	}
	_ = out.Close()

	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)

	err = os.Rename(exePath, oldPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename current executable (try running as administrator/root): %w", err)
	}

	err = os.Rename(tmpPath, exePath)
	if err != nil {
		_ = os.Rename(oldPath, exePath) // rollback
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	_ = os.Remove(oldPath)

	fmt.Println("✅ Successfully updated to", verResp.Version)
	return nil
}
