package service

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"x-ui/config"
	"x-ui/xray"
)

var coreHTTPClient = &http.Client{Timeout: 3 * time.Minute}
var coreVersionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func supportedCoreVersion(value string) bool {
	a, b := coreVersionPattern.FindStringSubmatch(value), coreVersionPattern.FindStringSubmatch(config.GetMinimumXrayVersion())
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, err := strconv.Atoi(a[i])
		if err != nil {
			return false
		}
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return true
}

func coreResponse(url string, limit int64) ([]byte, error) {
	response, err := coreHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("core download returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("core download exceeds size limit")
	}
	return data, err
}

func (s *ServerService) GetXrayVersions() ([]string, error) {
	data, err := coreResponse("https://api.github.com/repos/XTLS/Xray-core/releases", 8<<20)
	if err != nil {
		return nil, err
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(data, &releases); err != nil {
		return nil, err
	}
	versions := []string{}
	for _, r := range releases {
		if !r.Draft && !r.Prerelease && supportedCoreVersion(r.Tag) {
			versions = append(versions, r.Tag)
		}
	}
	return versions, nil
}

func coreArchiveName(goarch, goarm string) (string, error) {
	arch := map[string]string{"amd64": "64", "386": "32", "arm64": "arm64-v8a", "s390x": "s390x"}[goarch]
	if goarch == "arm" {
		switch strings.Split(goarm, ",")[0] {
		case "5":
			arch = "arm32-v5"
		case "6":
			arch = "arm32-v6"
		case "7":
			arch = "arm32-v7a"
		default:
			return "", fmt.Errorf("unknown built ARM variant %q", goarm)
		}
	}
	if arch == "" {
		return "", fmt.Errorf("unsupported core architecture %s", goarch)
	}
	return "Xray-linux-" + arch + ".zip", nil
}

func builtGoarm() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "GOARM" {
				return setting.Value
			}
		}
	}
	return ""
}

func (s *ServerService) UpdateXray(version string) error {
	if runtime.GOOS != "linux" {
		return errors.New("packaged core updates require Linux")
	}
	if !supportedCoreVersion(version) {
		return fmt.Errorf("this panel requires Xray %s or newer stable releases", config.GetMinimumXrayVersion())
	}
	version = "v" + strings.TrimPrefix(version, "v")
	name, err := coreArchiveName(runtime.GOARCH, builtGoarm())
	if err != nil {
		return err
	}
	data, err := coreResponse("https://api.github.com/repos/XTLS/Xray-core/releases/tags/"+version, 8<<20)
	if err != nil {
		return err
	}
	var release struct {
		Assets []struct {
			Name, Digest string
			URL          string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return err
	}
	var url, digest string
	for _, asset := range release.Assets {
		if asset.Name == name {
			url, digest = asset.URL, strings.TrimPrefix(asset.Digest, "sha256:")
			break
		}
	}
	if url == "" || len(digest) != 64 {
		return errors.New("official release is missing the architecture or SHA256 digest")
	}
	archive, err := coreResponse(url, 256<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), digest) {
		return errors.New("core archive SHA256 mismatch")
	}
	if err := os.MkdirAll(filepath.Dir(xray.GetBinaryPath()), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(xray.GetBinaryPath()), ".xray-update-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(archive); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	reader, err := zip.OpenReader(f.Name())
	if err != nil {
		return err
	}
	defer reader.Close()
	var binary *zip.File
	for _, entry := range reader.File {
		if entry.Name == "xray" {
			if binary != nil {
				return errors.New("duplicate core binary")
			}
			binary = entry
		}
	}
	if binary == nil || binary.UncompressedSize64 > 256<<20 {
		return errors.New("core archive has no valid binary")
	}
	input, err := binary.Open()
	if err != nil {
		return err
	}
	defer input.Close()
	candidate, err := os.CreateTemp(filepath.Dir(xray.GetBinaryPath()), ".xray-candidate-*")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	if _, err := io.Copy(candidate, io.LimitReader(input, 256<<20)); err != nil {
		candidate.Close()
		return err
	}
	if err := candidate.Chmod(0755); err != nil {
		candidate.Close()
		return err
	}
	if err := candidate.Close(); err != nil {
		return err
	}
	return s.installCoreCandidate(candidate.Name(), version)
}

func (s *ServerService) installCoreCandidate(candidate, version string) error {
	lock.Lock()
	defer lock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, candidate, "version").Output()
	if err != nil {
		return fmt.Errorf("check candidate core version: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 || strings.TrimPrefix(fields[1], "v") != strings.TrimPrefix(version, "v") {
		return errors.New("candidate core version differs from selected release")
	}
	conf, err := s.xrayService.GetXrayConfig()
	if err != nil {
		return err
	}
	if err := xray.ValidateConfigWithBinary(conf, candidate); err != nil {
		return err
	}
	path := xray.GetBinaryPath()
	// Inspect and reserve the rollback path before stopping the active core.
	_, statErr := os.Stat(path)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	backup, err := os.CreateTemp(filepath.Dir(path), ".xray-backup-*")
	if err != nil {
		return err
	}
	backup.Close()
	os.Remove(backup.Name())
	previous := currentXrayProcess()
	wasRunning := previous != nil && previous.IsRunning()
	if wasRunning {
		if err := previous.Stop(); err != nil {
			return err
		}
	}
	restoreRunning := func(cause error) error {
		if wasRunning {
			if err := previous.Start(); err != nil {
				return errors.Join(cause, fmt.Errorf("restore running core: %w", err))
			}
		}
		return cause
	}
	if statErr == nil {
		if err := os.Rename(path, backup.Name()); err != nil {
			return restoreRunning(err)
		}
	}
	rollback := func(cause error) error {
		os.Remove(path)
		if statErr == nil {
			if err := os.Rename(backup.Name(), path); err != nil {
				return errors.Join(cause, fmt.Errorf("restore core binary: %w", err))
			}
		}
		return restoreRunning(cause)
	}
	if err := os.Rename(candidate, path); err != nil {
		return rollback(err)
	}
	if wasRunning {
		next := xray.NewProcess(conf)
		if err := next.Start(); err != nil {
			return rollback(err)
		}
		processMu.Lock()
		p = next
		processMu.Unlock()
	}
	os.Remove(backup.Name())
	return nil
}
