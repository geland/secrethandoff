// Command release builds reproducible secrethandoff release assets.
// Run it from packages/cli-go:
//
//	go run ./release build
//	go run ./release package -base-url https://github.com/OWNER/REPO/releases/download/cli-vX.Y.Z
//
// "build" cross-compiles the six targets into dist/bin. CI may sign the
// macOS binaries in place between the two steps. "package" writes
// deterministic archives, SHA256SUMS, manifest.json, and the Homebrew,
// Scoop, and winget manifests into dist/release.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var targets = []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "windows/arm64"}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func main() {
	if _, err := os.Stat("go.mod"); err != nil {
		must(errors.New("run from packages/cli-go"))
	}
	if len(os.Args) < 2 {
		must(errors.New("usage: go run ./release build|package [-base-url URL]"))
	}
	switch os.Args[1] {
	case "build":
		build()
	case "package":
		fs := flag.NewFlagSet("package", flag.ExitOnError)
		baseURL := fs.String("base-url", "", "public URL of the release assets, without a trailing slash")
		must(fs.Parse(os.Args[2:]))
		if !strings.HasPrefix(*baseURL, "https://") {
			must(errors.New("-base-url must be an https URL"))
		}
		pkg(strings.TrimRight(*baseURL, "/"))
	default:
		must(fmt.Errorf("unknown step %q", os.Args[1]))
	}
}

func binaryName(goos string) string {
	if goos == "windows" {
		return "secrethandoff.exe"
	}
	return "secrethandoff"
}

func build() {
	must(os.RemoveAll("dist/bin"))
	for _, t := range targets {
		goos, goarch, _ := strings.Cut(t, "/")
		out := filepath.Join("dist", "bin", goos+"-"+goarch, binaryName(goos))
		must(os.MkdirAll(filepath.Dir(out), 0o755))
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", out, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		must(cmd.Run())
		fmt.Println("built", out)
	}
}

func readVersion() string {
	b, err := os.ReadFile("main.go")
	must(err)
	m := regexp.MustCompile(`const version = "([0-9]+\.[0-9]+\.[0-9]+)"`).FindSubmatch(b)
	if m == nil {
		must(errors.New("version const not found in main.go"))
	}
	return string(m[1])
}

// epoch is the fixed timestamp for archive entries, from SOURCE_DATE_EPOCH
// when set, so that the same inputs give the same bytes.
func epoch() time.Time {
	var sec int64
	fmt.Sscan(os.Getenv("SOURCE_DATE_EPOCH"), &sec) //nolint:errcheck // zero is a valid default
	if sec < 315532800 {
		sec = 315532800 // 1980-01-01, the earliest time a zip entry can hold
	}
	return time.Unix(sec, 0).UTC()
}

type file struct {
	name string
	data []byte
	mode int64
}

type asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func pkg(baseURL string) {
	ver := readVersion()
	license, err := os.ReadFile("LICENSE")
	must(err)
	readme, err := os.ReadFile("README.md")
	must(err)
	out := filepath.Join("dist", "release")
	must(os.RemoveAll(out))
	must(os.MkdirAll(out, 0o755))
	when := epoch()

	var assets, bundles []asset
	var sums strings.Builder
	for _, t := range targets {
		goos, goarch, _ := strings.Cut(t, "/")
		bin, err := os.ReadFile(filepath.Join("dist", "bin", goos+"-"+goarch, binaryName(goos)))
		must(err)
		files := []file{{binaryName(goos), bin, 0o755}, {"LICENSE", license, 0o644}, {"README.md", readme, 0o644}}
		name := fmt.Sprintf("secrethandoff_%s_%s_%s", ver, goos, goarch)
		var data []byte
		if goos == "windows" {
			name += ".zip"
			data = zipArchive(files, when)
		} else {
			name += ".tar.gz"
			data = tarGz(files, when)
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		must(os.WriteFile(filepath.Join(out, name), data, 0o644))
		fmt.Fprintf(&sums, "%s  %s\n", digest, name)
		assets = append(assets, asset{goos, goarch, name, baseURL + "/" + name, digest, len(data)})
		fmt.Printf("%s  %s\n", digest, name)
	}
	for _, t := range targets {
		goos, goarch, _ := strings.Cut(t, "/")
		bin, err := os.ReadFile(filepath.Join("dist", "bin", goos+"-"+goarch, binaryName(goos)))
		must(err)
		name := fmt.Sprintf("secrethandoff_%s_%s_%s.mcpb", ver, goos, goarch)
		data := zipArchive([]file{
			{"manifest.json", mcpbManifest(ver, goos), 0o644},
			{"server/" + binaryName(goos), bin, 0o755},
			{"LICENSE", license, 0o644},
		}, when)
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		must(os.WriteFile(filepath.Join(out, name), data, 0o644))
		fmt.Fprintf(&sums, "%s  %s\n", digest, name)
		bundles = append(bundles, asset{goos, goarch, name, baseURL + "/" + name, digest, len(data)})
	}
	must(os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(sums.String()), 0o644))
	writeServerJSON(out, ver, bundles)
	manifest, _ := json.MarshalIndent(map[string]any{"version": ver, "go": runtime.Version(), "assets": assets}, "", "  ")
	must(os.WriteFile(filepath.Join(out, "manifest.json"), append(manifest, '\n'), 0o644))
	writePackageManifests(out, ver, assets)
}

func tarGz(files []file, when time.Time) []byte {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	must(err)
	gz.ModTime = when
	tw := tar.NewWriter(gz)
	for _, f := range files {
		must(tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), ModTime: when, Format: tar.FormatPAX, Uname: "", Gname: ""}))
		_, err := tw.Write(f.data)
		must(err)
	}
	must(tw.Close())
	must(gz.Close())
	return buf.Bytes()
}

func zipArchive(files []file, when time.Time) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: when}
		h.SetMode(os.FileMode(f.mode))
		w, err := zw.CreateHeader(h)
		must(err)
		_, err = w.Write(f.data)
		must(err)
	}
	must(zw.Close())
	return buf.Bytes()
}

func find(assets []asset, goos, goarch string) asset {
	for _, a := range assets {
		if a.OS == goos && a.Arch == goarch {
			return a
		}
	}
	must(fmt.Errorf("no asset for %s/%s", goos, goarch))
	return asset{}
}

const homepage = "https://secrethandoff.com/agents"
const summary = "Give secrets to AI agents without the value entering the chat"

func writePackageManifests(out, ver string, assets []asset) {
	brew := fmt.Sprintf(`class Secrethandoff < Formula
  desc "%s"
  homepage "%s"
  version "%s"
  license "MIT"

  on_macos do
    on_arm do
      url "%s"
      sha256 "%s"
    end
    on_intel do
      url "%s"
      sha256 "%s"
    end
  end

  on_linux do
    on_arm do
      url "%s"
      sha256 "%s"
    end
    on_intel do
      url "%s"
      sha256 "%s"
    end
  end

  def install
    bin.install "secrethandoff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/secrethandoff version")
  end
end
`, summary, homepage, ver,
		find(assets, "darwin", "arm64").URL, find(assets, "darwin", "arm64").SHA256,
		find(assets, "darwin", "amd64").URL, find(assets, "darwin", "amd64").SHA256,
		find(assets, "linux", "arm64").URL, find(assets, "linux", "arm64").SHA256,
		find(assets, "linux", "amd64").URL, find(assets, "linux", "amd64").SHA256)
	must(os.MkdirAll(filepath.Join(out, "homebrew"), 0o755))
	must(os.WriteFile(filepath.Join(out, "homebrew", "secrethandoff.rb"), []byte(brew), 0o644))

	win64, winArm := find(assets, "windows", "amd64"), find(assets, "windows", "arm64")
	scoop, _ := json.MarshalIndent(map[string]any{
		"version": ver, "description": summary, "homepage": homepage, "license": "MIT",
		"architecture": map[string]any{
			"64bit": map[string]string{"url": win64.URL, "hash": win64.SHA256},
			"arm64": map[string]string{"url": winArm.URL, "hash": winArm.SHA256},
		},
		"bin": "secrethandoff.exe",
	}, "", "  ")
	must(os.MkdirAll(filepath.Join(out, "scoop"), 0o755))
	must(os.WriteFile(filepath.Join(out, "scoop", "secrethandoff.json"), append(scoop, '\n'), 0o644))

	id := "SecretHandoff.secrethandoff"
	dir := filepath.Join(out, "winget", ver)
	must(os.MkdirAll(dir, 0o755))
	must(os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(fmt.Sprintf("PackageIdentifier: %s\nPackageVersion: %s\nDefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.6.0\n", id, ver)), 0o644))
	must(os.WriteFile(filepath.Join(dir, id+".locale.en-US.yaml"), []byte(fmt.Sprintf("PackageIdentifier: %s\nPackageVersion: %s\nPackageLocale: en-US\nPublisher: Secret Handoff\nPackageName: secrethandoff\nLicense: MIT\nShortDescription: %s\nPackageUrl: %s\nManifestType: defaultLocale\nManifestVersion: 1.6.0\n", id, ver, summary, homepage)), 0o644))
	installer := fmt.Sprintf("PackageIdentifier: %s\nPackageVersion: %s\nInstallerType: zip\nNestedInstallerType: portable\nNestedInstallerFiles:\n  - RelativeFilePath: secrethandoff.exe\n    PortableCommandAlias: secrethandoff\nInstallers:\n  - Architecture: x64\n    InstallerUrl: %s\n    InstallerSha256: %s\n  - Architecture: arm64\n    InstallerUrl: %s\n    InstallerSha256: %s\nManifestType: installer\nManifestVersion: 1.6.0\n",
		id, ver, win64.URL, strings.ToUpper(win64.SHA256), winArm.URL, strings.ToUpper(winArm.SHA256))
	must(os.WriteFile(filepath.Join(dir, id+".installer.yaml"), []byte(installer), 0o644))
}

// mcpbPlatform maps GOOS to the MCPB platform names.
var mcpbPlatform = map[string]string{"darwin": "darwin", "linux": "linux", "windows": "win32"}

// mcpbManifest is the MCP Bundle manifest (MCPB spec, manifest_version
// 0.3) for one platform's binary.
func mcpbManifest(ver, goos string) []byte {
	b, _ := json.MarshalIndent(map[string]any{
		"manifest_version": "0.3",
		"name":             "secrethandoff",
		"display_name":     "Secret Handoff",
		"version":          ver,
		"description":      summary + ".",
		"author":           map[string]string{"name": "Greg Eland", "url": "https://gregeland.com"},
		"homepage":         homepage,
		"license":          "MIT",
		"server": map[string]any{
			"type":        "binary",
			"entry_point": "server/" + binaryName(goos),
			"mcp_config":  map[string]any{"command": "${__dirname}/server/" + binaryName(goos), "args": []string{"mcp"}},
		},
		"compatibility": map[string]any{"platforms": []string{mcpbPlatform[goos]}},
	}, "", "  ")
	return append(b, '\n')
}

// writeServerJSON writes the MCP Registry entry, with one MCPB package for
// each platform and its SHA-256.
func writeServerJSON(out, ver string, bundles []asset) {
	var packages []map[string]any
	for _, b := range bundles {
		packages = append(packages, map[string]any{
			"registryType": "mcpb",
			"identifier":   b.URL,
			"version":      ver,
			"fileSha256":   b.SHA256,
			"transport":    map[string]string{"type": "stdio"},
		})
	}
	server, _ := json.MarshalIndent(map[string]any{
		"$schema":     "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
		"name":        "com.secrethandoff/secrethandoff",
		"title":       "Secret Handoff",
		"description": summary + ".",
		"version":     ver,
		"websiteUrl":  homepage,
		"packages":    packages,
	}, "", "  ")
	must(os.MkdirAll(filepath.Join(out, "registry"), 0o755))
	must(os.WriteFile(filepath.Join(out, "registry", "server.json"), append(server, '\n'), 0o644))
}
