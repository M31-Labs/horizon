// hzn-helpergen walks a pinned libbpf source tree and produces candidate
// helper-registry entries for review against the hand-curated
// internal/registry/helpers-v1.json.
//
// This tool is a developer aid; it is intentionally NOT wired into
// `make ci-go`. The libbpf source lives outside the tree and a network
// fetch on every CI run would couple build-correctness to external
// availability.
//
// Usage:
//
//	hzn-helpergen check                        diff candidates against on-disk registry
//	hzn-helpergen emit -o <path|->             write the candidate document
//	hzn-helpergen verify                       re-fetch + re-hash the pinned file
//
// All modes fetch from LibbpfHelperDefsURL() (pin.go) and verify the
// fetched bytes against LibbpfHelperDefsSHA256 before parsing. A hash
// mismatch is always a hard error — it means either the pinned commit
// no longer exists on GitHub or the file has been tampered with in
// flight.
//
// See docs/internal/helper-registry-regeneration.md for the refresh
// workflow.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RegistryHelper mirrors the on-disk JSON shape of one entry in
// internal/registry/helpers-v1.json. Only fields the generator reads or
// emits are modeled; unknown fields round-trip via json.RawMessage to
// keep diffs cosmetic-free when other fields evolve.
type RegistryHelper struct {
	Name         string          `json:"name"`
	KernelSymbol string          `json:"kernel_symbol"`
	Observes     []string        `json:"observes,omitempty"`
	Mutates      []string        `json:"mutates,omitempty"`
	Requires     []string        `json:"requires,omitempty"`
	Resource     string          `json:"resource,omitempty"`
	Introduced   string          `json:"introduced,omitempty"`
	Extras       json.RawMessage `json:"-"`
}

// RegistryDoc mirrors the on-disk top-level JSON of helpers-v1.json plus
// an additive Candidates field the generator populates with libbpf
// helpers Horizon does not yet annotate. The Candidates array never
// appears in the production registry on disk — it is an emit-only
// artifact for human review.
type RegistryDoc struct {
	Schema     string           `json:"schema"`
	Version    string           `json:"version"`
	Helpers    []RegistryHelper `json:"helpers"`
	Candidates []RegistryHelper `json:"candidates,omitempty"`
}

const (
	// onDiskRegistryRelPath is the path (relative to repo root) of the
	// hand-curated registry the tool diffs against.
	onDiskRegistryRelPath = "internal/registry/helpers-v1.json"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "check":
		if err := runCheck(args); err != nil {
			fmt.Fprintln(os.Stderr, "hzn-helpergen check:", err)
			os.Exit(1)
		}
	case "emit":
		if err := runEmit(args); err != nil {
			fmt.Fprintln(os.Stderr, "hzn-helpergen emit:", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(args); err != nil {
			fmt.Fprintln(os.Stderr, "hzn-helpergen verify:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "hzn-helpergen: unknown subcommand %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hzn-helpergen <check|emit|verify> [flags]")
	fmt.Fprintln(os.Stderr, "  check                       diff candidates against on-disk registry; exit non-zero on drift")
	fmt.Fprintln(os.Stderr, "  emit -o <path|->            write the candidate document (use - for stdout)")
	fmt.Fprintln(os.Stderr, "  verify                      re-fetch the pinned file and verify its sha256")
}

func runCheck(_ []string) error {
	src, err := fetchAndVerifyPinned()
	if err != nil {
		return err
	}
	parsed, err := ParseBPFHelperDefs(src)
	if err != nil {
		return err
	}

	onDiskPath, err := findRegistryFile()
	if err != nil {
		return err
	}
	onDisk, err := loadRegistry(onDiskPath)
	if err != nil {
		return err
	}

	candidates := BuildCandidates(parsed, onDisk)
	diff := DiffRegistries(onDisk.Helpers, candidates.Helpers)
	if diff == "" && len(candidates.Helpers) == len(onDisk.Helpers) {
		fmt.Fprintf(os.Stderr, "hzn-helpergen: OK — %d hand-curated helpers, %d libbpf candidates (no drift)\n",
			len(onDisk.Helpers), len(candidates.Candidates))
		return nil
	}
	fmt.Println(diff)
	return fmt.Errorf("registry drift detected against libbpf pin %s", LibbpfCommit)
}

func runEmit(args []string) error {
	out := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" && i+1 < len(args) {
			out = args[i+1]
			i++
		}
	}
	if out == "" {
		return fmt.Errorf("missing required -o <path|-> flag")
	}

	src, err := fetchAndVerifyPinned()
	if err != nil {
		return err
	}
	parsed, err := ParseBPFHelperDefs(src)
	if err != nil {
		return err
	}

	onDiskPath, err := findRegistryFile()
	if err != nil {
		return err
	}
	onDisk, err := loadRegistry(onDiskPath)
	if err != nil {
		return err
	}

	doc := BuildCandidates(parsed, onDisk)
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal candidate doc: %w", err)
	}
	buf = append(buf, '\n')

	if out == "-" {
		_, err = os.Stdout.Write(buf)
		return err
	}
	if err := os.WriteFile(out, buf, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Fprintf(os.Stderr, "hzn-helpergen: wrote %s (%d helpers, %d candidates)\n",
		out, len(doc.Helpers), len(doc.Candidates))
	return nil
}

func runVerify(_ []string) error {
	_, err := fetchAndVerifyPinned()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "hzn-helpergen: verified pin %s (%s)\n", LibbpfCommit, LibbpfHelperDefsPath)
	return nil
}

// fetchAndVerifyPinned fetches LibbpfHelperDefsURL() over HTTPS and
// asserts the body's sha256 matches LibbpfHelperDefsSHA256.
func fetchAndVerifyPinned() ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, LibbpfHelperDefsURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "hzn-helpergen (m31labs.dev/horizon)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", LibbpfHelperDefsURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", LibbpfHelperDefsURL(), resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != LibbpfHelperDefsSHA256 {
		return nil, fmt.Errorf("sha256 mismatch for %s: got %s, want %s (pin is stale or fetch was tampered)",
			LibbpfHelperDefsPath, got, LibbpfHelperDefsSHA256)
	}
	return body, nil
}

// findRegistryFile locates internal/registry/helpers-v1.json by walking
// upward from the current working directory until the file is found.
// Allows the tool to run from any subdirectory of the repo without an
// explicit -registry flag.
func findRegistryFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, onDiskRegistryRelPath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate %s in any parent of working directory", onDiskRegistryRelPath)
		}
		dir = parent
	}
}

func loadRegistry(path string) (*RegistryDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc RegistryDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &doc, nil
}

// BuildCandidates assembles a RegistryDoc from a parsed libbpf helper
// set plus the on-disk registry. The Helpers array is the on-disk array
// verbatim (preserves hand-curated annotations); the Candidates array
// contains TODO placeholder entries for every libbpf helper whose
// kernel_symbol is not already in the on-disk Helpers.
func BuildCandidates(parsed []LibbpfHelper, onDisk *RegistryDoc) *RegistryDoc {
	known := make(map[string]bool, len(onDisk.Helpers))
	for _, h := range onDisk.Helpers {
		known[h.KernelSymbol] = true
	}

	cands := make([]RegistryHelper, 0, len(parsed))
	for _, h := range parsed {
		if known[h.KernelSymbol] {
			continue
		}
		cands = append(cands, RegistryHelper{
			Name:         "TODO." + strings.TrimPrefix(h.KernelSymbol, "bpf_"),
			KernelSymbol: h.KernelSymbol,
			Introduced:   "libbpf-pin@" + shortCommit(LibbpfCommit),
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].KernelSymbol < cands[j].KernelSymbol })

	return &RegistryDoc{
		Schema:     onDisk.Schema,
		Version:    onDisk.Version,
		Helpers:    onDisk.Helpers,
		Candidates: cands,
	}
}

func shortCommit(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	return sha
}
