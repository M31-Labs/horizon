package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"m31labs.dev/horizon/compiler"
)

// runCache implements `hzn cache <subcommand>` — module-cache hygiene
// (roadmap #14 follow-up). Subcommands:
//
//	hzn cache list            list cached entries + sizes (no deletion)
//	hzn cache prune [flags]   evict entries by policy
//
// `prune` policy flags:
//
//	-older-than <dur>   evict entries fetched longer ago than <dur>
//	-max-size <bytes>   evict oldest entries (LRU by fetched_at) until
//	                    the total cache size is at or under <bytes>
//	-dry-run            preview the eviction; delete nothing
//
// A bare `hzn cache prune` (no policy flag) is deliberately non-
// destructive: it lists entries + sizes and deletes nothing, so a
// fat-fingered invocation never evicts without an explicit policy.
// An empty / nonexistent cache is a clean no-op for every subcommand.
func runCache(args []string) error {
	sub := ""
	rest := args
	if len(args) > 0 {
		sub = args[0]
		rest = args[1:]
	}
	switch sub {
	case "prune":
		return runCachePrune(rest)
	case "", "list":
		return runCacheList()
	default:
		return fmt.Errorf("unknown cache subcommand %q (want: list, prune)", sub)
	}
}

// runCacheList prints every cache entry with its size and fetch time.
// It never deletes. Used directly by `hzn cache list` and as the
// non-destructive default for a bare `hzn cache prune`.
func runCacheList() error {
	entries, err := compiler.CacheEntries()
	if err != nil {
		return fmt.Errorf("read cache: %w", err)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "hzn cache: empty (no cached modules)")
		return nil
	}
	var total int64
	for _, e := range entries {
		total += e.SizeBytes
		fmt.Fprintf(os.Stderr, "  %s  %s  fetched %s\n",
			humanBytes(e.SizeBytes), e.Dir, fetchedLabel(e.Meta.FetchedAt))
	}
	fmt.Fprintf(os.Stderr, "hzn cache: %d entr%s, %s total\n",
		len(entries), plural(len(entries)), humanBytes(total))
	return nil
}

// runCachePrune evicts entries per the supplied policy. With no policy
// flag it falls back to the non-destructive list path.
func runCachePrune(args []string) error {
	fs := flag.NewFlagSet("cache prune", flag.ContinueOnError)
	olderThan := fs.Duration("older-than", 0, "evict entries fetched longer ago than this duration (e.g. 720h)")
	maxSize := fs.Int64("max-size", 0, "evict oldest entries until total cache size is at or under this many bytes")
	dryRun := fs.Bool("dry-run", false, "preview evictions without deleting")
	// Parse directly rather than via parseFlags/reorderFlags: cache
	// prune's value-taking flags (-older-than/-max-size) are not in the
	// shared flagNeedsValue allow-list, and reorderFlags would split a
	// flag from its value. `hzn cache prune` takes no positionals, so a
	// straight fs.Parse is correct and keeps the change inside cache.go.
	if err := fs.Parse(args); err != nil {
		return err
	}

	entries, err := compiler.CacheEntries()
	if err != nil {
		return fmt.Errorf("read cache: %w", err)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "hzn cache prune: cache is empty — nothing to do")
		return nil
	}

	// No policy flag → non-destructive list. Keeps a bare
	// `hzn cache prune` from ever deleting without an explicit policy.
	if *olderThan == 0 && *maxSize == 0 {
		fmt.Fprintln(os.Stderr, "hzn cache prune: no policy flag (-older-than/-max-size) — listing only, deleting nothing")
		return runCacheList()
	}

	evict := selectEvictions(entries, *olderThan, *maxSize, time.Now().UTC())
	if len(evict) == 0 {
		fmt.Fprintln(os.Stderr, "hzn cache prune: no entries match the eviction policy")
		return nil
	}

	var freed int64
	for _, e := range evict {
		freed += e.SizeBytes
		if *dryRun {
			fmt.Fprintf(os.Stderr, "hzn cache prune: would evict %s (%s)\n", e.Dir, humanBytes(e.SizeBytes))
			continue
		}
		if err := os.RemoveAll(e.Dir); err != nil {
			return fmt.Errorf("evict %s: %w", e.Dir, err)
		}
		fmt.Fprintf(os.Stderr, "hzn cache prune: evicted %s (%s)\n", e.Dir, humanBytes(e.SizeBytes))
	}
	verb := "evicted"
	if *dryRun {
		verb = "would evict"
	}
	fmt.Fprintf(os.Stderr, "hzn cache prune: %s %d entr%s, %s\n",
		verb, len(evict), plural(len(evict)), humanBytes(freed))
	return nil
}

// selectEvictions returns the entries to evict given the policy. The
// two policies compose: an entry is evicted if it is older than the
// by-age cutoff OR if it falls outside the size budget under LRU.
//
//   - by-age (-older-than > 0): evict entries whose FetchedAt is before
//     now-olderThan. A zero FetchedAt (missing/corrupt meta) is treated
//     as the epoch — i.e. always older than any positive cutoff — so a
//     half-written entry is prunable.
//   - LRU-by-size (-max-size > 0): sort entries oldest-first by
//     FetchedAt and evict from the front until the surviving total is
//     at or under the budget.
func selectEvictions(entries []compiler.CacheEntry, olderThan time.Duration, maxSize int64, now time.Time) []compiler.CacheEntry {
	evictSet := make(map[string]bool)
	var evict []compiler.CacheEntry

	mark := func(e compiler.CacheEntry) {
		if evictSet[e.Dir] {
			return
		}
		evictSet[e.Dir] = true
		evict = append(evict, e)
	}

	if olderThan > 0 {
		cutoff := now.Add(-olderThan)
		for _, e := range entries {
			// Zero time is before any positive cutoff (epoch) → evicted.
			if e.Meta.FetchedAt.Before(cutoff) {
				mark(e)
			}
		}
	}

	if maxSize > 0 {
		// LRU: oldest FetchedAt first. A zero FetchedAt sorts oldest.
		sorted := make([]compiler.CacheEntry, len(entries))
		copy(sorted, entries)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Meta.FetchedAt.Before(sorted[j].Meta.FetchedAt)
		})
		var total int64
		for _, e := range sorted {
			total += e.SizeBytes
		}
		// Evict oldest-first until total is at or under budget.
		for _, e := range sorted {
			if total <= maxSize {
				break
			}
			if !evictSet[e.Dir] {
				mark(e)
			}
			total -= e.SizeBytes
		}
	}

	return evict
}

// fetchedLabel renders a fetch timestamp for the list view, marking a
// zero (missing/corrupt meta) timestamp explicitly.
func fetchedLabel(t time.Time) string {
	if t.IsZero() {
		return "unknown (missing meta)"
	}
	return t.Format(time.RFC3339)
}

// humanBytes renders a byte count in a compact, human-readable unit.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// plural returns "y" for 1 and "ies" otherwise, for "entr%s".
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
