package main

import (
	"strings"
	"testing"
)

func TestParseBPFHelperDefs_SimpleEntry(t *testing.T) {
	src := []byte(`/* auto-generated header */
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
`)
	got, err := ParseBPFHelperDefs(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 helper, got %d (%+v)", len(got), got)
	}
	if got[0].KernelSymbol != "bpf_map_lookup_elem" {
		t.Errorf("kernel symbol: want bpf_map_lookup_elem, got %q", got[0].KernelSymbol)
	}
	if got[0].HelperID != 1 {
		t.Errorf("helper id: want 1, got %d", got[0].HelperID)
	}
}

func TestParseBPFHelperDefs_HandlesComments(t *testing.T) {
	// Real-world shape: block comments precede every declaration in
	// libbpf's bpf_helper_defs.h. Mix in line comments + a forward
	// declaration to confirm the parser ignores non-helper lines.
	src := []byte(`/* SPDX-License-Identifier: foo */

/* Forward declarations of BPF structs */
struct bpf_fib_lookup;
struct pt_regs;

/*
 * bpf_map_lookup_elem
 *
 *   Perform a lookup in *map* for an entry associated to *key*.
 *
 * Returns
 *   Map value associated to *key*, or NULL if no entry was found.
 */
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

// stray single-line comment

/*
 * bpf_map_update_elem
 */
static long (* const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
`)
	got, err := ParseBPFHelperDefs(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 helpers, got %d (%+v)", len(got), got)
	}
	if got[0].KernelSymbol != "bpf_map_lookup_elem" || got[1].KernelSymbol != "bpf_map_update_elem" {
		t.Errorf("symbols out of order: got [%s, %s]", got[0].KernelSymbol, got[1].KernelSymbol)
	}
}

func TestParseBPFHelperDefs_RejectsTruncated(t *testing.T) {
	// A static line that's helper-shaped but missing the id assignment
	// should error rather than silently dropping the declaration.
	src := []byte(`static long (* const bpf_map_update_elem)(void *map, const void *key) = (void *) ;
`)
	_, err := ParseBPFHelperDefs(src)
	if err == nil {
		t.Fatal("want error on truncated declaration, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognized static declaration") {
		t.Errorf("want shape-mismatch error, got %v", err)
	}
}

func TestParseBPFHelperDefs_RejectsEmpty(t *testing.T) {
	if _, err := ParseBPFHelperDefs(nil); err == nil {
		t.Fatal("want error on empty input, got nil")
	}
	if _, err := ParseBPFHelperDefs([]byte("// just comments\n/* and more */\n")); err == nil {
		t.Fatal("want error when input has no declarations, got nil")
	}
}

func TestParseBPFHelperDefs_ExtractsKernelSymbolName(t *testing.T) {
	// Sample shapes representative of every return-type the pinned
	// header exhibits (void *, long, __u64, struct foo *, etc.).
	src := []byte(`
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (* const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static __u64 (* const bpf_ktime_get_ns)(void) = (void *) 5;
static struct bpf_sock *(* const bpf_sk_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 84;
static __bpf_fastcall __u32 (* const bpf_get_smp_processor_id)(void) = (void *) 8;
`)
	got, err := ParseBPFHelperDefs(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Parser sorts by helper id ascending; the fixture ids are
	// 1, 2, 5, 8, 84 — so the expected order interleaves struct-return
	// and __u64-return shapes.
	wantSymbols := []string{"bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_ktime_get_ns", "bpf_get_smp_processor_id", "bpf_sk_lookup_tcp"}
	if len(got) != len(wantSymbols) {
		t.Fatalf("want %d helpers, got %d", len(wantSymbols), len(got))
	}
	for i, w := range wantSymbols {
		if got[i].KernelSymbol != w {
			t.Errorf("helper %d: want %q, got %q (id=%d)", i, w, got[i].KernelSymbol, got[i].HelperID)
		}
	}
}

func TestParseBPFHelperDefs_DetectsDuplicates(t *testing.T) {
	src := []byte(`
static long (* const bpf_dup)(void) = (void *) 1;
static long (* const bpf_dup)(void) = (void *) 2;
`)
	_, err := ParseBPFHelperDefs(src)
	if err == nil {
		t.Fatal("want duplicate-symbol error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate-symbol error, got %v", err)
	}
}

func TestParseBPFHelperDefs_SortsByID(t *testing.T) {
	// Header file is already sorted but parser must not depend on
	// input order — verify with an unsorted fixture.
	src := []byte(`
static long (* const bpf_helper_b)(void) = (void *) 5;
static long (* const bpf_helper_a)(void) = (void *) 1;
static long (* const bpf_helper_c)(void) = (void *) 3;
`)
	got, err := ParseBPFHelperDefs(src)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantOrder := []int{1, 3, 5}
	for i, w := range wantOrder {
		if got[i].HelperID != w {
			t.Errorf("position %d: want id %d, got id %d (%q)", i, w, got[i].HelperID, got[i].KernelSymbol)
		}
	}
}
