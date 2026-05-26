package capability

import (
	"reflect"
	"testing"
)

// TestLookupHelperEffectsByName exercises the public LookupHelperEffects
// accessor end-to-end against the embedded registry. The accessor is the
// integration handle downstream consumers (notably the maple track's
// helper-effect summary lattice in roadmap #13) call into; the table
// covers the three behavioural cases:
//
//   - a static observation helper (no map / ringbuf placeholder) — the
//     template surfaces with its observe vocabulary unchanged.
//   - a ringbuf resource helper — the template surfaces with its
//     placeholder "ringbuf:$" preserved verbatim, deferring substitution
//     to ComputeHelperEffectsForFunction at emit time.
//   - an unknown name — the accessor reports (_, false) without
//     allocating a default template.
func TestLookupHelperEffectsByName(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		want    HelperEffectTemplate
		wantOk  bool
	}{
		{
			name:   "static observation helper",
			query:  "bpf.current_pid",
			want:   HelperEffectTemplate{Name: "bpf.current_pid", Observes: []string{"task.tgid"}},
			wantOk: true,
		},
		{
			name:   "ringbuf resource helper preserves placeholder",
			query:  "ringbuf.reserve",
			want:   HelperEffectTemplate{Name: "ringbuf.reserve", Mutates: []string{"ringbuf:$"}, Resource: "reserve"},
			wantOk: true,
		},
		{
			name:   "current_ppid carries BTF requires",
			query:  "bpf.current_ppid",
			want:   HelperEffectTemplate{Name: "bpf.current_ppid", Observes: []string{"task.real_parent.tgid"}, Requires: []string{"task_struct.real_parent"}},
			wantOk: true,
		},
		{
			name:   "unknown helper returns false",
			query:  "bpf.unknown_helper",
			want:   HelperEffectTemplate{},
			wantOk: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := LookupHelperEffects(tc.query)
			if ok != tc.wantOk {
				t.Fatalf("LookupHelperEffects(%q) ok = %v, want %v", tc.query, ok, tc.wantOk)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("LookupHelperEffects(%q) = %+v, want %+v", tc.query, got, tc.want)
			}
		})
	}
}

// TestLookupHelperEffectsReturnsIndependentSlices guards the immutability
// promise the plan locks in §D-5: callers may freely mutate the slices
// they receive without poisoning the registry. The accessor must hand out
// fresh copies of every slice field — observe / mutate / requires — so a
// downstream consumer that wants to append a substituted token cannot
// corrupt the underlying singleton.
func TestLookupHelperEffectsReturnsIndependentSlices(t *testing.T) {
	first, ok := LookupHelperEffects("ringbuf.reserve")
	if !ok {
		t.Fatalf("ringbuf.reserve missing from registry")
	}
	if len(first.Mutates) == 0 {
		t.Fatalf("ringbuf.reserve has no mutates entry")
	}
	first.Mutates[0] = "ringbuf:CORRUPTED"

	second, ok := LookupHelperEffects("ringbuf.reserve")
	if !ok {
		t.Fatalf("ringbuf.reserve missing from registry on second lookup")
	}
	if second.Mutates[0] != "ringbuf:$" {
		t.Fatalf("registry mutates slice was poisoned: got %q, want %q", second.Mutates[0], "ringbuf:$")
	}
}
