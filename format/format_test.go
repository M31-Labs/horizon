package format

import (
	"testing"

	"m31labs.dev/horizon/parser"
)

func TestSourceFormatsCanonicalHorizon(t *testing.T) {
	input := []byte(`package probes
import bpf "m31labs.dev/horizon/runtime/kernel"
const FirstSeen u64=1
type Count struct {
seen u64
}
map Counts hash[u32,Count]
@capability("kernel.process.exec.count")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec)i32{
pid:=bpf.current_pid()
if Counts.update(pid, Count{seen:FirstSeen})!=0{return 0}
return 0
}`)
	got, err := Source(parser.SourceFile{Path: "inline.hzn", Bytes: input})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const FirstSeen u64 = 1

type Count struct {
    seen u64
}

map Counts hash[u32, Count]

@capability("kernel.process.exec.count")
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    pid := bpf.current_pid()
    if Counts.update(pid, Count{seen: FirstSeen}) != 0 {
        return 0
    }
    return 0
}
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestSourcePreservesStandaloneLineComments(t *testing.T) {
	got, err := Source(parser.SourceFile{Path: "commented.hzn", Bytes: []byte(`// package comment
package probes

// program comment
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    // return comment
    return 0
}
`)})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `// package comment
package probes

// program comment
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    // return comment
    return 0
}
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestSourcePreservesInlineLineComments(t *testing.T) {
	got, err := Source(parser.SourceFile{Path: "commented.hzn", Bytes: []byte(`package probes // package

type Event struct { // event
    pid u32 // process id
}

map Events ringbuf[Event] // event stream

@capability("kernel.process.exec.observe") // capability
@tracepoint("sched:sched_process_exec") // section
func OnExec(ctx tracepoint.Exec) i32 { // program
    event := Events.reserve() // reserve
    if event == nil { // guard
        return 0 // early return
    }
    Events.submit(event) // submit
    return 0 // done
} // end
`)})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `package probes // package

type Event struct { // event
    pid u32 // process id
}

map Events ringbuf[Event] // event stream

@capability("kernel.process.exec.observe") // capability
@tracepoint("sched:sched_process_exec") // section
func OnExec(ctx tracepoint.Exec) i32 { // program
    event := Events.reserve() // reserve
    if event == nil { // guard
        return 0 // early return
    }
    Events.submit(event) // submit
    return 0 // done
} // end
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestSourceFormatsMapAttributes(t *testing.T) {
	got, err := Source(parser.SourceFile{Path: "maps.hzn", Bytes: []byte(`package probes
@max_entries(4096)
map Counts hash[u32,u32]
`)})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `package probes

@max_entries(4096)
map Counts hash[u32, u32]
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestSourceFormatsPerCPUMaps(t *testing.T) {
	got, err := Source(parser.SourceFile{Path: "maps.hzn", Bytes: []byte(`package probes
map Counts percpu_hash[u32,u64]
map Slots percpu_array[u32,u64]
`)})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `package probes

map Counts percpu_hash[u32, u64]

map Slots percpu_array[u32, u64]
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestSourcePreservesElseInlineLineComment(t *testing.T) {
	got, err := Source(parser.SourceFile{Path: "commented.hzn", Bytes: []byte(`package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if true {
        return 0
    } else { // fallback
        return 1
    }
}
`)})
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	want := `package probes

@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    if true {
        return 0
    } else { // fallback
        return 1
    }
}
`
	if string(got) != want {
		t.Fatalf("formatted source mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}
