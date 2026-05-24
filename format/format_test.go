package format

import (
	"strings"
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

func TestSourceRefusesLineComments(t *testing.T) {
	_, err := Source(parser.SourceFile{Path: "commented.hzn", Bytes: []byte(`package probes

// keep this
@tracepoint("sched:sched_process_exec")
func OnExec(ctx tracepoint.Exec) i32 {
    return 0
}
`)})
	if err == nil || !strings.Contains(err.Error(), "does not preserve line comments") {
		t.Fatalf("Source error = %v, want line comment refusal", err)
	}
}
