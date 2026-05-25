package grammar

import (
	"slices"
	"testing"

	gotreesitter "github.com/odvcencio/gotreesitter"
)

const queryFixture = `package probes

import bpf "m31labs.dev/horizon/runtime/kernel"

const (
    EventBytes u32 = 262144
    HTTPS Port = 443
)

enum PacketAction i32 {
    PacketPass = 2
    PacketDrop = 1
}

capability DropCapability = "kernel.network.xdp.drop"

type Port = u16

type Event struct {
    pid u32
    port Port
    ok bool
}

@max_entries(EventBytes)
map Events ringbuf[Event]

@capability(DropCapability)
@xdp
func DropTCP(ctx xdp.Context) i32 {
    // keep packet access typed and nil-checked
    var port Port = HTTPS
    tcp := xdp.tcp(ctx)
    if tcp == nil {
        return xdp.Pass
    }
    if true && (xdp.ntohs(tcp.dst_port) == port) {
        return xdp.Drop
    }
    switch xdp.ntohs(tcp.dst_port) {
    case 80, 443:
        return xdp.Drop
    default:
        return xdp.Pass
    }
    return xdp.Pass
}
`

func TestQueriesCompile(t *testing.T) {
	lang := testLanguage(t)
	for name, query := range map[string]string{
		"highlights": HighlightsQuery,
		"locals":     LocalsQuery,
		"symbols":    SymbolsQuery,
	} {
		if _, err := gotreesitter.NewQuery(query, lang); err != nil {
			t.Fatalf("%s query failed to compile: %v", name, err)
		}
	}
}

func TestHighlightsQueryCoversCurrentLanguageSurface(t *testing.T) {
	captures := queryCaptures(t, HighlightsQuery, []byte(queryFixture))

	assertCaptureContains(t, captures, "keyword", "package", "import", "const", "enum", "capability", "type", "struct", "map", "func", "var", "if", "switch", "case", "default", "return")
	assertCaptureContains(t, captures, "attribute", "max_entries", "capability", "xdp")
	assertCaptureContains(t, captures, "comment", "// keep packet access typed and nil-checked")
	assertCaptureContains(t, captures, "string", `"m31labs.dev/horizon/runtime/kernel"`, `"kernel.network.xdp.drop"`)
	assertCaptureContains(t, captures, "number", "262144", "2", "1", "443", "80")
	assertCaptureContains(t, captures, "constant.builtin", "nil", "true")
	assertCaptureContains(t, captures, "function", "DropTCP")
	assertCaptureContains(t, captures, "function.method", "tcp", "ntohs")
	assertCaptureContains(t, captures, "namespace", "bpf", "xdp")
	assertCaptureContains(t, captures, "type", "Port", "Event")
	assertCaptureContains(t, captures, "variable.parameter", "ctx")
}

func TestLocalsQueryCapturesScopesDefinitionsAndReferences(t *testing.T) {
	captures := queryCaptures(t, LocalsQuery, []byte(queryFixture))

	assertCaptureContains(t, captures, "local.definition.function", "DropTCP")
	assertCaptureContains(t, captures, "local.definition.type", "Port", "Event")
	assertCaptureContains(t, captures, "local.definition.enum", "PacketAction")
	assertCaptureContains(t, captures, "local.definition.constant", "EventBytes", "HTTPS")
	assertCaptureContains(t, captures, "local.definition.constant", "PacketPass", "PacketDrop")
	assertCaptureContains(t, captures, "local.definition.capability", "DropCapability")
	assertCaptureContains(t, captures, "local.definition.map", "Events")
	assertCaptureContains(t, captures, "local.definition.parameter", "ctx")
	assertCaptureContains(t, captures, "local.definition.var", "tcp", "port")
	assertCaptureContains(t, captures, "local.definition.namespace", "bpf")
	assertCaptureContains(t, captures, "local.reference", "tcp", "ctx", "xdp", "DropCapability", "HTTPS", "port")
	if len(captures["local.scope"]) < 4 {
		t.Fatalf("local.scope captures = %d, want at least source, block, and switch case scopes", len(captures["local.scope"]))
	}
}

func TestSymbolsQueryCapturesAuthoringOutline(t *testing.T) {
	captures := queryCaptures(t, SymbolsQuery, []byte(queryFixture))

	assertCaptureContains(t, captures, "name", "probes", "bpf", "EventBytes", "HTTPS", "PacketAction", "PacketPass", "PacketDrop", "DropCapability", "Port", "Event", "pid", "port", "ok", "Events", "max_entries", "capability", "xdp", "DropTCP")
	if len(captures["definition.function"]) == 0 {
		t.Fatal("definition.function captures = 0, want function outline entry")
	}
	if len(captures["definition.enum"]) == 0 {
		t.Fatal("definition.enum captures = 0, want enum outline entry")
	}
	if len(captures["definition.capability"]) == 0 {
		t.Fatal("definition.capability captures = 0, want capability outline entry")
	}
	if len(captures["definition.map"]) == 0 {
		t.Fatal("definition.map captures = 0, want map outline entry")
	}
	if len(captures["definition.attribute"]) < 3 {
		t.Fatalf("definition.attribute captures = %d, want max_entries, capability, and xdp", len(captures["definition.attribute"]))
	}
}

func queryCaptures(t *testing.T, querySource string, source []byte) map[string][]string {
	t.Helper()
	lang := testLanguage(t)
	parser := gotreesitter.NewParser(lang)
	tree, err := parser.Parse(source)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if tree.RootNode().HasError() {
		t.Fatalf("fixture parsed with errors: %s", tree.RootNode().SExpr(lang))
	}
	query, err := gotreesitter.NewQuery(querySource, lang)
	if err != nil {
		t.Fatalf("compile query: %v", err)
	}
	out := map[string][]string{}
	for _, match := range query.ExecuteNode(tree.RootNode(), lang, source) {
		for _, capture := range match.Captures {
			if capture.Name == "" {
				t.Fatalf("empty capture name in match %#v", match)
			}
			out[capture.Name] = append(out[capture.Name], capture.Text(source))
		}
	}
	return out
}

func assertCaptureContains(t *testing.T, captures map[string][]string, name string, texts ...string) {
	t.Helper()
	got := captures[name]
	for _, text := range texts {
		if !slices.Contains(got, text) {
			t.Fatalf("%s captures = %#v, want %q", name, got, text)
		}
	}
}

func testLanguage(t *testing.T) *gotreesitter.Language {
	t.Helper()
	lang, err := Language()
	if err != nil {
		t.Fatalf("load language: %v", err)
	}
	return lang
}
