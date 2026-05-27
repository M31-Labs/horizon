package types_test

import (
	"testing"

	"m31labs.dev/horizon/types"
)

func TestParseDangerAxesFromString(t *testing.T) {
	t.Run("flat observe maps to axes", func(t *testing.T) {
		got, err := types.ParseDangerAxes("observe")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("flat mutate maps to axes", func(t *testing.T) {
		got, err := types.ParseDangerAxes("mutate")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "mutate", Scope: "process", Reversibility: "restart"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("flat drop maps to axes", func(t *testing.T) {
		got, err := types.ParseDangerAxes("drop")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("flat block maps to axes", func(t *testing.T) {
		got, err := types.ParseDangerAxes("block")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "control", Scope: "process", Reversibility: "restart"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("flat privileged maps to axes", func(t *testing.T) {
		got, err := types.ParseDangerAxes("privileged")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "mutate", Scope: "system", Reversibility: "persistent"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("explicit triple control,network,restart", func(t *testing.T) {
		got, err := types.ParseDangerAxes("control,network,restart")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("explicit triple observe,event,none", func(t *testing.T) {
		got, err := types.ParseDangerAxes("observe,event,none")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("explicit triple control,filesystem,restart", func(t *testing.T) {
		got, err := types.ParseDangerAxes("control,filesystem,restart")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := types.DangerAxes{Mode: "control", Scope: "filesystem", Reversibility: "restart"}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("invalid mode foo returns error", func(t *testing.T) {
		_, err := types.ParseDangerAxes("foo")
		if err == nil {
			t.Fatal("expected error for invalid flat mode, got nil")
		}
	})

	t.Run("invalid explicit triple bad mode", func(t *testing.T) {
		_, err := types.ParseDangerAxes("foo,network,restart")
		if err == nil {
			t.Fatal("expected error for invalid mode in triple, got nil")
		}
	})

	t.Run("invalid explicit triple bad scope", func(t *testing.T) {
		_, err := types.ParseDangerAxes("control,badscope,restart")
		if err == nil {
			t.Fatal("expected error for invalid scope in triple, got nil")
		}
	})

	t.Run("invalid explicit triple bad reversibility", func(t *testing.T) {
		_, err := types.ParseDangerAxes("control,network,badrev")
		if err == nil {
			t.Fatal("expected error for invalid reversibility in triple, got nil")
		}
	})

	t.Run("empty string returns error", func(t *testing.T) {
		_, err := types.ParseDangerAxes("")
		if err == nil {
			t.Fatal("expected error for empty string, got nil")
		}
	})
}

func TestDangerLevelAxes(t *testing.T) {
	tests := []struct {
		level types.DangerLevel
		want  types.DangerAxes
	}{
		{types.DangerObserve, types.DangerAxes{Mode: "observe", Scope: "event", Reversibility: "none"}},
		{types.DangerMutate, types.DangerAxes{Mode: "mutate", Scope: "process", Reversibility: "restart"}},
		{types.DangerDrop, types.DangerAxes{Mode: "control", Scope: "network", Reversibility: "restart"}},
		{types.DangerBlock, types.DangerAxes{Mode: "control", Scope: "process", Reversibility: "restart"}},
		{types.DangerPrivileged, types.DangerAxes{Mode: "mutate", Scope: "system", Reversibility: "persistent"}},
	}
	for _, tt := range tests {
		got := tt.level.Axes()
		if got != tt.want {
			t.Errorf("DangerLevel(%q).Axes() = %+v, want %+v", tt.level, got, tt.want)
		}
	}
}
