package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func touch(t *testing.T, path string, when time.Time) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// Reproduz o pfSense 2.9: uma recarga em que o ruleset não mudou reescreve só o
// filter_reload_status, não o rules.debug, e mesmo assim esvazia as tabelas.
// Observando só o rules.debug, essa recarga passava despercebida.
func TestReloadWatcherSeesSkippedReload(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.debug")
	status := filepath.Join(dir, "filter_reload_status")
	base := time.Now().Add(-time.Hour)
	touch(t, rules, base)
	touch(t, status, base)

	w := newReloadWatcher(rules, status)
	if f, ok := w.changed(); ok {
		t.Fatalf("nada mudou, mas changed() disse %q", f)
	}

	// Recarga "pulada": só o arquivo de status muda.
	touch(t, status, base.Add(time.Minute))
	f, ok := w.changed()
	if !ok || f != status {
		t.Fatalf("recarga pulada não detectada: changed() = %q, %v", f, ok)
	}
	if f, ok := w.changed(); ok {
		t.Fatalf("a mesma recarga contou duas vezes: %q", f)
	}

	// Recarga completa: os dois mudam, conta uma vez só.
	touch(t, rules, base.Add(2*time.Minute))
	touch(t, status, base.Add(2*time.Minute))
	if _, ok := w.changed(); !ok {
		t.Fatal("recarga completa não detectada")
	}
	if f, ok := w.changed(); ok {
		t.Fatalf("recarga completa contou duas vezes: %q", f)
	}
}

func TestReloadWatcherIgnoresEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "ainda-nao-existe")
	w := newReloadWatcher("", missing)
	if _, ok := w.changed(); ok {
		t.Fatal("arquivo ausente não pode contar como recarga")
	}
	// Quando o arquivo aparece, conta como recarga.
	touch(t, missing, time.Now())
	if f, ok := w.changed(); !ok || f != missing {
		t.Fatalf("arquivo que surgiu não detectado: %q, %v", f, ok)
	}
}
