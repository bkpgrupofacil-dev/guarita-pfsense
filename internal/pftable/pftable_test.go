package pftable

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/grupofacil/guarita/internal/config"
)

// fakeRunner registra as chamadas em vez de executar o pfctl.
type fakeRunner struct {
	mu       sync.Mutex
	replaced []string // "tabela=conteúdo do arquivo"
	failOn   string
}

func (f *fakeRunner) ReplaceTable(table, file string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != "" && table == f.failOn {
		return fmt.Errorf("tabela %s não existe no ruleset", table)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	f.replaced = append(f.replaced, table+"="+strings.TrimSpace(string(data)))
	return nil
}

func (f *fakeRunner) FlushTable(table string) error { return nil }

func (f *fakeRunner) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.replaced...)
	sort.Strings(out)
	return out
}

var groups = []config.Group{
	{Name: "Restrito", Table: "restrito"},
	{Name: "Liberado", Table: "liberado"},
}

func TestSyncWritesFilesAndCallsPfctl(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	w := NewWriter(dir, fr)

	snap := map[string][]string{
		"restrito": {"10.0.0.20", "10.0.0.10"},
		"liberado": {"10.0.0.30"},
	}
	if err := w.Sync(snap, groups); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// O arquivo precisa existir, com um IP por linha e em ordem.
	got, err := os.ReadFile(filepath.Join(dir, "restrito.txt"))
	if err != nil {
		t.Fatalf("lendo restrito.txt: %v", err)
	}
	want := "10.0.0.10\n10.0.0.20\n"
	if string(got) != want {
		t.Fatalf("restrito.txt = %q, esperava %q", got, want)
	}

	// O pfctl deve ter sido chamado com o nome prefixado da tabela.
	calls := fr.calls()
	if len(calls) != 2 {
		t.Fatalf("esperava 2 chamadas ao pfctl, veio %d: %v", len(calls), calls)
	}
	if calls[0] != "guarita_liberado=10.0.0.30" {
		t.Fatalf("chamada inesperada: %q", calls[0])
	}
}

func TestSyncCreatesEmptyTableForGroupWithoutMembers(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	w := NewWriter(dir, fr)

	// "liberado" não tem ninguém: o arquivo precisa existir vazio, senão o
	// alias do pfSense fica sem arquivo e a regra correspondente falha.
	if err := w.Sync(map[string][]string{"restrito": {"10.0.0.10"}}, groups); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "liberado.txt"))
	if err != nil {
		t.Fatalf("liberado.txt deveria existir: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("liberado.txt deveria estar vazio, tem %d bytes", fi.Size())
	}
}

func TestSyncRemovesStaleEntries(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	w := NewWriter(dir, fr)

	if err := w.Sync(map[string][]string{"restrito": {"10.0.0.10", "10.0.0.11"}}, groups); err != nil {
		t.Fatal(err)
	}
	// Segunda rodada com menos IPs: o arquivo é reescrito inteiro, o IP antigo sai.
	if err := w.Sync(map[string][]string{"restrito": {"10.0.0.11"}}, groups); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "restrito.txt"))
	if string(got) != "10.0.0.11\n" {
		t.Fatalf("esperava só o IP novo, veio %q", got)
	}
}

func TestSyncIncludesUnknownTablesFromSnapshot(t *testing.T) {
	// Defensivo: se uma sessão carregada do disco referencia um grupo que saiu
	// da configuração, ainda assim gravamos o arquivo, para não deixar lixo no pf.
	dir := t.TempDir()
	fr := &fakeRunner{}
	w := NewWriter(dir, fr)

	err := w.Sync(map[string][]string{"grupo_antigo": {"10.0.0.50"}}, groups)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "grupo_antigo.txt")); err != nil {
		t.Fatalf("grupo_antigo.txt deveria ter sido gravado: %v", err)
	}
}

func TestSyncReportsPfctlErrorButKeepsGoing(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{failOn: "guarita_restrito"}
	w := NewWriter(dir, fr)

	err := w.Sync(map[string][]string{
		"restrito": {"10.0.0.10"},
		"liberado": {"10.0.0.30"},
	}, groups)
	if err == nil {
		t.Fatal("esperava erro do pfctl")
	}
	// Apesar do erro em um grupo, o outro deve ter sido aplicado.
	calls := fr.calls()
	found := false
	for _, c := range calls {
		if strings.HasPrefix(c, "guarita_liberado=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("o grupo sem erro deveria ter sido aplicado: %v", calls)
	}
	// E o arquivo do grupo que falhou no pfctl ainda foi gravado em disco.
	if _, statErr := os.Stat(filepath.Join(dir, "restrito.txt")); statErr != nil {
		t.Fatalf("restrito.txt deveria existir mesmo com falha no pfctl: %v", statErr)
	}
}

func TestPfTableName(t *testing.T) {
	if got := config.PfTableName("vendas"); got != "guarita_vendas" {
		t.Fatalf("PfTableName = %q", got)
	}
}

func TestAtomicWriteLeavesNoTmp(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	w := NewWriter(dir, fr)
	if err := w.Sync(map[string][]string{"restrito": {"10.0.0.1"}}, groups); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("arquivo temporário ficou para trás: %s", e.Name())
		}
	}
}
