package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grupofacil/guarita/internal/config"
	"github.com/grupofacil/guarita/internal/session"
)

// E3 do laboratório: o usuário foi movido de "liberado" para "bloqueio" no AD,
// e o "Reaplicar tabelas" (Resync) não mudava a sessão, porque não reconsultava
// os grupos. refreshSessions é o que o Resync e o refreshLoop usam agora.
func TestRefreshSessionsMovesUserToNewGroup(t *testing.T) {
	m := session.New(time.Hour, filepath.Join(t.TempDir(), "s.json"))
	ip := netip.MustParseAddr("192.168.1.100")
	m.Upsert(ip, "leandroliberado", "TESTE", []string{"liberado"}, "ad-agent")

	ad := func(user string) ([]string, error) { return []string{"bloqueio"}, nil }
	n := refreshSessions(context.Background(), m, m.NeedGroupRefresh(0), ad, t.Logf)
	if n != 1 {
		t.Fatalf("esperava 1 sessão alterada, veio %d", n)
	}
	s, _ := m.Lookup(ip)
	if len(s.Groups) != 1 || s.Groups[0] != "bloqueio" {
		t.Fatalf("grupos = %v, quero [bloqueio]", s.Groups)
	}
}

// Uma falha ao consultar o AD mantém os grupos que a sessão já tinha.
func TestRefreshSessionsKeepsGroupsOnError(t *testing.T) {
	m := session.New(time.Hour, filepath.Join(t.TempDir(), "s.json"))
	ip := netip.MustParseAddr("192.168.1.100")
	m.Upsert(ip, "leandro", "TESTE", []string{"liberado"}, "ad-agent")

	fail := func(string) ([]string, error) { return nil, errors.New("AD fora do ar") }
	if n := refreshSessions(context.Background(), m, m.NeedGroupRefresh(0), fail, t.Logf); n != 0 {
		t.Fatalf("nenhuma sessão deveria mudar, mudaram %d", n)
	}
	s, _ := m.Lookup(ip)
	if len(s.Groups) != 1 || s.Groups[0] != "liberado" {
		t.Fatalf("grupos = %v, quero [liberado]", s.Groups)
	}
}

type nopRunner struct{}

func (nopRunner) ReplaceTable(string, string) error { return nil }
func (nopRunner) FlushTable(string) error           { return nil }

// E4 do laboratório: a "duração da sessão" foi baixada na interface para
// testar a expiração, mas o serviço só lia o TTL ao iniciar e o SIGHUP não o
// trocava. A sessão seguia com o TTL antigo de 4 horas.
func TestReloadConfigAppliesSessionTTL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guarita.json")
	write := func(ttl int) {
		js := fmt.Sprintf(`{"agent_secret":"segredo-bem-longo-aqui","session_ttl":%d,`+
			`"state_path":%q,"table_dir":%q}`, ttl, filepath.Join(dir, "s.json"), filepath.Join(dir, "t"))
		if err := os.WriteFile(cfgPath, []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(14400)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	d := newDaemon(cfg, cfgPath, log.New(io.Discard, "", 0), nopRunner{})
	d.sessions.Upsert(netip.MustParseAddr("192.168.1.100"), "leandro", "TESTE", []string{"liberado"}, "ad-agent")

	write(1) // 1 segundo
	if err := d.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if n := d.sessions.ExpireOlderThan(); n != 1 {
		t.Fatalf("com o TTL novo de 1 s a sessão deveria ter expirado (expiradas: %d)", n)
	}
}

// A reconsulta não pode renovar a sessão: sem eventos do agente, ela tem de
// expirar pelo TTL mesmo que os grupos sejam reconsultados no meio do caminho.
func TestRefreshSessionsDoesNotKeepSessionAlive(t *testing.T) {
	ttl := 200 * time.Millisecond
	m := session.New(ttl, filepath.Join(t.TempDir(), "s.json"))
	ip := netip.MustParseAddr("192.168.1.100")
	m.Upsert(ip, "leandro", "TESTE", []string{"liberado"}, "ad-agent")

	ad := func(string) ([]string, error) { return []string{"liberado"}, nil }
	for i := 0; i < 3; i++ {
		time.Sleep(ttl / 2)
		refreshSessions(context.Background(), m, m.NeedGroupRefresh(0), ad, t.Logf)
	}
	if n := m.ExpireOlderThan(); n != 1 {
		t.Fatalf("a sessão sem eventos deveria ter expirado (expiradas: %d)", n)
	}
}
