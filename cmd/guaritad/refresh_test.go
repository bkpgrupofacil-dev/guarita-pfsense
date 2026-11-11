package main

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

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
