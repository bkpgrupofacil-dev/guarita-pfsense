package session

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func ip(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestUpsertAndSnapshot(t *testing.T) {
	m := New(time.Hour, "")
	m.Upsert(ip("10.0.0.10"), "joao", "EMPRESA", []string{"restrito"}, "ad-agent")
	m.Upsert(ip("10.0.0.11"), "maria", "EMPRESA", []string{"liberado"}, "ad-agent")
	m.Upsert(ip("10.0.0.12"), "ana", "EMPRESA", []string{"liberado"}, "ad-agent")

	snap := m.TablesSnapshot()
	if got := len(snap["liberado"]); got != 2 {
		t.Fatalf("grupo liberado: esperava 2 IPs, veio %d (%v)", got, snap["liberado"])
	}
	if got := len(snap["restrito"]); got != 1 {
		t.Fatalf("grupo restrito: esperava 1 IP, veio %d", got)
	}
	// Snapshot deve vir ordenado, para o arquivo da tabela ser estável.
	if snap["liberado"][0] != "10.0.0.11" || snap["liberado"][1] != "10.0.0.12" {
		t.Fatalf("snapshot não ordenado: %v", snap["liberado"])
	}
}

func TestUpsertDetectsChange(t *testing.T) {
	m := New(time.Hour, "")

	if !m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"restrito"}, "ad-agent") {
		t.Fatal("primeiro upsert deveria indicar mudança")
	}
	// Mesmo usuário, mesmos grupos: não mudou nada, não precisa reescrever pf.
	if m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"restrito"}, "ad-agent") {
		t.Fatal("upsert idêntico não deveria indicar mudança")
	}
	// Ordem diferente dos mesmos grupos também não é mudança.
	if m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"restrito", "restrito"}, "ad-agent") {
		t.Fatal("grupos duplicados/reordenados não deveriam indicar mudança")
	}
	// Troca de grupo é mudança.
	if !m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"liberado"}, "ad-agent") {
		t.Fatal("troca de grupo deveria indicar mudança")
	}
	// Troca de usuário no mesmo IP é mudança.
	if !m.Upsert(ip("10.0.0.10"), "maria", "D", []string{"liberado"}, "ad-agent") {
		t.Fatal("troca de usuário deveria indicar mudança")
	}
}

func TestLoginAtResetOnUserChange(t *testing.T) {
	m := New(time.Hour, "")
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	first, _ := m.Lookup(ip("10.0.0.10"))

	time.Sleep(10 * time.Millisecond)
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	same, _ := m.Lookup(ip("10.0.0.10"))
	if !same.LoginAt.Equal(first.LoginAt) {
		t.Fatal("LoginAt não deveria mudar para o mesmo usuário")
	}

	time.Sleep(10 * time.Millisecond)
	m.Upsert(ip("10.0.0.10"), "maria", "D", []string{"a"}, "ad-agent")
	other, _ := m.Lookup(ip("10.0.0.10"))
	if !other.LoginAt.After(first.LoginAt) {
		t.Fatal("LoginAt deveria ser atualizado ao trocar de usuário no mesmo IP")
	}
}

func TestExpiry(t *testing.T) {
	m := New(50*time.Millisecond, "")
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	m.Upsert(ip("10.0.0.11"), "fixa", "D", []string{"a"}, "ad-agent")
	m.SetSticky(ip("10.0.0.11"), true)

	if n := m.ExpireOlderThan(); n != 0 {
		t.Fatalf("nada deveria expirar ainda, expiraram %d", n)
	}
	time.Sleep(80 * time.Millisecond)

	n := m.ExpireOlderThan()
	if n != 1 {
		t.Fatalf("esperava 1 expiração, veio %d", n)
	}
	if _, ok := m.Lookup(ip("10.0.0.11")); !ok {
		t.Fatal("sessão fixada (sticky) não deveria expirar")
	}
	if _, ok := m.Lookup(ip("10.0.0.10")); ok {
		t.Fatal("sessão comum deveria ter expirado")
	}
}

func TestTouchRenewsSession(t *testing.T) {
	m := New(100*time.Millisecond, "")
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")

	// Mantém a sessão viva com Touch enquanto o TTL passaria.
	for i := 0; i < 4; i++ {
		time.Sleep(40 * time.Millisecond)
		if !m.Touch(ip("10.0.0.10")) {
			t.Fatalf("Touch falhou na iteração %d", i)
		}
		m.ExpireOlderThan()
	}
	if _, ok := m.Lookup(ip("10.0.0.10")); !ok {
		t.Fatal("sessão renovada por Touch não deveria ter expirado")
	}
	if m.Touch(ip("10.0.0.99")) {
		t.Fatal("Touch em IP sem sessão deveria devolver false")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	m := New(time.Hour, path)
	m.Upsert(ip("10.0.0.10"), "joao", "EMPRESA", []string{"restrito"}, "ad-agent")
	m.Upsert(ip("10.0.0.11"), "maria", "EMPRESA", []string{"liberado"}, "ad-agent")
	m.SetSticky(ip("10.0.0.11"), true)
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := New(time.Hour, path)
	if m2.Count() != 2 {
		t.Fatalf("esperava 2 sessões restauradas, veio %d", m2.Count())
	}
	s, ok := m2.Lookup(ip("10.0.0.10"))
	if !ok || s.User != "joao" || len(s.Groups) != 1 || s.Groups[0] != "restrito" {
		t.Fatalf("sessão restaurada incorreta: %+v", s)
	}
	s2, _ := m2.Lookup(ip("10.0.0.11"))
	if !s2.Sticky {
		t.Fatal("flag sticky deveria sobreviver ao reinício")
	}
}

func TestPersistenceDropsExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	m := New(30*time.Millisecond, path)
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	// Ao carregar, a sessão já está além do TTL e deve ser descartada: depois de
	// um reboot longo ninguém deve herdar permissão antiga.
	m2 := New(30*time.Millisecond, path)
	if m2.Count() != 0 {
		t.Fatalf("sessão expirada não deveria ser restaurada, veio %d", m2.Count())
	}
}

func TestOnChangeFires(t *testing.T) {
	m := New(time.Hour, "")
	calls := 0
	m.SetOnChange(func() { calls++ })

	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	if calls != 1 {
		t.Fatalf("esperava 1 chamada, veio %d", calls)
	}
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent") // idêntico
	if calls != 1 {
		t.Fatalf("upsert idêntico não deveria disparar onChange (%d)", calls)
	}
	m.Remove(ip("10.0.0.10"))
	if calls != 2 {
		t.Fatalf("remove deveria disparar onChange (%d)", calls)
	}
	m.Remove(ip("10.0.0.10")) // já removido
	if calls != 2 {
		t.Fatalf("remove de inexistente não deveria disparar (%d)", calls)
	}
}

func TestNeedGroupRefresh(t *testing.T) {
	m := New(time.Hour, "")
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"a"}, "ad-agent")
	m.Upsert(ip("10.0.0.11"), "manual", "D", []string{"a"}, "manual")

	if got := m.NeedGroupRefresh(time.Hour); len(got) != 0 {
		t.Fatalf("nada deveria precisar de refresh ainda: %v", got)
	}
	time.Sleep(20 * time.Millisecond)
	got := m.NeedGroupRefresh(10 * time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("esperava 1 item para refresh, veio %d (%v)", len(got), got)
	}
	if got[0].User != "joao" {
		t.Fatalf("sessões manuais não devem ser reconsultadas no AD, veio %q", got[0].User)
	}
}

func TestMultiGroupMembership(t *testing.T) {
	// Um IP pode estar em vários grupos quando o resolvedor não força
	// exclusividade; o snapshot precisa refletir isso em todas as tabelas.
	m := New(time.Hour, "")
	m.Upsert(ip("10.0.0.10"), "joao", "D", []string{"vendas", "liberado"}, "ad-agent")
	snap := m.TablesSnapshot()
	if len(snap["vendas"]) != 1 || len(snap["liberado"]) != 1 {
		t.Fatalf("IP deveria constar nos dois grupos: %v", snap)
	}
}
