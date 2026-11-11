package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "guarita.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaults(t *testing.T) {
	p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","ldap":{"host":"dc01.local"}}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAgent != "0.0.0.0:8923" {
		t.Errorf("ListenAgent = %q", c.ListenAgent)
	}
	if c.SessionTTL.D() != 4*time.Hour {
		t.Errorf("SessionTTL = %v", c.SessionTTL.D())
	}
	if c.LDAP.Port != 389 {
		t.Errorf("porta padrão LDAP = %d", c.LDAP.Port)
	}
	if c.LDAP.UserAttr != "sAMAccountName" {
		t.Errorf("UserAttr = %q", c.LDAP.UserAttr)
	}
	// local4 e não local5: o pfSense roteia local5.* para o nginx.log e
	// local3.* para o vpn.log, então usar local5 duplicaria os nossos
	// registros dentro do log do nginx.
	if c.LogFacility != "local4" {
		t.Errorf("LogFacility = %q", c.LogFacility)
	}
	// O pfSense 2.9 pula a recarga quando o ruleset não mudou e não reescreve
	// o rules.debug, mas esvazia as tabelas mesmo assim. O arquivo de status é
	// o único sinal que muda em toda recarga.
	if c.ReloadStatusFile != "/var/run/filter_reload_status" {
		t.Errorf("ReloadStatusFile = %q", c.ReloadStatusFile)
	}
}

func TestLDAPSPortDefault(t *testing.T) {
	p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","ldap":{"host":"dc01","tls_mode":"ssl"}}`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.LDAP.Port != 636 {
		t.Fatalf("com ssl a porta padrão deveria ser 636, veio %d", c.LDAP.Port)
	}
}

func TestDurationFormats(t *testing.T) {
	// String no formato do Go e número em segundos devem funcionar.
	p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","session_ttl":"90m","group_refresh":600}`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL.D() != 90*time.Minute {
		t.Errorf("SessionTTL = %v", c.SessionTTL.D())
	}
	if c.GroupRefresh.D() != 10*time.Minute {
		t.Errorf("GroupRefresh = %v", c.GroupRefresh.D())
	}
}

func TestRejectsShortSecret(t *testing.T) {
	p := write(t, `{"agent_secret":"curto"}`)
	if _, err := Load(p); err == nil {
		t.Fatal("segredo curto deveria ser rejeitado")
	}
}

func TestRejectsMissingSecret(t *testing.T) {
	p := write(t, `{}`)
	if _, err := Load(p); err == nil {
		t.Fatal("configuração sem segredo deveria ser rejeitada")
	}
}

func TestRejectsBadTableName(t *testing.T) {
	bad := []string{"com espaço", "com-hifen", "", "acentuação", "tabela.ponto",
		"muito_longo_demais_para_caber_no_limite"}
	for _, name := range bad {
		p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","groups":[{"name":"X","table":"`+name+`"}]}`)
		if _, err := Load(p); err == nil {
			t.Errorf("table %q deveria ser rejeitado", name)
		}
	}
}

func TestAcceptsGoodTableName(t *testing.T) {
	good := []string{"vendas", "Vendas", "grupo_1", "TI", "a", "nivel_2_restrito"}
	for _, name := range good {
		p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","groups":[{"name":"X","table":"`+name+`"}]}`)
		if _, err := Load(p); err != nil {
			t.Errorf("table %q deveria ser aceito: %v", name, err)
		}
	}
}

func TestRejectsDuplicateTable(t *testing.T) {
	p := write(t, `{"agent_secret":"segredo-bem-longo-aqui","groups":[
		{"name":"A","table":"vendas"},
		{"name":"B","table":"VENDAS"}]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("tabelas duplicadas (ignorando caixa) deveriam ser rejeitadas")
	}
}

func TestRejectsInvalidJSON(t *testing.T) {
	p := write(t, `{isto não é json}`)
	if _, err := Load(p); err == nil {
		t.Fatal("JSON inválido deveria ser rejeitado")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nao-existe.json")); err == nil {
		t.Fatal("arquivo ausente deveria dar erro")
	}
}

func TestFullConfig(t *testing.T) {
	p := write(t, `{
	  "listen_agent": "10.10.20.5:8923",
	  "agent_secret": "um-segredo-suficientemente-longo",
	  "session_ttl": "8h",
	  "default_group": "nao_autenticado",
	  "ldap": {
	    "host": "dc01.empresa.local", "tls_mode": "starttls",
	    "bind_dn": "EMPRESA\\svc_guarita", "bind_pw": "senha",
	    "base_dn": "DC=empresa,DC=local", "nested": true
	  },
	  "groups": [
	    {"name":"TI","table":"ti","ad_groups":["GG_TI"],"priority":0},
	    {"name":"Vendas","table":"vendas","ad_groups":["GG_Vendas","GG_Comercial"],"priority":10}
	  ]
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Groups) != 2 {
		t.Fatalf("esperava 2 grupos, veio %d", len(c.Groups))
	}
	if !c.LDAP.Nested {
		t.Error("nested deveria estar ligado")
	}
	if c.LDAP.Port != 389 {
		t.Errorf("starttls usa 389, veio %d", c.LDAP.Port)
	}
	if len(c.Groups[1].ADGroups) != 2 {
		t.Errorf("grupo Vendas deveria ter 2 grupos de AD")
	}
	if c.DefaultGroup != "nao_autenticado" {
		t.Errorf("DefaultGroup = %q", c.DefaultGroup)
	}
}
