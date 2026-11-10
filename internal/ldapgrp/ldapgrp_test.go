package ldapgrp

import (
	"testing"
	"time"

	"github.com/grupofacil/guarita/internal/config"
)

func TestFirstCN(t *testing.T) {
	cases := map[string]string{
		"CN=GG_Vendas,OU=Grupos,DC=empresa,DC=local": "GG_Vendas",
		"cn=minusculo,DC=x":                          "minusculo",
		"OU=Grupos,CN=DepoisDeOU,DC=x":               "DepoisDeOU",
		"CN=Com Espaco,DC=x":                         "Com Espaco",
		// Vírgula escapada dentro do CN não deve partir o componente.
		`CN=Sobrenome\, Nome,OU=Users,DC=x`: `Sobrenome\, Nome`,
		"DC=sem,DC=cn":                      "",
		"":                                  "",
	}
	for dn, want := range cases {
		if got := firstCN(dn); got != want {
			t.Errorf("firstCN(%q) = %q, esperava %q", dn, got, want)
		}
	}
}

func TestDedup(t *testing.T) {
	in := []string{"GG_TI", "gg_ti", "GG_Vendas", "GG_TI"}
	got := dedup(in)
	if len(got) != 2 {
		t.Fatalf("dedup = %v, esperava 2 itens", got)
	}
	// Preserva a primeira grafia encontrada.
	if got[0] != "GG_TI" || got[1] != "GG_Vendas" {
		t.Fatalf("dedup = %v", got)
	}
}

func TestSplitDN(t *testing.T) {
	got := splitDN(`CN=Sobrenome\, Nome,OU=TI,DC=empresa,DC=local`)
	want := []string{`CN=Sobrenome\, Nome`, "OU=TI", "DC=empresa", "DC=local"}
	if len(got) != len(want) {
		t.Fatalf("splitDN = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitDN[%d] = %q, esperava %q", i, got[i], want[i])
		}
	}
}

func TestReloadBuildsMapping(t *testing.T) {
	cfg := &config.Config{
		Groups: []config.Group{
			{Name: "TI", Table: "ti", ADGroups: []string{"GG_TI", "GG_Infra"}, Priority: 0},
			{Name: "Vendas", Table: "vendas", ADGroups: []string{"GG_Vendas"}, Priority: 10},
		},
	}
	r := New(cfg)

	// A busca por nome de grupo do AD deve ignorar a caixa.
	if tbls := r.adToLogical["gg_ti"]; len(tbls) != 1 || tbls[0] != "ti" {
		t.Fatalf("mapeamento de gg_ti = %v", r.adToLogical["gg_ti"])
	}
	if tbls := r.adToLogical["gg_infra"]; len(tbls) != 1 || tbls[0] != "ti" {
		t.Fatalf("dois grupos do AD devem apontar para a mesma tabela: %v", tbls)
	}
	if r.prio["vendas"] != 10 {
		t.Fatalf("prioridade de vendas = %d", r.prio["vendas"])
	}
}

func TestReloadReplacesOldMapping(t *testing.T) {
	r := New(&config.Config{Groups: []config.Group{
		{Table: "antigo", ADGroups: []string{"GG_Antigo"}},
	}})
	r.Reload(&config.Config{Groups: []config.Group{
		{Table: "novo", ADGroups: []string{"GG_Novo"}},
	}})
	if _, ok := r.adToLogical["gg_antigo"]; ok {
		t.Fatal("mapeamento antigo deveria ter sido descartado no Reload")
	}
	if _, ok := r.adToLogical["gg_novo"]; !ok {
		t.Fatal("mapeamento novo deveria existir")
	}
}

func TestCacheHitAndExpiry(t *testing.T) {
	c := NewCache(50 * time.Millisecond)
	c.Put("joao", []string{"ti"}, []string{"GG_TI"})

	logical, ad, ok := c.Get("joao")
	if !ok || len(logical) != 1 || logical[0] != "ti" || ad[0] != "GG_TI" {
		t.Fatalf("cache miss inesperado: %v %v %v", logical, ad, ok)
	}
	// Chave insensível à caixa.
	if _, _, ok := c.Get("JOAO"); !ok {
		t.Fatal("cache deveria ignorar a caixa do nome de usuário")
	}
	time.Sleep(80 * time.Millisecond)
	if _, _, ok := c.Get("joao"); ok {
		t.Fatal("entrada deveria ter expirado")
	}
}

func TestCacheErrorsExpireFaster(t *testing.T) {
	// Erro fica em cache por no máximo 60s, mesmo com TTL longo, para que uma
	// falha momentânea do AD não deixe o usuário sem grupo por meia hora.
	c := NewCache(1 * time.Hour)
	c.PutErr("joao", errFake{})
	if _, _, ok := c.Get("joao"); !ok {
		t.Fatal("erro recém-gravado deveria estar em cache")
	}
	// Força o envelhecimento da entrada.
	c.mu.Lock()
	e := c.m["joao"]
	e.at = time.Now().Add(-2 * time.Minute)
	c.m["joao"] = e
	c.mu.Unlock()

	if _, _, ok := c.Get("joao"); ok {
		t.Fatal("erro com mais de 60s não deveria contar como cache válido")
	}
}

func TestCacheInvalidateAndPurge(t *testing.T) {
	c := NewCache(time.Hour)
	c.Put("joao", []string{"ti"}, nil)
	c.Put("maria", []string{"vendas"}, nil)

	c.Invalidate("JOAO")
	if _, _, ok := c.Get("joao"); ok {
		t.Fatal("Invalidate deveria remover a entrada")
	}
	if _, _, ok := c.Get("maria"); !ok {
		t.Fatal("Invalidate não deveria afetar outros usuários")
	}
	c.Purge()
	if _, _, ok := c.Get("maria"); ok {
		t.Fatal("Purge deveria limpar tudo")
	}
}

type errFake struct{}

func (errFake) Error() string { return "ad fora do ar" }
