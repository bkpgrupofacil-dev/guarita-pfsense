// Package ldapgrp consulta o Active Directory para descobrir os grupos de um
// usuário e traduz os grupos do AD nos grupos lógicos (tabelas) do Guarita.
package ldapgrp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/grupofacil/guarita/internal/config"
)

// Resolver resolve usuário -> grupos lógicos. É seguro para uso concorrente.
type Resolver struct {
	mu  sync.RWMutex
	cfg config.LDAP
	// adToLogical mapeia nome de grupo do AD (minúsculo) -> lista de tabelas
	// lógicas, derivado da lista de Groups da configuração.
	adToLogical map[string][]string
	prio        map[string]int // tabela lógica -> prioridade
}

// New cria um Resolver a partir da configuração completa.
func New(c *config.Config) *Resolver {
	r := &Resolver{}
	r.Reload(c)
	return r
}

// Reload atualiza a configuração do resolver (chamado em SIGHUP).
func (r *Resolver) Reload(c *config.Config) {
	ad := map[string][]string{}
	prio := map[string]int{}
	for _, g := range c.Groups {
		prio[g.Table] = g.Priority
		for _, name := range g.ADGroups {
			k := strings.ToLower(strings.TrimSpace(name))
			if k == "" {
				continue
			}
			ad[k] = append(ad[k], g.Table)
		}
	}
	r.mu.Lock()
	r.cfg = c.LDAP
	r.adToLogical = ad
	r.prio = prio
	r.mu.Unlock()
}

// Resolve devolve os grupos lógicos (tabelas) de um usuário. Consulta o AD,
// obtém os grupos do AD e os mapeia. Se winnerOnly, devolve só o grupo de maior
// prioridade (menor número) — útil quando as regras são mutuamente exclusivas.
func (r *Resolver) Resolve(user string, winnerOnly bool) ([]string, []string, error) {
	r.mu.RLock()
	cfg := r.cfg
	adMap := r.adToLogical
	prio := r.prio
	r.mu.RUnlock()

	adGroups, err := r.queryADGroups(cfg, user)
	if err != nil {
		return nil, nil, err
	}

	// Mapeia para tabelas lógicas.
	set := map[string]bool{}
	for _, g := range adGroups {
		for _, tbl := range adMap[strings.ToLower(g)] {
			set[tbl] = true
		}
	}
	logical := make([]string, 0, len(set))
	for t := range set {
		logical = append(logical, t)
	}

	if winnerOnly && len(logical) > 1 {
		best := logical[0]
		for _, t := range logical[1:] {
			if prio[t] < prio[best] {
				best = t
			}
		}
		logical = []string{best}
	}
	return logical, adGroups, nil
}

// queryADGroups conecta no AD, autentica e devolve os nomes (CN) dos grupos do
// usuário. Respeita nested quando habilitado.
func (r *Resolver) queryADGroups(cfg config.LDAP, user string) ([]string, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("ldap: host não configurado")
	}
	conn, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetTimeout(cfg.Timeout.D())

	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPw); err != nil {
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}

	// 1) Encontra o DN e o memberOf do usuário.
	userFilter := fmt.Sprintf("(&(objectClass=user)(%s=%s))",
		cfg.UserAttr, ldap.EscapeFilter(user))
	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(cfg.Timeout.D()/time.Second), false,
		userFilter,
		[]string{"distinguishedName", cfg.GroupAttr, "objectSid", "primaryGroupID"},
		nil,
	)
	res, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search user: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("usuário %q não encontrado no AD", user)
	}
	entry := res.Entries[0]
	userDN := entry.GetAttributeValue("distinguishedName")
	if userDN == "" {
		userDN = entry.DN
	}

	search := func(filter string) ([]*ldap.Entry, error) {
		req := ldap.NewSearchRequest(
			cfg.BaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(cfg.Timeout.D()/time.Second), false,
			filter,
			[]string{"cn", "distinguishedName"},
			nil,
		)
		r, err := conn.Search(req)
		if err != nil {
			return nil, err
		}
		return r.Entries, nil
	}
	// inChain devolve os CNs dos grupos que contêm dn em qualquer nível
	// (LDAP_MATCHING_RULE_IN_CHAIN = 1.2.840.113556.1.4.1941).
	inChain := func(dn string) ([]string, error) {
		es, err := search(fmt.Sprintf("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))",
			ldap.EscapeFilter(dn)))
		if err != nil {
			return nil, err
		}
		var out []string
		for _, e := range es {
			if cn := e.GetAttributeValue("cn"); cn != "" {
				out = append(out, cn)
			}
		}
		return out, nil
	}

	var cns []string
	if cfg.Nested {
		got, err := inChain(userDN)
		if err != nil {
			return nil, fmt.Errorf("ldap search nested groups: %w", err)
		}
		cns = append(cns, got...)
	} else {
		for _, dn := range entry.GetAttributeValues(cfg.GroupAttr) {
			if cn := firstCN(dn); cn != "" {
				cns = append(cns, cn)
			}
		}
	}

	// Grupo primário: não aparece em memberOf nem em member (ver sid.go).
	if rid, err := strconv.ParseUint(entry.GetAttributeValue("primaryGroupID"), 10, 32); err == nil && rid > 0 {
		gsid, err := primaryGroupSID(entry.GetRawAttributeValue("objectSid"), uint32(rid))
		if err != nil {
			return nil, fmt.Errorf("grupo primário de %q: %w", user, err)
		}
		es, err := search(fmt.Sprintf("(&(objectClass=group)(objectSid=%s))", escapeBinary(gsid)))
		if err != nil {
			return nil, fmt.Errorf("ldap search primary group %s: %w", sidString(gsid), err)
		}
		if len(es) > 0 {
			pg := es[0]
			if cn := pg.GetAttributeValue("cn"); cn != "" {
				cns = append(cns, cn)
			}
			if cfg.Nested {
				pgDN := pg.GetAttributeValue("distinguishedName")
				if pgDN == "" {
					pgDN = pg.DN
				}
				got, err := inChain(pgDN)
				if err != nil {
					return nil, fmt.Errorf("ldap search nested groups of primary group: %w", err)
				}
				cns = append(cns, got...)
			}
		}
	}
	return dedup(cns), nil
}

func dial(cfg config.LDAP) (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	switch cfg.TLSMode {
	case "ssl":
		tc, err := tlsConfig(cfg)
		if err != nil {
			return nil, err
		}
		return ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSConfig(tc))
	case "starttls":
		conn, err := ldap.DialURL("ldap://" + addr)
		if err != nil {
			return nil, err
		}
		tc, err := tlsConfig(cfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
		return conn, nil
	default:
		return ldap.DialURL("ldap://" + addr)
	}
}

func tlsConfig(cfg config.LDAP) (*tls.Config, error) {
	tc := &tls.Config{ServerName: cfg.Host}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("ca_cert: PEM inválido")
		}
		tc.RootCAs = pool
	} else {
		// Sem CA informada: não valida a cadeia. O ideal é informar a CA do AD.
		tc.InsecureSkipVerify = true
	}
	return tc, nil
}

// firstCN extrai o primeiro componente CN= de um DN.
func firstCN(dn string) string {
	for _, comp := range splitDN(dn) {
		if len(comp) >= 3 && strings.EqualFold(comp[:3], "cn=") {
			return comp[3:]
		}
	}
	return ""
}

// splitDN separa um DN em componentes respeitando a vírgula escapada "\,".
func splitDN(dn string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(dn); i++ {
		c := dn[i]
		if c == '\\' && i+1 < len(dn) {
			cur.WriteByte(c)
			cur.WriteByte(dn[i+1])
			i++
			continue
		}
		if c == ',' {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}
