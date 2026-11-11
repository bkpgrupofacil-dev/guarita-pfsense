// Package session mantém o estado "usuário <-> IP <-> grupos" em memória,
// persiste em disco e calcula, para cada grupo lógico, o conjunto de IPs que
// deve estar na tabela pf correspondente.
package session

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Session é uma associação ativa entre um IP e um usuário do AD.
type Session struct {
	IP       netip.Addr `json:"ip"`
	User     string     `json:"user"`   // sAMAccountName em minúsculas
	Domain   string     `json:"domain"` // domínio NetBIOS, informativo
	Groups   []string   `json:"groups"` // tabelas lógicas às quais o IP pertence
	LoginAt  time.Time  `json:"login_at"`
	SeenAt   time.Time  `json:"seen_at"`   // último evento recebido
	GroupsAt time.Time  `json:"groups_at"` // última resolução de grupos
	Source   string     `json:"source"`    // "ad-agent", "manual", etc.
	Sticky   bool       `json:"sticky"`    // não expira por TTL (sessão fixada manualmente)
}

// Manager é seguro para uso concorrente.
type Manager struct {
	mu        sync.RWMutex
	byIP      map[netip.Addr]*Session
	ttl       time.Duration
	statePath string
	onChange  func() // chamado (fora do lock) quando o conjunto de IPs por grupo muda
}

// New cria um Manager e tenta carregar o estado persistido.
func New(ttl time.Duration, statePath string) *Manager {
	m := &Manager{
		byIP:      make(map[netip.Addr]*Session),
		ttl:       ttl,
		statePath: statePath,
	}
	m.load()
	return m
}

// SetOnChange registra um callback disparado quando o mapeamento IP->grupos muda.
func (m *Manager) SetOnChange(f func()) { m.onChange = f }

// Upsert registra ou atualiza a sessão de um IP. groups são as tabelas lógicas
// resolvidas para o usuário. Devolve true se o conjunto de grupos daquele IP
// mudou (o que exige reescrever as tabelas pf).
func (m *Manager) Upsert(ip netip.Addr, user, domain string, groups []string, source string) bool {
	now := time.Now()
	groups = normGroups(groups)

	m.mu.Lock()
	prev := m.byIP[ip]
	changed := prev == nil || prev.User != user || !sameStrings(prev.Groups, groups)
	s := &Session{
		IP:       ip,
		User:     user,
		Domain:   domain,
		Groups:   groups,
		SeenAt:   now,
		GroupsAt: now,
		Source:   source,
	}
	if prev != nil {
		s.LoginAt = prev.LoginAt
		s.Sticky = prev.Sticky
		if prev.User != user {
			s.LoginAt = now // novo usuário no mesmo IP
		}
	} else {
		s.LoginAt = now
	}
	if s.LoginAt.IsZero() {
		s.LoginAt = now
	}
	m.byIP[ip] = s
	m.mu.Unlock()

	if changed {
		m.fireChange()
	}
	return changed
}

// UpdateGroups troca só os grupos de uma sessão existente, depois de
// reconsultar o AD. NÃO renova o SeenAt: quem diz que o usuário continua na
// estação são os eventos do agente, não a reconsulta. Antes a reconsulta usava
// Upsert, que renova o SeenAt, e uma sessão sem nenhum evento era renovada a cada
// 30 minutos e nunca expirava; com o IP reaproveitado pelo DHCP, outra pessoa
// herdaria a política do usuário anterior sem prazo.
//
// Só atualiza se o IP ainda for do mesmo usuário (pode ter havido um logon de
// outro usuário enquanto o AD era consultado). Devolve true se os grupos
// mudaram.
func (m *Manager) UpdateGroups(ip netip.Addr, user string, groups []string) bool {
	groups = normGroups(groups)
	m.mu.Lock()
	s := m.byIP[ip]
	if s == nil || s.User != user {
		m.mu.Unlock()
		return false
	}
	changed := !sameStrings(s.Groups, groups)
	s.Groups = groups
	s.GroupsAt = time.Now()
	m.mu.Unlock()
	if changed {
		m.fireChange()
	}
	return changed
}

// Touch apenas renova o SeenAt de um IP (ex.: evento de atividade), sem mudar
// usuário/grupos. Devolve false se não havia sessão.
func (m *Manager) Touch(ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byIP[ip]
	if s == nil {
		return false
	}
	s.SeenAt = time.Now()
	return true
}

// Remove apaga a sessão de um IP (ex.: evento de logoff). Devolve true se existia.
func (m *Manager) Remove(ip netip.Addr) bool {
	m.mu.Lock()
	_, ok := m.byIP[ip]
	if ok {
		delete(m.byIP, ip)
	}
	m.mu.Unlock()
	if ok {
		m.fireChange()
	}
	return ok
}

// SetSticky marca/desmarca uma sessão como fixa (não expira por TTL).
func (m *Manager) SetSticky(ip netip.Addr, sticky bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byIP[ip]
	if s == nil {
		return false
	}
	s.Sticky = sticky
	return true
}

// NeedGroupRefresh devolve os IPs cujos grupos foram resolvidos há mais de
// 'age' e que, portanto, devem ser reconsultados no AD.
func (m *Manager) NeedGroupRefresh(age time.Duration) []RefreshItem {
	cutoff := time.Now().Add(-age)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []RefreshItem
	for ip, s := range m.byIP {
		if s.Source == "manual" {
			continue
		}
		if s.GroupsAt.Before(cutoff) {
			out = append(out, RefreshItem{IP: ip, User: s.User, Domain: s.Domain})
		}
	}
	return out
}

// RefreshItem identifica uma sessão a reconsultar no AD.
type RefreshItem struct {
	IP     netip.Addr
	User   string
	Domain string
}

// ExpireOlderThan remove sessões não-fixas com SeenAt anterior a agora-ttl.
// Devolve quantas foram removidas.
func (m *Manager) ExpireOlderThan() int {
	if m.ttl <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-m.ttl)
	m.mu.Lock()
	n := 0
	for ip, s := range m.byIP {
		if s.Sticky {
			continue
		}
		if s.SeenAt.Before(cutoff) {
			delete(m.byIP, ip)
			n++
		}
	}
	m.mu.Unlock()
	if n > 0 {
		m.fireChange()
	}
	return n
}

// TablesSnapshot devolve, para cada grupo lógico presente, a lista ordenada de
// IPs (como string) que pertencem a ele. É isto que vai para os arquivos pf.
func (m *Manager) TablesSnapshot() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string][]string{}
	for ip, s := range m.byIP {
		ips := ip.String()
		for _, g := range s.Groups {
			out[g] = append(out[g], ips)
		}
	}
	for g := range out {
		sort.Strings(out[g])
	}
	return out
}

// Lookup devolve uma cópia da sessão de um IP.
func (m *Manager) Lookup(ip netip.Addr) (Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.byIP[ip]
	if s == nil {
		return Session{}, false
	}
	return *s, true
}

// List devolve todas as sessões, ordenadas por IP.
func (m *Manager) List() []Session {
	m.mu.RLock()
	out := make([]Session, 0, len(m.byIP))
	for _, s := range m.byIP {
		out = append(out, *s)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// Count devolve o número de sessões ativas.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byIP)
}

func (m *Manager) fireChange() {
	if m.onChange != nil {
		m.onChange()
	}
}

// Save grava o estado atual em disco de forma atômica.
func (m *Manager) Save() error {
	m.mu.RLock()
	list := make([]*Session, 0, len(m.byIP))
	for _, s := range m.byIP {
		list = append(list, s)
	}
	m.mu.RUnlock()

	if m.statePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o750); err != nil {
		return err
	}
	tmp := m.statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(list); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath)
}

func (m *Manager) load() {
	if m.statePath == "" {
		return
	}
	raw, err := os.ReadFile(m.statePath)
	if err != nil {
		return
	}
	var list []*Session
	if err := json.Unmarshal(raw, &list); err != nil {
		return
	}
	now := time.Now()
	for _, s := range list {
		if !s.IP.IsValid() {
			continue
		}
		// Descarta o que já estava expirado no momento do carregamento.
		if m.ttl > 0 && !s.Sticky && s.SeenAt.Before(now.Add(-m.ttl)) {
			continue
		}
		s.Groups = normGroups(s.Groups)
		m.byIP[s.IP] = s
	}
}

func normGroups(g []string) []string {
	if len(g) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(g))
	for _, x := range g {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
