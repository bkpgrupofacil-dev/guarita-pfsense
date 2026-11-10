// Package apilocal expõe uma API HTTP sobre socket unix para a interface do
// pfSense (PHP) consultar sessões, status e disparar ações.
//
// O socket fica em /var/run/guarita.sock com permissão 0660 e dono root:wheel,
// de modo que só o próprio firewall (webgui roda como root) consegue falar com
// ele. Não há autenticação adicional: quem tem acesso ao socket já é root.
package apilocal

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Backend é implementado pelo daemon.
type Backend interface {
	Status() StatusInfo
	Sessions() []SessionInfo
	RemoveSession(ip netip.Addr) bool
	SetSticky(ip netip.Addr, on bool) bool
	Resync() error
	TestLDAP(user string) (LDAPTest, error)
	ReloadConfig() error
}

// StatusInfo é o resumo mostrado na aba de status.
type StatusInfo struct {
	Version        string               `json:"version"`
	StartedAt      time.Time            `json:"started_at"`
	Sessions       int                  `json:"sessions"`
	Groups         []GroupInfo          `json:"groups"`
	AgentsLastSeen map[string]time.Time `json:"agents_last_seen"`
	EventsReceived int64                `json:"events_received"`
	EventsAccepted int64                `json:"events_accepted"`
	EventsRejected int64                `json:"events_rejected"`
	LastSyncAt     time.Time            `json:"last_sync_at"`
	LastSyncError  string               `json:"last_sync_error,omitempty"`
	LDAPHost       string               `json:"ldap_host"`
}

// GroupInfo é um grupo lógico e quantos IPs estão nele.
type GroupInfo struct {
	Name    string `json:"name"`
	Table   string `json:"table"`
	PfTable string `json:"pf_table"`
	Members int    `json:"members"`
}

// SessionInfo é uma sessão para a GUI.
type SessionInfo struct {
	IP      string    `json:"ip"`
	User    string    `json:"user"`
	Domain  string    `json:"domain"`
	Groups  []string  `json:"groups"`
	LoginAt time.Time `json:"login_at"`
	SeenAt  time.Time `json:"seen_at"`
	Source  string    `json:"source"`
	Sticky  bool      `json:"sticky"`
}

// LDAPTest é o resultado do teste de resolução de um usuário.
type LDAPTest struct {
	User     string   `json:"user"`
	ADGroups []string `json:"ad_groups"`
	Logical  []string `json:"logical"`
	Elapsed  string   `json:"elapsed"`
}

// Server serve a API no socket unix.
type Server struct {
	path    string
	backend Backend
	srv     *http.Server
	ln      net.Listener
}

func New(path string, b Backend) *Server {
	return &Server{path: path, backend: b}
}

// Listen cria o socket (removendo um anterior órfão) e começa a servir.
func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// Remove socket órfão de uma execução anterior.
	if fi, err := os.Stat(s.path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(s.path)
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.path, 0o660); err != nil {
		ln.Close()
		return err
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Close encerra o servidor e remove o socket.
func (s *Server) Close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	_ = os.Remove(s.path)
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.backend.Status())
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.backend.Sessions())
	})
	mux.HandleFunc("/session/remove", func(w http.ResponseWriter, r *http.Request) {
		ip, ok := parseIP(w, r)
		if !ok {
			return
		}
		writeJSON(w, 200, map[string]bool{"removed": s.backend.RemoveSession(ip)})
	})
	mux.HandleFunc("/session/sticky", func(w http.ResponseWriter, r *http.Request) {
		ip, ok := parseIP(w, r)
		if !ok {
			return
		}
		on := r.URL.Query().Get("on") == "1"
		writeJSON(w, 200, map[string]bool{"ok": s.backend.SetSticky(ip, on)})
	})
	mux.HandleFunc("/resync", func(w http.ResponseWriter, r *http.Request) {
		if err := s.backend.Resync(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.backend.ReloadConfig(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/test-ldap", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if user == "" {
			writeJSON(w, 400, map[string]string{"error": "informe ?user="})
			return
		}
		res, err := s.backend.TestLDAP(user)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, res)
	})
	return mux
}

func parseIP(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "IP inválido"})
		return netip.Addr{}, false
	}
	return ip, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
