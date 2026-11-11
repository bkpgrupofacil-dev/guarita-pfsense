// Package apiagent expõe a API HTTP que os agentes instalados nos
// controladores de domínio usam para enviar os eventos de logon/logoff.
//
// Autenticação: cada requisição leva os cabeçalhos
//
//	X-Guarita-Agent:     nome do host do DC (informativo)
//	X-Guarita-Timestamp: unix time em segundos
//	X-Guarita-Signature: hex(HMAC-SHA256(segredo, timestamp + "\n" + corpo))
//
// Requisições com timestamp fora de ±5 minutos são rejeitadas, o que limita
// reenvio de requisições capturadas. A comparação da assinatura é feita em
// tempo constante. Esta API deve escutar apenas na interface interna e ter uma
// regra de firewall permitindo somente os IPs dos DCs.
package apiagent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MaxBody limita o tamanho do corpo aceito (proteção contra abuso de memória).
const MaxBody = 4 << 20 // 4 MiB

// ClockSkew é a tolerância de relógio entre o DC e o firewall.
const ClockSkew = 5 * time.Minute

// Event é um evento de logon/logoff vindo de um DC.
type Event struct {
	// Type: "logon", "logoff" ou "activity".
	Type string `json:"type"`
	// User é o sAMAccountName (sem domínio).
	User string `json:"user"`
	// Domain é o domínio NetBIOS, informativo.
	Domain string `json:"domain"`
	// IP é o endereço da estação.
	IP string `json:"ip"`
	// Time é quando o evento ocorreu no DC (RFC3339). Informativo.
	Time time.Time `json:"time"`
	// EventID é o ID do evento do Windows (4624, 4634, 4768, 4769...), informativo.
	EventID int `json:"event_id"`
	// Computer é o nome da estação, informativo.
	Computer string `json:"computer"`
}

// Batch é o corpo de POST /v1/events.
type Batch struct {
	Agent  string  `json:"agent"`
	Events []Event `json:"events"`
}

// Result é a resposta de POST /v1/events.
type Result struct {
	// Accepted conta os eventos que viraram (ou renovaram) uma sessão,
	// incluindo os que foram aplicados com alguma ressalva.
	Accepted int `json:"accepted"`
	// Ignored conta os eventos que não puderam ser usados.
	Ignored int `json:"ignored"`
	// Errors descreve os eventos ignorados.
	Errors []string `json:"errors,omitempty"`
	// Warnings descreve os eventos aplicados com ressalva: a sessão existe,
	// mas algo não saiu perfeito (tipicamente os grupos do AD não puderam ser
	// consultados e o grupo padrão foi usado).
	Warnings []string `json:"warnings,omitempty"`
}

// Warning marca um erro que NÃO impediu o evento de ser aplicado.
//
// Existe porque "a sessão foi criada, mas os grupos do AD não puderam ser
// consultados agora" é muito diferente de "este evento não serve para nada".
// Tratar os dois como falha fazia o contador de eventos aplicados ficar em zero
// justamente quando o Active Directory estava fora do ar — ou seja, no momento
// em que o operador mais precisa confiar no diagnóstico.
type Warning struct {
	Err error
}

func (w Warning) Error() string { return w.Err.Error() }
func (w Warning) Unwrap() error { return w.Err }

// Warnf monta um Warning.
func Warnf(format string, args ...any) Warning {
	return Warning{Err: fmt.Errorf(format, args...)}
}

// Handler processa os eventos. Implementado pelo daemon.
type Handler interface {
	// OnLogon associa um IP a um usuário. Resolve grupos conforme necessário.
	OnLogon(ip netip.Addr, user, domain, computer string) error
	// OnLogoff encerra a sessão de um IP para aquele usuário.
	OnLogoff(ip netip.Addr, user string) error
	// OnActivity apenas renova a sessão.
	OnActivity(ip netip.Addr, user string) error
}

// Server é o servidor HTTP da API de agentes.
type Server struct {
	secret  atomic.Pointer[[]byte]
	handler Handler
	logf    func(format string, args ...any)

	// Estatísticas simples expostas na GUI.
	stats Stats

	// isLocal diz se um IP pertence a esta máquina (o próprio pfSense).
	// Trocável nos testes.
	isLocal func(netip.Addr) bool
}

// localInterfaceAddr diz se ip está numa interface desta máquina.
//
// Por que: quando o pfSense consulta o AD com a conta de serviço do LDAP, o DC
// registra um logon de rede (4624) dessa conta vindo do IP do pfSense, e o
// agente o envia como se fosse uma estação. No laboratório isso criou a sessão
// "guarita 192.168.1.1": o firewall entrava como usuário, e numa política
// apontada para "Usuários do domínio" o próprio pfSense cairia na tabela. O
// firewall nunca é a estação de um usuário.
func localInterfaceAddr(ip netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var raw net.IP
		switch v := a.(type) {
		case *net.IPNet:
			raw = v.IP
		case *net.IPAddr:
			raw = v.IP
		}
		if x, ok := netip.AddrFromSlice(raw); ok && x.Unmap() == ip {
			return true
		}
	}
	return false
}

// Stats guarda contadores e o último contato de cada agente.
type Stats struct {
	Received atomic.Int64
	Accepted atomic.Int64
	Rejected atomic.Int64
	lastSeen atomic.Pointer[map[string]time.Time]
}

// New cria o servidor.
func New(secret string, h Handler, logf func(string, ...any)) *Server {
	s := &Server{handler: h, logf: logf, isLocal: localInterfaceAddr}
	s.SetSecret(secret)
	m := map[string]time.Time{}
	s.stats.lastSeen.Store(&m)
	return s
}

// SetSecret troca o segredo em uso (SIGHUP).
func (s *Server) SetSecret(secret string) {
	b := []byte(secret)
	s.secret.Store(&b)
}

// LastSeen devolve uma cópia do mapa agente -> último contato.
func (s *Server) LastSeen() map[string]time.Time {
	p := s.stats.lastSeen.Load()
	out := map[string]time.Time{}
	if p != nil {
		for k, v := range *p {
			out[k] = v
		}
	}
	return out
}

// Counters devolve os contadores atuais.
func (s *Server) Counters() (received, accepted, rejected int64) {
	return s.stats.Received.Load(), s.stats.Accepted.Load(), s.stats.Rejected.Load()
}

func (s *Server) markSeen(agent string) {
	if agent == "" {
		agent = "desconhecido"
	}
	for {
		old := s.stats.lastSeen.Load()
		nm := map[string]time.Time{}
		if old != nil {
			for k, v := range *old {
				nm[k] = v
			}
		}
		nm[agent] = time.Now()
		if s.stats.lastSeen.CompareAndSwap(old, &nm) {
			return
		}
	}
}

// Routes devolve o mux pronto.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ping", s.handlePing)
	mux.HandleFunc("/v1/events", s.handleEvents)
	return mux
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	body, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	_ = body
	s.markSeen(r.Header.Get("X-Guarita-Agent"))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
		return
	}
	body, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var batch Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		s.stats.Rejected.Add(1)
		http.Error(w, "json inválido", http.StatusBadRequest)
		return
	}
	agent := batch.Agent
	if agent == "" {
		agent = r.Header.Get("X-Guarita-Agent")
	}
	s.markSeen(agent)

	res := Result{}
	for _, ev := range batch.Events {
		s.stats.Received.Add(1)
		err := s.apply(ev)

		/* Aplicado com ressalva: conta como aceito, mas registra o aviso. */
		var w Warning
		if errors.As(err, &w) {
			res.Accepted++
			s.stats.Accepted.Add(1)
			if len(res.Warnings) < 20 {
				res.Warnings = append(res.Warnings, w.Error())
			}
			continue
		}

		if err != nil {
			res.Ignored++
			if len(res.Errors) < 20 {
				res.Errors = append(res.Errors, err.Error())
			}
			continue
		}
		res.Accepted++
		s.stats.Accepted.Add(1)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) apply(ev Event) error {
	user := strings.ToLower(strings.TrimSpace(ev.User))
	if user == "" {
		return fmt.Errorf("evento sem usuário")
	}
	// Remove prefixo de domínio se vier "EMPRESA\joao" ou "joao@empresa.local".
	if i := strings.LastIndex(user, "\\"); i >= 0 {
		user = user[i+1:]
	}
	if i := strings.Index(user, "@"); i > 0 {
		user = user[:i]
	}
	// Contas de máquina terminam em "$" e não interessam.
	if strings.HasSuffix(user, "$") {
		return fmt.Errorf("conta de máquina ignorada: %s", user)
	}

	ipStr := strings.TrimSpace(ev.IP)
	// O Windows às vezes registra "::ffff:10.0.0.5" ou "-".
	ipStr = strings.TrimPrefix(ipStr, "::ffff:")
	if ipStr == "" || ipStr == "-" {
		return fmt.Errorf("evento de %s sem IP", user)
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("IP inválido %q: %v", ev.IP, err)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return fmt.Errorf("IP ignorado: %s", ip)
	}
	if s.isLocal != nil && s.isLocal(ip) {
		return fmt.Errorf("IP do próprio firewall ignorado: %s (%s)", ip, user)
	}

	switch ev.Type {
	case "logon", "":
		return s.handler.OnLogon(ip, user, ev.Domain, ev.Computer)
	case "logoff":
		return s.handler.OnLogoff(ip, user)
	case "activity":
		return s.handler.OnActivity(ip, user)
	default:
		return fmt.Errorf("tipo de evento desconhecido: %q", ev.Type)
	}
}

// authenticate valida a assinatura HMAC e devolve o corpo lido.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	secretP := s.secret.Load()
	if secretP == nil || len(*secretP) == 0 {
		s.stats.Rejected.Add(1)
		http.Error(w, "serviço sem segredo configurado", http.StatusServiceUnavailable)
		return nil, false
	}
	secret := *secretP

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		s.stats.Rejected.Add(1)
		http.Error(w, "corpo inválido", http.StatusBadRequest)
		return nil, false
	}

	tsStr := r.Header.Get("X-Guarita-Timestamp")
	sig := r.Header.Get("X-Guarita-Signature")
	if tsStr == "" || sig == "" {
		s.stats.Rejected.Add(1)
		http.Error(w, "assinatura ausente", http.StatusUnauthorized)
		return nil, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil {
		s.stats.Rejected.Add(1)
		http.Error(w, "timestamp inválido", http.StatusUnauthorized)
		return nil, false
	}
	skew := time.Since(time.Unix(ts, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > ClockSkew {
		s.stats.Rejected.Add(1)
		s.logf("agente %s rejeitado: relógio fora de sincronia (%s)",
			r.Header.Get("X-Guarita-Agent"), skew.Round(time.Second))
		http.Error(w, "timestamp fora da janela aceita", http.StatusUnauthorized)
		return nil, false
	}

	want := Sign(secret, ts, body)
	got, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil || !hmac.Equal(want, got) {
		s.stats.Rejected.Add(1)
		s.logf("agente %s rejeitado: assinatura inválida", r.Header.Get("X-Guarita-Agent"))
		http.Error(w, "assinatura inválida", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

// Sign calcula a assinatura esperada para (timestamp, corpo).
func Sign(secret []byte, ts int64, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d\n", ts)
	mac.Write(body)
	return mac.Sum(nil)
}

// SignHex é a forma hexadecimal, igual à que o agente envia.
func SignHex(secret string, ts int64, body []byte) string {
	return hex.EncodeToString(Sign([]byte(secret), ts, body))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
