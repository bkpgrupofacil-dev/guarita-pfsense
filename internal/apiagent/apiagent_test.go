package apiagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

const secret = "segredo-de-teste-bem-longo-123456"

// fakeHandler registra as chamadas recebidas.
type fakeHandler struct {
	mu       sync.Mutex
	logons   []string
	logoffs  []string
	activity []string
	err      error
}

func (f *fakeHandler) OnLogon(ip netip.Addr, user, domain, computer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logons = append(f.logons, fmt.Sprintf("%s@%s", user, ip))
	return f.err
}

func (f *fakeHandler) OnLogoff(ip netip.Addr, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoffs = append(f.logoffs, fmt.Sprintf("%s@%s", user, ip))
	return f.err
}

func (f *fakeHandler) OnActivity(ip netip.Addr, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activity = append(f.activity, fmt.Sprintf("%s@%s", user, ip))
	return f.err
}

func newTestServer(h Handler) *Server {
	return New(secret, h, func(string, ...any) {})
}

// signedRequest monta uma requisição assinada corretamente.
func signedRequest(t *testing.T, path string, body any, ts int64) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("X-Guarita-Agent", "DC01")
	req.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Guarita-Signature", SignHex(secret, ts, raw))
	return req
}

func TestAcceptsValidBatch(t *testing.T) {
	h := &fakeHandler{}
	s := newTestServer(h)
	batch := Batch{Agent: "DC01", Events: []Event{
		{Type: "logon", User: "joao", Domain: "EMPRESA", IP: "10.0.0.10", EventID: 4624},
		{Type: "logoff", User: "maria", IP: "10.0.0.11", EventID: 4634},
		{Type: "activity", User: "ana", IP: "10.0.0.12"},
	}}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", batch, time.Now().Unix()))

	if rec.Code != 200 {
		t.Fatalf("status %d, corpo: %s", rec.Code, rec.Body.String())
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 3 || res.Ignored != 0 {
		t.Fatalf("resultado inesperado: %+v", res)
	}
	if len(h.logons) != 1 || h.logons[0] != "joao@10.0.0.10" {
		t.Fatalf("logons: %v", h.logons)
	}
	if len(h.logoffs) != 1 || len(h.activity) != 1 {
		t.Fatalf("logoffs=%v activity=%v", h.logoffs, h.activity)
	}
}

func TestRejectsBadSignature(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	ts := time.Now().Unix()
	raw, _ := json.Marshal(Batch{Events: []Event{{User: "joao", IP: "10.0.0.10"}}})

	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(raw))
	req.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Guarita-Signature", SignHex("segredo-errado-mas-do-mesmo-tamanho", ts, raw))

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, veio %d", rec.Code)
	}
}

func TestRejectsTamperedBody(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	ts := time.Now().Unix()
	original, _ := json.Marshal(Batch{Events: []Event{{User: "joao", IP: "10.0.0.10"}}})
	sig := SignHex(secret, ts, original)

	// Corpo alterado depois de assinado: troca o usuário por um privilegiado.
	tampered, _ := json.Marshal(Batch{Events: []Event{{User: "administrator", IP: "10.0.0.10"}}})
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(tampered))
	req.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Guarita-Signature", sig)

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("corpo alterado deveria dar 401, veio %d", rec.Code)
	}
}

func TestRejectsOldTimestamp(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	old := time.Now().Add(-30 * time.Minute).Unix()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", Batch{}, old))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("timestamp antigo deveria dar 401, veio %d", rec.Code)
	}
}

func TestRejectsFutureTimestamp(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	future := time.Now().Add(30 * time.Minute).Unix()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", Batch{}, future))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("timestamp futuro deveria dar 401, veio %d", rec.Code)
	}
}

func TestRejectsMissingSignature(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("esperava 401, veio %d", rec.Code)
	}
}

func TestSecretRotation(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	const novo = "outro-segredo-bem-longo-para-teste"
	s.SetSecret(novo)

	ts := time.Now().Unix()
	raw, _ := json.Marshal(Batch{})
	// Assinatura com o segredo antigo deve falhar...
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(raw))
	req.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Guarita-Signature", SignHex(secret, ts, raw))
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("segredo antigo deveria falhar após rotação, veio %d", rec.Code)
	}
	// ...e com o novo, passar.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(raw))
	req2.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req2.Header.Set("X-Guarita-Signature", SignHex(novo, ts, raw))
	rec2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("segredo novo deveria passar, veio %d", rec2.Code)
	}
}

func TestEventNormalization(t *testing.T) {
	cases := []struct {
		name     string
		ev       Event
		wantUser string
		wantErr  bool
	}{
		{"usuário simples", Event{Type: "logon", User: "joao", IP: "10.0.0.10"}, "joao@10.0.0.10", false},
		{"maiúsculas", Event{Type: "logon", User: "JOAO", IP: "10.0.0.10"}, "joao@10.0.0.10", false},
		{"prefixo de domínio", Event{Type: "logon", User: `EMPRESA\joao`, IP: "10.0.0.10"}, "joao@10.0.0.10", false},
		{"UPN", Event{Type: "logon", User: "joao@empresa.local", IP: "10.0.0.10"}, "joao@10.0.0.10", false},
		{"IPv4 mapeado", Event{Type: "logon", User: "joao", IP: "::ffff:10.0.0.10"}, "joao@10.0.0.10", false},
		{"conta de máquina", Event{Type: "logon", User: "PC01$", IP: "10.0.0.10"}, "", true},
		{"sem IP", Event{Type: "logon", User: "joao", IP: "-"}, "", true},
		{"IP vazio", Event{Type: "logon", User: "joao", IP: ""}, "", true},
		{"IP inválido", Event{Type: "logon", User: "joao", IP: "nao-e-ip"}, "", true},
		{"loopback", Event{Type: "logon", User: "joao", IP: "127.0.0.1"}, "", true},
		{"sem usuário", Event{Type: "logon", User: "", IP: "10.0.0.10"}, "", true},
		{"tipo desconhecido", Event{Type: "xyz", User: "joao", IP: "10.0.0.10"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHandler{}
			s := newTestServer(h)
			rec := httptest.NewRecorder()
			s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events",
				Batch{Events: []Event{tc.ev}}, time.Now().Unix()))

			var res Result
			_ = json.Unmarshal(rec.Body.Bytes(), &res)
			if tc.wantErr {
				if res.Ignored != 1 {
					t.Fatalf("esperava o evento ser ignorado, resultado %+v", res)
				}
				return
			}
			if res.Accepted != 1 {
				t.Fatalf("esperava aceitar, resultado %+v (erros: %v)", res, res.Errors)
			}
			if len(h.logons) != 1 || h.logons[0] != tc.wantUser {
				t.Fatalf("logons = %v, esperava %q", h.logons, tc.wantUser)
			}
		})
	}
}

func TestPartialBatchFailureIsReported(t *testing.T) {
	h := &fakeHandler{}
	s := newTestServer(h)
	batch := Batch{Events: []Event{
		{Type: "logon", User: "joao", IP: "10.0.0.10"},
		{Type: "logon", User: "PC01$", IP: "10.0.0.11"}, // ignorado
		{Type: "logon", User: "maria", IP: "invalido"},  // ignorado
		{Type: "logon", User: "ana", IP: "10.0.0.12"},
	}}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", batch, time.Now().Unix()))

	var res Result
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Accepted != 2 || res.Ignored != 2 {
		t.Fatalf("resultado %+v", res)
	}
	if len(res.Errors) != 2 {
		t.Fatalf("esperava 2 mensagens de erro, veio %v", res.Errors)
	}
	// Os eventos válidos devem ter passado mesmo com outros inválidos no lote.
	if len(h.logons) != 2 {
		t.Fatalf("logons = %v", h.logons)
	}
}

func TestPingUpdatesLastSeen(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	rec := httptest.NewRecorder()
	req := signedRequest(t, "/v1/ping", map[string]string{}, time.Now().Unix())
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ping: status %d", rec.Code)
	}
	seen := s.LastSeen()
	if _, ok := seen["DC01"]; !ok {
		t.Fatalf("LastSeen deveria conter DC01: %v", seen)
	}
}

func TestCountersAdvance(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	batch := Batch{Events: []Event{
		{Type: "logon", User: "joao", IP: "10.0.0.10"},
		{Type: "logon", User: "PC01$", IP: "10.0.0.11"},
	}}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", batch, time.Now().Unix()))

	recv, acc, _ := s.Counters()
	if recv != 2 || acc != 1 {
		t.Fatalf("contadores: recebidos=%d aceitos=%d", recv, acc)
	}
}

func TestRejectsGetOnEvents(t *testing.T) {
	s := newTestServer(&fakeHandler{})
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("esperava 405, veio %d", rec.Code)
	}
}

// fakeWarnHandler aplica o evento mas devolve um aviso, como o daemon faz
// quando o Active Directory está inacessível e o grupo padrão é usado.
type fakeWarnHandler struct{ fakeHandler }

func (f *fakeWarnHandler) OnLogon(ip netip.Addr, user, domain, computer string) error {
	_ = f.fakeHandler.OnLogon(ip, user, domain, computer)
	return Warnf("grupos de %s não resolvidos, usando grupo padrão: ad fora do ar", user)
}

// TestWarningCountsAsAccepted trava a distinção entre "evento recusado" e
// "evento aplicado com ressalva".
//
// Antes desta distinção, um logon cuja consulta de grupos falhasse era contado
// como ignorado, mesmo tendo criado a sessão. O efeito prático era o contador
// de eventos aplicados ficar em zero justamente quando o AD estava fora do ar,
// levando o operador a achar que os agentes não estavam funcionando.
func TestWarningCountsAsAccepted(t *testing.T) {
	h := &fakeWarnHandler{}
	s := New(secret, h, func(string, ...any) {})

	batch := Batch{Events: []Event{
		{Type: "logon", User: "joao", IP: "10.0.0.10"},
		{Type: "logon", User: "PC01$", IP: "10.0.0.11"}, // esse sim é para ignorar
	}}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, signedRequest(t, "/v1/events", batch, time.Now().Unix()))

	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 1 {
		t.Errorf("evento aplicado com ressalva deveria contar como aceito: accepted=%d", res.Accepted)
	}
	if res.Ignored != 1 {
		t.Errorf("a conta de máquina deveria ser a única ignorada: ignored=%d", res.Ignored)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("esperava 1 aviso, veio %v", res.Warnings)
	}
	if len(res.Errors) != 1 {
		t.Errorf("esperava 1 erro (conta de máquina), veio %v", res.Errors)
	}
	// E a sessão realmente foi criada.
	if len(h.logons) != 1 || h.logons[0] != "joao@10.0.0.10" {
		t.Errorf("a sessão deveria ter sido criada: %v", h.logons)
	}

	// O contador global também conta o aviso como aceito.
	recv, acc, _ := s.Counters()
	if recv != 2 || acc != 1 {
		t.Errorf("contadores: recebidos=%d aceitos=%d", recv, acc)
	}
}

// TestWarningUnwraps garante que errors.As/Is continuam funcionando no Warning.
func TestWarningUnwraps(t *testing.T) {
	base := fmt.Errorf("falha original")
	w := Warning{Err: base}
	if !errors.Is(w, base) {
		t.Error("errors.Is deveria achar o erro original dentro do Warning")
	}
	var got Warning
	if !errors.As(error(w), &got) {
		t.Error("errors.As deveria reconhecer um Warning")
	}
	if w.Error() != "falha original" {
		t.Errorf("Error() = %q", w.Error())
	}
}
