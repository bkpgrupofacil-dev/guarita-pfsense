package apiagent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fixture é o que build/ps_mimic.py produz: o JSON e a assinatura exatamente
// como o agente em PowerShell os monta.
type fixture struct {
	Secret    string `json:"secret"`
	TS        int64  `json:"ts"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

// TestAgentConformance garante que o agente em PowerShell e este serviço
// concordam quanto ao formato do JSON e ao cálculo do HMAC.
//
// O agente roda em Windows e não pode ser executado aqui, então
// build/ps_mimic.py replica, linha por linha, as funções ConvertTo-JsonString,
// Build-BatchJson e Get-GuaritaSignature do .ps1. Se alguém mudar o esquema de
// assinatura em um dos lados sem mudar o outro, este teste quebra — em
// produção a falha apareceria como "assinatura inválida" vinda dos DCs.
func TestAgentConformance(t *testing.T) {
	fx := loadFixture(t)

	// 1) A assinatura calculada pelo lado Go tem de ser idêntica à do agente.
	got := SignHex(fx.Secret, fx.TS, []byte(fx.Body))
	if got != fx.Signature {
		t.Fatalf("assinatura divergente:\n  agente (PowerShell) = %s\n  serviço (Go)        = %s",
			fx.Signature, got)
	}

	// 2) O JSON montado à mão pelo agente tem de ser lido corretamente aqui.
	var batch Batch
	if err := json.Unmarshal([]byte(fx.Body), &batch); err != nil {
		t.Fatalf("o serviço não conseguiu ler o JSON do agente: %v", err)
	}
	if batch.Agent != "DC01" {
		t.Errorf("agent = %q", batch.Agent)
	}
	if len(batch.Events) != 3 {
		t.Fatalf("esperava 3 eventos, veio %d", len(batch.Events))
	}
	// Os escapes \uXXXX do agente têm de voltar como UTF-8 correto.
	if batch.Events[1].User != "joão.conceição" {
		t.Errorf("acentos corrompidos: user = %q", batch.Events[1].User)
	}
	if batch.Events[1].Computer != "PC-ÇÃO" {
		t.Errorf("acentos corrompidos: computer = %q", batch.Events[1].Computer)
	}
	// Aspas, barras, nova linha e tabulação.
	if batch.Events[2].User != `aspas"e\barra` {
		t.Errorf("escape incorreto: user = %q", batch.Events[2].User)
	}
	if batch.Events[2].Domain != "LINHA\nNOVA" {
		t.Errorf("escape incorreto: domain = %q", batch.Events[2].Domain)
	}
	if batch.Events[0].EventID != 4768 {
		t.Errorf("event_id = %d", batch.Events[0].EventID)
	}

	// 3) Ponta a ponta com os bytes exatos que o agente produz.
	//
	// O fixture usa um timestamp fixo, que já está fora da janela de ±5 minutos,
	// então reassinamos com a hora atual — mas enviamos o MESMO corpo, byte por
	// byte, em vez de remontá-lo com o encoder do Go.
	h := &fakeHandler{}
	s := New(fx.Secret, h, func(string, ...any) {})

	ts := time.Now().Unix()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader([]byte(fx.Body)))
	req.Header.Set("X-Guarita-Agent", "DC01")
	req.Header.Set("X-Guarita-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Guarita-Signature", SignHex(fx.Secret, ts, []byte(fx.Body)))

	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var res Result
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	// O terceiro evento tem usuário com caracteres estranhos mas IP válido, e o
	// segundo é "activity"; todos devem ser aceitos.
	if res.Accepted != 3 {
		t.Fatalf("esperava aceitar os 3 eventos, resultado %+v (erros %v)", res, res.Errors)
	}
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	// Gera o fixture na hora, a partir do mimic em Python, para que ele nunca
	// fique desatualizado em relação ao script.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "build", "ps_mimic.py")
	if _, err := os.Stat(script); err != nil {
		t.Skipf("ps_mimic.py não encontrado: %v", err)
	}
	cmd := exec.Command("python3", "-I", script)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("não consegui rodar o ps_mimic.py (python3 ausente?): %v", err)
	}
	var fx fixture
	if err := json.Unmarshal(out, &fx); err != nil {
		t.Fatalf("saída do ps_mimic.py inválida: %v", err)
	}
	return fx
}
