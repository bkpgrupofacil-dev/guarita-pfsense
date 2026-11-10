// Package pftable materializa os grupos lógicos em tabelas do pf.
//
// Para cada grupo o daemon grava um arquivo texto com um IP por linha em
// TableDir/<tabela>.txt e, em seguida, recarrega a tabela no pf com:
//
//	pfctl -t guarita_<tabela> -T replace -f <arquivo>
//
// As regras de firewall do pfSense referenciam essas tabelas através de um
// alias do tipo "URL Table (IPs)" cujo conteúdo aponta para o arquivo local,
// ou diretamente pelo nome da tabela em regras manuais. Reescrever o arquivo e
// dar "replace" é atômico do ponto de vista do pf: as conexões já estabelecidas
// não são derrubadas, apenas as novas passam a valer pela tabela atualizada.
package pftable

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/grupofacil/guarita/internal/config"
)

// Runner executa o pfctl. Em produção use OSRunner; nos testes, um fake.
type Runner interface {
	ReplaceTable(table, file string) error
	FlushTable(table string) error
}

// Writer grava os arquivos de tabela e aciona o Runner.
type Writer struct {
	dir    string
	runner Runner
}

func NewWriter(dir string, r Runner) *Writer {
	return &Writer{dir: dir, runner: r}
}

// Sync recebe o snapshot (tabela lógica -> IPs) e a lista de grupos conhecidos,
// grava os arquivos e recarrega o pf. Grupos conhecidos sem IPs recebem arquivo
// vazio e tabela esvaziada, para que o alias exista mesmo sem membros.
func (w *Writer) Sync(snapshot map[string][]string, known []config.Group) error {
	if err := os.MkdirAll(w.dir, 0o750); err != nil {
		return fmt.Errorf("criando %s: %w", w.dir, err)
	}

	// Conjunto de todas as tabelas que devem existir: as conhecidas + as que
	// aparecem no snapshot (defensivo).
	tables := map[string]bool{}
	for _, g := range known {
		tables[g.Table] = true
	}
	for t := range snapshot {
		tables[t] = true
	}

	var firstErr error
	for t := range tables {
		ips := snapshot[t]
		sort.Strings(ips)
		if err := w.writeOne(t, ips); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (w *Writer) writeOne(table string, ips []string) error {
	file := filepath.Join(w.dir, table+".txt")
	var buf bytes.Buffer
	for _, ip := range ips {
		buf.WriteString(ip)
		buf.WriteByte('\n')
	}
	if err := atomicWrite(file, buf.Bytes()); err != nil {
		return err
	}
	pfName := config.PfTableName(table)
	if len(ips) == 0 {
		// replace com arquivo vazio também serve, mas flush é mais explícito.
		if err := w.runner.ReplaceTable(pfName, file); err != nil {
			return fmt.Errorf("pfctl replace %s: %w", pfName, err)
		}
		return nil
	}
	if err := w.runner.ReplaceTable(pfName, file); err != nil {
		return fmt.Errorf("pfctl replace %s: %w", pfName, err)
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// OSRunner chama o pfctl de verdade.
type OSRunner struct {
	Pfctl string // caminho; vazio => /sbin/pfctl
}

func (r OSRunner) bin() string {
	if r.Pfctl != "" {
		return r.Pfctl
	}
	return "/sbin/pfctl"
}

func (r OSRunner) ReplaceTable(table, file string) error {
	// -q silencioso; -t tabela; -T replace -f arquivo
	cmd := exec.Command(r.bin(), "-t", table, "-T", "replace", "-f", file)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Se a tabela ainda não existe no ruleset, pfctl recusa. Nesse caso
		// tentamos criar via "-T add" implícito não é possível; devolvemos o
		// erro para o chamador registrar. A tabela passa a existir assim que o
		// alias/regra do pfSense é aplicado por filter_configure().
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r OSRunner) FlushTable(table string) error {
	cmd := exec.Command(r.bin(), "-t", table, "-T", "flush")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
