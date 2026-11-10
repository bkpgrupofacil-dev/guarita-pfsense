// Package config carrega a configuração do guaritad a partir de um arquivo JSON
// gravado pela interface do pfSense (guarita.inc). O daemon nunca edita este
// arquivo; ele apenas o lê e recarrega quando recebe SIGHUP.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultPath é o caminho padrão do arquivo de configuração no pfSense.
const DefaultPath = "/usr/local/pkg/guarita/guarita.json"

// Config é a configuração completa do daemon.
type Config struct {
	// ListenAgent é o endereço TCP onde a API dos agentes do AD escuta
	// (ex.: "0.0.0.0:8923"). O pfSense deve ter uma regra de firewall
	// permitindo apenas os IPs dos controladores de domínio.
	ListenAgent string `json:"listen_agent"`

	// ListenLocal é o socket unix da API local usada pela GUI em PHP.
	ListenLocal string `json:"listen_local"`

	// AgentSecret é o segredo compartilhado (HMAC-SHA256) entre o daemon e os
	// agentes dos DCs. Toda requisição de agente é assinada com ele.
	AgentSecret string `json:"agent_secret"`

	// SessionTTL é por quanto tempo uma associação usuário<->IP vale sem um novo
	// evento de logon. Expirada, o IP sai das tabelas de grupo.
	SessionTTL Duration `json:"session_ttl"`

	// GroupRefresh é o intervalo para reconsultar os grupos de um usuário no AD.
	GroupRefresh Duration `json:"group_refresh"`

	// StatePath é onde o daemon persiste as sessões ativas (sobrevive a reboot).
	StatePath string `json:"state_path"`

	// TableDir é o diretório dos arquivos de tabela pf (um por grupo).
	TableDir string `json:"table_dir"`

	// RulesFile é o arquivo que o pfSense reescreve a cada recarga de filtro
	// (normalmente /tmp/rules.debug). O daemon observa a data de modificação
	// dele para saber que precisa repor o conteúdo das tabelas: um alias com
	// lista vazia faz o pfSense agendar "pfctl -T flush" após cada recarga.
	// Vazio desliga a observação.
	RulesFile string `json:"rules_file"`

	// ReapplyInterval é o intervalo da reaplicação periódica das tabelas, como
	// rede de segurança para qualquer coisa que as esvazie sem passar pelo
	// arquivo de regras. Zero desliga.
	ReapplyInterval Duration `json:"reapply_interval"`

	// DefaultGroup é o nome lógico do grupo aplicado a IPs sem usuário
	// identificado (ex.: "nao_autenticado"). Pode ficar vazio.
	DefaultGroup string `json:"default_group"`

	// LDAP é a configuração de consulta de grupos no Active Directory.
	LDAP LDAP `json:"ldap"`

	// Groups é a lista de grupos lógicos e o mapeamento para grupos do AD.
	Groups []Group `json:"groups"`

	// LogFacility é a facility de syslog (ex.: "local4") para os logs por usuário.
	// O que faz os registros caírem em /var/log/guarita.log no pfSense é a TAG
	// do processo ("guaritad"), que o pfSense usa como filtro de programa; a
	// facility só precisa não colidir com outro destino.
	LogFacility string `json:"log_facility"`

	// Debug habilita log detalhado.
	Debug bool `json:"debug"`
}

// LDAP descreve como consultar os grupos de um usuário no AD.
type LDAP struct {
	Host      string   `json:"host"`       // ex.: dc01.empresa.local
	Port      int      `json:"port"`       // 389 ou 636
	TLSMode   string   `json:"tls_mode"`   // "none", "starttls", "ssl"
	CACert    string   `json:"ca_cert"`    // PEM da CA, opcional
	BindDN    string   `json:"bind_dn"`    // ex.: CONEXTI\\svc_guarita ou DN completo
	BindPw    string   `json:"bind_pw"`    //
	BaseDN    string   `json:"base_dn"`    // ex.: DC=empresa,DC=local
	UserAttr  string   `json:"user_attr"`  // normalmente sAMAccountName
	GroupAttr string   `json:"group_attr"` // normalmente memberOf
	Nested    bool     `json:"nested"`     // seguir grupos aninhados (LDAP_MATCHING_RULE_IN_CHAIN)
	Timeout   Duration `json:"timeout"`
}

// Group é um grupo lógico do Guarita. Cada grupo vira uma tabela pf chamada
// "guarita_<Table>". As regras de firewall do pfSense referenciam essa tabela
// por um alias de mesmo nome.
type Group struct {
	// Name é o nome amigável exibido na GUI.
	Name string `json:"name"`

	// Table é o identificador curto usado no nome da tabela pf e do alias.
	// Precisa casar com ^[a-zA-Z0-9_]{1,24}$.
	Table string `json:"table"`

	// ADGroups são os nomes (CN) dos grupos do AD que colocam o usuário neste
	// grupo lógico. A comparação é case-insensitive.
	ADGroups []string `json:"ad_groups"`

	// Priority: quando um usuário cai em vários grupos, o de menor número vence
	// (é o único em que o IP entra). 0 = maior prioridade.
	Priority int `json:"priority"`
}

// Duration é um time.Duration que aceita JSON tanto numérico (segundos) quanto
// string ("4h", "10m").
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		return nil
	}
	if s[0] == '"' {
		dur, err := time.ParseDuration(strings.Trim(s, `"`))
		if err != nil {
			return err
		}
		*d = Duration(dur)
		return nil
	}
	// número = segundos
	var secs float64
	if err := json.Unmarshal(b, &secs); err != nil {
		return err
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// Load lê e valida a configuração.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("json inválido em %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.ListenAgent == "" {
		c.ListenAgent = "0.0.0.0:8923"
	}
	if c.ListenLocal == "" {
		c.ListenLocal = "/var/run/guarita.sock"
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = Duration(4 * time.Hour)
	}
	if c.GroupRefresh == 0 {
		c.GroupRefresh = Duration(30 * time.Minute)
	}
	if c.StatePath == "" {
		c.StatePath = "/var/db/guarita/sessions.json"
	}
	if c.TableDir == "" {
		c.TableDir = "/var/db/guarita/tables"
	}
	if c.RulesFile == "" {
		c.RulesFile = "/tmp/rules.debug"
	}
	if c.ReapplyInterval == 0 {
		c.ReapplyInterval = Duration(60 * time.Second)
	}
	if c.LogFacility == "" {
		// local4 nao e roteada para nenhum outro log pelo pfSense; local5 vai
		// para o nginx.log e local3 para o vpn.log.
		c.LogFacility = "local4"
	}
	if c.LDAP.UserAttr == "" {
		c.LDAP.UserAttr = "sAMAccountName"
	}
	if c.LDAP.GroupAttr == "" {
		c.LDAP.GroupAttr = "memberOf"
	}
	if c.LDAP.Timeout == 0 {
		c.LDAP.Timeout = Duration(10 * time.Second)
	}
	if c.LDAP.Port == 0 {
		switch c.LDAP.TLSMode {
		case "ssl":
			c.LDAP.Port = 636
		default:
			c.LDAP.Port = 389
		}
	}
}

func (c *Config) validate() error {
	if len(c.AgentSecret) < 16 {
		return fmt.Errorf("agent_secret ausente ou curto demais (mínimo 16 caracteres)")
	}
	seen := map[string]bool{}
	for i, g := range c.Groups {
		if !validTableName(g.Table) {
			return fmt.Errorf("grupo %d: table %q inválido (use a-z, A-Z, 0-9, _, até 24 caracteres)", i, g.Table)
		}
		if seen[strings.ToLower(g.Table)] {
			return fmt.Errorf("grupo %d: table %q duplicado", i, g.Table)
		}
		seen[strings.ToLower(g.Table)] = true
	}
	return nil
}

func validTableName(s string) bool {
	if len(s) == 0 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

// PfTableName devolve o nome da tabela pf de um grupo lógico.
func PfTableName(table string) string { return "guarita_" + table }
