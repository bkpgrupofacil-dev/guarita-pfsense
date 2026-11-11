// Command guaritad é o serviço do pacote Guarita para pfSense.
//
// Ele recebe eventos de logon dos agentes instalados nos controladores de
// domínio, descobre os grupos de cada usuário no Active Directory e mantém uma
// tabela do pf por grupo com os IPs das estações daquele grupo. As regras de
// firewall do pfSense referenciam essas tabelas, de modo que a política passa a
// valer por usuário e não por IP fixo.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/grupofacil/guarita/internal/apiagent"
	"github.com/grupofacil/guarita/internal/apilocal"
	"github.com/grupofacil/guarita/internal/config"
	"github.com/grupofacil/guarita/internal/ldapgrp"
	"github.com/grupofacil/guarita/internal/pftable"
	"github.com/grupofacil/guarita/internal/session"
)

// Version é preenchida no build via -ldflags.
var Version = "0.1.2-dev"

func main() {
	var (
		cfgPath  = flag.String("config", config.DefaultPath, "caminho do arquivo de configuração JSON")
		showVer  = flag.Bool("version", false, "mostra a versão e sai")
		pidFile  = flag.String("pid", "/var/run/guaritad.pid", "arquivo de PID (vazio = não grava)")
		testOnly = flag.Bool("test", false, "valida a configuração e sai")
		pfctl    = flag.String("pfctl", "/sbin/pfctl", "caminho do pfctl")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("guaritad %s\n", Version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guaritad: configuração: %v\n", err)
		os.Exit(2)
	}
	if *testOnly {
		fmt.Printf("configuração válida: %d grupo(s), ldap=%s\n", len(cfg.Groups), cfg.LDAP.Host)
		return
	}

	logger := newLogger(cfg)
	logger.Printf("guaritad %s iniciando (config=%s)", Version, *cfgPath)

	d := newDaemon(cfg, *cfgPath, logger, pftable.OSRunner{Pfctl: *pfctl})

	if err := d.start(); err != nil {
		logger.Printf("erro ao iniciar: %v", err)
		os.Exit(1)
	}

	// O PID só é gravado depois que as portas foram abertas. No boot do
	// pfSense 2.9.0 o serviço foi iniciado duas vezes no mesmo segundo; a
	// segunda instância falha em "address already in use". Gravando antes,
	// ela podia deixar no arquivo o PID dela, já morta (o os.Exit não roda os
	// defer), e o SIGHUP de cada configuração salva ia para um processo que
	// não existe: grupos e LDAP alterados na interface nunca chegavam ao
	// serviço, sem erro nenhum.
	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			logger.Printf("aviso: não consegui gravar o PID em %s: %v", *pidFile, err)
		} else {
			defer os.Remove(*pidFile)
		}
	}

	// Sinais: SIGHUP recarrega a configuração, SIGTERM/SIGINT encerram.
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	for s := range sigc {
		switch s {
		case syscall.SIGHUP:
			logger.Printf("SIGHUP: recarregando configuração")
			if err := d.ReloadConfig(); err != nil {
				logger.Printf("falha ao recarregar: %v", err)
			}
		default:
			logger.Printf("sinal %s: encerrando", s)
			d.stop()
			return
		}
	}
}

func newLogger(cfg *config.Config) *log.Logger {
	// No pfSense, o que leva estes registros para /var/log/guarita.log (e para
	// Status > System Logs > Guarita) é a TAG do processo, "guaritad": o
	// pfSense gera em /var/etc/syslog.d/ uma regra "!guaritad" seguida de
	// "*.* /var/log/guarita.log", e em syslog BSD "!nome" filtra pelo nome do
	// programa. A facility abaixo só precisa não colidir com outro destino.
	fac := syslogFacility(cfg.LogFacility)
	w, err := syslog.New(fac|syslog.LOG_INFO, "guaritad")
	if err != nil {
		return log.New(os.Stderr, "guaritad: ", log.LstdFlags)
	}
	return log.New(w, "", 0)
}

func syslogFacility(name string) syslog.Priority {
	switch name {
	case "local0":
		return syslog.LOG_LOCAL0
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local6":
		return syslog.LOG_LOCAL6
	case "local5":
		return syslog.LOG_LOCAL5
	case "local7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_LOCAL4
	}
}

// daemon mantém o estado do serviço.
type daemon struct {
	mu      sync.RWMutex
	cfg     *config.Config
	cfgPath string

	log      *log.Logger
	sessions *session.Manager
	tables   *pftable.Writer
	resolver *ldapgrp.Resolver
	cache    *ldapgrp.Cache

	agentSrv *apiagent.Server
	httpSrv  *http.Server
	localSrv *apilocal.Server

	startedAt     time.Time
	lastSyncAt    time.Time
	lastSyncError string

	syncReq chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newDaemon(cfg *config.Config, cfgPath string, logger *log.Logger, runner pftable.Runner) *daemon {
	ctx, cancel := context.WithCancel(context.Background())
	d := &daemon{
		cfg:       cfg,
		cfgPath:   cfgPath,
		log:       logger,
		sessions:  session.New(cfg.SessionTTL.D(), cfg.StatePath),
		tables:    pftable.NewWriter(cfg.TableDir, runner),
		resolver:  ldapgrp.New(cfg),
		cache:     ldapgrp.NewCache(cfg.GroupRefresh.D()),
		startedAt: time.Now(),
		syncReq:   make(chan struct{}, 1),
		ctx:       ctx,
		cancel:    cancel,
	}
	d.sessions.SetOnChange(d.requestSync)
	d.agentSrv = apiagent.New(cfg.AgentSecret, d, logger.Printf)
	return d
}

func (d *daemon) start() error {
	cfg := d.snapshotCfg()

	// API dos agentes (TCP).
	ln, err := net.Listen("tcp", cfg.ListenAgent)
	if err != nil {
		return fmt.Errorf("escutando em %s: %w", cfg.ListenAgent, err)
	}
	d.httpSrv = &http.Server{
		Handler:           d.agentSrv.Routes(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		if err := d.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Printf("API de agentes encerrada: %v", err)
		}
	}()
	d.log.Printf("API de agentes escutando em %s", cfg.ListenAgent)

	// API local (socket unix) para a GUI.
	d.localSrv = apilocal.New(cfg.ListenLocal, d)
	if err := d.localSrv.Listen(); err != nil {
		return fmt.Errorf("socket local %s: %w", cfg.ListenLocal, err)
	}
	d.log.Printf("API local escutando em %s", cfg.ListenLocal)

	// Laços de manutenção.
	d.wg.Add(4)
	go d.syncLoop()
	go d.maintenanceLoop()
	go d.refreshLoop()
	go d.filterWatchLoop()

	// Escreve as tabelas já no boot, a partir do estado carregado do disco.
	d.requestSync()
	d.log.Printf("%d sessão(ões) restauradas do disco", d.sessions.Count())
	return nil
}

func (d *daemon) stop() {
	d.cancel()
	if d.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.httpSrv.Shutdown(ctx)
	}
	if d.localSrv != nil {
		d.localSrv.Close()
	}
	d.wg.Wait()
	if err := d.sessions.Save(); err != nil {
		d.log.Printf("erro ao salvar sessões: %v", err)
	}
	d.log.Printf("guaritad encerrado")
}

func (d *daemon) snapshotCfg() *config.Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg
}

// requestSync pede uma reescrita das tabelas. Chamadas repetidas são
// coalescidas: o canal tem capacidade 1 e o laço espera um curto intervalo
// antes de gravar, de modo que uma rajada de 500 eventos gera uma gravação.
func (d *daemon) requestSync() {
	select {
	case d.syncReq <- struct{}{}:
	default:
	}
}

func (d *daemon) syncLoop() {
	defer d.wg.Done()
	const debounce = 750 * time.Millisecond
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.syncReq:
			// Agrupa pedidos que chegarem durante a janela de debounce.
			t := time.NewTimer(debounce)
			draining := true
			for draining {
				select {
				case <-d.ctx.Done():
					t.Stop()
					return
				case <-d.syncReq:
					// mais um pedido: continua esperando
				case <-t.C:
					draining = false
				}
			}
			d.doSync()
		}
	}
}

func (d *daemon) doSync() {
	cfg := d.snapshotCfg()
	snap := d.sessions.TablesSnapshot()
	err := d.tables.Sync(snap, cfg.Groups)

	d.mu.Lock()
	d.lastSyncAt = time.Now()
	if err != nil {
		d.lastSyncError = err.Error()
	} else {
		d.lastSyncError = ""
	}
	d.mu.Unlock()

	if err != nil {
		d.log.Printf("erro ao sincronizar tabelas do pf: %v", err)
		return
	}
	if cfg.Debug {
		total := 0
		for _, ips := range snap {
			total += len(ips)
		}
		d.log.Printf("tabelas sincronizadas: %d grupo(s), %d entrada(s)", len(cfg.Groups), total)
	}
}

// filterWatchLoop repõe o conteúdo das tabelas depois que o pfSense recarrega
// o filtro, e periodicamente como rede de segurança.
//
// Por que é necessário: os aliases do Guarita são do tipo "host" com a lista de
// endereços vazia, e para esse caso o pfSense emite "table <nome> persist" e
// agenda um "pfctl -T flush -t <nome>" para rodar DEPOIS do filter_configure.
// Ou seja, qualquer alteração de configuração no firewall esvazia as nossas
// tabelas, e quem tem o conteúdo de verdade é este serviço.
//
// Há uma corrida: o flush acontece depois da recarga, então reaplicar no
// instante em que notamos a mudança do arquivo de regras pode ser cedo demais e
// o flush apagaria o que acabamos de pôr. Por isso reaplicamos algumas vezes,
// espaçadas, e mantemos a reaplicação periódica.
func (d *daemon) filterWatchLoop() {
	defer d.wg.Done()

	cfg := d.snapshotCfg()
	watch := newReloadWatcher(cfg.RulesFile, cfg.ReloadStatusFile)

	check := time.NewTicker(5 * time.Second)
	defer check.Stop()

	var periodic <-chan time.Time
	if cfg.ReapplyInterval.D() > 0 {
		t := time.NewTicker(cfg.ReapplyInterval.D())
		defer t.Stop()
		periodic = t.C
	}

	for {
		select {
		case <-d.ctx.Done():
			return

		case <-check.C:
			if _, ok := watch.changed(); !ok {
				continue
			}
			d.log.Printf("o filtro do pfSense foi recarregado; repondo as tabelas")
			// Reaplica algumas vezes para passar por cima do flush que o
			// pfSense agenda depois da recarga, qualquer que seja a ordem.
			go d.reapplyAfterReload()

		case <-periodic:
			d.requestSync()
		}
	}
}

// reapplyAfterReload reaplica as tabelas em alguns instantes depois de uma
// recarga de filtro.
func (d *daemon) reapplyAfterReload() {
	for _, delay := range []time.Duration{2 * time.Second, 6 * time.Second, 15 * time.Second} {
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(delay):
			d.requestSync()
		}
	}
}

// maintenanceLoop expira sessões e persiste o estado periodicamente.
func (d *daemon) maintenanceLoop() {
	defer d.wg.Done()
	tick := time.NewTicker(1 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-tick.C:
			if n := d.sessions.ExpireOlderThan(); n > 0 {
				d.log.Printf("%d sessão(ões) expiradas por inatividade", n)
			}
			if err := d.sessions.Save(); err != nil {
				d.log.Printf("erro ao salvar sessões: %v", err)
			}
		}
	}
}

// refreshLoop reconsulta no AD os grupos de sessões antigas, para que mudanças
// de grupo passem a valer sem o usuário precisar fazer logoff.
func (d *daemon) refreshLoop() {
	defer d.wg.Done()
	tick := time.NewTicker(2 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-tick.C:
			cfg := d.snapshotCfg()
			items := d.sessions.NeedGroupRefresh(cfg.GroupRefresh.D())
			for _, it := range items {
				select {
				case <-d.ctx.Done():
					return
				default:
				}
				d.cache.Invalidate(it.User)
				groups, _, err := d.resolveGroups(it.User)
				if err != nil {
					if cfg.Debug {
						d.log.Printf("refresh de %s falhou: %v", it.User, err)
					}
					continue
				}
				d.sessions.Upsert(it.IP, it.User, it.Domain, groups, "ad-agent")
			}
		}
	}
}

// resolveGroups consulta o cache e, em falta, o AD.
func (d *daemon) resolveGroups(user string) ([]string, []string, error) {
	if logical, ad, ok := d.cache.Get(user); ok {
		return logical, ad, nil
	}
	logical, ad, err := d.resolver.Resolve(user, true)
	if err != nil {
		d.cache.PutErr(user, err)
		return nil, nil, err
	}
	d.cache.Put(user, logical, ad)
	return logical, ad, nil
}

// ---- apiagent.Handler ----

func (d *daemon) OnLogon(ip netip.Addr, user, domain, computer string) error {
	cfg := d.snapshotCfg()
	groups, adGroups, err := d.resolveGroups(user)
	if err != nil {
		// Sem conseguir falar com o AD, ainda registramos a sessão com o grupo
		// padrão, para que o usuário não fique sem política nenhuma. O laço de
		// refresh corrige quando o AD voltar.
		//
		// Devolvemos um Warning, e não um erro comum: a sessão FOI criada, então
		// contar isto como evento recusado faria o contador de eventos aplicados
		// ficar em zero exatamente quando o AD está fora do ar.
		if cfg.DefaultGroup != "" {
			groups = []string{cfg.DefaultGroup}
		}
		changed := d.sessions.Upsert(ip, user, domain, groups, "ad-agent")
		if changed {
			d.log.Printf("logon user=%s ip=%s grupos=%v (AD indisponível: %v)",
				user, ip, groups, err)
		}
		return apiagent.Warnf("grupos de %s não resolvidos, usando grupo padrão: %v", user, err)
	}
	if len(groups) == 0 && cfg.DefaultGroup != "" {
		groups = []string{cfg.DefaultGroup}
	}
	changed := d.sessions.Upsert(ip, user, domain, groups, "ad-agent")
	if changed {
		d.log.Printf("logon user=%s ip=%s computer=%s grupos=%v ad=%v",
			user, ip, computer, groups, adGroups)
	}
	return nil
}

func (d *daemon) OnLogoff(ip netip.Addr, user string) error {
	s, ok := d.sessions.Lookup(ip)
	if !ok {
		return nil
	}
	// Só encerra se o logoff for do usuário que está naquele IP. Em estações
	// compartilhadas isso evita que o logoff de um usuário antigo derrube a
	// sessão de quem entrou depois.
	if s.User != user {
		return nil
	}
	if d.sessions.Remove(ip) {
		d.log.Printf("logoff user=%s ip=%s", user, ip)
	}
	return nil
}

func (d *daemon) OnActivity(ip netip.Addr, user string) error {
	if !d.sessions.Touch(ip) {
		// Sem sessão conhecida: trata como logon.
		return d.OnLogon(ip, user, "", "")
	}
	return nil
}

// ---- apilocal.Backend ----

func (d *daemon) Status() apilocal.StatusInfo {
	cfg := d.snapshotCfg()
	snap := d.sessions.TablesSnapshot()
	recv, acc, rej := d.agentSrv.Counters()

	groups := make([]apilocal.GroupInfo, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		groups = append(groups, apilocal.GroupInfo{
			Name:    g.Name,
			Table:   g.Table,
			PfTable: config.PfTableName(g.Table),
			Members: len(snap[g.Table]),
		})
	}

	d.mu.RLock()
	lastSync, lastErr := d.lastSyncAt, d.lastSyncError
	d.mu.RUnlock()

	return apilocal.StatusInfo{
		Version:        Version,
		StartedAt:      d.startedAt,
		Sessions:       d.sessions.Count(),
		Groups:         groups,
		AgentsLastSeen: d.agentSrv.LastSeen(),
		EventsReceived: recv,
		EventsAccepted: acc,
		EventsRejected: rej,
		LastSyncAt:     lastSync,
		LastSyncError:  lastErr,
		LDAPHost:       cfg.LDAP.Host,
	}
}

func (d *daemon) Sessions() []apilocal.SessionInfo {
	in := d.sessions.List()
	out := make([]apilocal.SessionInfo, 0, len(in))
	for _, s := range in {
		out = append(out, apilocal.SessionInfo{
			IP:      s.IP.String(),
			User:    s.User,
			Domain:  s.Domain,
			Groups:  s.Groups,
			LoginAt: s.LoginAt,
			SeenAt:  s.SeenAt,
			Source:  s.Source,
			Sticky:  s.Sticky,
		})
	}
	return out
}

func (d *daemon) RemoveSession(ip netip.Addr) bool {
	ok := d.sessions.Remove(ip)
	if ok {
		d.log.Printf("sessão de %s removida pela interface", ip)
	}
	return ok
}

func (d *daemon) SetSticky(ip netip.Addr, on bool) bool {
	return d.sessions.SetSticky(ip, on)
}

func (d *daemon) Resync() error {
	d.cache.Purge()
	d.doSync()
	d.mu.RLock()
	err := d.lastSyncError
	d.mu.RUnlock()
	if err != "" {
		return errors.New(err)
	}
	return nil
}

func (d *daemon) TestLDAP(user string) (apilocal.LDAPTest, error) {
	start := time.Now()
	d.cache.Invalidate(user)
	logical, ad, err := d.resolver.Resolve(user, false)
	if err != nil {
		return apilocal.LDAPTest{}, err
	}
	return apilocal.LDAPTest{
		User:     user,
		ADGroups: ad,
		Logical:  logical,
		Elapsed:  time.Since(start).Round(time.Millisecond).String(),
	}, nil
}

func (d *daemon) ReloadConfig() error {
	cfg, err := config.Load(d.cfgPath)
	if err != nil {
		return err
	}
	old := d.snapshotCfg()

	d.mu.Lock()
	d.cfg = cfg
	d.mu.Unlock()

	d.resolver.Reload(cfg)
	d.cache.SetTTL(cfg.GroupRefresh.D())
	d.cache.Purge()
	d.agentSrv.SetSecret(cfg.AgentSecret)

	if cfg.ListenAgent != old.ListenAgent || cfg.ListenLocal != old.ListenLocal {
		d.log.Printf("aviso: mudança de endereço de escuta exige reiniciar o serviço "+
			"(agentes: %s -> %s)", old.ListenAgent, cfg.ListenAgent)
	}
	d.requestSync()
	d.log.Printf("configuração recarregada: %d grupo(s)", len(cfg.Groups))
	return nil
}
