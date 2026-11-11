package main

import (
	"os"
	"time"
)

// reloadWatcher diz se o pfSense recarregou o filtro desde a última consulta,
// observando a data de modificação de um ou mais arquivos.
//
// Por que mais de um arquivo: até o 2.7, toda recarga reescrevia o
// /tmp/rules.debug. Desde o 2.8/2.9, o filter_configure_sync() só reescreve
// esse arquivo quando o ruleset mudou ("Skipping filter configuration
// reload"), mas os comandos de depois da recarga, entre eles o
// "pfctl -T flush" das nossas tabelas, rodam sempre. Observando só o
// rules.debug, o daemon não percebia esse flush e as tabelas ficavam vazias até
// a reaplicação periódica: quem tinha a política "restrito" ficava sem ela por
// até um minuto, a cada configuração salva no firewall. O
// /var/run/filter_reload_status é reescrito em toda recarga, inclusive nas
// puladas, e cobre esse caso.
type reloadWatcher struct {
	files []string
	last  map[string]time.Time
}

// newReloadWatcher guarda a data atual de cada arquivo. Nomes vazios são
// ignorados; um arquivo que ainda não existe passa a contar quando surgir.
func newReloadWatcher(files ...string) *reloadWatcher {
	w := &reloadWatcher{last: make(map[string]time.Time)}
	for _, f := range files {
		if f == "" {
			continue
		}
		w.files = append(w.files, f)
		if fi, err := os.Stat(f); err == nil {
			w.last[f] = fi.ModTime()
		}
	}
	return w
}

// changed informa se algum arquivo mudou desde a última chamada e devolve o
// primeiro que mudou. Atualiza a data de todos, para uma mesma recarga, que
// mexe nos dois arquivos, não contar duas vezes.
func (w *reloadWatcher) changed() (string, bool) {
	first := ""
	for _, f := range w.files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		if prev, ok := w.last[f]; ok && fi.ModTime().Equal(prev) {
			continue
		}
		w.last[f] = fi.ModTime()
		if first == "" {
			first = f
		}
	}
	return first, first != ""
}
