#!/bin/sh
# verify-on-pfsense.sh - roda DENTRO do pfSense e confere a instalação do Guarita.
#
# Cobre o que não dá para testar fora de um pfSense de verdade:
# registro no pkg e no config.xml, criação do alias, existência da tabela no
# pf, geração do JSON do daemon, serviço no ar, API local e um evento de agente
# ponta a ponta até o IP aparecer na tabela do firewall.
#
# USE EM LABORATÓRIO. Para testar, o script habilita o Guarita, faz o serviço
# escutar em 127.0.0.1 e troca a lista de grupos por um grupo de teste. Ao
# terminar — com sucesso, com falha ou com Ctrl+C — ele RESTAURA as
# configurações e os grupos que existiam antes e apaga a sessão de teste. Sem
# isso, rodar o script depois de configurar os grupos reais apagaria os grupos
# e deixaria o agente do controlador de domínio sem conseguir falar com o
# pfSense.
#
# Uso:  sh verify-on-pfsense.sh

PASS=0
FAIL=0
ok()  { echo "  [ok] $*";     PASS=$((PASS+1)); }
bad() { echo "  [FALHOU] $*"; FAIL=$((FAIL+1)); }
inf() { echo ""; echo "== $*"; }

PKG=pfSense-pkg-Guarita
PHP=/usr/local/bin/php
BACKUP=/tmp/guarita-verify-backup.ser
TEST_IP=192.168.99.50

echo "pfSense $(cat /etc/version 2>/dev/null) | PHP $($PHP -r 'echo PHP_VERSION;' 2>/dev/null)"

# filter_configure() é ASSÍNCRONO: só faz send_event("filter reload") e volta na
# hora; quem recarrega é o check_reload_status, um pouco depois (~1 s no 2.9.0).
# Conferir a tabela logo depois dele mede o momento errado. Estas funções esperam
# a recarga terminar de fato.
#
# O sinal é o /var/run/filter_reload_status, e não o /tmp/rules.debug: desde o
# 2.8/2.9 uma recarga em que o ruleset não mudou é "pulada" e não reescreve o
# rules.debug, mas roda os comandos de depois da recarga (o flush das nossas
# tabelas) e reescreve o status, que termina em "Done" depois deles.
STATUS=/var/run/filter_reload_status
rules_mtime() { stat -f %m "$STATUS" 2>/dev/null || echo 0; }
# wait_reload <mtime de antes>: espera uma recarga nova terminar (até 30 s).
wait_reload() {
	_i=0
	while [ $_i -lt 60 ]; do
		if [ "$(rules_mtime)" -gt "$1" ] && [ "$(tail -1 "$STATUS" 2>/dev/null)" = "Done" ]; then
			return 0
		fi
		sleep 0.5
		_i=$((_i+1))
	done
	return 1
}
# reload_filter: pede a recarga e espera ela acontecer.
reload_filter() {
	_m=$(rules_mtime)
	sleep 1  # o mtime tem resolução de 1 s
	$PHP -r 'require_once("config.inc"); require_once("filter.inc"); filter_configure();' >/dev/null 2>&1
	wait_reload "$_m"
}
table_exists() { pfctl -sT 2>/dev/null | grep -qx "$1"; }
table_count()  { pfctl -t "$1" -T show 2>/dev/null | grep -c .; }

# Guarda as configurações e os grupos atuais do Guarita, para restaurar no fim.
$PHP -r '
require_once("config.inc");
$b = [
	"settings" => config_get_path("installedpackages/guarita", null),
	"groups"   => config_get_path("installedpackages/guaritagroups", null),
];
/* serialize() e nao json_encode(): o JSON falha calado com bytes que nao sao
 * UTF-8 valido, e o backup sairia vazio. */
$data = serialize($b);
if (file_put_contents("'"$BACKUP"'", $data) !== strlen($data)) { exit(1); }
' || { echo "nao consegui salvar a configuracao atual; abortando sem mexer em nada"; exit 2; }
# Se um grupo real usar a tabela "teste", ela deve continuar no pf no fim.
HAD_TEST_GROUP=$($PHP -r 'require_once("config.inc");
foreach (config_get_path("installedpackages/guaritagroups/config", []) as $g)
	if (($g["table"] ?? "") === "teste") { echo 1; break; }' 2>/dev/null)

restore_config() {
	[ -f "$BACKUP" ] || return
	echo ""
	echo "== restaurando a configuracao anterior do Guarita"
	$PHP -r '
	require_once("config.inc");
	require_once("/usr/local/pkg/guarita.inc");
	/* Apaga a sessao de teste antes de restaurar, para o IP ficticio nao
	 * acabar numa tabela de grupo real. */
	guarita_remove_session("'"$TEST_IP"'");
	/* Com o servico parado (o passo de desabilitar para o daemon), a API nao
	 * responde e a sessao continuava no arquivo de estado: o daemon a
	 * restaurava do disco no proximo inicio. Parado, o arquivo e so nosso. */
	if (!guarita_is_running() && file_exists(GUARITA_STATE)) {
		$st = json_decode(file_get_contents(GUARITA_STATE), true);
		if (is_array($st)) {
			$st = array_values(array_filter($st, function ($x) {
				return ($x["ip"] ?? "") !== "'"$TEST_IP"'";
			}));
			file_put_contents(GUARITA_STATE, json_encode($st, JSON_PRETTY_PRINT));
		}
	}
	$b = unserialize(file_get_contents("'"$BACKUP"'"));
	if (!is_array($b)) { echo "  backup ilegivel; restaure manualmente\n"; exit(1); }
	foreach (["settings" => "installedpackages/guarita",
	          "groups"   => "installedpackages/guaritagroups"] as $k => $path) {
		if ($b[$k] === null) {
			config_del_path($path);
		} else {
			config_set_path($path, $b[$k]);
		}
	}
	write_config("Guarita: verify-on-pfsense.sh restaurou a configuracao anterior");
	guarita_resync_config();
	echo "  configuracoes e grupos de antes do teste restaurados\n";
	' 2>&1
	rm -f "$BACKUP"
	# A tabela de teste so sai do pf com uma recarga de filtro. Se ela ficar,
	# o resync deixou de recarregar o filtro em algum caminho.
	if [ "$HAD_TEST_GROUP" != "1" ]; then
		_i=0
		while table_exists guarita_teste && [ $_i -lt 30 ]; do sleep 1; _i=$((_i+1)); done
		if table_exists guarita_teste; then
			echo "  [FALHOU] a tabela guarita_teste ficou no pf depois de restaurar"
			exit 1
		fi
		echo "  tabela de teste removida do pf"
	fi
	# A sessao de teste nao pode sobrar, nem no disco nem no daemon.
	if grep -q "\"$TEST_IP\"" /var/db/guarita/sessions.json 2>/dev/null; then
		echo "  [FALHOU] a sessao de teste $TEST_IP ficou em /var/db/guarita/sessions.json"
		exit 1
	fi
	echo "  sessao de teste removida"
}
trap restore_config EXIT
trap 'exit 130' INT TERM

inf "1. registro no gerenciador de pacotes"
if pkg info -e $PKG; then
	ok "pkg reconhece $PKG ($(pkg query %v $PKG))"
else
	bad "pkg NAO reconhece $PKG"
fi

inf "2. arquivos no lugar"
for f in /usr/local/pkg/guarita.xml /usr/local/pkg/guaritagroups.xml \
         /usr/local/pkg/guarita.inc /usr/local/sbin/guaritad \
         /usr/local/www/guarita_sessions.php /usr/local/www/guarita_status.php \
         /usr/local/www/guarita_agents.php /etc/inc/priv/guarita.priv.inc \
         /usr/local/share/pfSense-pkg-Guarita/info.xml; do
	[ -f "$f" ] && ok "$f" || bad "falta $f"
done

inf "3. o binario roda neste FreeBSD"
if V=$(/usr/local/sbin/guaritad -version 2>&1); then
	ok "guaritad executa: $V"
else
	bad "guaritad nao executa: $V"
fi

inf "4. menu e servico registrados no config.xml"
$PHP -r '
require_once("config.inc");
$m = false;
foreach (config_get_path("installedpackages/menu", []) as $x) {
	if ($x["name"] === "Guarita") { $m = $x; break; }
}
echo $m ? "MENU_OK " . $m["section"] . " " . $m["url"] . "\n" : "MENU_FALTA\n";
$s = false;
foreach (config_get_path("installedpackages/service", []) as $x) {
	if ($x["name"] === "guaritad") { $s = $x; break; }
}
echo $s ? "SERVICO_OK " . $s["rcfile"] . "\n" : "SERVICO_FALTA\n";
$p = false;
foreach (config_get_path("installedpackages/package", []) as $x) {
	if ($x["name"] === "Guarita") { $p = $x; break; }
}
echo $p ? "PACOTE_OK cfg=" . $p["configurationfile"] . "\n" : "PACOTE_FALTA\n";
' > /tmp/v4.txt 2>&1
grep -q MENU_OK    /tmp/v4.txt && ok "menu em Services > Guarita"      || bad "menu nao registrado"
grep -q SERVICO_OK /tmp/v4.txt && ok "servico guaritad registrado"     || bad "servico nao registrado"
grep -q PACOTE_OK  /tmp/v4.txt && ok "pacote registrado no config.xml" || bad "pacote nao registrado"
sed 's/^/     /' /tmp/v4.txt

inf "5. habilitando o pacote e criando um grupo de teste"
$PHP -r '
require_once("config.inc");
require_once("/usr/local/pkg/guarita.inc");
config_set_path("installedpackages/guarita/config/0/enable", "on");
config_set_path("installedpackages/guarita/config/0/listen_ip", "127.0.0.1");
config_set_path("installedpackages/guarita/config/0/listen_port", "8923");
config_set_path("installedpackages/guarita/config/0/session_ttl", "240");
config_set_path("installedpackages/guarita/config/0/group_refresh", "30");
config_set_path("installedpackages/guarita/config/0/default_group", "teste");
if (empty(config_get_path("installedpackages/guarita/config/0/agent_secret"))) {
	config_set_path("installedpackages/guarita/config/0/agent_secret", guarita_generate_secret());
}
config_set_path("installedpackages/guaritagroups/config", [[
	"name" => "Grupo de Teste", "table" => "teste",
	"ad_groups" => "GG_Teste", "priority" => "0", "descr" => "criado pelo verify.sh",
]]);
write_config("Guarita: configuracao de teste");
echo "config gravada\n";
guarita_resync_config();
echo "resync executado\n";
' 2>&1 | sed 's/^/     /'

inf "6. JSON de configuracao do daemon"
if [ -f /usr/local/pkg/guarita/guarita.json ]; then
	ok "guarita.json gerado"
	PERM=$(stat -f %Lp /usr/local/pkg/guarita/guarita.json)
	[ "$PERM" = "600" ] && ok "permissao 600 (contem segredos)" || bad "permissao $PERM, esperava 600"
	$PHP -r '
	$j = json_decode(file_get_contents("/usr/local/pkg/guarita/guarita.json"), true);
	if (!$j) { echo "JSON_INVALIDO\n"; exit; }
	echo "JSON_OK\n";
	echo "listen=" . $j["listen_agent"] . "\n";
	echo "grupos=" . count($j["groups"]) . "\n";
	echo "tabela0=" . ($j["groups"][0]["table"] ?? "-") . "\n";
	echo "default=" . $j["default_group"] . "\n";
	echo "segredo_len=" . strlen($j["agent_secret"]) . "\n";
	' > /tmp/v6.txt 2>&1
	grep -q JSON_OK /tmp/v6.txt && ok "JSON valido" || bad "JSON invalido"
	grep -q "grupos=1" /tmp/v6.txt && ok "o grupo de teste esta no JSON" || bad "grupo ausente no JSON"
	sed 's/^/     /' /tmp/v6.txt
else
	bad "guarita.json NAO foi gerado"
fi

inf "7. alias criado em Firewall > Aliases"
$PHP -r '
require_once("config.inc");
$a = false;
foreach (config_get_path("aliases/alias", []) as $x) {
	if ($x["name"] === "guarita_teste") { $a = $x; break; }
}
if (!$a) { echo "ALIAS_FALTA\n"; exit; }
echo "ALIAS_OK\n";
echo "tipo=" . $a["type"] . "\n";
echo "address=[" . ($a["address"] ?? "") . "]\n";
echo "descr=" . $a["descr"] . "\n";
' > /tmp/v7.txt 2>&1
grep -q ALIAS_OK  /tmp/v7.txt && ok "alias guarita_teste criado" || bad "alias nao criado"
grep -q "tipo=host" /tmp/v7.txt && ok "alias e do tipo host (gera table persist)" || bad "alias com tipo errado"
sed 's/^/     /' /tmp/v7.txt

inf "8. tabela existe no pf"
# O resync do passo 5 pediu a recarga do filtro; ela acontece em segundo plano,
# e pode haver outras recargas na fila (a da instalacao, por exemplo). Por isso
# o teste espera o resultado (a tabela existir), e nao "uma recarga qualquer".
i=0
while ! table_exists guarita_teste && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
if table_exists guarita_teste; then
	ok "tabela guarita_teste existe no pf (criada pelo resync em ${i}s, sem recarga manual)"
else
	bad "tabela guarita_teste NAO existe no pf depois do resync"
	echo "     tentando recarregar o filtro..."
	reload_filter
	table_exists guarita_teste && echo "     existe apos recarga manual: o resync nao recarregou o filtro" \
		|| echo "     continua sem existir"
fi
echo "     declaracao no ruleset:"
grep -n "guarita_teste" /tmp/rules.debug 2>/dev/null | head -3 | sed 's/^/     /'

inf "9. servico no ar"
if pgrep -q guaritad; then
	ok "processo guaritad rodando (pid $(pgrep guaritad | head -1))"
else
	bad "guaritad nao esta rodando"
	echo "     ultimas linhas do log:"
	tail -15 /var/log/guarita.log 2>/dev/null | sed 's/^/     /'
fi
[ -f /usr/local/etc/rc.d/guaritad.sh ] && ok "script rc.d criado" || bad "rc.d nao criado"
[ -S /var/run/guarita.sock ] && ok "socket da API local criado" || bad "socket da API local ausente"

inf "10. API local responde"
$PHP -r '
require_once("/usr/local/pkg/guarita.inc");
$s = guarita_get_status();
if ($s === null) { echo "API_SEM_RESPOSTA\n"; exit(1); }
echo "API_OK\n";
echo "versao=" . $s["version"] . "\n";
echo "sessoes=" . $s["sessions"] . "\n";
echo "grupos_no_status=" . count($s["groups"]) . "\n";
echo "ldap_host=[" . $s["ldap_host"] . "]\n";
' > /tmp/v10.txt 2>&1
grep -q API_OK /tmp/v10.txt && ok "a interface consegue falar com o daemon" || bad "API local nao respondeu"
sed 's/^/     /' /tmp/v10.txt

inf "11. evento de agente ponta a ponta"
# Assina e envia um evento como o agente do Windows faria, e confere se o IP
# aparece na tabela do pf. Este e o teste que prova o conceito todo.
$PHP -r '
$cfg = json_decode(file_get_contents("/usr/local/pkg/guarita/guarita.json"), true);
$secret = $cfg["agent_secret"];
$listen = $cfg["listen_agent"];
$body = json_encode(["agent" => "DC-VERIFY", "events" => [[
	"type" => "logon", "user" => "joao.teste", "domain" => "LAB",
	"ip" => "192.168.99.50", /* = TEST_IP, removido no fim */ "computer" => "PC-LAB", "event_id" => 4768,
	"time" => gmdate("Y-m-d\TH:i:s\Z"),
]]]);
$ts = time();
$sig = hash_hmac("sha256", $ts . "\n" . $body, $secret);
$ch = curl_init("http://" . $listen . "/v1/events");
curl_setopt_array($ch, [
	CURLOPT_POST => true,
	CURLOPT_POSTFIELDS => $body,
	CURLOPT_RETURNTRANSFER => true,
	CURLOPT_TIMEOUT => 15,
	CURLOPT_HTTPHEADER => [
		"Content-Type: application/json",
		"X-Guarita-Agent: DC-VERIFY",
		"X-Guarita-Timestamp: " . $ts,
		"X-Guarita-Signature: " . $sig,
	],
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
echo "HTTP=" . $code . "\n";
echo "RESP=" . trim($resp) . "\n";
' > /tmp/v11.txt 2>&1
sed 's/^/     /' /tmp/v11.txt
grep -q "HTTP=200" /tmp/v11.txt && ok "o daemon aceitou o evento assinado" || bad "o daemon recusou o evento"
grep -q '"accepted":1' /tmp/v11.txt && ok "evento aplicado (1 aceito)" || bad "evento nao foi aplicado"

echo "     esperando a sincronizacao das tabelas..."
i=0
while [ $i -lt 20 ]; do
	sleep 1
	pfctl -t guarita_teste -T show 2>/dev/null | grep -q "192.168.99.50" && break
	i=$((i+1))
done
if pfctl -t guarita_teste -T show 2>/dev/null | grep -q "192.168.99.50"; then
	ok "O IP CHEGOU NA TABELA DO FIREWALL (conceito provado)"
else
	bad "o IP nao apareceu na tabela do pf"
	echo "     conteudo do arquivo:"; cat /var/db/guarita/tables/teste.txt 2>/dev/null | sed 's/^/       /'
	echo "     conteudo da tabela:";  pfctl -t guarita_teste -T show 2>&1 | sed 's/^/       /'
fi
echo "     tabela no pf:"; pfctl -t guarita_teste -T show 2>&1 | sed 's/^/       /'

inf "12. a sessao aparece para a interface"
$PHP -r '
require_once("/usr/local/pkg/guarita.inc");
$s = guarita_get_sessions();
if (!is_array($s)) { echo "SEM_SESSOES\n"; exit; }
echo "total=" . count($s) . "\n";
foreach ($s as $x) {
	echo "sessao: " . $x["ip"] . " " . $x["user"] . " grupos=" . implode(",", (array)$x["groups"]) . "\n";
}
' > /tmp/v12.txt 2>&1
grep -q "total=1" /tmp/v12.txt && ok "a sessao aparece na API usada pela interface" || bad "sessao nao listada"
grep -q "grupos=teste" /tmp/v12.txt && ok "caiu no grupo padrao (sem LDAP configurado, como esperado)" \
	|| bad "nao caiu no grupo padrao"
sed 's/^/     /' /tmp/v12.txt

inf "13. reposicao apos recarga de filtro (o caso que o pfSense provoca)"
# Espera passarem as reposicoes que o daemon agendou para a recarga do passo 5
# (2, 6 e 15 s depois de notar a recarga, que ele confere a cada 5 s). Sem isso,
# uma delas pode cair logo depois da recarga abaixo e fazer o teste passar por
# coincidencia, sem o daemon ter notado recarga nenhuma.
echo "     esperando 25 s as reposicoes da recarga anterior terminarem..."
sleep 25
LOGN=$(grep -c "o filtro do pfSense foi recarregado" /var/log/guarita.log 2>/dev/null)
BEFORE=$(table_count guarita_teste)
echo "     IPs antes: $BEFORE"
# Uma recarga sem mudanca no ruleset: o caso mais comum (salvar qualquer
# configuracao, renovar o DHCP da WAN). No 2.9 ela nao reescreve o rules.debug,
# mas esvazia a tabela. Sem esperar a recarga terminar, a comparacao abaixo
# passava antes do flush, sem testar nada.
if reload_filter; then
	echo "     filtro recarregado; IPs logo depois: $(table_count guarita_teste)"
else
	bad "o filtro nao recarregou em 30 s"
fi
# O daemon confere a recarga a cada 5 s e reaplica 2 s depois. 20 s cobre isso
# com folga e fica bem abaixo da reaplicacao periodica (60 s), que antes era o
# unico jeito de a tabela voltar.
i=0
while [ $i -lt 20 ]; do
	sleep 1
	AFTER=$(table_count guarita_teste)
	[ "$AFTER" = "$BEFORE" ] && break
	i=$((i+1))
done
AFTER=$(table_count guarita_teste)
if [ "$AFTER" = "$BEFORE" ]; then
	ok "o daemon repos a tabela depois da recarga ($AFTER IPs, em ${i}s)"
else
	bad "tabela nao reposta em 20 s: antes $BEFORE, depois $AFTER"
fi
LOGN2=$(grep -c "o filtro do pfSense foi recarregado" /var/log/guarita.log 2>/dev/null)
[ "$LOGN2" -gt "$LOGN" ] && ok "o daemon notou a recarga sem mudanca no ruleset" \
	|| bad "o daemon NAO notou a recarga (o rules.debug nao muda quando o ruleset nao muda)"

inf "14. privilegios registrados"
$PHP -r '
$priv_list = [];
require_once("/etc/inc/priv/guarita.priv.inc");
echo "privilegios=" . count($priv_list) . "\n";
foreach (array_keys($priv_list) as $k) { echo "  " . $k . "\n"; }
' > /tmp/v14.txt 2>&1
grep -qE "privilegios=[1-9]" /tmp/v14.txt && ok "privilegios do pacote carregam" || bad "priv.inc com problema"
sed 's/^/     /' /tmp/v14.txt

inf "15. log do servico"
if [ -f /var/log/guarita.log ]; then
	ok "arquivo de log existe"
	echo "     ultimas linhas:"
	tail -12 /var/log/guarita.log | sed 's/^/       /'
else
	bad "/var/log/guarita.log nao existe"
fi

inf "16. servidor LDAP escolhido chega ao daemon"
# "authserver" esta em listtags() do pfSense: lido do config.xml, o campo vira
# array('nome'). Antes, auth_get_authserver() recebia o array e o LDAP ficava
# sem host. O teste grava o campo, relê o config.xml do disco (como o pfSense
# faz a cada requisicao) e confere o nome que o pacote enxerga.
$PHP -r '
require_once("config.inc");
require_once("xmlparse.inc");
require_once("/usr/local/pkg/guarita.inc");
config_set_path("installedpackages/guarita/config/0/authserver", "servidor_de_teste");
write_config("Guarita: verify testa o campo authserver");
$fresh = parse_xml_config("/cf/conf/config.xml", "pfsense");
$lido = $fresh["installedpackages"]["guarita"]["config"][0]["authserver"] ?? null;
echo "tipo_lido=" . gettype($lido) . "\n";
echo "nome=" . guarita_authserver_name(["authserver" => $lido]) . "\n";
echo "nome_string=" . guarita_authserver_name(["authserver" => "x"]) . "\n";
echo "nome_vazio=[" . guarita_authserver_name([]) . "]\n";
' > /tmp/v16.txt 2>&1
sed 's/^/     /' /tmp/v16.txt
grep -q "nome=servidor_de_teste" /tmp/v16.txt && ok "o nome do servidor LDAP sobrevive a releitura do config.xml" \
	|| bad "o nome do servidor LDAP se perde na releitura do config.xml"
grep -q "nome_string=x" /tmp/v16.txt && grep -q "nome_vazio=\[\]" /tmp/v16.txt \
	&& ok "texto e vazio tambem sao tratados" || bad "guarita_authserver_name com texto ou vazio"

inf "17. mudar a porta de escuta reinicia o servico"
# O SIGHUP nao reabre a porta. Antes, quem habilitava o pacote e depois escolhia
# o IP da LAN ficava com o servico no endereco antigo.
PID17=$(pgrep guaritad | head -1)
$PHP -r '
require_once("config.inc");
require_once("/usr/local/pkg/guarita.inc");
config_set_path("installedpackages/guarita/config/0/listen_port", "8924");
write_config("Guarita: verify muda a porta de escuta");
guarita_resync_config();
' >/dev/null 2>&1
i=0
while ! sockstat -4l 2>/dev/null | grep guaritad | grep -q "127.0.0.1:8924" && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done
sockstat -4l 2>/dev/null | grep guaritad | sed 's/^/     /'
sockstat -4l 2>/dev/null | grep guaritad | grep -q "127.0.0.1:8924" \
	&& ok "o servico passou a escutar em 127.0.0.1:8924 (em ${i}s)" \
	|| bad "o servico NAO passou a escutar na porta nova"
[ "$(pgrep guaritad | head -1)" != "$PID17" ] && ok "o servico foi reiniciado (pid $PID17 -> $(pgrep guaritad | head -1))" \
	|| bad "o servico nao foi reiniciado"
[ "$(table_count guarita_teste)" -gt 0 ] && ok "a sessao sobreviveu ao reinicio" \
	|| bad "a tabela ficou vazia depois do reinicio"

inf "18. desabilitar esvazia as tabelas"
# Desabilitado, o servico para e ninguem mais atualiza as tabelas. Se o filtro
# nao for recarregado, os IPs das ultimas sessoes ficam nelas e as regras
# continuam aplicando a politica de quem ja saiu.
BEFORE=$(table_count guarita_teste)
echo "     IPs na tabela antes de desabilitar: $BEFORE"
[ "$BEFORE" -gt 0 ] || bad "a tabela ja estava vazia; o teste nao prova nada"
$PHP -r '
require_once("config.inc");
require_once("/usr/local/pkg/guarita.inc");
config_set_path("installedpackages/guarita/config/0/enable", "");
write_config("Guarita: verify desabilita o pacote");
guarita_resync_config();
' >/dev/null 2>&1
pgrep -q guaritad && bad "guaritad continua rodando depois de desabilitar" \
	|| ok "guaritad parou"
# Espera o resultado (tabela vazia), pelo mesmo motivo do passo 8.
i=0
while [ "$(table_count guarita_teste)" != "0" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
AFTER=$(table_count guarita_teste)
[ "$AFTER" = "0" ] && ok "tabela esvaziada ao desabilitar (em ${i}s)" \
	|| bad "tabela continua com $AFTER IP(s) depois de desabilitar"

echo ""
echo "================================================"
echo "  passaram: $PASS     falharam: $FAIL"
echo "================================================"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
