#!/bin/sh
# verify.sh - roda DENTRO do pfSense e confere a instalação do Guarita.
#
# Cobre o que não dá para testar fora de um pfSense de verdade:
# registro no pkg e no config.xml, criação do alias, existência da tabela no
# pf, geração do JSON do daemon, serviço no ar, API local e um evento de agente
# ponta a ponta até o IP aparecer na tabela do firewall.

PASS=0
FAIL=0
ok()  { echo "  [ok] $*";     PASS=$((PASS+1)); }
bad() { echo "  [FALHOU] $*"; FAIL=$((FAIL+1)); }
inf() { echo ""; echo "== $*"; }

PKG=pfSense-pkg-Guarita
PHP=/usr/local/bin/php

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
if pfctl -t guarita_teste -T show >/dev/null 2>&1; then
	ok "tabela guarita_teste existe no pf"
else
	bad "tabela guarita_teste NAO existe no pf"
	echo "     tentando recarregar o filtro..."
	$PHP -r 'require_once("config.inc"); require_once("filter.inc"); filter_configure();' >/dev/null 2>&1
	sleep 3
	pfctl -t guarita_teste -T show >/dev/null 2>&1 && ok "existe apos recarregar o filtro" \
		|| bad "continua sem existir"
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
	"ip" => "192.168.99.50", "computer" => "PC-LAB", "event_id" => 4768,
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
BEFORE=$(pfctl -t guarita_teste -T show 2>/dev/null | grep -c .)
echo "     IPs antes: $BEFORE"
$PHP -r 'require_once("config.inc"); require_once("filter.inc"); filter_configure();' >/dev/null 2>&1
echo "     filtro recarregado; esperando o daemon repor..."
i=0
while [ $i -lt 40 ]; do
	sleep 1
	AFTER=$(pfctl -t guarita_teste -T show 2>/dev/null | grep -c .)
	[ "$AFTER" = "$BEFORE" ] && break
	i=$((i+1))
done
AFTER=$(pfctl -t guarita_teste -T show 2>/dev/null | grep -c .)
if [ "$AFTER" = "$BEFORE" ]; then
	ok "o daemon repos a tabela depois da recarga ($AFTER IPs, em ${i}s)"
else
	bad "tabela nao reposta: antes $BEFORE, depois $AFTER"
fi

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

echo ""
echo "================================================"
echo "  passaram: $PASS     falharam: $FAIL"
echo "================================================"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
