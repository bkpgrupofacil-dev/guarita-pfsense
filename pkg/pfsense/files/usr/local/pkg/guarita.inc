<?php
/*
 * guarita.inc
 *
 * Funções de apoio do pacote Guarita para pfSense.
 *
 * Responsabilidades:
 *   - gerar /usr/local/pkg/guarita/guarita.json a partir do config.xml
 *   - criar e manter os aliases do tipo "URL Table (IPs)" de cada grupo
 *   - escrever o script rc.d do serviço
 *   - falar com o daemon pelo socket unix (status, sessões, ações)
 *
 * Licenciado sob a Apache License 2.0.
 */

require_once("config.inc");
require_once("util.inc");
require_once("functions.inc");
require_once("pkg-utils.inc");
require_once("service-utils.inc");
require_once("certs.inc");
require_once("filter.inc");
/* auth.inc traz auth_get_authserver() e auth_get_authserver_list(), usados para
 * reaproveitar o servidor LDAP já cadastrado no User Manager. */
require_once("auth.inc");

define('GUARITA_DIR',        '/usr/local/pkg/guarita');
define('GUARITA_JSON',       GUARITA_DIR . '/guarita.json');
define('GUARITA_BIN',        '/usr/local/sbin/guaritad');
define('GUARITA_RCFILE',     'guaritad.sh');
define('GUARITA_PIDFILE',    '/var/run/guaritad.pid');
define('GUARITA_SOCKET',     '/var/run/guarita.sock');
define('GUARITA_TABLEDIR',   '/var/db/guarita/tables');
define('GUARITA_STATE',      '/var/db/guarita/sessions.json');
define('GUARITA_LOG',        '/var/log/guarita.log');
define('GUARITA_ALIAS_PFX',  'guarita_');

/* ------------------------------------------------------------------ helpers */

/* Lê as configurações gerais do pacote. */
function guarita_settings() {
	return config_get_path('installedpackages/guarita/config/0', array());
}

/* Lê a lista de grupos configurados. */
function guarita_groups() {
	$rows = config_get_path('installedpackages/guaritagroups/config', array());
	$out = array();
	foreach ($rows as $row) {
		if (empty($row['table'])) {
			continue;
		}
		$out[] = $row;
	}
	return $out;
}

/* Nome da tabela/alias no pf para um grupo lógico. */
function guarita_pf_table($table) {
	return GUARITA_ALIAS_PFX . $table;
}

/* Caminho do arquivo de IPs de um grupo. */
function guarita_table_file($table) {
	return GUARITA_TABLEDIR . '/' . $table . '.txt';
}

/* Valida o nome curto de um grupo (precisa casar com o lado Go). */
function guarita_valid_table_name($name) {
	return (bool) preg_match('/^[a-zA-Z0-9_]{1,24}$/', $name);
}

/*
 * guarita_config_keeps_accents() diz se esta versão do pfSense consegue gravar
 * texto acentuado no config.xml sem corrompê-lo.
 *
 * O pfSense 2.7.x grava os valores com htmlentities($valor), sem a flag
 * ENT_XML1, o que transforma "ação" em "a&ccedil;&atilde;o". Essa entidade não
 * existe em XML (só &amp;, &lt;, &gt;, &quot;, &apos; e as numéricas são
 * válidas). O config.xml fica ilegível para o próprio pfSense, que o salva como
 * config.xml.bad e RESTAURA UM BACKUP — ou seja, uma instalação de pacote pode
 * reverter a configuração do firewall. O 2.8 passou a usar ENT_XML1 e não tem
 * esse problema.
 */
function guarita_config_keeps_accents() {
	static $ok = null;
	if ($ok !== null) {
		return $ok;
	}
	$v = '';
	if (file_exists('/etc/version')) {
		$v = trim((string) @file_get_contents('/etc/version'));
	}
	/* "2.7.2-RELEASE" => "2.7.2" ; "2.9.0-DEVELOPMENT" => "2.9.0" */
	$num = preg_replace('/[^0-9.].*$/', '', $v);
	$num = trim($num, '.');
	if ($num === '') {
		/* Sem saber a versão, assume o comportamento antigo: é o seguro. */
		$ok = false;
	} else {
		$ok = version_compare($num, '2.8', '>=');
	}
	return $ok;
}

/* Transliteração simples de acentos para ASCII. */
function guarita_deaccent($s) {
	$map = array(
		'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a','å'=>'a',
		'é'=>'e','è'=>'e','ê'=>'e','ë'=>'e',
		'í'=>'i','ì'=>'i','î'=>'i','ï'=>'i',
		'ó'=>'o','ò'=>'o','õ'=>'o','ô'=>'o','ö'=>'o',
		'ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u',
		'ç'=>'c','ñ'=>'n','ý'=>'y',
		'Á'=>'A','À'=>'A','Ã'=>'A','Â'=>'A','Ä'=>'A','Å'=>'A',
		'É'=>'E','È'=>'E','Ê'=>'E','Ë'=>'E',
		'Í'=>'I','Ì'=>'I','Î'=>'I','Ï'=>'I',
		'Ó'=>'O','Ò'=>'O','Õ'=>'O','Ô'=>'O','Ö'=>'O',
		'Ú'=>'U','Ù'=>'U','Û'=>'U','Ü'=>'U',
		'Ç'=>'C','Ñ'=>'N',
		'º'=>'o','ª'=>'a','°'=>'',
	);
	$s = strtr($s, $map);
	/* O que sobrar de não-ASCII sai, para nunca corromper o config.xml. */
	return preg_replace('/[^\x20-\x7E]/', '', $s);
}

/*
 * guarita_config_safe_text() prepara um texto para ser gravado no config.xml.
 * Nas versões afetadas, tira os acentos; nas corrigidas, passa intacto.
 */
function guarita_config_safe_text($s) {
	if (guarita_config_keeps_accents()) {
		return $s;
	}
	return guarita_deaccent($s);
}

/*
 * guarita_lookup_ca_cert() devolve o certificado da CA (PEM) a partir do refid,
 * ou string vazia se não achar.
 *
 * Existe porque lookup_ca() mudou de forma entre versões do pfSense:
 *
 *   2.7.x:  function & lookup_ca($refid)   devolve o array da CA, ou false
 *   2.8.x:  function   lookup_ca($refid)   devolve ['idx' => .., 'item' => ..]
 *
 * Ler só $ca['item']['crt'] funciona no 2.8 e falha calado no 2.7: a CA
 * configurada pelo administrador seria ignorada e a conexão LDAP terminaria
 * sem validar a cadeia, sem nada no log dizendo isso. Por isso aqui tratamos
 * as duas formas e registramos um aviso quando o refid existe mas o
 * certificado não pôde ser lido.
 */
function guarita_lookup_ca_cert($refid) {
	if (empty($refid)) {
		return '';
	}
	$ca = lookup_ca($refid);
	if (empty($ca)) {
		log_error(sprintf("Guarita: a CA %s não foi encontrada no pfSense; " .
			"a conexão LDAP não vai validar a cadeia do certificado.", $refid));
		return '';
	}
	/* Formato do 2.8.x em diante. */
	if (is_array($ca) && array_key_exists('item', $ca)) {
		$ca = $ca['item'];
	}
	if (!is_array($ca) || empty($ca['crt'])) {
		log_error(sprintf("Guarita: não consegui ler o certificado da CA %s; " .
			"a conexão LDAP não vai validar a cadeia do certificado.", $refid));
		return '';
	}
	$pem = base64_decode($ca['crt']);
	if (($pem === false) || (strpos($pem, 'BEGIN CERTIFICATE') === false)) {
		log_error(sprintf("Guarita: o certificado da CA %s não é um PEM válido.", $refid));
		return '';
	}
	return $pem;
}

/* Gera um segredo novo para os agentes. */
function guarita_generate_secret() {
	// 32 bytes em base64 url-safe, sem padding: 43 caracteres.
	$raw = random_bytes(32);
	return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

/* ------------------------------------------------------ geração do JSON */

/*
 * guarita_write_config() grava o arquivo JSON que o daemon lê.
 * Devolve true em caso de sucesso.
 */
function guarita_write_config() {
	$s = guarita_settings();

	safe_mkdir(GUARITA_DIR, 0750);
	safe_mkdir(dirname(GUARITA_STATE), 0750);
	safe_mkdir(GUARITA_TABLEDIR, 0750);

	/* Endereço de escuta da API dos agentes. */
	$listen_ip = !empty($s['listen_ip']) ? $s['listen_ip'] : '0.0.0.0';
	$listen_port = !empty($s['listen_port']) ? (int) $s['listen_port'] : 8923;

	/* Servidor LDAP: reaproveita um servidor de autenticação já cadastrado em
	 * System > User Manager > Authentication Servers, para não duplicar
	 * credenciais na configuração do pacote. */
	$ldap = array(
		'host'       => '',
		'port'       => 389,
		'tls_mode'   => 'none',
		'ca_cert'    => '',
		'bind_dn'    => '',
		'bind_pw'    => '',
		'base_dn'    => '',
		'user_attr'  => 'sAMAccountName',
		'group_attr' => 'memberOf',
		'nested'     => !empty($s['ldap_nested']),
		'timeout'    => 10,
	);

	if (!empty($s['authserver'])) {
		$auth = auth_get_authserver($s['authserver']);
		if (is_array($auth) && ($auth['type'] == 'ldap')) {
			$ldap['host']      = $auth['host'];
			$ldap['port']      = !empty($auth['ldap_port']) ? (int) $auth['ldap_port'] : 389;
			$ldap['bind_dn']   = $auth['ldap_binddn'];
			$ldap['bind_pw']   = $auth['ldap_bindpw'];
			$ldap['base_dn']   = $auth['ldap_basedn'];
			$ldap['user_attr'] = !empty($auth['ldap_attr_user']) ? $auth['ldap_attr_user'] : 'sAMAccountName';

			switch ($auth['ldap_urltype']) {
				case 'SSL/TLS Encrypted':
					$ldap['tls_mode'] = 'ssl';
					if (empty($auth['ldap_port'])) {
						$ldap['port'] = 636;
					}
					break;
				case 'STARTTLS Encrypted':
					$ldap['tls_mode'] = 'starttls';
					break;
				default:
					$ldap['tls_mode'] = 'none';
					break;
			}

			/* CA do servidor LDAP, se houver. */
			if (!empty($auth['ldap_caref']) && ($auth['ldap_caref'] != 'global')) {
				$ldap['ca_cert'] = guarita_lookup_ca_cert($auth['ldap_caref']);
			}
			if (!empty($auth['ldap_timeout'])) {
				$ldap['timeout'] = (int) $auth['ldap_timeout'];
			}
		}
	}

	/* Grupos. */
	$groups = array();
	foreach (guarita_groups() as $g) {
		if (!guarita_valid_table_name($g['table'])) {
			log_error("Guarita: grupo com nome inválido ignorado: " . $g['table']);
			continue;
		}
		$ad = array();
		if (!empty($g['ad_groups'])) {
			foreach (preg_split('/[\r\n,]+/', $g['ad_groups']) as $line) {
				$line = trim($line);
				if ($line !== '') {
					$ad[] = $line;
				}
			}
		}
		$groups[] = array(
			'name'      => !empty($g['name']) ? $g['name'] : $g['table'],
			'table'     => $g['table'],
			'ad_groups' => $ad,
			'priority'  => isset($g['priority']) ? (int) $g['priority'] : 0,
		);
	}

	$cfg = array(
		'listen_agent'  => $listen_ip . ':' . $listen_port,
		'listen_local'  => GUARITA_SOCKET,
		'agent_secret'  => isset($s['agent_secret']) ? $s['agent_secret'] : '',
		'session_ttl'   => !empty($s['session_ttl']) ? (int) $s['session_ttl'] * 60 : 14400,
		'group_refresh' => !empty($s['group_refresh']) ? (int) $s['group_refresh'] * 60 : 1800,
		'state_path'    => GUARITA_STATE,
		'table_dir'     => GUARITA_TABLEDIR,
		'default_group' => isset($s['default_group']) ? $s['default_group'] : '',
		/* Facility real usada pelo daemon. Evita local5 (o pfSense roteia
		 * local5.* para o nginx.log) e local3 (vpn.log). O roteamento para
		 * /var/log/guarita.log acontece pelo nome do programa, nao pela
		 * facility: ver o comentario em info.xml. */
		'log_facility'  => 'local4',
		'debug'         => !empty($s['debug']),
		'ldap'          => $ldap,
		'groups'        => $groups,
	);

	$json = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if ($json === false) {
		log_error("Guarita: falha ao gerar o JSON de configuração: " . json_last_error_msg());
		return false;
	}

	/* Gravação atômica, e o arquivo contém a senha do LDAP e o segredo dos
	 * agentes: permissão restrita ao root. */
	$tmp = GUARITA_JSON . '.tmp';
	if (file_put_contents($tmp, $json . "\n") === false) {
		log_error("Guarita: não consegui gravar " . $tmp);
		return false;
	}
	@chmod($tmp, 0600);
	if (!@rename($tmp, GUARITA_JSON)) {
		log_error("Guarita: não consegui mover " . $tmp . " para " . GUARITA_JSON);
		@unlink($tmp);
		return false;
	}
	@chmod(GUARITA_JSON, 0600);
	return true;
}

/* ------------------------------------------------------------- aliases pf */

/*
 * guarita_sync_aliases() cria/atualiza, em Firewall > Aliases, um alias do tipo
 * "URL Table (IPs)" por grupo, apontando para o arquivo local que o daemon
 * mantém. É assim que as regras de firewall passam a poder selecionar o grupo
 * pelo nome, na lista de aliases da própria interface do pfSense.
 *
 * Aliases de grupos que foram removidos da configuração são apagados, mas
 * somente se nenhuma regra os estiver usando.
 */
function guarita_sync_aliases() {
	$groups = guarita_groups();
	$aliases = config_get_path('aliases/alias', array());
	$wanted = array();
	$changed = false;

	foreach ($groups as $g) {
		if (!guarita_valid_table_name($g['table'])) {
			continue;
		}
		$name = guarita_pf_table($g['table']);
		$wanted[$name] = true;
		$file = guarita_table_file($g['table']);

		/* Garante que o arquivo de IPs existe, mesmo vazio, para o daemon poder
		 * aplicá-lo logo na primeira sincronização. */
		if (!file_exists($file)) {
			safe_mkdir(GUARITA_TABLEDIR, 0750);
			@file_put_contents($file, '');
		}

		/* Vai para o config.xml: passa por guarita_config_safe_text(), que
		 * tira os acentos nas versões do pfSense que corrompem o arquivo com
		 * eles. O nome do grupo é digitado pelo administrador, então o acento
		 * pode vir dele também. */
		$descr = guarita_config_safe_text(sprintf(
			gettext('Guarita: grupo %s (conteudo gerenciado pelo servico)'),
			!empty($g['name']) ? $g['name'] : $g['table']));

		/*
		 * Tipo "host" com a lista de endereços VAZIA, de propósito.
		 *
		 * filter_generate_alias_tables() trata esse caso assim:
		 *
		 *     if (empty($tableaddrs)) {
		 *         $aliases .= "table <nome> persist\n";
		 *
		 * ou seja, a tabela nasce no ruleset como "persist" e passa a existir
		 * sempre, mesmo sem nenhum membro. É isso que queremos: o alias fica
		 * selecionável nas regras, a tabela nunca falta, e quem manda no
		 * conteúdo é o daemon, via "pfctl -t <nome> -T replace -f <arquivo>".
		 * Assim um logon muda a política na hora, sem reescrever o config.xml
		 * nem recarregar o filtro.
		 *
		 * O tipo "urltable" NÃO serve aqui: alias_expand_urltable() exige que
		 * o campo url seja uma URL HTTP de verdade e devolve null para um
		 * caminho local, e nesse caso o pfSense não emite tabela nenhuma.
		 *
		 * Como a lista fica vazia, o pfSense agenda um "pfctl -T flush" depois
		 * de cada recarga de filtro. Quem repõe o conteúdo é o daemon, que
		 * observa o /tmp/rules.debug e reaplica.
		 */
		$found = false;
		foreach ($aliases as $idx => $a) {
			if ($a['name'] !== $name) {
				continue;
			}
			$found = true;
			if (($a['type'] !== 'host') || ($a['address'] !== '') ||
			    ($a['descr'] !== $descr) || !empty($a['url'])) {
				$aliases[$idx]['type']    = 'host';
				$aliases[$idx]['address'] = '';
				$aliases[$idx]['detail']  = '';
				$aliases[$idx]['descr']   = $descr;
				/* Restos de uma versão anterior que usava urltable. */
				unset($aliases[$idx]['url']);
				unset($aliases[$idx]['updatefreq']);
				$changed = true;
			}
			break;
		}
		if (!$found) {
			$aliases[] = array(
				'name'    => $name,
				'type'    => 'host',
				'address' => '',
				'detail'  => '',
				'descr'   => $descr,
			);
			$changed = true;
		}
	}

	/* Remove aliases nossos que não correspondem mais a nenhum grupo. */
	foreach ($aliases as $idx => $a) {
		if (strpos($a['name'], GUARITA_ALIAS_PFX) !== 0) {
			continue;
		}
		if (isset($wanted[$a['name']])) {
			continue;
		}
		if (guarita_alias_in_use($a['name'])) {
			log_error(sprintf("Guarita: alias %s não foi removido porque " .
				"ainda existe regra de firewall usando ele.", $a['name']));
			continue;
		}
		unset($aliases[$idx]);
		$changed = true;
	}

	if ($changed) {
		config_set_path('aliases/alias', array_values($aliases));
		write_config(gettext('Guarita: aliases dos grupos sincronizados'));
	}
	return $changed;
}

/*
 * guarita_alias_in_use() procura o alias nas regras de filtro, NAT e shaper.
 * Evita remover um alias que deixaria uma regra inválida.
 */
function guarita_alias_in_use($name) {
	$paths = array(
		'filter/rule',
		'nat/rule',
		'nat/onetoone',
		'nat/outbound/rule',
	);
	foreach ($paths as $p) {
		foreach (config_get_path($p, array()) as $rule) {
			foreach (array('source', 'destination') as $side) {
				if (!empty($rule[$side]['address']) && ($rule[$side]['address'] === $name)) {
					return true;
				}
			}
			foreach (array('target', 'external', 'destination') as $k) {
				if (isset($rule[$k]) && is_string($rule[$k]) && ($rule[$k] === $name)) {
					return true;
				}
			}
		}
	}
	return false;
}

/* ------------------------------------------------------------- rc script */

/* Escreve o script de inicialização do serviço. */
function guarita_write_rcfile() {
	$start  = "/usr/bin/install -d -m 0750 " . escapeshellarg(GUARITA_TABLEDIR) . "\n\t";
	$start .= "/usr/bin/install -d -m 0750 " . escapeshellarg(dirname(GUARITA_STATE)) . "\n\t";
	$start .= GUARITA_BIN . " -config " . escapeshellarg(GUARITA_JSON) .
	          " -pid " . escapeshellarg(GUARITA_PIDFILE) . " &";

	$stop  = "if [ -f " . escapeshellarg(GUARITA_PIDFILE) . " ]; then\n";
	$stop .= "\t\t/bin/kill -TERM $(/bin/cat " . escapeshellarg(GUARITA_PIDFILE) . ") 2>/dev/null\n";
	$stop .= "\t\t/bin/sleep 1\n";
	$stop .= "\tfi\n";
	$stop .= "\t/usr/bin/killall guaritad 2>/dev/null\n";
	$stop .= "\t/bin/rm -f " . escapeshellarg(GUARITA_SOCKET);

	write_rcfile(array(
		'file'       => GUARITA_RCFILE,
		'start'      => $start,
		'stop'       => $stop,
		'executable' => 'guaritad',
	));
}

/* Manda SIGHUP para o daemon recarregar a configuração sem perder as sessões. */
function guarita_reload_service() {
	if (!file_exists(GUARITA_PIDFILE)) {
		return false;
	}
	$pid = trim(@file_get_contents(GUARITA_PIDFILE));
	if (!ctype_digit($pid)) {
		return false;
	}
	mwexec("/bin/kill -HUP " . escapeshellarg($pid), true);
	return true;
}

/* ------------------------------------------------- comunicação com o daemon */

/*
 * guarita_api() faz uma requisição HTTP ao daemon pelo socket unix e devolve
 * o JSON decodificado, ou null em caso de falha.
 */
function guarita_api($path, $timeout = 5) {
	if (!file_exists(GUARITA_SOCKET)) {
		return null;
	}
	$errno = 0;
	$errstr = '';
	$fp = @stream_socket_client('unix://' . GUARITA_SOCKET, $errno, $errstr, $timeout);
	if (!$fp) {
		return null;
	}
	stream_set_timeout($fp, $timeout);

	$req  = "GET {$path} HTTP/1.0\r\n";
	$req .= "Host: localhost\r\n";
	$req .= "Connection: close\r\n\r\n";
	fwrite($fp, $req);

	$raw = '';
	while (!feof($fp)) {
		$chunk = fread($fp, 8192);
		if ($chunk === false) {
			break;
		}
		$raw .= $chunk;
		/* Proteção: não deixa a GUI travar com resposta gigante. */
		if (strlen($raw) > 8 * 1024 * 1024) {
			break;
		}
	}
	fclose($fp);

	$sep = strpos($raw, "\r\n\r\n");
	if ($sep === false) {
		return null;
	}
	$body = substr($raw, $sep + 4);
	$data = json_decode($body, true);
	if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
		return null;
	}
	return $data;
}

function guarita_get_status()   { return guarita_api('/status'); }
function guarita_get_sessions() { return guarita_api('/sessions'); }

function guarita_remove_session($ip) {
	return guarita_api('/session/remove?ip=' . rawurlencode($ip));
}
function guarita_set_sticky($ip, $on) {
	return guarita_api('/session/sticky?ip=' . rawurlencode($ip) . '&on=' . ($on ? '1' : '0'));
}
function guarita_resync() {
	return guarita_api('/resync', 20);
}
function guarita_test_ldap($user) {
	return guarita_api('/test-ldap?user=' . rawurlencode($user), 20);
}

/* Diz se o serviço está rodando. */
function guarita_is_running() {
	return (bool) is_process_running('guaritad');
}

/* ------------------------------------------------------- ciclo do pacote */

/*
 * guarita_install() roda uma vez, na instalação do pacote.
 */
function guarita_install() {
	safe_mkdir(GUARITA_DIR, 0750);
	safe_mkdir(GUARITA_TABLEDIR, 0750);
	safe_mkdir(dirname(GUARITA_STATE), 0750);
	@touch(GUARITA_LOG);

	/* Já cria uma entrada de configuração com um segredo gerado, para o
	 * administrador não precisar inventar um. */
	$s = guarita_settings();
	if (empty($s)) {
		$s = array(
			'enable'        => '',
			'listen_ip'     => '',
			'listen_port'   => '8923',
			'agent_secret'  => guarita_generate_secret(),
			'session_ttl'   => '240',
			'group_refresh' => '30',
			'ldap_nested'   => 'on',
		);
		config_set_path('installedpackages/guarita/config/0', $s);
		write_config(gettext('Guarita: configuração inicial criada'));
	}
	guarita_write_rcfile();
}

/*
 * guarita_resync() é chamada sempre que a configuração do pacote é salva.
 */
function guarita_resync_config() {
	guarita_write_rcfile();

	if (!guarita_write_config()) {
		return;
	}
	guarita_sync_aliases();

	$s = guarita_settings();
	$enabled = !empty($s['enable']);

	if (!$enabled) {
		if (guarita_is_running()) {
			stop_service('guaritad');
		}
		return;
	}

	if (guarita_is_running()) {
		/* Recarrega sem perder as sessões em andamento. */
		guarita_reload_service();
	} else {
		start_service('guaritad');
	}

	/* Recarrega o filtro para que as tabelas novas existam no ruleset. */
	filter_configure();
}

/*
 * guarita_deinstall() roda na remoção do pacote.
 */
function guarita_deinstall() {
	if (guarita_is_running()) {
		stop_service('guaritad');
	}
	@unlink(RCFILEPREFIX . GUARITA_RCFILE);
	@unlink(GUARITA_JSON);
	@unlink(GUARITA_SOCKET);
	@unlink(GUARITA_PIDFILE);

	/* Remove os aliases do pacote que não estejam em uso. As regras que o
	 * administrador criou continuam lá; ele decide o que fazer com elas. */
	$aliases = config_get_path('aliases/alias', array());
	$changed = false;
	foreach ($aliases as $idx => $a) {
		if (strpos($a['name'], GUARITA_ALIAS_PFX) !== 0) {
			continue;
		}
		if (guarita_alias_in_use($a['name'])) {
			log_error(sprintf("Guarita: alias %s mantido: há regra usando ele.", $a['name']));
			continue;
		}
		unset($aliases[$idx]);
		$changed = true;
	}
	if ($changed) {
		config_set_path('aliases/alias', array_values($aliases));
		write_config(gettext('Guarita: aliases removidos na desinstalação'));
		filter_configure();
	}

	/* O estado das sessões e os logs ficam, para auditoria. */
	log_error("Guarita: pacote removido. Estado e logs mantidos em " .
	          dirname(GUARITA_STATE) . " e " . GUARITA_LOG);
}

/* ----------------------------------------------------------- validação */

/*
 * guarita_validate_settings() valida o formulário de configurações.
 */
function guarita_validate_settings($post, &$input_errors) {
	if (!empty($post['listen_port'])) {
		if (!is_port($post['listen_port'])) {
			$input_errors[] = gettext('A porta da API dos agentes é inválida.');
		}
	}
	if (!empty($post['listen_ip']) && ($post['listen_ip'] != '0.0.0.0')) {
		if (!is_ipaddr($post['listen_ip'])) {
			$input_errors[] = gettext('O endereço de escuta precisa ser um IP válido ou 0.0.0.0.');
		}
	}
	if (empty($post['agent_secret']) || (strlen($post['agent_secret']) < 16)) {
		$input_errors[] = gettext('O segredo dos agentes precisa ter ao menos 16 caracteres.');
	}
	foreach (array('session_ttl' => gettext('Duração da sessão'),
	               'group_refresh' => gettext('Intervalo de reconsulta de grupos')) as $k => $label) {
		if ($post[$k] === '') {
			continue;
		}
		if (!ctype_digit((string) $post[$k]) || ((int) $post[$k] < 1)) {
			$input_errors[] = sprintf(gettext('%s precisa ser um número de minutos maior que zero.'), $label);
		}
	}
	if (empty($post['authserver'])) {
		$input_errors[] = gettext('Escolha o servidor LDAP do Active Directory. ' .
			'Cadastre-o antes em System > User Manager > Authentication Servers.');
	}
	if (!empty($post['default_group']) && !guarita_valid_table_name($post['default_group'])) {
		$input_errors[] = gettext('O grupo padrão precisa ser o nome curto de um grupo já cadastrado.');
	}
}

/*
 * guarita_validate_group() valida o formulário de um grupo.
 */
function guarita_validate_group($post, &$input_errors) {
	if (empty($post['table'])) {
		$input_errors[] = gettext('Informe o nome curto do grupo.');
	} elseif (!guarita_valid_table_name($post['table'])) {
		$input_errors[] = gettext('O nome curto aceita apenas letras, números e _, ' .
			'com até 24 caracteres (ele vira o nome da tabela no firewall).');
	} else {
		/* Impede dois grupos com o mesmo nome curto. */
		$id = isset($_REQUEST['id']) ? (int) $_REQUEST['id'] : -1;
		foreach (config_get_path('installedpackages/guaritagroups/config', array()) as $idx => $g) {
			if (($idx !== $id) && isset($g['table']) &&
			    (strtolower($g['table']) === strtolower($post['table']))) {
				$input_errors[] = sprintf(gettext('Já existe um grupo com o nome curto "%s".'), $post['table']);
				break;
			}
		}
	}
	if (empty($post['ad_groups'])) {
		$input_errors[] = gettext('Informe ao menos um grupo do Active Directory.');
	}
	if (($post['priority'] !== '') && !ctype_digit((string) $post['priority'])) {
		$input_errors[] = gettext('A prioridade precisa ser um número inteiro (0 = maior prioridade).');
	}

	/*
	 * Em pfSense 2.7.x, texto acentuado gravado no config.xml o corrompe: o
	 * escritor usa htmlentities() sem ENT_XML1 e produz entidades que não
	 * existem em XML. O pfSense então restaura um backup, revertendo a
	 * configuração do firewall. Melhor recusar o acento com uma explicação do
	 * que deixar o administrador perder a configuração.
	 */
	if (!guarita_config_keeps_accents()) {
		foreach (array('name' => gettext('Nome'), 'descr' => gettext('Descrição')) as $k => $label) {
			if (empty($post[$k])) {
				continue;
			}
			if (preg_match('/[^\x20-\x7E]/', $post[$k])) {
				$input_errors[] = sprintf(gettext(
					'%s: esta versão do pfSense não grava acentos no config.xml ' .
					'sem corrompê-lo, então use apenas letras sem acento aqui. ' .
					'(Corrigido no pfSense 2.8.)'), $label);
			}
		}
	}
}

/*
 * guarita_authservers_list() alimenta o seletor de servidores LDAP.
 */
function guarita_authservers_list() {
	$out = array();
	foreach (auth_get_authserver_list() as $name => $auth) {
		if ($auth['type'] !== 'ldap') {
			continue;
		}
		$out[] = array('name' => sprintf('%s (%s)', $name, $auth['host']), 'value' => $name);
	}
	if (empty($out)) {
		$out[] = array(
			'name'  => gettext('nenhum servidor LDAP cadastrado — cadastre em System > User Manager'),
			'value' => '',
		);
	}
	return $out;
}

?>
