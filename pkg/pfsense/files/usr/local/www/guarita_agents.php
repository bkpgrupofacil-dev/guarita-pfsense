<?php
/*
 * guarita_agents.php
 *
 * Mostra o último contato de cada agente e dá as instruções de instalação
 * nos controladores de domínio, já com os valores desta instalação.
 *
 * Licenciado sob a Apache License, versão 2.0.
 */

##|+PRIV
##|*IDENT=page-services-guarita-agents
##|*NAME=Services: Guarita: Agentes
##|*DESCR=Permite ver os agentes e baixar o instalador
##|*MATCH=guarita_agents.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/guarita.inc");

$pgtitle = array(gettext("Services"), gettext("Guarita"), gettext("Agentes"));

$settings = guarita_settings();
$savemsg = '';
$msgclass = 'success';

/* O token CSRF é validado pelo csrf-magic (guiconfig.inc). */
if (isset($_POST['act'])) {
	switch ($_POST['act']) {
		case 'newsecret':
			$novo = guarita_generate_secret();
			config_set_path('installedpackages/guarita/config/0/agent_secret', $novo);
			write_config(gettext('Guarita: segredo dos agentes trocado'));
			guarita_resync_config();
			$settings = guarita_settings();
			$savemsg = gettext('Segredo trocado. Reinstale ou reconfigure o agente em TODOS os ' .
			                   'controladores de domínio: até lá, os eventos deles serão recusados.');
			$msgclass = 'warning';
			break;
	}
}

/* Download do agente/instalador. */
if (isset($_GET['download'])) {
	$files = array(
		'agent'     => '/usr/local/share/pfSense-pkg-Guarita/agent/guarita-agent.ps1',
		'installer' => '/usr/local/share/pfSense-pkg-Guarita/agent/install-agent.ps1',
	);
	$which = $_GET['download'];
	if (isset($files[$which]) && file_exists($files[$which])) {
		$name = basename($files[$which]);
		header('Content-Type: text/plain; charset=utf-8');
		header('Content-Disposition: attachment; filename="' . $name . '"');
		header('Content-Length: ' . filesize($files[$which]));
		readfile($files[$which]);
		exit;
	}
	$savemsg = gettext('Arquivo do agente não encontrado no pacote.');
	$msgclass = 'danger';
}

$running = guarita_is_running();
$status  = $running ? guarita_get_status() : null;

/* Endereço que o agente deve usar: o IP de escuta configurado ou, se estiver em
 * 0.0.0.0, o IP da interface LAN, que é o caminho normal dos DCs. */
$listen_ip   = !empty($settings['listen_ip']) ? $settings['listen_ip'] : '';
$listen_port = !empty($settings['listen_port']) ? (int) $settings['listen_port'] : 8923;
$server_addr = $listen_ip;
if (empty($server_addr) || ($server_addr === '0.0.0.0')) {
	$server_addr = get_interface_ip('lan');
	if (empty($server_addr)) {
		$server_addr = gettext('<IP do pfSense>');
	}
}

$secret = isset($settings['agent_secret']) ? $settings['agent_secret'] : '';

include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Configurações"), false, "/pkg_edit.php?xml=guarita.xml");
$tab_array[] = array(gettext("Grupos"),        false, "/pkg.php?xml=guaritagroups.xml");
$tab_array[] = array(gettext("Sessões"),       false, "/guarita_sessions.php");
$tab_array[] = array(gettext("Status"),        false, "/guarita_status.php");
$tab_array[] = array(gettext("Agentes"),       true,  "/guarita_agents.php");
display_top_tabs($tab_array);

if (!empty($savemsg)) {
	print_info_box($savemsg, $msgclass);
}
?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?= gettext("Agentes que já se comunicaram") ?></h2>
	</div>
	<div class="panel-body">
<?php
$seen = ($running && is_array($status) && is_array($status['agents_last_seen']))
	? $status['agents_last_seen'] : array();

if (!$running) {
	print_info_box(gettext('O serviço Guarita não está rodando.'), 'danger', false);
} elseif (empty($seen)) {
?>
		<div class="alert alert-warning" role="alert">
			<?= gettext("Nenhum agente se comunicou com este firewall ainda.") ?>
			<br><br>
			<?= gettext("Siga as instruções abaixo para instalar o agente nos controladores " .
			            "de domínio. Se já instalou, verifique:") ?>
			<ul>
				<li><?= gettext("se existe regra de firewall liberando o IP do controlador de domínio " .
				                "nesta porta;") ?></li>
				<li><?= gettext("se o segredo usado na instalação é o mesmo mostrado abaixo;") ?></li>
				<li><?= gettext("o log do agente no servidor, em C:\\ProgramData\\Guarita\\agent.log.") ?></li>
			</ul>
		</div>
<?php } else { ?>
		<div class="table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?= gettext("Controlador de domínio") ?></th>
					<th><?= gettext("Último contato") ?></th>
					<th><?= gettext("Situação") ?></th>
				</tr>
			</thead>
			<tbody>
<?php
	foreach ($seen as $agent => $when) {
		$ts = strtotime($when);
		$idade = $ts ? (time() - $ts) : null;
?>
				<tr>
					<td><strong><?= htmlspecialchars($agent) ?></strong></td>
					<td>
						<?= $ts ? htmlspecialchars(date('d/m/Y H:i:s', $ts)) : '-' ?>
						<?php if ($idade !== null): ?>
							<span class="text-muted">
								(<?= htmlspecialchars(convert_seconds_to_dhms($idade)) ?> <?= gettext("atrás") ?>)
							</span>
						<?php endif ?>
					</td>
					<td>
						<?php if ($idade === null): ?>
							<span class="label label-default"><?= gettext("desconhecida") ?></span>
						<?php elseif ($idade < 300): ?>
							<span class="label label-success"><?= gettext("ativo") ?></span>
						<?php elseif ($idade < 3600): ?>
							<span class="label label-warning"><?= gettext("atrasado") ?></span>
						<?php else: ?>
							<span class="label label-danger"><?= gettext("sem contato") ?></span>
						<?php endif ?>
					</td>
				</tr>
<?php } ?>
			</tbody>
		</table>
		</div>
<?php } ?>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?= gettext("Instalar o agente num controlador de domínio") ?></h2>
	</div>
	<div class="panel-body">

		<p><strong><?= gettext("1. Baixe os dois arquivos e copie-os para o controlador de domínio") ?></strong></p>
		<p>
			<a href="guarita_agents.php?download=installer" class="btn btn-primary">
				<i class="fa-solid fa-download"></i> install-agent.ps1
			</a>
			<a href="guarita_agents.php?download=agent" class="btn btn-default">
				<i class="fa-solid fa-download"></i> guarita-agent.ps1
			</a>
			<br><small class="text-muted">
				<?= gettext("Mantenha os dois na mesma pasta. O instalador procura o agente ao lado dele.") ?>
			</small>
		</p>

		<p><strong><?= gettext("2. Abra o PowerShell como Administrador e rode") ?></strong></p>
		<pre style="white-space:pre-wrap">.\install-agent.ps1 -Server <?= htmlspecialchars($server_addr) ?> -Port <?= $listen_port ?> -Secret "<?= htmlspecialchars($secret) ?>" -EnableAudit</pre>
		<p>
			<small class="text-muted">
				<?= gettext("O instalador copia o agente, grava o segredo num arquivo com permissão " .
				            "restrita, liga a auditoria de logon necessária, testa a conexão com este " .
				            "firewall e cria uma tarefa agendada rodando como SYSTEM a cada minuto.") ?>
				<br>
				<?= gettext("Sem -EnableAudit ele apenas avisa o que falta, sem mexer na auditoria. " .
				            "Em ambiente com vários controladores de domínio, prefira ligar a auditoria " .
				            "por GPO e instalar o agente em cada um deles.") ?>
			</small>
		</p>

		<p><strong><?= gettext("3. Libere o acesso no firewall") ?></strong></p>
		<p>
			<?= sprintf(gettext("Crie uma regra na interface onde ficam os controladores de domínio, " .
			                    "permitindo TCP de cada DC para %s na porta %d."),
				'<code>' . htmlspecialchars($server_addr) . '</code>', $listen_port) ?>
			<br>
			<a href="/firewall_rules.php" class="btn btn-sm btn-default">
				<?= gettext("Ir para Firewall > Rules") ?>
			</a>
		</p>
		<div class="alert alert-warning" role="alert">
			<?= gettext("Libere apenas os IPs dos controladores de domínio. Quem alcançar esta porta " .
			            "e conhecer o segredo pode afirmar que qualquer usuário está em qualquer IP, " .
			            "e assim assumir a política de acesso daquele usuário.") ?>
		</div>

		<p><strong><?= gettext("4. Confira") ?></strong></p>
		<p>
			<?= gettext("Depois do primeiro logon de um usuário do domínio, a sessão aparece em") ?>
			<a href="/guarita_sessions.php"><?= gettext("Sessões") ?></a>.
			<?= gettext("Esta mesma tela mostra o último contato de cada agente.") ?>
		</p>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?= gettext("Segredo compartilhado") ?></h2>
	</div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?= gettext("Endereço para os agentes") ?></dt>
			<dd><code><?= htmlspecialchars($server_addr) ?>:<?= $listen_port ?></code></dd>
			<dt><?= gettext("Segredo atual") ?></dt>
			<dd>
				<code id="segredo"><?= htmlspecialchars($secret) ?></code>
			</dd>
		</dl>
		<form action="guarita_agents.php" method="post"
		      onsubmit="return confirm('<?= gettext('Trocar o segredo? Todos os agentes param de ser aceitos até serem reconfigurados com o novo valor.') ?>')">
			<input type="hidden" name="act" value="newsecret">
			<button type="submit" class="btn btn-warning">
				<i class="fa-solid fa-key"></i> <?= gettext("Gerar um segredo novo") ?>
			</button>
		</form>
	</div>
</div>

<div class="infoblock">
<?php print_info_box(
	gettext('<b>Como o agente identifica o usuário:</b> ele lê no log de Segurança do ' .
	        'controlador de domínio os eventos de autenticação Kerberos (4768 e 4769) e de ' .
	        'logon de rede (4624), que trazem o nome da conta e o IP da estação. Não é ' .
	        'instalado nada nas estações.') .
	'<br><br>' .
	gettext('<b>Se nada aparecer:</b> o mais comum é a auditoria de logon estar desligada no ' .
	        'controlador de domínio — sem ela esses eventos nem são gravados. Rode o ' .
	        'instalador com -EnableAudit, ou ligue por GPO em Configuração Avançada da ' .
	        'Política de Auditoria, nas subcategorias "Serviço de Autenticação Kerberos", ' .
	        '"Operações de Tickets de Serviço Kerberos" e "Logon".') .
	'<br><br>' .
	gettext('<b>Grupos do AD:</b> o Active Directory só devolve grupos de escopo Global ou ' .
	        'Universal em consultas comuns. Se um grupo não aparecer no teste da aba Status, ' .
	        'confira o escopo dele.'),
	'info', false);
?>
</div>

<?php include("foot.inc"); ?>
