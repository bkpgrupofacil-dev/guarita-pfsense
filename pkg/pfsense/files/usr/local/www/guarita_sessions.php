<?php
/*
 * guarita_sessions.php
 *
 * Mostra as sessões ativas (usuário <-> IP <-> grupos) e permite encerrar ou
 * fixar uma sessão.
 *
 * Licenciado sob a Apache License, versão 2.0.
 */

##|+PRIV
##|*IDENT=page-services-guarita-sessions
##|*NAME=Services: Guarita: Sessões
##|*DESCR=Permite ver e gerenciar as sessões do Guarita
##|*MATCH=guarita_sessions.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/guarita.inc");

$pgtitle = array(gettext("Services"), gettext("Guarita"), gettext("Sessões"));
$shortcut_section = "guarita";

$savemsg = '';
$msgclass = 'success';

/* O token CSRF é validado pelo csrf-magic, carregado via guiconfig.inc, e
 * injetado automaticamente nos formulários abaixo. */
if ($_POST) {
	$ip = isset($_POST['ip']) ? trim($_POST['ip']) : '';

	if (isset($_POST['act'])) {
		switch ($_POST['act']) {
			case 'remove':
				if (!is_ipaddr($ip)) {
					$savemsg = gettext("IP inválido.");
					$msgclass = 'danger';
					break;
				}
				$res = guarita_remove_session($ip);
				if ($res === null) {
					$savemsg = gettext("Não consegui falar com o serviço Guarita. Ele está rodando?");
					$msgclass = 'danger';
				} elseif (!empty($res['removed'])) {
					$savemsg = sprintf(gettext("Sessão de %s encerrada."), htmlspecialchars($ip));
				} else {
					$savemsg = sprintf(gettext("Não havia sessão ativa para %s."), htmlspecialchars($ip));
					$msgclass = 'warning';
				}
				break;

			case 'sticky':
				if (!is_ipaddr($ip)) {
					$savemsg = gettext("IP inválido.");
					$msgclass = 'danger';
					break;
				}
				$on = !empty($_POST['on']);
				$res = guarita_set_sticky($ip, $on);
				if ($res === null) {
					$savemsg = gettext("Não consegui falar com o serviço Guarita.");
					$msgclass = 'danger';
				} else {
					$savemsg = $on
						? sprintf(gettext("Sessão de %s fixada: não vai expirar por inatividade."), htmlspecialchars($ip))
						: sprintf(gettext("Sessão de %s desafixada."), htmlspecialchars($ip));
				}
				break;

			case 'resync':
				$res = guarita_resync();
				if ($res === null) {
					$savemsg = gettext("Não consegui falar com o serviço Guarita.");
					$msgclass = 'danger';
				} elseif (isset($res['error'])) {
					$savemsg = sprintf(gettext("Erro ao reaplicar: %s"), htmlspecialchars($res['error']));
					$msgclass = 'danger';
				} else {
					$savemsg = gettext("Tabelas do firewall reaplicadas e cache de grupos limpo.");
				}
				break;
		}
	}
}

$running  = guarita_is_running();
$sessions = $running ? guarita_get_sessions() : null;
$settings = guarita_settings();

/* Filtro de busca simples. */
$filter = isset($_GET['filtro']) ? trim($_GET['filtro']) : '';

include("head.inc");

/* Abas, iguais às do pacote. */
$tab_array = array();
$tab_array[] = array(gettext("Configurações"), false, "/pkg_edit.php?xml=guarita.xml");
$tab_array[] = array(gettext("Grupos"),        false, "/pkg.php?xml=guaritagroups.xml");
$tab_array[] = array(gettext("Sessões"),       true,  "/guarita_sessions.php");
$tab_array[] = array(gettext("Status"),        false, "/guarita_status.php");
$tab_array[] = array(gettext("Agentes"),       false, "/guarita_agents.php");
display_top_tabs($tab_array);

if (!empty($savemsg)) {
	print_info_box($savemsg, $msgclass);
}

if (empty($settings['enable'])) {
	print_info_box(
		gettext('O Guarita está desabilitado. Ligue-o na aba Configurações.') .
		' <a href="/pkg_edit.php?xml=guarita.xml" class="alert-link">' . gettext('Ir para Configurações') . '</a>',
		'warning', false);
} elseif (!$running) {
	print_info_box(
		gettext('O serviço Guarita não está rodando. Verifique em Status > Services, ' .
		        'e veja o log em Status > System Logs > Guarita.'),
		'danger', false);
}

if ($running && is_array($sessions)) {
	$total = count($sessions);

	/* Aplica o filtro. */
	$rows = array();
	foreach ($sessions as $s) {
		if ($filter !== '') {
			$hay = strtolower($s['ip'] . ' ' . $s['user'] . ' ' . $s['domain'] . ' ' .
			                  implode(' ', (array) $s['groups']));
			if (strpos($hay, strtolower($filter)) === false) {
				continue;
			}
		}
		$rows[] = $s;
	}
?>
<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title">
			<?= gettext("Sessões ativas") ?>
			<span class="badge"><?= $total ?></span>
		</h2>
	</div>
	<div class="panel-body">
		<form action="guarita_sessions.php" method="get" class="form-inline" style="margin-bottom:10px">
			<div class="form-group">
				<label for="filtro"><?= gettext("Filtrar") ?>&nbsp;</label>
				<input type="text" name="filtro" id="filtro" class="form-control"
				       value="<?= htmlspecialchars($filter) ?>"
				       placeholder="<?= gettext('usuário, IP ou grupo') ?>" size="30">
			</div>
			<button type="submit" class="btn btn-sm btn-primary">
				<i class="fa-solid fa-filter"></i> <?= gettext("Filtrar") ?>
			</button>
			<?php if ($filter !== ''): ?>
				<a href="guarita_sessions.php" class="btn btn-sm btn-default">
					<?= gettext("Limpar") ?>
				</a>
			<?php endif ?>
		</form>

<?php if (empty($rows)): ?>
		<div class="alert alert-info" role="alert">
			<?php if ($total === 0): ?>
				<?= gettext("Nenhuma sessão ativa ainda.") ?>
				<br><br>
				<?= gettext("Se os agentes já estão instalados nos controladores de domínio, " .
				            "confira na aba Agentes quando foi o último contato de cada um. " .
				            "Uma sessão aparece aqui quando um usuário do domínio faz logon " .
				            "numa estação.") ?>
			<?php else: ?>
				<?= sprintf(gettext("Nenhuma das %d sessões casa com o filtro."), $total) ?>
			<?php endif ?>
		</div>
<?php else: ?>
		<div class="table-responsive">
		<table class="table table-striped table-hover table-condensed sortable-theme-bootstrap" data-sortable>
			<thead>
				<tr>
					<th><?= gettext("IP") ?></th>
					<th><?= gettext("Usuário") ?></th>
					<th><?= gettext("Domínio") ?></th>
					<th><?= gettext("Grupos") ?></th>
					<th><?= gettext("Logon") ?></th>
					<th><?= gettext("Último evento") ?></th>
					<th><?= gettext("Origem") ?></th>
					<th data-sortable="false"><?= gettext("Ações") ?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($rows as $s):
	$grupos = (array) $s['groups'];
	$login  = strtotime($s['login_at']);
	$seen   = strtotime($s['seen_at']);
?>
				<tr>
					<td><?= htmlspecialchars($s['ip']) ?></td>
					<td>
						<strong><?= htmlspecialchars($s['user']) ?></strong>
						<?php if (!empty($s['sticky'])): ?>
							<i class="fa-solid fa-thumbtack text-info"
							   title="<?= gettext('Sessão fixada: não expira por inatividade') ?>"></i>
						<?php endif ?>
					</td>
					<td><?= htmlspecialchars($s['domain']) ?></td>
					<td>
						<?php if (empty($grupos)): ?>
							<span class="text-muted"><?= gettext("nenhum") ?></span>
						<?php else: ?>
							<?php foreach ($grupos as $grupo): ?>
								<span class="label label-info"><?= htmlspecialchars($grupo) ?></span>
							<?php endforeach ?>
						<?php endif ?>
					</td>
					<td><?= $login ? htmlspecialchars(date('d/m H:i', $login)) : '-' ?></td>
					<td><?= $seen ? htmlspecialchars(date('d/m H:i:s', $seen)) : '-' ?></td>
					<td><small><?= htmlspecialchars($s['source']) ?></small></td>
					<td>
						<form action="guarita_sessions.php" method="post" style="display:inline">
							<input type="hidden" name="ip" value="<?= htmlspecialchars($s['ip']) ?>">
							<input type="hidden" name="act" value="sticky">
							<input type="hidden" name="on" value="<?= empty($s['sticky']) ? '1' : '0' ?>">
							<button type="submit" class="btn btn-xs btn-default"
							        title="<?= empty($s['sticky'])
							                  ? gettext('Fixar: a sessão passa a não expirar')
							                  : gettext('Desafixar') ?>">
								<i class="fa-solid fa-thumbtack"></i>
							</button>
						</form>
						<form action="guarita_sessions.php" method="post" style="display:inline"
						      onsubmit="return confirm('<?= gettext('Encerrar a sessão deste IP? O usuário sai das tabelas de grupo até o próximo evento de logon.') ?>')">
							<input type="hidden" name="ip" value="<?= htmlspecialchars($s['ip']) ?>">
							<input type="hidden" name="act" value="remove">
							<button type="submit" class="btn btn-xs btn-danger"
							        title="<?= gettext('Encerrar sessão') ?>">
								<i class="fa-solid fa-trash-can"></i>
							</button>
						</form>
					</td>
				</tr>
<?php endforeach ?>
			</tbody>
		</table>
		</div>
<?php endif ?>
	</div>
</div>

<nav class="action-buttons">
	<form action="guarita_sessions.php" method="post" style="display:inline">
		<input type="hidden" name="act" value="resync">
		<button type="submit" class="btn btn-primary">
			<i class="fa-solid fa-rotate"></i>
			<?= gettext("Reaplicar tabelas") ?>
		</button>
	</form>
	<a href="guarita_sessions.php" class="btn btn-default">
		<i class="fa-solid fa-arrows-rotate"></i>
		<?= gettext("Atualizar") ?>
	</a>
</nav>

<div class="infoblock">
<?php print_info_box(
	gettext('<b>Reaplicar tabelas</b> limpa o cache de grupos e reescreve todas as tabelas ' .
	        'do firewall a partir das sessões atuais. Use depois de mudar grupos no Active ' .
	        'Directory, se não quiser esperar a reconsulta automática.') .
	'<br><br>' .
	gettext('<b>Encerrar sessão</b> não desconecta o usuário da rede: apenas tira o IP das ' .
	        'tabelas de grupo. No próximo logon ou atividade daquele usuário, a sessão volta.'),
	'info', false);
?>
</div>

<?php
} /* fim: serviço rodando */

include("foot.inc");
