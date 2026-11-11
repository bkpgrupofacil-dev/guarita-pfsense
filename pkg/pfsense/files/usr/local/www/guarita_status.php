<?php
/*
 * guarita_status.php
 *
 * Status do serviço, contadores, grupos com a contagem de membros e uma
 * ferramenta para testar a resolução de grupos de um usuário no AD.
 *
 * Licenciado sob a Apache License, versão 2.0.
 */

##|+PRIV
##|*IDENT=page-services-guarita-status
##|*NAME=Services: Guarita: Status
##|*DESCR=Permite ver o status do Guarita
##|*MATCH=guarita_status.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/guarita.inc");

$pgtitle = array(gettext("Services"), gettext("Guarita"), gettext("Status"));

$ldap_test = null;
$test_user = '';
$savemsg = '';
$msgclass = 'success';

/* O token CSRF é validado pelo csrf-magic (guiconfig.inc). */
if (isset($_POST['act']) && ($_POST['act'] === 'testldap')) {
	$test_user = trim($_POST['test_user']);
	if ($test_user === '') {
		$savemsg = gettext("Informe um nome de usuário do domínio para testar.");
		$msgclass = 'warning';
	} elseif (!guarita_is_running()) {
		$savemsg = gettext("O serviço Guarita não está rodando.");
		$msgclass = 'danger';
	} else {
		$ldap_test = guarita_test_ldap($test_user);
		if ($ldap_test === null) {
			$savemsg = gettext("Não consegui falar com o serviço Guarita.");
			$msgclass = 'danger';
		} elseif (isset($ldap_test['error'])) {
			$savemsg = sprintf(gettext("O Active Directory recusou a consulta: %s"),
				htmlspecialchars($ldap_test['error']));
			$msgclass = 'danger';
			$ldap_test = null;
		}
	}
}

$running  = guarita_is_running();
$status   = $running ? guarita_get_status() : null;
$settings = guarita_settings();

/* Lê a contagem real das tabelas no pf, para comparar com o que o daemon pensa
 * que aplicou. Divergência aqui indica regra/alias faltando. */
function guarita_pf_table_count($table) {
	$out = array();
	$rc = 0;
	exec("/sbin/pfctl -t " . escapeshellarg($table) . " -T show 2>/dev/null | /usr/bin/wc -l",
		$out, $rc);
	if ($rc !== 0 || empty($out)) {
		return null;
	}
	return (int) trim($out[0]);
}

include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Configurações"), false, "/pkg_edit.php?xml=guarita.xml");
$tab_array[] = array(gettext("Grupos"),        false, "/pkg.php?xml=guaritagroups.xml");
$tab_array[] = array(gettext("Sessões"),       false, "/guarita_sessions.php");
$tab_array[] = array(gettext("Status"),        true,  "/guarita_status.php");
$tab_array[] = array(gettext("Agentes"),       false, "/guarita_agents.php");
display_top_tabs($tab_array);

if (!empty($savemsg)) {
	print_info_box($savemsg, $msgclass);
}

if (empty($settings['enable'])) {
	print_info_box(gettext('O Guarita está desabilitado na aba Configurações.'), 'warning', false);
}
?>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?= gettext("Serviço") ?></h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?= gettext("Situação") ?></dt>
			<dd>
				<?php if ($running): ?>
					<span class="label label-success"><?= gettext("rodando") ?></span>
				<?php else: ?>
					<span class="label label-danger"><?= gettext("parado") ?></span>
					&nbsp;<a href="/status_services.php"><?= gettext("Status > Services") ?></a>
				<?php endif ?>
			</dd>

<?php if ($running && is_array($status)): ?>
			<dt><?= gettext("Versão") ?></dt>
			<dd><?= htmlspecialchars($status['version']) ?></dd>

			<dt><?= gettext("No ar desde") ?></dt>
			<dd>
				<?php
				$st = strtotime($status['started_at']);
				echo $st ? htmlspecialchars(date('d/m/Y H:i:s', $st)) : '-';
				if ($st) {
					echo ' <span class="text-muted">(' .
					     htmlspecialchars(convert_seconds_to_dhms(time() - $st)) . ')</span>';
				}
				?>
			</dd>

			<dt><?= gettext("Sessões ativas") ?></dt>
			<dd>
				<a href="/guarita_sessions.php"><?= (int) $status['sessions'] ?></a>
			</dd>

			<dt><?= gettext("Servidor LDAP") ?></dt>
			<dd>
				<?php if (!empty($status['ldap_host'])): ?>
					<?= htmlspecialchars($status['ldap_host']) ?>
				<?php else: ?>
					<span class="text-danger"><?= gettext("não configurado") ?></span>
				<?php endif ?>
			</dd>

			<dt><?= gettext("Eventos recebidos") ?></dt>
			<dd>
				<?= (int) $status['events_received'] ?>
				<span class="text-muted">
					(<?= sprintf(gettext("%d aplicados, %d recusados"),
						(int) $status['events_accepted'], (int) $status['events_rejected']) ?>)
				</span>
				<?php if ((int) $status['events_rejected'] > 0): ?>
					<br><small class="text-warning">
						<?= gettext("Eventos recusados indicam segredo diferente entre o pacote e o agente, " .
						            "ou relógio fora de sincronia entre o firewall e o controlador de domínio.") ?>
					</small>
				<?php endif ?>
			</dd>

			<dt><?= gettext("Última aplicação") ?></dt>
			<dd>
				<?php
				$ls = strtotime($status['last_sync_at']);
				echo $ls ? htmlspecialchars(date('d/m/Y H:i:s', $ls)) : gettext('ainda não');
				?>
				<?php if (!empty($status['last_sync_error'])): ?>
					<br><span class="text-danger">
						<?= htmlspecialchars($status['last_sync_error']) ?>
					</span>
					<br><small class="text-muted">
						<?= gettext('Se o erro for "table does not exist", confira se o alias do grupo ' .
						            'existe em Firewall > Aliases e salve as Configurações de novo para ' .
						            'forçar uma recarga do filtro.') ?>
					</small>
				<?php endif ?>
			</dd>
<?php endif ?>
		</dl>
	</div>
</div>

<?php if ($running && is_array($status) && !empty($status['groups'])): ?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?= gettext("Grupos") ?></h2></div>
	<div class="panel-body">
		<div class="table-responsive">
		<table class="table table-striped table-hover table-condensed">
			<thead>
				<tr>
					<th><?= gettext("Grupo") ?></th>
					<th><?= gettext("Alias / tabela no firewall") ?></th>
					<th><?= gettext("IPs (serviço)") ?></th>
					<th><?= gettext("IPs (pf)") ?></th>
					<th><?= gettext("Regras") ?></th>
				</tr>
			</thead>
			<tbody>
<?php foreach ($status['groups'] as $grp):
	$pfcount = guarita_pf_table_count($grp['pf_table']);
	$insvc = (int) $grp['members'];
?>
				<tr>
					<td><strong><?= htmlspecialchars($grp['name']) ?></strong></td>
					<td><code><?= htmlspecialchars($grp['pf_table']) ?></code></td>
					<td><?= $insvc ?></td>
					<td>
						<?php if ($pfcount === null): ?>
							<span class="label label-danger" title="<?= gettext('A tabela não existe no firewall; o alias pode não ter sido criado') ?>">
								<?= gettext("sem tabela") ?>
							</span>
						<?php elseif ($pfcount !== $insvc): ?>
							<span class="label label-warning" title="<?= gettext('Divergência: reaplique as tabelas') ?>">
								<?= $pfcount ?>
							</span>
						<?php else: ?>
							<?= $pfcount ?>
						<?php endif ?>
					</td>
					<td>
						<a href="/firewall_rules.php" class="btn btn-xs btn-default">
							<?= gettext("ver regras") ?>
						</a>
						<a href="/diag_tables.php?type=<?= urlencode($grp['pf_table']) ?>"
						   class="btn btn-xs btn-default">
							<?= gettext("ver tabela") ?>
						</a>
					</td>
				</tr>
<?php endforeach ?>
			</tbody>
		</table>
		</div>
		<?php if (count($status['groups']) === 0): ?>
			<div class="alert alert-info"><?= gettext("Nenhum grupo cadastrado.") ?></div>
		<?php endif ?>
	</div>
</div>
<?php endif ?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?= gettext("Testar um usuário no Active Directory") ?></h2>
	</div>
	<div class="panel-body">
		<p>
			<?= gettext("Consulta o AD agora e mostra em quais grupos o usuário está e em qual " .
			            "grupo do Guarita ele cairia. Serve para conferir se os nomes de grupo " .
			            "cadastrados na aba Grupos estão escritos como o AD os devolve.") ?>
		</p>
		<form action="guarita_status.php" method="post" class="form-inline">
			<input type="hidden" name="act" value="testldap">
			<div class="form-group">
				<label for="test_user"><?= gettext("Usuário") ?>&nbsp;</label>
				<input type="text" name="test_user" id="test_user" class="form-control"
				       value="<?= htmlspecialchars($test_user) ?>"
				       placeholder="<?= gettext('ex.: joao.silva') ?>" size="30">
			</div>
			<button type="submit" class="btn btn-primary">
				<i class="fa-solid fa-magnifying-glass"></i> <?= gettext("Consultar") ?>
			</button>
		</form>

<?php if (is_array($ldap_test)): ?>
		<hr>
		<dl class="dl-horizontal">
			<dt><?= gettext("Usuário") ?></dt>
			<dd><?= htmlspecialchars($ldap_test['user']) ?></dd>

			<dt><?= gettext("Tempo da consulta") ?></dt>
			<dd><?= htmlspecialchars($ldap_test['elapsed']) ?></dd>

			<dt><?= gettext("Grupos no AD") ?></dt>
			<dd>
				<?php if (empty($ldap_test['ad_groups'])): ?>
					<span class="text-muted"><?= gettext("nenhum grupo devolvido") ?></span>
				<?php else: ?>
					<?php foreach ((array) $ldap_test['ad_groups'] as $adgrp): ?>
						<span class="label label-default"><?= htmlspecialchars($adgrp) ?></span>
					<?php endforeach ?>
				<?php endif ?>
			</dd>

			<dt><?= gettext("Grupos do Guarita") ?></dt>
			<dd>
				<?php if (empty($ldap_test['logical'])): ?>
					<span class="text-warning">
						<?= gettext("nenhum — nenhum grupo do AD acima casa com os grupos cadastrados") ?>
					</span>
				<?php else: ?>
					<?php foreach ((array) $ldap_test['logical'] as $lgrp): ?>
						<span class="label label-info"><?= htmlspecialchars($lgrp) ?></span>
					<?php endforeach ?>
					<br><small class="text-muted">
						<?= gettext("No logon real vale apenas o de maior prioridade (menor número).") ?>
					</small>
				<?php endif ?>
			</dd>
		</dl>
<?php endif ?>
	</div>
</div>

<div class="infoblock">
<?php print_info_box(
	gettext('As colunas <b>IPs (serviço)</b> e <b>IPs (pf)</b> devem bater. A tabela de ' .
	        'cada grupo é declarada como "persist" no firewall, então existe desde que o ' .
	        'alias exista — não é preciso ter regra usando ela. "sem tabela" indica ' .
	        'problema, não situação normal.') .
	'<br><br>' .
	gettext('Cada recarga de filtro do pfSense esvazia essas tabelas, e o serviço as ' .
	        'repõe automaticamente em alguns segundos. Uma divergência momentânea logo ' .
	        'após salvar uma configuração é esperada.') .
	'<br><br>' .
	gettext('Logs do serviço: ') .
	'<a href="/status_logs_packages.php?pkg=guarita.log" class="alert-link">' .
	gettext('Status > System Logs > Guarita') . '</a>',
	'info', false);
?>
</div>

<?php include("foot.inc"); ?>
