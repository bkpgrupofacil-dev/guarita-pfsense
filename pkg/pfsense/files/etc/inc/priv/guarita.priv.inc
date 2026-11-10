<?php
/*
 * guarita.priv.inc
 *
 * Privilégios do pacote Guarita, para que seja possível dar acesso às telas
 * do pacote a um usuário do pfSense sem dar acesso total ao firewall.
 *
 * Licenciado sob a Apache License, versão 2.0.
 */

global $priv_list;

$priv_list['page-services-guarita'] = array();
$priv_list['page-services-guarita']['name'] = "WebCfg - Services: Guarita";
$priv_list['page-services-guarita']['descr'] = "Permite configurar o pacote Guarita";
$priv_list['page-services-guarita']['match'] = array();
$priv_list['page-services-guarita']['match'][] = "pkg_edit.php?xml=guarita.xml*";
$priv_list['page-services-guarita']['match'][] = "pkg.php?xml=guaritagroups.xml*";
$priv_list['page-services-guarita']['match'][] = "pkg_edit.php?xml=guaritagroups.xml*";

$priv_list['page-services-guarita-sessions'] = array();
$priv_list['page-services-guarita-sessions']['name'] = "WebCfg - Services: Guarita: Sessões";
$priv_list['page-services-guarita-sessions']['descr'] = "Permite ver e encerrar sessões do Guarita";
$priv_list['page-services-guarita-sessions']['match'] = array();
$priv_list['page-services-guarita-sessions']['match'][] = "guarita_sessions.php*";

$priv_list['page-services-guarita-status'] = array();
$priv_list['page-services-guarita-status']['name'] = "WebCfg - Services: Guarita: Status";
$priv_list['page-services-guarita-status']['descr'] = "Permite ver o status do Guarita";
$priv_list['page-services-guarita-status']['match'] = array();
$priv_list['page-services-guarita-status']['match'][] = "guarita_status.php*";

$priv_list['page-services-guarita-agents'] = array();
$priv_list['page-services-guarita-agents']['name'] = "WebCfg - Services: Guarita: Agentes";
$priv_list['page-services-guarita-agents']['descr'] = "Permite ver os agentes e baixar o instalador (mostra o segredo compartilhado)";
$priv_list['page-services-guarita-agents']['match'] = array();
$priv_list['page-services-guarita-agents']['match'][] = "guarita_agents.php*";

?>
