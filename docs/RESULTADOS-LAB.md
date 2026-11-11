# Resultados do laboratório

## Ambiente
- Data: 2026-11-10/11
- Hipervisor: Hyper-V (Windows 11 Pro). VMs do domínio na rede interna
  `pfSense-LAN` (192.168.1.0/24), com o pfSense como gateway. O DNS das VMs é o DC
  (192.168.1.10), que encaminha para o pfSense.
- pfSense: 2.9.0-RELEASE (FreeBSD 16.0-CURRENT) / ZFS / LAN 192.168.1.1 / NTP sincronizado
- DC: Windows Server 2008 R2 / PowerShell 2.0 (nativo) / domínio `teste.local` / 192.168.1.10
- Estação: Windows 10 22H2, no domínio, 192.168.1.100 (DHCP do pfSense)
- Usuários de teste e grupos (escopo Global):
  - `leandroliberado`, no grupo `liberado`
  - `leandrobloq`, no grupo `bloqueio`
  - `leandro`, no grupo `interno`, que é membro de `liberado` (aninhado)
- Acesso: SSH com chave ao pfSense (admin). Comandos no DC rodados pelo usuário,
  com a saída colada. Logons na estação feitos pelo usuário.
- Tarball: `guarita-0.1.1.tar.gz` (sha256 `5c36364a91e44978daea1d9c09855a03b746d4fe8d37038060a2517d20642961`),
  conferido contra a `main` 6ad1a16 (scripts do agente e `verify-on-pfsense.sh` idênticos).

O DC do laboratório já roda PowerShell 2.0, o mesmo motor do DC de produção
(Windows Server 2008). Por isso as fases C3 a C6 já exercitam o caminho do C7.

## Resultados
| Passo | Resultado | Observação |
|---|---|---|
| A1 instalar 0.1.1 | ok | "Guarita 0.1.1 instalado", sem `config.xml.bad` |
| A2 verify 0.1.1 | **falhou** | 33 ok, 1 falha (passo 8). Restauração da config ok, mas a tabela `guarita_teste` ficou no pf. Ver defeitos 1, 2 e 3 |
| A1 instalar 0.1.2 (por cima da 0.1.1) | ok | "versão 0.1.1 já instalada; atualizando para 0.1.2", sem `config.xml.bad` |
| A2 verify 0.1.2 | ok | 36/36 em duas rodadas seguidas; restauração ok e tabela de teste removida do pf |
| A3 telas | **falhou**, corrigido | A aba Sessões quebrava o rodapé do pfSense e gerava "crash report". Ver defeito 4. Depois da correção: as 5 abas sem erro, `PHP_errors.log` sem linhas novas |
| B1 servidor LDAP | ok | AD `dc01` (192.168.1.10:389), bind com conta comum; "Select a container" listou `CN=Users`, `OU=TESTE` e `OU=Domain Controllers`. O pfSense só habilita esse botão com o campo de containers já preenchido |
| B3 grupos | ok | `liberado` (AD `liberado`, prio 0) e `bloqueio` (AD `bloqueio`, prio 10), salvos pela interface. Nome amigável "Bloqueio de Navegação": gravado em UTF-8 no `config.xml`, que continuou bem formado e sem `config.xml.bad`; chegou ao alias, ao JSON do daemon e à tela de Status |
| B4 testar usuários | **falhou**, corrigido | Antes: os usuários voltavam sem grupo nenhum (defeito 8). Depois: `leandroliberado` -> `liberado`, `leandrobloq` -> `bloqueio`; `naoexiste` -> "não encontrado no AD" |
| B5 grupo aninhado | ok | `leandro` em `interno`, que está em `liberado`. Aninhados ligado: AD `interno,liberado` -> `liberado`. Desligado: AD `interno` -> nenhum grupo do Guarita |
| C1 versões | ok | Windows Server 2008 R2 Standard SP1, pt-BR, **PowerShell 2.0** (o mesmo motor do DC de produção) |
| C2 alcance da porta 8923 | ok | DC -> 192.168.1.1:8923 conecta (regra padrão "LAN to any") |
| C3 teste de conexão | ok | `-TestOnly` no PowerShell 2.0: "ok, o pfSense respondeu: {"ok":true,...}" |
| C4 instalação | **falhou**, corrigido | Quatro defeitos em sequência (9 a 12). Depois: tarefa "Guarita Agent" como SISTEMA a cada 1 min, último resultado 0; `secret.txt` só com SISTEMA e Administradores; auditoria lida pelo GUID |
| C5 dry-run | ok, com ressalvas | `logon leandrobloq 192.168.1.100`, sem contas de máquina. A linha sai com `(id 4624)` e não `(id 4768)`: o agente deduplica por (tipo, usuário, IP) e o 4624 do mesmo logon vem antes. Apareceram também os defeitos 14 e 15 |
| C6 falha de Kerberos | ok | Auditoria de falha ligada pelo GUID. `runas /user:TESTE\naoexiste` gerou um 4768 de falha (status 6, de 192.168.1.100). O `naoexiste` não aparece no `-DryRun` nem em Sessões |
| C7 PowerShell 2.0 | ok | Todo o C3 a C6 rodou no motor 2.0, nativo do 2008 R2 ("agente Guarita iniciando em DC01 (PowerShell 2.0)") |
| D1 logon restrito | ok | `leandrobloq` -> sessão no grupo `bloqueio` e 192.168.1.100 em `guarita_bloqueio`, até 1 min depois do logon |
| D2 bloqueio | ok | Regra de teste no topo da LAN (block `guarita_bloqueio` -> `example.com`, com log): o site não abriu; 82 bloqueios de 192.168.1.100 no log do firewall |
| D3 teste cruzado | ok | Mesma estação, logon com `leandroliberado`: às 17:20:00 o IP saiu de `guarita_bloqueio` e entrou em `guarita_liberado` no mesmo segundo, os bloqueios pararam e o site abriu. Regra de teste removida |
| E1 reinício | ok, com ressalva | Reboot pelo sistema: a sessão `leandroliberado` foi restaurada do disco e o IP voltou a `guarita_liberado` 1 s depois de o serviço subir. Ressalva: o pfSense iniciou o serviço duas vezes no boot, e isso expôs o defeito 16 |
| E2 recarga do filtro | ok | Salvar a configuração sem mudar o ruleset esvaziou a tabela, e ela foi reposta sozinha em cerca de 7 s, com "o filtro do pfSense foi recarregado; repondo as tabelas" (depende da correção do defeito 3) |
| E3 mudança de grupo no AD | **falhou**, corrigido | `leandroliberado` movido de `liberado` para `bloqueio` no AD, sem logoff. "Testar um usuário" já mostrava `bloqueio`, mas "Reaplicar tabelas" não mudou a sessão (defeito 18). Depois da correção: a sessão e o IP passaram para `bloqueio` na hora, e o `seen_at` não foi renovado |
| B2 configurações | **falhou**, corrigido | Salvou, mas o daemon ficou sem LDAP (`host` vazio) e escutando em `*:8923`. Ver defeitos 5 e 6. Depois: LDAP 192.168.1.10 e escuta `192.168.1.1:8923`; verify 41/41 |

## Defeitos encontrados

### 1. O verify media a tabela antes de a recarga assíncrona terminar
- Sintoma: no 2.9.0, o passo 8 dizia que a tabela `guarita_teste` não existia,
  e ela aparecia depois de uma recarga manual. O passo 13 passava "em 0s" sem
  ter testado nada.
- Causa: `filter_configure()` só faz `send_event("filter reload")` e volta; quem
  recarrega é o `check_reload_status`, ~1 s depois. O passo 8 olhava na hora, e
  o 13 comparava a tabela antes de o flush acontecer. No 2.7.2 o tempo calhou.
- Correção: os passos 8 e 16 esperam o resultado (a tabela existir, ou ficar
  vazia) por até 30 s. O passo 13 espera a recarga terminar
  (`/var/run/filter_reload_status` reescrito e terminado em "Done").
- Teste que trava: o próprio `build/verify-on-pfsense.sh`.

### 2. Desabilitar o Guarita não recarregava o filtro
- Sintoma: depois de desabilitar (ou restaurar a config pelo verify), o alias
  saía do `config.xml`, mas a tabela continuava no pf e no `/tmp/rules.debug`. As
  tabelas que ficavam guardavam os IPs das últimas sessões, com o serviço parado.
- Causa: `guarita_resync_config()` retornava antes do `filter_configure()`
  quando o pacote estava desabilitado.
- Correção: recarregar o filtro também ao desabilitar.
- Teste que trava: passo 16 do verify ("desabilitar esvazia as tabelas") e a
  conferência no fim da restauração. Com o `guarita.inc` antigo: passo 16 falhou
  com 1 IP na tabela, e a tabela ficou no pf depois de restaurar.

### 3. No 2.9, uma recarga sem mudança no ruleset esvaziava as tabelas e o daemon não percebia
- Sintoma: com uma sessão ativa, salvar qualquer configuração (ou qualquer
  recarga em que o ruleset não muda) deixava a tabela vazia até a reaplicação
  periódica de 60 s. Nesse intervalo, um usuário "restrito" fica sem restrição.
- Causa: o 2.9 (`filter_configure_sync()`, `filter_sync_needed()`) pula a carga
  do ruleset quando ele não mudou ("Skipping filter configuration reload") e não
  reescreve o `/tmp/rules.debug`, que é o sinal que o daemon observava. Mas o
  `filter_run_commands_late()`, que roda o `pfctl -T flush` das tabelas dos
  aliases "host" vazios, roda sempre.
- Correção: o daemon passa a observar também o `/var/run/filter_reload_status`,
  reescrito em toda recarga, inclusive nas puladas (`reload_status_file` na
  config, com esse padrão).
- Teste que trava: `TestReloadWatcherSeesSkippedReload` (Go) e o passo 13 do
  verify, que agora espera as reposições anteriores terminarem e exige que o
  daemon note a recarga. Com o daemon 0.1.1: "tabela não reposta em 20 s" e
  "o daemon NÃO notou a recarga".

### 4. As páginas sobrescreviam a variável global `$g` do pfSense
- Sintoma: ao abrir **Services > Guarita > Sessões**, o pfSense registrou um
  relatório de falha: `array_key_exists(): Argument #2 ($array) must be of type
  array, string given in /etc/inc/globals.inc:745`, vindo de
  `foot.inc -> print_credit() -> g_get()`.
- Causa: as páginas rodam no escopo global do PHP, onde `$g` é o array de
  configuração do sistema. `guarita_sessions.php` (grupos de cada sessão) e
  `guarita_status.php` (tabela de grupos e o resultado de "Testar um usuário")
  usavam `$g` como variável de laço. Quando o rodapé chamava `g_get()`, `$g` era
  uma string.
- Correção: variáveis de laço com outros nomes (`$grupo`, `$grp`, `$adgrp`,
  `$lgrp`).
- Teste que trava: `build/check-page-globals.sh`, chamado pelo `build.sh`, aborta
  o build se uma página usar `$g` ou `$config` como variável de laço ou atribuir
  a elas. Com as páginas antigas, ele aponta os 4 pontos e o build para.

### 5. O servidor LDAP escolhido nunca chegava ao daemon
- Sintoma: com o servidor `dc01` escolhido em Configurações, o `guarita.json`
  saía com `"host": ""` e todo usuário caía em "LDAP não configurado".
- Causa: o campo se chama `authserver`, e `authserver` está em `listtags()` do
  pfSense (é a lista de Authentication Servers). O leitor do `config.xml`
  transforma toda tag com esse nome em lista: `<authserver>dc01</authserver>`
  volta como `array('dc01')`, e `auth_get_authserver()` com um array não acha
  nada. O verify no 2.7.2 nunca configurou LDAP, então não pegou.
- Correção: `guarita_authserver_name()` aceita texto ou lista. O nome do campo
  ficou o mesmo, para não perder a configuração de quem já instalou.
- Teste que trava: passo 16 do verify (grava o campo, relê o `config.xml` do
  disco com `parse_xml_config()` e confere o nome).

### 6. Mudar o endereço de escuta não tinha efeito
- Sintoma: o daemon continuava em `*:8923` depois de salvar "Endereço de escuta =
  192.168.1.1".
- Causa: o `guarita.inc` só mandava SIGHUP, e o daemon não reabre a porta no
  SIGHUP (ele mesmo registrava "mudança de endereço de escuta exige reiniciar o
  serviço"). Quem habilitava primeiro e escolhia o IP depois ficava no endereço
  antigo.
- Correção: o resync compara o endereço no JSON antes e depois de gravar e, se
  mudou, reinicia o serviço. As sessões sobrevivem (ficam em disco).
- Teste que trava: passo 17 do verify (muda a porta e exige o serviço na porta
  nova, com pid novo e a sessão preservada).

### 7. O verify deixava a sessão de teste para trás (introduzido nesta sessão)
- Sintoma: depois do verify, a sessão `192.168.99.50 joao.teste` voltava do disco
  e aparecia em Sessões.
- Causa: o passo de desabilitar (novo, do defeito 2) para o daemon antes da
  restauração, e a restauração apagava a sessão pela API, que não respondia.
- Correção: com o serviço parado, a restauração tira a sessão do arquivo de
  estado antes de religar o pacote, e no fim exige que ela não esteja lá.

### 8. O grupo primário do usuário era ignorado
- Sintoma: em Status > Testar um usuário, `leandroliberado` e `leandrobloq`
  voltavam sem nenhum grupo do AD, embora estivessem em `liberado` e
  `bloqueio`.
- Causa: o administrador marcou esses grupos como **grupo primário** dos
  usuários (`primaryGroupID` 1110 e 1111). O AD não lista o grupo primário no
  `memberOf` do usuário nem no `member` do grupo, e a busca em cadeia
  (`1.2.840.113556.1.4.1941`) também não o vê. Na produção isso pega todo
  mundo: "Usuários do domínio" (RID 513) é o grupo primário de quase todos, e um
  grupo do Guarita apontado para ele nunca casaria com ninguém.
- Correção: o daemon lê `objectSid` e `primaryGroupID` do usuário, monta o SID do
  grupo primário (SID do domínio + RID), busca o grupo por `objectSid` e, com
  aninhados ligado, também os grupos que o contêm.
- Teste que trava: `TestPrimaryGroupSID`, `TestPrimaryGroupSIDRejectsInvalid` e
  `TestEscapeBinary` (Go). No AD real, depois da correção: `leandroliberado` ->
  `liberado` e `leandrobloq` -> `bloqueio`.

### 9 a 12. O instalador do agente não funcionava no Windows Server 2008 R2 em português

Antes de rodar, um diagnóstico de leitura apenas no DC confirmou as suspeitas
(Windows Server 2008 R2 SP1, pt-BR, PowerShell 2.0). Cada defeito só apareceu
depois de corrigir o anterior:

9. **`$PSScriptRoot` vazio.** Em scripts `.ps1` ele só existe a partir do
   PowerShell 3.0. O instalador não achava o `guarita-agent.ps1` e parava.
   Correção: `Split-Path -Parent $MyInvocation.MyCommand.Path`.
10. **Segredo legível por qualquer usuário.** A permissão do `secret.txt` usava os
    nomes `BUILTIN\Administrators` e `NT AUTHORITY\SYSTEM`. No DC em português a
    tradução falhou ("Não foi possível converter algumas ou todas as referências
    de identidade"), a falha virava só um aviso, e o arquivo ficava com a
    permissão herdada de Program Files. Correção: contas pelo SID (`S-1-5-18`,
    `S-1-5-32-544`), permissão aplicada e conferida num arquivo vazio e o
    segredo gravado só depois; se falhar, o arquivo é apagado e a instalação para.
11. **A auditoria não era conferida nem ligada.** `auditpol /subcategory:"Kerberos
    Authentication Service"` dá "Erro 0x00000057: Parâmetro incorreto" num
    Windows em português, e a saída diz "Êxito", não "Success". Correção:
    subcategorias pelo GUID e o estado pela coluna numérica "Setting Value" do
    `auditpol /backup`.
12. **A tarefa agendada não era criada.** Primeiro, o `schtasks /Delete` da tarefa
    anterior (que não existe na primeira instalação) escreve na saída de erro, e
    no PowerShell 2.0, com `$ErrorActionPreference = 'Stop'`, isso derrubava o
    script, que ainda saía com código 0. Corrigido isso, o `/TR` com o caminho
    entre aspas chegava cortado ao `schtasks` ("Argumento/opção inválido -
    'Files\Guarita\guarita-agent.ps1'"). Correção: `Invoke-Native` para os
    executáveis externos, `trap` para sair com código 1, e a tarefa criada por
    `schtasks /Create /XML`, com o programa e os argumentos em campos separados.

- Teste que trava: `build/check-agent-compat.sh` (no `build.sh`) reprova
  `$PSScriptRoot`, nomes de conta em inglês, `auditpol` por nome, `& schtasks`
  ou `& auditpol` direto, `/TR`, cmdlets do PowerShell 3.0+ e acentos nos
  `.ps1`. Com o instalador original, ele aponta 9 linhas.

### 13. A segunda barreira contra eventos de falha do Kerberos estava desligada
- Sintoma: no 2008 R2, o Status do 4768 lido pelo `Get-WinEvent` vem como número
  (`0`), não `0x0`. `Get-StatusField` só aceitava `0x...` e devolvia vazio, então a
  checagem do status era ignorada em todo evento.
- Correção: aceitar o decimal e converter para `0x...`.
- Teste que trava: `build/test-agent.ps1` (no `build.sh`, quando há PowerShell
  na máquina do build), que carrega as funções do agente sem executá-lo. Com o
  agente antigo, 4 falhas, entre elas "status 0x6 barra: obtido True".
- Também: "nenhum evento encontrado" passa a ser reconhecido pelo
  `FullyQualifiedErrorId` (`NoMatchingEventsFound`), que não muda com o idioma.

### 14. A conta de serviço do LDAP virava sessão no IP do próprio pfSense
- Sintoma: `logon user=guarita ip=192.168.1.1` no log do daemon, e a sessão
  "guarita 192.168.1.1" em Sessões.
- Causa: quando o pfSense consulta o AD, o DC registra um logon de rede (4624
  tipo 3) da conta de serviço vindo do IP do pfSense, e o agente o envia como se
  fosse uma estação. Numa política apontada para "Usuários do domínio" (que
  agora é resolvida, ver defeito 8), o próprio firewall entraria na tabela.
- Correção: o daemon descarta eventos cujo IP pertence a uma interface do
  próprio pfSense ("IP do próprio firewall ignorado"). Vale para qualquer
  agente e qualquer conta.
- Teste que trava: `TestIgnoresFirewallOwnIP` e `TestLocalInterfaceAddr` (Go).
  No laboratório, depois da atualização, a conta `guarita` não voltou a
  aparecer em Sessões.

### 15. O nome do computador vinha com o texto da linha seguinte
- Sintoma: `computer=Endereço da rede de origem:	192.168.1.100`.
- Causa: no 4624 de rede em português, "Nome da Estação de Trabalho" vem vazio.
  A expressão que procura o rótulo usava `\s*`, que casa a quebra de linha, e
  pegava a linha seguinte.
- Correção: `[ \t]*` no lugar de `\s*` e `\r?` antes do fim da linha (no .NET,
  com `(?m)`, o `$` não casa antes do `\r` das mensagens do Windows).
- Teste que trava: casos novos em `build/test-agent.ps1` (13/13). Com o agente
  anterior: "nome da estacao vazio fica vazio: obtido 'Endereco da rede de
  origem: 192.168.1.100'".

### 16. Uma segunda instância podia deixar o PID de um processo morto
- Sintoma: no boot do 2.9.0 o serviço foi iniciado duas vezes no mesmo segundo;
  a segunda instância falhou em "address already in use". O `verify` mostrou
  que, depois disso, o arquivo de PID podia apontar para a instância morta.
- Causa: o PID era gravado antes de abrir as portas. A instância que falhava
  deixava o PID dela (o `os.Exit` não roda os `defer`), e o SIGHUP de cada
  configuração salva ia para um processo inexistente: grupos e LDAP alterados na
  interface nunca chegavam ao serviço, sem erro nenhum.
- Correção: gravar o PID só depois que o serviço abriu as portas.
- Teste que trava: passo 18 do verify (inicia uma segunda instância e exige o
  PID da viva). Com o daemon anterior: "o arquivo de PID aponta para 31479, mas
  a instancia viva e 25167".

### 17. O verify falhava num pfSense com sessões reais
- Sintoma: "sessao nao listada" no passo 12, com a sessão real de
  `leandroliberado` ativa.
- Causa: o passo exigia `total=1`.
- Correção: procura a sessão de teste pelo IP. A sessão real foi preservada pela
  restauração. Verify 43/43.

### 18. "Reaplicar tabelas" não reconsultava os grupos no AD
- Sintoma: com o usuário já movido para `bloqueio` no AD (e "Testar um usuário"
  mostrando isso), "Reaplicar tabelas" não mudou nada.
- Causa: `Resync()` limpava o cache e reaplicava as tabelas com os grupos já
  guardados nas sessões. A mudança só chegava no próximo evento do agente depois
  de o cache expirar (até 30 minutos).
- Correção: `Resync()` reconsulta no AD os grupos de todas as sessões. O
  `refreshLoop` passou a usar a mesma função (`refreshSessions`).
- Teste que trava: `TestRefreshSessionsMovesUserToNewGroup` e
  `TestRefreshSessionsKeepsGroupsOnError`. No laboratório: "reaplicar: 1
  sessão(ões) mudaram de grupo após reconsultar o AD".

### 19. A reconsulta de grupos impedia as sessões de expirar
- Sintoma: achado lendo o código durante o E3 e confirmado por teste. A
  reconsulta periódica dos grupos (a cada 30 min) usava `Upsert`, que renova o
  `SeenAt`. Uma sessão sem nenhum evento do agente era renovada a cada 30 minutos
  e nunca expirava pelo TTL (4 h). Com o IP reaproveitado pelo DHCP, outra pessoa
  herdaria a política do usuário anterior sem prazo.
- Correção: `session.UpdateGroups`, que troca só os grupos (e só se o IP ainda
  for do mesmo usuário) sem renovar o `SeenAt`.
- Teste que trava: `TestRefreshSessionsDoesNotKeepSessionAlive`. Com o `Upsert`
  no lugar: "a sessão sem eventos deveria ter expirado (expiradas: 0)".

### Observação: "Reaplicar tabelas" com muitas sessões
A reconsulta do AD é sequencial e a tela espera até 20 s pela resposta. Com
centenas de sessões ativas o botão pode estourar esse tempo (a reconsulta segue
no serviço, mas a tela mostra erro). Não medido no laboratório.

### Observação: a política leva até 1 minuto para mudar
O daemon aplica na hora (o logon do D3 chegou às 17:20:00 e a tabela mudou no
mesmo segundo). A espera está no agente, que roda como tarefa agendada a cada
1 minuto, o mínimo do Agendador do Windows. Enquanto o logon novo não chega, o IP
segue com a política do usuário anterior, porque o logoff do Windows (4634/4647)
não traz o IP e não é usado. No sentido "liberado -> restrito", um usuário
restrito fica liberado por até 1 minuto. Não é defeito do teste; é uma melhoria
possível: agente em modo contínuo (o script já tem, com `-IntervalSeconds`)
rodando como serviço, ou assinatura de eventos (`EventLogWatcher`, .NET 3.5).

Os testes de `cmd/guaritad` não compilam no Windows (`log/syslog`): foram
compilados para FreeBSD (`GOOS=freebsd go test -c`) e rodados dentro do pfSense.
A versão foi para 0.1.2 para não haver dois builds diferentes com o número 0.1.1.
