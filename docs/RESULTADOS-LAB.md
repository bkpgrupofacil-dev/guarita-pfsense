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

Os testes de `cmd/guaritad` não compilam no Windows (`log/syslog`): foram
compilados para FreeBSD (`GOOS=freebsd go test -c`) e rodados dentro do pfSense.
A versão foi para 0.1.2 para não haver dois builds diferentes com o número 0.1.1.
