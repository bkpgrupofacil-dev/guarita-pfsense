# Guarita

Controle de acesso à internet **por usuário do Active Directory** no pfSense.

O Guarita descobre qual usuário do domínio está atrás de cada IP da rede e
mantém uma tabela do firewall por grupo de usuários. Com isso as regras do
pfSense passam a valer por usuário, e não por endereço IP.

É a peça que falta quando se usa só o pfBlockerNG: ele bloqueia para a rede
inteira, ou por IP, e não sabe quem está atrás de cada endereço.

> **Não é um produto oficial da Netgate.** Não é homologado nem suportado pela
> Netgate/ESF. Use por sua conta e risco, e teste em laboratório antes da
> produção.

---

## Como funciona

```
┌──────────────────────┐
│ Controlador de       │  O agente lê os eventos de autenticação
│ domínio (AD)         │  Kerberos do log de Segurança:
│                      │  4768 (logon), 4769 (atividade), 4624 (NTLM)
│  guarita-agent.ps1   │
└──────────┬───────────┘
           │ HTTPS/HTTP assinado com HMAC-SHA256
           │ "o usuário joao está no IP 10.10.20.50"
           ▼
┌──────────────────────────────────────────────────────┐
│ pfSense                                              │
│                                                      │
│  guaritad ──LDAP──► pergunta ao AD os grupos de joao │
│     │                                                │
│     └──► tabela pf "guarita_vendas" ← IP de joao     │
│               │                                      │
│               ▼                                      │
│      alias guarita_vendas, usado nas suas regras     │
└──────────────────────────────────────────────────────┘
```

Nada é instalado nas estações. O agente roda apenas nos controladores de
domínio e só lê o log de eventos.

---

## O que esta versão (0.1.0) entrega

Esta é a **fase 1**: identidade e regras de firewall por usuário.

- Identificação do usuário do AD por trás de cada IP, pelos eventos de logon
  dos controladores de domínio.
- Consulta de grupos no AD por LDAP, com suporte a grupos aninhados.
- Uma tabela do pf e um alias por grupo, atualizados automaticamente.
- Prioridade entre grupos, para resolver usuários que estão em mais de um.
- Sessões com expiração por inatividade, e opção de fixar uma sessão.
- Interface em **Services > Guarita**: sessões ativas, status, grupos, agentes.
- Teste de resolução de grupos de um usuário direto na interface.
- Logs por usuário em **Status > System Logs > Guarita**.
- Estado sobrevive a reboot do firewall.
- Recarga de configuração sem derrubar as sessões.

Com isso você já consegue, **por grupo de usuários**: liberar ou bloquear
destinos e portas, aplicar horários (Schedules do pfSense), limitar banda
(Limiters) e separar o acesso às redes internas.

### O que ainda não está nesta versão

O bloqueio por **nome de site ou aplicação** (YouTube, Netflix, WhatsApp)
**por grupo** é a fase 2. Hoje o Guarita entrega o "quem"; o "o quê" por nome
ainda depende das ferramentas que você já usa.

Veja [docs/REGRAS.md](docs/REGRAS.md) para o que já é possível hoje, incluindo
o que dá e o que não dá para fazer com YouTube na fase 1.

Fases seguintes, em ordem:

| Fase | Entrega |
|------|---------|
| 2 | Filtro DNS por grupo, categorias, bloqueio de QUIC e DNS criptografado |
| 3 | Filtro por SNI no HTTPS, sem instalar certificado nas estações |
| 4 | Relatórios de acesso por usuário, com retenção |
| 5 | 2FA na VPN, com os mesmos grupos valendo para quem conecta de fora |
| 6 | Captive portal para visitantes e máquinas fora do domínio |

---

## Requisitos

| Item | Requisito |
|------|-----------|
| pfSense | CE 2.7.x ou 2.8.x, amd64 |
| Controlador de domínio | Windows Server 2008 ou mais novo, com PowerShell 2.0+ |
| Auditoria no DC | Eventos de logon e Kerberos habilitados (o instalador pode ligar) |
| Conta de serviço no AD | Uma conta comum, que só precisa poder ler os grupos |
| Grupos do AD | Escopo **Global** ou **Universal** |

> **Windows Server 2008:** o agente foi escrito para rodar em PowerShell 2.0,
> mas o 2008 original vem com o 1.0 — é preciso instalar o Windows Management
> Framework 2.0. O 2008 está fora de suporte da Microsoft; quando migrar para o
> 2022, o mesmo agente continua funcionando sem alteração.

---

## Instalação

### 1. No pfSense

```bash
fetch -o guarita-0.1.0.tar.gz <url-do-tarball>
```

```bash
tar -xzf guarita-0.1.0.tar.gz
```

```bash
cd guarita-0.1.0 && sh install.sh
```

O `install.sh` monta um pacote `.pkg` de verdade com o `pkg` do próprio
firewall e o instala, então o Guarita aparece em **System > Package Manager >
Installed Packages** e pode ser removido de lá.

### 2. Cadastre o Active Directory

Em **System > User Manager > Authentication Servers**, adicione o seu AD como
servidor LDAP, se ainda não existir. Use uma conta de serviço do domínio, sem
privilégios especiais. Clique em *Select a container* para confirmar que a
conexão funciona antes de seguir.

### 3. Configure o Guarita

Em **Services > Guarita > Configurações**: marque **Habilitar**, escolha o
servidor LDAP e salve. Anote o segredo dos agentes (aba **Agentes**).

### 4. Cadastre os grupos

Em **Services > Guarita > Grupos**, crie um grupo por política de acesso. Cada
grupo gera um alias chamado `guarita_<nome curto>`.

Exemplo:

| Nome | Nome curto | Grupos do AD | Prioridade |
|------|-----------|--------------|-----------|
| Diretoria | `diretoria` | `GG_Diretoria` | 0 |
| TI | `ti` | `GG_TI`, `GG_Infra` | 10 |
| Vendas | `vendas` | `GG_Vendas` | 20 |
| Restrito | `restrito` | `GG_Restrito` | 30 |

Use a aba **Status** para testar um usuário e conferir se os nomes de grupo
estão escritos como o AD os devolve.

### 5. Instale o agente nos controladores de domínio

Na aba **Agentes**, baixe `install-agent.ps1` e `guarita-agent.ps1`, copie os
dois para o controlador de domínio (na mesma pasta) e rode como Administrador:

```powershell
.\install-agent.ps1 -Server 10.10.20.5 -Secret "<segredo da aba Agentes>" -EnableAudit
```

Repita em **cada** controlador de domínio. Com vários DCs, prefira ligar a
auditoria por GPO e rodar o instalador sem `-EnableAudit`.

### 6. Libere o agente no firewall

Crie uma regra permitindo TCP de cada controlador de domínio para o pfSense na
porta do Guarita (padrão 8923).

> Libere **apenas** os IPs dos controladores de domínio. Quem alcançar essa
> porta e conhecer o segredo pode afirmar que qualquer usuário está em qualquer
> IP, e assim herdar a política de acesso daquele usuário.

### 7. Use os aliases nas suas regras

Em **Firewall > Rules**, use `guarita_<grupo>` como **origem**. Exemplos
completos em [docs/REGRAS.md](docs/REGRAS.md).

---

## Verificação

Depois do primeiro logon de um usuário do domínio:

- **Services > Guarita > Sessões** mostra usuário, IP e grupo.
- **Services > Guarita > Status** mostra os contadores e compara o que o
  serviço aplicou com o que está no pf.
- **Services > Guarita > Agentes** mostra o último contato de cada DC.
- **Status > System Logs > Guarita** mostra os logons.

Roteiro de teste completo em [docs/TESTES.md](docs/TESTES.md).

---

## Problemas comuns

**Nenhuma sessão aparece, e nenhum agente consta na aba Agentes.**
O agente não está alcançando o firewall. Confira a regra de firewall, e veja o
log do agente em `C:\ProgramData\Guarita\agent.log` no DC.

**O agente aparece, mas nenhuma sessão é criada.**
Quase sempre é auditoria desligada no controlador de domínio: sem ela os
eventos 4768/4769 nem são gravados. Rode o instalador com `-EnableAudit`, ou
ligue por GPO. Para ver o que o agente está lendo, sem enviar nada:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\Guarita\guarita-agent.ps1" -Server 10.10.20.5 -SecretFile "C:\Program Files\Guarita\secret.txt" -Once -DryRun
```

**O contador de eventos recusados sobe.**
Segredo diferente entre o pacote e o agente, ou relógio fora de sincronia entre
o firewall e o DC (a tolerância é de 5 minutos). Configure NTP nos dois.

**As sessões aparecem, mas sem grupo.**
Os nomes de grupo cadastrados não casam com o que o AD devolve. Use o teste na
aba **Status**. Lembre que grupos de escopo "Domínio Local" podem não aparecer.

**O status mostra "sem tabela" num grupo.**
Normal até existir uma regra de firewall usando aquele alias: o pf só cria a
tabela quando ela é referenciada por uma regra. Crie a regra e o aviso sai.

---

## Desenvolvimento

```bash
go test ./...
```

```bash
bash build/integration-test.sh
```

```bash
sh build/build.sh
```

O teste de integração sobe o daemon de verdade com um `pfctl` falso e verifica
o fluxo completo: evento assinado, criação da sessão, escrita da tabela, API
local, persistência e recarga por SIGHUP. Não precisa de pfSense nem de AD.

O agente em PowerShell não pode ser executado em Linux, então
`build/ps_mimic.py` replica as funções de montagem do JSON e de assinatura do
`.ps1`, e um teste em Go confere que os dois lados concordam. Se alguém mudar o
esquema de assinatura de um lado só, o teste quebra.

### Estrutura

```
cmd/guaritad/          serviço que roda no pfSense
internal/apiagent/     API dos agentes (HMAC, normalização de eventos)
internal/apilocal/     API no socket unix, usada pela interface em PHP
internal/config/       leitura e validação da configuração
internal/ldapgrp/      consulta de grupos no AD, com cache
internal/pftable/      escrita das tabelas e chamada do pfctl
internal/session/      estado usuário ↔ IP ↔ grupos
agent/                 agente e instalador para os controladores de domínio
pkg/pfsense/files/     arquivos do pacote (XML, PHP, privilégios)
build/                 build, instalador e teste de integração
```

---

## Segurança

- Toda mensagem de agente é assinada com HMAC-SHA256 e tem janela de 5 minutos,
  o que limita reenvio de mensagens capturadas.
- O arquivo de configuração do daemon contém a senha do LDAP e o segredo dos
  agentes, e é gravado com permissão `0600` para o root.
- No DC, o segredo fica num arquivo com permissão restrita a SYSTEM e
  Administradores, e não na linha de comando da tarefa agendada.
- A API local fica num socket unix `0660`, alcançável só por quem já é root no
  firewall.
- A conta de serviço no AD precisa apenas de leitura de grupos.

O ponto fraco do modelo é a porta dos agentes: trate o segredo como uma
credencial e restrinja a porta aos IPs dos DCs.

---

## Licença

Apache License 2.0.

Escrito do zero. Não contém código, listas ou marcas de produtos de terceiros.
