# Testes reais no laboratório

Plano para a sessão que vai testar o Guarita num laboratório de verdade:
pfSense 2.9.0, um controlador de domínio Windows e uma estação no domínio.
Escrito para uma sessão do Claude Code rodando na máquina do usuário, mas serve
igualmente para uma pessoa.

Leia tudo antes de começar. A seção [Armadilhas conhecidas](#armadilhas-conhecidas)
vem de horas de testes anteriores e evita retrabalho.

---

## Regras

- **Nunca acesse nem altere o firewall de produção (`10.10.20.5`).** Tudo aqui é
  no laboratório. Se precisar de algo da produção, peça ao usuário.
- **Nunca grave segredos** — o segredo dos agentes, a senha da conta de serviço
  do LDAP, senhas de usuários — em commit, arquivo de resultado, issue ou log
  colado no chat. Oculte antes de registrar.
- Trabalhe numa branch nova (por exemplo `teste-lab-2-9`) e abra um pull request
  no fim, para o usuário revisar.
- Para cada defeito encontrado: corrija, **adicione um teste que trave o
  defeito** (teste Go, caso no `build/integration-test.sh` ou verificação no
  `build/verify-on-pfsense.sh`) e explique no commit **por que** o defeito
  acontecia. É o padrão do histórico deste repositório.
- Registre cada passo em `docs/RESULTADOS-LAB.md` (modelo no fim deste arquivo).

---

## O que já foi testado, e o que nunca rodou

| Componente | Situação |
|---|---|
| Serviço `guaritad` (Go) | 51 testes unitários + 33 verificações de integração (Linux, `pfctl` falso) |
| Pacote no pfSense **2.7.2** | Instalado e verificado numa VM: 33/33 em `build/verify-on-pfsense.sh` |
| Pacote no pfSense **2.8 / 2.9** | **Nunca rodou.** Só comparação do código-fonte das 20 funções do pfSense usadas |
| Agente PowerShell | **Nunca rodou.** Formato do JSON e assinatura HMAC conferidos contra o serviço por um equivalente em Python (`build/ps_mimic.py`), mas o script em si nunca foi executado |
| LDAP contra um AD real | **Nunca rodou.** Só a interpretação de DNs e o cache têm testes |
| Logon real de usuário até a regra do firewall | **Nunca rodou** |

Os quatro itens "nunca rodou" são o objetivo deste laboratório. O agente
PowerShell é o mais arriscado: espere encontrar defeitos nele.

### Defeitos já encontrados e corrigidos (para não reintroduzir)

1. Alias do tipo `urltable` com caminho local não gera tabela no pf. Os aliases
   são `host` com lista vazia, que viram `table <nome> persist`.
2. Cada recarga de filtro esvazia essas tabelas. O daemon observa
   `/tmp/rules.debug` e repõe.
3. `lookup_ca()` mudou de formato entre 2.7 e 2.8 (`guarita_lookup_ca_cert()`).
4. Caminhos do plist eram relativos ao `/usr/local` e saíam duplicados.
5. Acentos em campos que vão para o `config.xml` corrompiam o arquivo no
   2.7.x. Verificado no build por `build/check-config-ascii.py`.
6. O `<facilityname>` do `info.xml` é filtro de **programa** do syslog, não
   facility. Tem de ser `guaritad`.
7. O agente aceitava eventos de **falha** de autenticação como logon. Corrigido
   por último e **sem execução**: é o primeiro teste da fase C6 abaixo.

---

## Passo 0: levantar o ambiente

Antes de qualquer teste, descubra e anote em `docs/RESULTADOS-LAB.md`:

- hipervisor e rede das VMs (as VMs do domínio precisam ter o pfSense como
  gateway e como DNS);
- IP da LAN do pfSense de teste e a versão exata (`cat /etc/version`);
- sistema de arquivos do pfSense (ZFS ou UFS: **Diagnostics > ZFS**);
- versão do Windows Server do DC e do PowerShell (`$PSVersionTable.PSVersion`);
- nome do domínio;
- estação cliente: versão do Windows e se está no domínio;
- usuários de teste e em quais grupos do AD estão. São necessários pelo menos
  dois usuários em grupos diferentes, por exemplo `GG_Liberado` e
  `GG_Restrito`, e um terceiro num grupo **aninhado** (grupo dentro de grupo);
- como você alcança cada VM.

### Acesso ao pfSense

Habilite o SSH no pfSense de teste (opção **14** do console, ou **System >
Advanced > Admin Access > Secure Shell**). Comando mandado por SSH roda em
`/bin/sh`:

```bash
ssh admin@<IP-do-pfSense> 'cat /etc/version'
```

Para copiar arquivos: `scp` para `/tmp`, ou **Diagnostics > Command Prompt >
Upload File** na interface web, que também grava em `/tmp`.

### Acesso ao DC e à estação

O ideal é OpenSSH Server no DC (Windows Server 2019 e 2022:
`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`). Sem isso,
peça ao usuário para executar os comandos e colar a saída. Logons na estação
são feitos pelo usuário, na tela da VM.

---

## Armadilhas conhecidas

- **O shell interativo do root no pfSense é `tcsh`** (opção 8 do console).
  Nele `cmd > arq 2>&1` dá "Ambiguous output redirect"; o equivalente é
  `cmd >& arq`. Prefira `ssh admin@IP 'comando'` (roda em `sh`) ou ponha os
  comandos num script e rode com `sh script.sh`.
- **Console serial do pfSense:** não navegue os menus com setas. O `ESC` da
  seta é lido como "cancelar" e aborta o instalador. Use as letras de atalho
  (maiúsculas, aparecem sublinhadas).
- **`verify-on-pfsense.sh`** habilita o Guarita, faz o serviço escutar em
  `127.0.0.1` e troca os grupos por um grupo de teste. Ao terminar ele
  **restaura** o que havia antes. Se for interrompido de um jeito que não
  restaure (por exemplo, a VM desligada no meio), confira **Services > Guarita**
  antes de seguir: o agente do DC não alcança um serviço em `127.0.0.1`.
- **Atualizar o pfSense ou restaurar um backup remove o Guarita**, porque ele
  não está no repositório da Netgate. Configurações e grupos sobrevivem; rode o
  `install.sh` de novo.
- **Relógio:** o serviço recusa mensagens com mais de 5 minutos de diferença.
  Confira NTP no pfSense e no DC (`w32tm /query /status`).
- **Grupos do AD:** só escopo Global ou Universal aparecem com segurança.
- **Auditoria:** sem "Serviço de Autenticação Kerberos" e "Operações de Tickets
  de Serviço Kerberos" auditando sucesso, o DC nem grava os eventos que o agente
  lê.
- **Desligamento abrupto:** numa VM em UFS, um desligamento sem shutdown apagou
  o `config.xml` e todos os backups. Use ZFS no pfSense de teste e desligue as
  VMs pelo sistema.

---

## Plano de teste

Siga a ordem. Cada fase depende da anterior.

### Fase A — o pacote no pfSense 2.9.0

**A1. Instalar.** Gere o tarball com `sh build/build.sh` (precisa de Go 1.24+
e Python 3) ou use o `guarita-0.1.1.tar.gz` que o usuário tem. Descarte
qualquer tarball `0.1.0`: houve dois builds diferentes com esse número e o
primeiro não instala.

```bash
scp dist/guarita-0.1.1.tar.gz admin@<IP>:/tmp/
```

```bash
ssh admin@<IP> 'cd /tmp && tar -xzf guarita-0.1.1.tar.gz && cd guarita-0.1.1 && sh install.sh'
```

Esperado: termina com "Guarita 0.1.1 instalado" e o pacote aparece em
**System > Package Manager > Installed Packages**. Confira também que **não**
apareceu `/cf/conf/config.xml.bad` (sinal de `config.xml` corrompido).

**A2. Verificação mecânica.** Primeira execução real no 2.9.0:

```bash
ssh admin@<IP> 'sh /tmp/guarita-0.1.1/verify-on-pfsense.sh'
```

Esperado: `passaram: 33  falharam: 0`, seguido de "configurações e grupos de
antes do teste restaurados". **Qualquer falha aqui é a prioridade número um.**

O A2 é também o primeiro teste real da **restauração** que o script faz no fim
(ela só foi conferida na sintaxe). Por isso ele roda antes de existir qualquer
grupo real. Depois dele, confira que **Services > Guarita** voltou ao estado de
antes do teste (desabilitado, sem o grupo `teste`, sem o alias
`guarita_teste`). Se a restauração falhar, corrija antes de seguir: as fases
seguintes podem precisar rodar o script de novo com grupos reais configurados.

**A3. Telas.** Abra **Services > Guarita** e cada aba (Configurações, Grupos,
Sessões, Status, Agentes). Nenhuma pode mostrar erro de PHP. Erros de PHP do
pfSense ficam em `/tmp/PHP_errors.log`.

### Fase B — LDAP contra o AD real

**B1.** Em **System > User Manager > Authentication Servers**, cadastre o AD
como LDAP com uma conta de serviço comum. Use **Select a container** para
confirmar a conexão.

**B2.** Em **Services > Guarita > Configurações**: Habilitar, escolher o
servidor LDAP, **Endereço de escuta = IP da LAN do pfSense** (ou vazio) e
salvar.

**B3.** Em **Grupos**, crie pelo menos `liberado` (grupo do AD `GG_Liberado`,
prioridade 0) e `restrito` (`GG_Restrito`, prioridade 10). Use acentos no nome
amigável de um deles: no 2.9.0 isso tem de funcionar.

**B4.** Em **Status > Testar um usuário**, consulte cada usuário de teste.
Esperado: os grupos do AD aparecem e mapeiam para o grupo certo do Guarita.

**B5.** Consulte o usuário do grupo aninhado com **Seguir grupos aninhados**
ligado e depois desligado. Ligado, ele deve herdar o grupo de fora.

### Fase C — o agente no DC (o mais arriscado)

**C1.** Anote a versão do Windows e do PowerShell.

**C2.** Garanta que o DC alcança o pfSense na porta 8923. Se o DC estiver na
LAN, a regra padrão "LAN to any" já cobre.

**C3.** Teste de conexão, sem instalar nada:

```powershell
.\guarita-agent.ps1 -Server <IP-do-pfSense> -Secret "<segredo>" -TestOnly
```

Esperado: "ok, o pfSense respondeu". Em **Services > Guarita > Agentes**, o DC
aparece.

**C4.** Instalação:

```powershell
.\install-agent.ps1 -Server <IP-do-pfSense> -Secret "<segredo>" -EnableAudit
```

Confira a tarefa (`schtasks /Query /TN "Guarita Agent" /V /FO LIST`) e as
permissões de `C:\Program Files\Guarita\secret.txt` (só SYSTEM e
Administradores).

**C5.** Faça um logon na estação e rode, no DC:

```powershell
& "C:\Program Files\Guarita\guarita-agent.ps1" -Server <IP> -SecretFile "C:\Program Files\Guarita\secret.txt" -Once -DryRun
```

Esperado: linhas `logon <usuario> <IP-da-estacao> (id 4768)`. Contas de
máquina (terminadas em `$`) não podem aparecer.

**C6. Eventos de falha não viram sessão.** Este é o teste da correção nº 7,
nunca executada:

1. Ligue também a auditoria de **falha**:
   `auditpol /set /subcategory:"Kerberos Authentication Service" /failure:enable`
2. Na estação, provoque um 4768 de falha com um usuário que não existe:
   `runas /user:<DOMINIO>\naoexiste cmd` (digite qualquer senha).
3. No Visualizador de Eventos do DC, confirme que surgiu um 4768 de **falha**.
4. Rode o `-DryRun` do C5: o usuário `naoexiste` **não** pode aparecer.
5. Em **Services > Guarita > Sessões**, ele também não pode aparecer.

Se aparecer, o agente está deixando passar falhas: um computador poderia
assumir a política de outro usuário. É um defeito de segurança; corrija antes
de seguir.

**C7. PowerShell 2.0.** O DC de produção é **Windows Server 2008**, que roda
PowerShell 2.0. Esse caminho do código nunca rodou e é o que mais importa.
Num Windows Server 2016 a 2022 dá para testar o motor 2.0:

```powershell
Install-WindowsFeature NET-Framework-Core, PowerShell-V2
```

```powershell
powershell.exe -Version 2 -ExecutionPolicy Bypass -File .\guarita-agent.ps1 -Server <IP> -Secret "<segredo>" -TestOnly
```

Confirme que o log do agente mostra "PowerShell 2.0". Repita o C5 e o C6 com
`-Version 2`. O `NET-Framework-Core` pode pedir a mídia de instalação
(`-Source D:\sources\sxs`). No Windows Server 2025 o motor 2.0 foi removido;
nesse caso, registre que o C7 não pôde ser feito.

### Fase D — ponta a ponta

**D1.** Logon na estação com o usuário **restrito**. Em até ~2 minutos (a
tarefa roda a cada minuto) a sessão aparece em **Sessões** com o grupo
`restrito`, e o IP da estação aparece em **Diagnostics > Tables** em
`guarita_restrito`.

**D2.** Crie uma regra de teste no topo da LAN: **Block**, origem
`guarita_restrito`, destino um site específico, com log ligado. Na estação, o
site deve ser bloqueado, e a regra aparece em **Status > System Logs >
Firewall**.

**D3. Teste cruzado — é este que prova o conceito.** Na **mesma estação**, faça
logoff e logon com o usuário **liberado**. O mesmo site agora deve abrir. O
comportamento tem de mudar pelo **usuário**, não pela máquina.

Apague a regra de teste ao terminar.

### Fase E — resiliência

**E1.** Reinicie o pfSense pelo sistema. Depois do boot, as sessões continuam
lá e as tabelas são repostas sozinhas.

**E2.** Salve qualquer configuração no pfSense (isso recarrega o filtro). Em
poucos segundos a tabela é reposta, e o log mostra "o filtro do pfSense foi
recarregado; repondo as tabelas":

```bash
ssh admin@<IP> 'tail -20 /var/log/guarita.log'
```

**E3.** Mude o usuário de grupo no AD. Em até 30 minutos (ou na hora, com
**Reaplicar tabelas**), a sessão passa para o novo grupo, sem logoff.

**E4.** Desabilite a tarefa do agente no DC. As sessões expiram depois da
duração configurada (para testar rápido, baixe para 2 minutos e volte depois).

**E5.** Gere um segredo novo na aba **Agentes**. O agente passa a ser recusado
(contador de recusados sobe) até ser reconfigurado com o novo valor.

---

## Comandos úteis

| Para | Comando |
|---|---|
| Log do serviço | `ssh admin@<IP> 'tail -50 /var/log/guarita.log'` |
| Membros de um grupo no pf | `ssh admin@<IP> 'pfctl -t guarita_<grupo> -T show'` |
| Tabela declarada no ruleset | `ssh admin@<IP> 'grep guarita /tmp/rules.debug'` |
| Erros de PHP | `ssh admin@<IP> 'cat /tmp/PHP_errors.log'` |
| Log do agente | `Get-Content C:\ProgramData\Guarita\agent.log -Tail 50` |
| Estado do agente | `C:\ProgramData\Guarita\agent-state.xml` |

A configuração gerada para o daemon (`/usr/local/pkg/guarita/guarita.json`) tem
a senha do LDAP e o segredo dos agentes. Para olhar sem expor:

```bash
ssh admin@<IP> "sed 's/\"bind_pw\".*/\"bind_pw\": \"oculto\",/; s/\"agent_secret\".*/\"agent_secret\": \"oculto\",/' /usr/local/pkg/guarita/guarita.json"
```

---

## Modelo para `docs/RESULTADOS-LAB.md`

```markdown
# Resultados do laboratório

## Ambiente
- Data:
- pfSense: versão / ZFS ou UFS / IP da LAN
- DC: Windows Server ____ / PowerShell ____ / domínio
- Estação: Windows ____
- Usuários de teste e grupos:

## Resultados
| Passo | Resultado | Observação |
|---|---|---|
| A1 instalar | ok / falhou | |
| A2 verify 33/33 | | |
| ... | | |

## Defeitos encontrados
### 1. <título>
- Sintoma:
- Causa:
- Correção (commit):
- Teste que trava:
```
