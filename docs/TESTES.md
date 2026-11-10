# Roteiro de teste

Siga nesta ordem. Cada passo depende do anterior ter funcionado, e o roteiro é
feito para isolar onde está o problema quando algo não funciona.

Faça isso primeiro num pfSense de laboratório (uma VM basta), não em produção.

---

## Antes de começar

Tenha à mão:

- um pfSense de teste, com acesso ao shell (SSH ou console);
- um controlador de domínio de teste, ou um DC de produção onde você possa
  ligar auditoria e instalar uma tarefa agendada;
- uma estação no domínio, para fazer logon de verdade;
- uma conta de usuário no AD que esteja num grupo conhecido.

---

## 1. O serviço sobe

No shell do pfSense:

```bash
/usr/local/sbin/guaritad -version
```

Deve imprimir a versão. Se der "Exec format error", o binário não é da
arquitetura da máquina (o pacote é amd64).

```bash
/usr/local/sbin/guaritad -config /usr/local/pkg/guarita/guarita.json -test
```

Deve dizer que a configuração é válida e quantos grupos existem. Se reclamar do
`agent_secret`, salve as Configurações na interface primeiro.

Em **Status > Services**, o serviço `guaritad` deve estar rodando. Se não:

```bash
tail -50 /var/log/guarita.log
```

**Resultado esperado:** serviço rodando, sem erro no log.

---

## 2. O LDAP responde

Em **Services > Guarita > Status**, no painel *Testar um usuário no Active
Directory*, digite o `sAMAccountName` de um usuário (ex.: `joao.silva`) e
clique em Consultar.

**Resultado esperado:** a lista de grupos do AD daquele usuário aparece em
*Grupos no AD*.

Se der erro:

| Erro | Causa provável |
|------|----------------|
| `usuário não encontrado no AD` | O `sAMAccountName` está errado, ou a Base DN não cobre o usuário |
| `ldap bind` | Usuário ou senha da conta de serviço errados |
| `connection refused` / timeout | Porta errada, firewall entre o pfSense e o DC, ou host errado |
| `certificate` | Modo TLS errado, ou falta a CA do AD cadastrada no pfSense |

Confira os dados em **System > User Manager > Authentication Servers** e use o
botão *Select a container* lá: ele testa a conexão de forma independente.

Se os grupos aparecem em *Grupos no AD* mas *Grupos do Guarita* está vazio, os
nomes cadastrados em **Grupos** não casam com o que o AD devolve. Copie os
nomes exatamente como aparecem no teste.

---

## 3. O agente alcança o firewall

No controlador de domínio, como Administrador:

```powershell
.\install-agent.ps1 -Server <IP do pfSense> -Secret "<segredo>" -EnableAudit
```

O instalador testa a conexão ao final.

Para testar isoladamente, sem instalar nada:

```powershell
.\guarita-agent.ps1 -Server <IP do pfSense> -Secret "<segredo>" -TestOnly
```

**Resultado esperado:** "ok, o pfSense respondeu". E, em **Services > Guarita >
Agentes**, o nome do DC aparece com o último contato.

Se falhar:

| Sintoma | O que verificar |
|---------|-----------------|
| timeout / "não foi possível conectar" | Regra de firewall liberando o DC na porta 8923 |
| 401 "assinatura inválida" | O segredo não é o mesmo da aba Agentes |
| 401 "timestamp fora da janela" | Relógio do DC e do firewall diferem em mais de 5 minutos |

Para o relógio, configure NTP nos dois. No DC: `w32tm /query /status`.

---

## 4. O agente lê os eventos

Ainda no DC, veja o que ele está lendo sem enviar nada:

```powershell
.\guarita-agent.ps1 -Server <IP> -SecretFile "C:\Program Files\Guarita\secret.txt" -Once -DryRun
```

**Resultado esperado:** linhas como `logon joao 10.10.20.50 (id 4768)`.

Se não aparecer nada, a auditoria está desligada. Confira:

```powershell
auditpol /get /subcategory:"Kerberos Authentication Service"
```

Deve dizer `Success` (ou `Success and Failure`). Para ligar:

```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
```

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
```

Com vários DCs, ligue por GPO:
*Configuração do Computador > Políticas > Configurações do Windows >
Configurações de Segurança > Configuração Avançada da Política de Auditoria >
Logon/Logoff de Conta*.

Depois de ligar, faça um logon novo numa estação e rode o `-DryRun` de novo: a
auditoria só vale para eventos a partir de agora.

---

## 5. A sessão aparece

Numa estação do domínio, faça logoff e logon com o usuário de teste.

Em **Services > Guarita > Sessões**, dentro de ~1 minuto (o intervalo da tarefa
agendada):

**Resultado esperado:** uma linha com o usuário, o IP da estação e o grupo
esperado.

| Sintoma | Causa |
|---------|-------|
| Nada aparece | Volte ao passo 4; veja `C:\ProgramData\Guarita\agent.log` |
| Aparece sem grupo | Passo 2: os nomes de grupo não casam |
| IP errado | A estação está atrás de NAT, ou o logon foi via VPN/RDP de outro lugar |

Confira também em **Status** que o contador *Eventos recebidos* subiu e que
*recusados* está em zero.

---

## 6. A tabela do firewall é preenchida

No shell do pfSense:

```bash
cat /var/db/guarita/tables/<nome curto do grupo>.txt
```

**Resultado esperado:** o IP da estação.

```bash
pfctl -t guarita_<nome curto> -T show
```

**Resultado esperado:** a tabela existe e lista o IP, mesmo que você ainda não
tenha criado nenhuma regra usando o alias. O alias é criado com a lista vazia, e
nesse caso o pfSense declara a tabela como `persist`, então ela existe desde o
começo.

Se der `table does not exist`, algo falhou: confira se o alias
`guarita_<grupo>` aparece em **Firewall > Aliases** e salve as Configurações do
Guarita de novo, para forçar uma recarga do filtro.

Em **Services > Guarita > Status**, as colunas *IPs (serviço)* e *IPs (pf)*
devem bater.

---

## 7. A regra pega

Crie uma regra de teste bem visível. Em **Firewall > Rules > LAN**, no topo:

| Campo | Valor |
|-------|-------|
| Action | Block |
| Source | `guarita_<seu grupo de teste>` |
| Destination | um site específico, ex. `example.com` |
| Log | marcado |
| Description | TESTE Guarita |

Na estação, tente acessar aquele site.

**Resultado esperado:** o acesso é bloqueado, e a regra aparece em
**Status > System Logs > Firewall**.

Depois faça o teste cruzado, que é o que realmente prova o conceito: faça
logon na **mesma estação** com um usuário de **outro** grupo e tente de novo.
O acesso deve passar. Se o comportamento mudar conforme o usuário, e não
conforme a máquina, o Guarita está funcionando.

> Entre os dois testes, a sessão antiga pode levar alguns segundos para ser
> substituída. Para forçar, encerre a sessão do IP na aba **Sessões**.

Apague a regra de teste quando terminar.

---

## 8. Expiração e persistência

**Expiração:** baixe a duração da sessão para 2 minutos nas Configurações,
desligue a estação e espere. A sessão deve desaparecer da lista e o IP sair da
tabela. Volte o valor depois.

**Persistência:** reinicie o firewall. Depois do boot, as sessões que ainda
estavam no prazo devem reaparecer, e as tabelas devem ser reescritas
automaticamente. Isso evita que todos perdam a política de acesso durante os
minutos seguintes a um reboot.

**Recarga:** mude algo nas Configurações e salve. As sessões ativas devem
continuar lá — o serviço recarrega sem reiniciar.

---

## 9. Mudança de grupo no AD

Mova o usuário de teste para outro grupo no AD. Em até o intervalo configurado
em *Reconsultar grupos* (padrão 30 minutos), a sessão deve passar para o novo
grupo, sem o usuário fazer logoff.

Para não esperar, clique em **Reaplicar tabelas** na aba Sessões: isso limpa o
cache de grupos e reconsulta.

---

## Checklist final

- [ ] Serviço rodando em Status > Services
- [ ] Teste de LDAP devolve os grupos de um usuário
- [ ] Cada DC aparece na aba Agentes com contato recente
- [ ] Eventos recusados em zero
- [ ] Sessão aparece após logon, com o grupo correto
- [ ] Colunas IPs (serviço) e IPs (pf) batem
- [ ] Regra por grupo pega, e o teste cruzado com outro usuário na mesma
      máquina se comporta de forma diferente
- [ ] Sessões sobrevivem a um reboot
- [ ] Mudança de grupo no AD passa a valer sem logoff

---

## Reunindo informação para investigar

```bash
tail -100 /var/log/guarita.log
```

```bash
cat /usr/local/pkg/guarita/guarita.json | sed 's/"bind_pw".*/"bind_pw": "oculto",/; s/"agent_secret".*/"agent_secret": "oculto",/'
```

No DC:

```powershell
Get-Content C:\ProgramData\Guarita\agent.log -Tail 50
```

```powershell
schtasks /Query /TN "Guarita Agent" /V /FO LIST
```

> O `guarita.json` contém a senha do LDAP e o segredo dos agentes. O comando
> acima já oculta os dois; não publique o arquivo cru em lugar nenhum.
