<#
    install-agent.ps1 - Instala o agente Guarita num controlador de dominio

    O que faz:
      1. Copia o guarita-agent.ps1 para %ProgramFiles%\Guarita
      2. Grava o segredo num arquivo com permissao restrita (SYSTEM + Admins)
      3. Verifica (e opcionalmente liga) a auditoria de logon necessaria
      4. Cria uma tarefa agendada que roda como SYSTEM a cada N minutos
      5. Testa a conexao com o pfSense

    Rode num prompt do PowerShell como Administrador, no controlador de dominio.

    Exemplo:
      .\install-agent.ps1 -Server 10.10.20.5 -Secret "<segredo do pacote>"

    Para remover:
      .\install-agent.ps1 -Uninstall

    Compativel com PowerShell 2.0 (Windows Server 2008 R2) em diante. Em 2008/
    2008 R2 a tarefa e criada com schtasks.exe; em 2012 R2+ tambem, para manter
    um unico caminho de codigo testado.
#>

[CmdletBinding()]
param(
    [string] $Server,
    [int]    $Port = 8923,
    [string] $Secret,

    # Intervalo da tarefa agendada, em minutos. O minimo do schtasks e 1.
    [int] $IntervalMinutes = 1,

    # Diretorio de instalacao.
    [string] $InstallDir = "$env:ProgramFiles\Guarita",

    # Liga automaticamente as politicas de auditoria necessarias.
    [switch] $EnableAudit,

    # Remove a tarefa e os arquivos.
    [switch] $Uninstall,

    # Nao cria a tarefa; so instala os arquivos e testa.
    [switch] $NoTask
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Guarita Agent'

# Pasta deste script. $PSScriptRoot so existe em scripts a partir do
# PowerShell 3.0 (na 2.0 so em modulos .psm1): no Windows Server 2008 R2 ele
# vinha vazio e o instalador parava sem achar o guarita-agent.ps1.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Contas pelo SID, nunca pelo nome: os nomes mudam com o idioma do Windows. Num
# DC em portugues, 'BUILTIN\Administrators' nao existe (e
# 'BUILTIN\Administradores'), a traducao falhava e o arquivo do segredo ficava
# com a permissao herdada de Program Files, legivel por qualquer usuario.
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
$SidAdmins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'

# Qualquer erro inesperado sai com codigo 1. Sem isto, no PowerShell 2.0 um
# erro que interrompia o script saia com codigo 0, como se tivesse dado certo.
trap {
    Write-Host "[x] erro inesperado: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Roda um executavel externo e devolve a saida como texto; o codigo de saida
# fica em $LASTEXITCODE. Com $ErrorActionPreference = 'Stop', no PowerShell 2.0
# cada linha que o programa escreve na saida de erro vira um erro que DERRUBA o
# script: o "schtasks /Delete" de uma tarefa que ainda nao existe (o caso de
# toda primeira instalacao) interrompia o instalador antes de criar a tarefa.
function Invoke-Native {
    param([string] $Exe, [string[]] $Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | ForEach-Object { [string] $_ }
    } finally {
        $ErrorActionPreference = $old
    }
}

function Test-Admin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Step { param([string] $Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Msg) Write-Host "[ok] $Msg" -ForegroundColor Green }
function Write-Warn2 { param([string] $Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err2 { param([string] $Msg) Write-Host "[x] $Msg" -ForegroundColor Red }

if (-not (Test-Admin)) {
    Write-Err2 "rode este script como Administrador."
    exit 1
}

# ------------------------------------------------------------- desinstalacao

if ($Uninstall) {
    Write-Step "removendo a tarefa agendada"
    Invoke-Native schtasks.exe @("/Delete", "/TN", $TaskName, "/F") | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "tarefa removida" } else { Write-Warn2 "tarefa nao existia" }

    if (Test-Path $InstallDir) {
        Write-Step "removendo $InstallDir"
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Ok "arquivos removidos"
    }
    Write-Host ""
    Write-Host "O estado e os logs em $env:ProgramData\Guarita foram mantidos."
    Write-Host "Apague-os manualmente se nao forem mais necessarios."
    exit 0
}

# ------------------------------------------------------------- validacao

if (-not $Server) {
    Write-Err2 "informe -Server com o IP do pfSense (ex.: -Server 10.10.20.5)"
    exit 1
}
if (-not $Secret) {
    Write-Err2 "informe -Secret com o segredo mostrado na aba Agentes do pacote no pfSense"
    exit 1
}
if ($Secret.Length -lt 16) {
    Write-Err2 "o segredo precisa ter ao menos 16 caracteres"
    exit 1
}

$srcAgent = Join-Path $ScriptDir 'guarita-agent.ps1'
if (-not (Test-Path $srcAgent)) {
    Write-Err2 "guarita-agent.ps1 nao encontrado em $ScriptDir"
    exit 1
}

Write-Host ""
Write-Host "Instalando o agente Guarita" -ForegroundColor White
Write-Host "  servidor ....... $Server`:$Port"
Write-Host "  destino ........ $InstallDir"
Write-Host "  intervalo ...... $IntervalMinutes minuto(s)"
Write-Host "  PowerShell ..... $($PSVersionTable.PSVersion)"
Write-Host ""

# ------------------------------------------------------- 1. copia de arquivos

Write-Step "criando $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Copy-Item -Path $srcAgent -Destination $InstallDir -Force
Write-Ok "agente copiado"

# ------------------------------------------------- 2. segredo em arquivo ACL

$secretPath = Join-Path $InstallDir 'secret.txt'
Write-Step "gravando o segredo em $secretPath"

# Primeiro restringe a permissao de um arquivo VAZIO e so depois grava o
# segredo. Se a permissao falhar, o segredo nunca chega ao disco com a
# permissao herdada (antes, a falha virava so um aviso e o segredo ficava
# legivel por qualquer usuario).
try {
    Set-Content -Path $secretPath -Value '' -Encoding ASCII -Force
    $acl = Get-Acl $secretPath
    $acl.SetAccessRuleProtection($true, $false)   # desliga heranca, descarta herdadas
    foreach ($r in @($acl.Access)) { [void] $acl.RemoveAccessRule($r) }

    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow  = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($who in @($SidSystem, $SidAdmins)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($who, $rights, $allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $secretPath -AclObject $acl

    # Confere o resultado: nenhuma regra herdada e so os dois SIDs.
    $check = Get-Acl $secretPath
    foreach ($r in @($check.Access)) {
        $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($r.IsInherited -or ($sid -ne $SidSystem.Value -and $sid -ne $SidAdmins.Value)) {
            throw "permissao inesperada para $($r.IdentityReference)"
        }
    }
} catch {
    Remove-Item -Path $secretPath -Force -ErrorAction SilentlyContinue
    Write-Err2 "nao consegui restringir a permissao de $secretPath : $($_.Exception.Message)"
    Write-Err2 "o segredo NAO foi gravado. Instalacao interrompida."
    exit 1
}
Set-Content -Path $secretPath -Value $Secret -Encoding ASCII -Force
Write-Ok "permissao restrita a SYSTEM e Administradores"

# --------------------------------------------------------- 3. auditoria

# O agente depende de o DC registrar os eventos de autenticacao Kerberos.
# Sem isso o log de Seguranca nao tera 4768/4769 e nada sera detectado.
Write-Step "verificando a auditoria de logon"

# Subcategorias pelo GUID, nunca pelo nome: o auditpol so aceita o nome no
# idioma do Windows. Num DC em portugues, /subcategory:"Kerberos Authentication
# Service" da "Erro 0x00000057: Parametro incorreto", e a saida diz "Exito" e
# nao "Success". Por isso o estado vem da coluna numerica "Setting Value" do
# auditpol /backup (1 = sucesso, 2 = falha, 3 = ambos), que nao muda com o
# idioma.
$auditSubcategories = @(
    @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service' },
    @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Operations' },
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon' }
)

# Le o "Setting Value" de todas as subcategorias. Devolve GUID -> valor.
function Get-AuditSettings {
    $map = @{}
    $tmp = Join-Path $env:TEMP ('guarita-audit-{0}.csv' -f [guid]::NewGuid())
    try {
        Invoke-Native auditpol.exe @("/backup", "/file:$tmp") | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmp)) { return $map }
        foreach ($row in @(Import-Csv -Path $tmp)) {
            $g = [string] $row.'Subcategory GUID'
            $v = [string] $row.'Setting Value'
            if ($g -and $v -match '^\d+$') { $map[$g.ToUpper()] = [int] $v }
        }
    } catch {
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
    return $map
}

function Get-AuditState {
    param($Settings, [string] $Guid)
    if (-not $Settings.ContainsKey($Guid.ToUpper())) { return 'unknown' }
    if (($Settings[$Guid.ToUpper()] -band 1) -ne 0) { return 'on' }
    return 'off'
}

$auditSettings = Get-AuditSettings
$auditProblem = $false
foreach ($s in $auditSubcategories) {
    $sub = $s.Name
    $state = Get-AuditState -Settings $auditSettings -Guid $s.Guid
    if ($state -eq 'on') {
        Write-Ok "auditoria ligada: $sub"
    } elseif ($state -eq 'off') {
        $auditProblem = $true
        if ($EnableAudit) {
            Write-Step "ligando a auditoria de: $sub"
            Invoke-Native auditpol.exe @("/set", "/subcategory:$($s.Guid)", "/success:enable") | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "auditoria ligada: $sub"
                $auditProblem = $false
            } else {
                Write-Err2 "falhou ao ligar a auditoria de $sub"
            }
        } else {
            Write-Warn2 "auditoria DESLIGADA: $sub"
        }
    } else {
        Write-Warn2 "nao consegui determinar a auditoria de: $sub"
    }
}

if ($auditProblem -and -not $EnableAudit) {
    Write-Host ""
    Write-Warn2 "Sem a auditoria de logon o agente nao vera eventos."
    Write-Warn2 "Rode novamente com -EnableAudit, ou ligue pela GPO em:"
    Write-Warn2 "  Configuracao do Computador > Politicas > Configuracoes do Windows >"
    Write-Warn2 "  Configuracoes de Seguranca > Configuracao Avancada da Politica de Auditoria >"
    Write-Warn2 "  Logon/Logoff de Conta  ->  Servico de Autenticacao Kerberos (Sucesso)"
    Write-Warn2 "                         ->  Operacoes de Tickets de Servico Kerberos (Sucesso)"
    Write-Warn2 "  Logon/Logoff           ->  Logon (Sucesso)"
    Write-Host ""
    Write-Warn2 "Prefira a GPO: ela vale para todos os controladores de dominio."
}

# ----------------------------------------------------------- 4. teste

Write-Step "testando a conexao com o pfSense"
$agentPath = Join-Path $InstallDir 'guarita-agent.ps1'
$testArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$agentPath`"",
    '-Server', $Server, '-Port', $Port, '-SecretFile', "`"$secretPath`"", '-TestOnly'
)
$proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $testArgs `
            -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -eq 0) {
    Write-Ok "o pfSense respondeu corretamente"
} else {
    Write-Err2 "o teste de conexao falhou (codigo $($proc.ExitCode))"
    Write-Warn2 "veja o log em $env:ProgramData\Guarita\agent.log"
    Write-Warn2 "a instalacao continua; corrija a conexao e a tarefa passara a funcionar."
}

# ------------------------------------------------------ 5. tarefa agendada

if ($NoTask) {
    Write-Host ""
    Write-Ok "arquivos instalados; tarefa nao criada (-NoTask)."
    exit 0
}

Write-Step "criando a tarefa agendada '$TaskName'"

# Remove uma anterior, se houver.
Invoke-Native schtasks.exe @("/Delete", "/TN", $TaskName, "/F") | Out-Null

# O comando da tarefa roda um ciclo e sai (-Once). A repeticao fica a cargo do
# agendador, o que e mais robusto que um loop infinito: se um ciclo travar ou
# morrer, o proximo comeca limpo.
#
# A tarefa e criada por XML (schtasks /Create /XML), com o programa e os
# argumentos em campos separados. Pelo /TR, o caminho com espaco
# (C:\Program Files) exigia aspas dentro de aspas, e o PowerShell 2.0 as
# repassa de um jeito que o schtasks corta o argumento no espaco: "ERRO:
# Argumento/opcao invalido - 'Files\Guarita\guarita-agent.ps1'". No XML a
# conta tambem vai pelo SID (S-1-5-18), que nao muda com o idioma.
$esc = { param($s) [System.Security.SecurityElement]::Escape([string] $s) }
$taskArgs = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Server {1} -Port {2} -SecretFile "{3}" -Once' -f `
    $agentPath, $Server, $Port, $secretPath
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Guarita: envia ao pfSense os logons lidos neste controlador de dominio</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT$([int] $IntervalMinutes)M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2000-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$(& $esc $taskArgs)</Arguments>
    </Exec>
  </Actions>
</Task>
"@
$xmlPath = Join-Path $env:TEMP ('guarita-task-{0}.xml' -f [guid]::NewGuid())
# O schtasks exige o XML em UTF-16, como declarado no cabecalho.
[System.IO.File]::WriteAllText($xmlPath, $taskXml, [System.Text.Encoding]::Unicode)
try {
    Invoke-Native schtasks.exe @('/Create', '/TN', $TaskName, '/XML', $xmlPath, '/F') |
        ForEach-Object { Write-Host "    $_" }
} finally {
    Remove-Item -Path $xmlPath -Force -ErrorAction SilentlyContinue
}

if ($LASTEXITCODE -ne 0) {
    Write-Err2 "falhou ao criar a tarefa agendada"
    exit 1
}
Write-Ok "tarefa criada"

Write-Step "executando a tarefa uma vez agora"
Invoke-Native schtasks.exe @("/Run", "/TN", $TaskName) | Out-Null
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "Instalacao concluida." -ForegroundColor Green
Write-Host ""
Write-Host "Verificar:"
Write-Host "  log do agente ..... $env:ProgramData\Guarita\agent.log"
Write-Host "  estado ............ $env:ProgramData\Guarita\agent-state.xml"
Write-Host "  tarefa ............ schtasks /Query /TN `"$TaskName`" /V /FO LIST"
Write-Host ""
Write-Host "No pfSense, veja as sessoes em: Services > Guarita > Sessoes"
Write-Host ""
Write-Host "Rodar manualmente, mostrando o que seria enviado, sem enviar:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$agentPath`" ``"
Write-Host "    -Server $Server -SecretFile `"$secretPath`" -Once -DryRun"
Write-Host ""
