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
    & schtasks.exe /Delete /TN $TaskName /F 2>&1 | Out-Null
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

$srcAgent = Join-Path $PSScriptRoot 'guarita-agent.ps1'
if (-not (Test-Path $srcAgent)) {
    Write-Err2 "guarita-agent.ps1 nao encontrado em $PSScriptRoot"
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
Set-Content -Path $secretPath -Value $Secret -Encoding UTF8 -Force

# Permissao: so SYSTEM e Administradores. Remove heranca.
try {
    $acl = Get-Acl $secretPath
    $acl.SetAccessRuleProtection($true, $false)   # desliga heranca, descarta herdadas
    foreach ($r in @($acl.Access)) { [void] $acl.RemoveAccessRule($r) }

    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow  = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($who, $rights, $allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $secretPath -AclObject $acl
    Write-Ok "permissao restrita a SYSTEM e Administradores"
} catch {
    Write-Warn2 "nao consegui ajustar a permissao do arquivo: $($_.Exception.Message)"
    Write-Warn2 "ajuste manualmente para que apenas SYSTEM e Administradores leiam $secretPath"
}

# --------------------------------------------------------- 3. auditoria

# O agente depende de o DC registrar os eventos de autenticacao Kerberos.
# Sem isso o log de Seguranca nao tera 4768/4769 e nada sera detectado.
Write-Step "verificando a auditoria de logon"

$auditSubcategories = @(
    'Kerberos Authentication Service',
    'Kerberos Service Ticket Operations',
    'Logon'
)

function Get-AuditState {
    param([string] $Subcategory)
    try {
        $out = & auditpol.exe /get /subcategory:"$Subcategory" 2>&1 | Out-String
        if ($out -match 'Success') {
            if ($out -match 'Success and Failure|Success') { return 'on' }
        }
        if ($out -match 'No Auditing|Nenhuma Auditoria') { return 'off' }
        return 'unknown'
    } catch {
        return 'unknown'
    }
}

$auditProblem = $false
foreach ($sub in $auditSubcategories) {
    $state = Get-AuditState -Subcategory $sub
    if ($state -eq 'on') {
        Write-Ok "auditoria ligada: $sub"
    } elseif ($state -eq 'off') {
        $auditProblem = $true
        if ($EnableAudit) {
            Write-Step "ligando a auditoria de: $sub"
            & auditpol.exe /set /subcategory:"$sub" /success:enable 2>&1 | Out-Null
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
& schtasks.exe /Delete /TN $TaskName /F 2>&1 | Out-Null

# O comando da tarefa roda um ciclo e sai (-Once). A repeticao fica a cargo do
# agendador, o que e mais robusto que um loop infinito: se um ciclo travar ou
# morrer, o proximo comeca limpo.
$cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"`"$agentPath`"`" " +
       "-Server $Server -Port $Port -SecretFile `"`"$secretPath`"`" -Once"

$create = @(
    '/Create',
    '/TN', $TaskName,
    '/TR', $cmd,
    '/SC', 'MINUTE',
    '/MO', [string] $IntervalMinutes,
    '/RU', 'SYSTEM',
    '/RL', 'HIGHEST',
    '/F'
)
& schtasks.exe @create 2>&1 | ForEach-Object { Write-Host "    $_" }

if ($LASTEXITCODE -ne 0) {
    Write-Err2 "falhou ao criar a tarefa agendada"
    exit 1
}
Write-Ok "tarefa criada"

Write-Step "executando a tarefa uma vez agora"
& schtasks.exe /Run /TN $TaskName 2>&1 | Out-Null
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
