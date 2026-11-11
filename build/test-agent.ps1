<#
    test-agent.ps1 - testes das funcoes do agente, sem executar o agente.

    Carrega as funcoes de agent/guarita-agent.ps1 pelo parser do PowerShell (o
    script em si tem parametros obrigatorios e um laco principal, entao nao da
    para so carrega-lo) e confere casos vistos no Windows Server 2008 R2 do
    laboratorio. O agente roda no PowerShell 2.0; este teste usa o parser do
    PowerShell 3.0+, entao roda em qualquer Windows atual ou no pwsh:

      powershell -NoProfile -ExecutionPolicy Bypass -File build\test-agent.ps1
      pwsh -NoProfile -File build/test-agent.ps1
#>
$ErrorActionPreference = 'Stop'
$root  = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$agent = Join-Path (Join-Path $root 'agent') 'guarita-agent.ps1'

$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($agent, [ref] $tokens, [ref] $errs)
if ($errs.Count -gt 0) { throw "erro de sintaxe no agente: $($errs[0].Message)" }
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

$script:fail = 0
$script:pass = 0
function Check([string] $name, $got, $want) {
    if ($got -ceq $want) { $script:pass++; Write-Host "  [ok] $name" }
    else { $script:fail++; Write-Host "  [FALHOU] $name : obtido '$got', esperado '$want'" -ForegroundColor Red }
}

Write-Host "== Get-StatusField"
# No 2008 R2, pelo Get-WinEvent, o Status do 4768 vem como numero: "0", nao "0x0".
Check 'sucesso em decimal (Get-WinEvent)'  (Get-StatusField @('a','b','c','d','e','f','0') 6)  '0x0'
Check 'falha em decimal (6 = usuario desconhecido)' (Get-StatusField @('a','b','c','d','e','f','6') 6) '0x6'
Check 'falha em decimal (24 = senha errada)' (Get-StatusField @('a','b','c','d','e','f','24') 6) '0x18'
Check 'sucesso em hexa (Get-EventLog)'     (Get-StatusField @('a','b','c','d','e','f','0x0') 6) '0x0'
Check 'hexa em maiusculas vira minusculas' (Get-StatusField @('a','b','c','d','e','f','0X1A') 6) '0x1a'
Check 'campo que nao e codigo'             (Get-StatusField @('a','b','c','d','e','f','-') 6) ''
Check 'indice alem do fim'                 (Get-StatusField @('a') 6) ''

Write-Host "== Get-Field nao atravessa a quebra de linha"
# Trecho da mensagem do 4624 de rede no 2008 R2 em portugues: o nome da estacao
# vem vazio e a linha seguinte e o endereco de origem.
$msg = "Informacoes de Rede:`r`n`tNome da Estacao de Trabalho:`t`r`n`tEndereco da rede de origem:`t192.168.1.100`r`n`tPorta de Origem:`t49700"
Check 'nome da estacao vazio fica vazio' (Get-Field @() 11 $msg 'Nome da Estacao de Trabalho|Workstation Name') ''
$msg2 = "`tNome da Estacao de Trabalho:`tDESKTOP-U4AD0AQ`r`n`tEndereco da rede de origem:`t192.168.1.100"
Check 'nome da estacao preenchido' (Get-Field @() 11 $msg2 'Nome da Estacao de Trabalho|Workstation Name') 'DESKTOP-U4AD0AQ'
$msg3 = "`tEndereco da Rede de Origem:`t`r`n`tPorta de Origem:`t49700"
Check 'endereco vazio nao pega a linha seguinte' (Get-IpField @() $msg3) ''

Write-Host "== Test-ShouldSend descarta falha de Kerberos"
$IgnoreAccounts = @('SYSTEM'); $IgnoreNetworks = @()
function Rec($status) {
    New-Object PSObject -Property @{ Type = 'logon'; User = 'leandro'; Ip = '192.168.1.100'; EventId = 4768;
        Success = $true; KerberosStatus = $status; LogonType = '' }
}
Check 'status 0x0 passa'  (Test-ShouldSend (Rec '0x0')) $true
Check 'status 0x6 barra'  (Test-ShouldSend (Rec (Get-StatusField @('a','b','c','d','e','f','6') 6))) $false
Check 'sem status passa (protecao principal e o filtro de auditoria)' (Test-ShouldSend (Rec '')) $true

Write-Host ""
Write-Host "passaram: $script:pass  falharam: $script:fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
