<#
    guarita-agent.ps1 - Agente Guarita para controladores de dominio

    Le os eventos de autenticacao do log de Seguranca do controlador de dominio
    e envia ao pfSense a associacao "usuario -> IP da estacao", para que o
    firewall aplique regras por usuario do Active Directory.

    Eventos usados:
      4768  Kerberos: TGT solicitado   -> logon (evento principal)
      4769  Kerberos: ticket de servico -> atividade (renova a sessao)
      4624  Logon bem-sucedido (tipo 3 e 10) -> logon (caminho NTLM)
      4634  Logoff                      -> logoff (melhor esforco)
      4647  Logoff iniciado pelo usuario -> logoff (melhor esforco)

    Compatibilidade: PowerShell 2.0 (Windows Server 2008 / 2008 R2) ate as
    versoes atuais (2012 R2, 2016, 2019, 2022, 2025). Por isso o script NAO usa
    ConvertTo-Json, Invoke-RestMethod nem operadores de versoes novas: monta o
    JSON e faz o HTTP com classes do .NET 2.0.

    Este arquivo nao tem acentos de proposito, para evitar problemas de
    codificacao em consoles antigos.

    Uso:
      .\guarita-agent.ps1 -Server 10.10.20.5 -Secret "<segredo>" -Once
      .\guarita-agent.ps1 -Server 10.10.20.5 -Secret "<segredo>"   (loop)
      .\guarita-agent.ps1 -Server 10.10.20.5 -Secret "<segredo>" -TestOnly
#>

[CmdletBinding()]
param(
    # Endereco (IP ou nome) do pfSense onde o guaritad escuta.
    [Parameter(Mandatory = $true)]
    [string] $Server,

    # Porta da API de agentes.
    [int] $Port = 8923,

    # Segredo compartilhado, igual ao configurado no pacote no pfSense.
    # Prefira -SecretFile: o segredo passado aqui fica visivel na linha de
    # comando do processo para quem for administrador da maquina.
    [string] $Secret,

    # Arquivo que contem apenas o segredo (primeira linha nao vazia). O
    # instalador cria este arquivo com permissao restrita a SYSTEM e
    # Administradores. Tem precedencia sobre -Secret.
    [string] $SecretFile,

    # Usa HTTPS. O guaritad escuta HTTP; deixe desligado salvo se houver um
    # proxy TLS na frente.
    [switch] $UseHttps,

    # Intervalo entre as leituras do log, em segundos (modo loop).
    [int] $IntervalSeconds = 20,

    # Quantos segundos de log reler na primeira execucao.
    [int] $BackfillSeconds = 300,

    # Maximo de eventos lidos por ciclo (protege o DC de picos).
    [int] $MaxEventsPerCycle = 2000,

    # Contas a ignorar (alem das contas de maquina, que terminam em $).
    [string[]] $IgnoreAccounts = @('ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SYSTEM', 'DWM-1', 'UMFD-0', 'UMFD-1'),

    # Redes de origem a ignorar (prefixos). Util para excluir a propria rede de
    # servidores, por exemplo.
    [string[]] $IgnoreNetworks = @(),

    # Arquivo de estado (guarda o ultimo evento lido).
    [string] $StateFile = "$env:ProgramData\Guarita\agent-state.xml",

    # Arquivo de log do agente.
    [string] $LogFile = "$env:ProgramData\Guarita\agent.log",

    # Executa um unico ciclo e sai (modo tarefa agendada).
    [switch] $Once,

    # Apenas testa a conectividade e a assinatura com o pfSense, e sai.
    [switch] $TestOnly,

    # Le e mostra os eventos, mas nao envia nada.
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

# PowerShell 1.0 nao tem Set-StrictMode nem [CmdletBinding()]; se o script
# chegou a executar, a versao e 2.0 ou maior. A checagem abaixo serve para dar
# uma mensagem clara em Windows Server 2008 sem o WMF instalado.
if ($PSVersionTable -eq $null -or $PSVersionTable.PSVersion.Major -lt 2) {
    Write-Error ("este agente precisa do PowerShell 2.0 ou superior. " +
                 "No Windows Server 2008, instale o Windows Management Framework 2.0.")
    exit 2
}
Set-StrictMode -Version 2.0

# Resolve o segredo: -SecretFile tem precedencia sobre -Secret.
if ($SecretFile) {
    if (-not (Test-Path $SecretFile)) {
        Write-Error "arquivo de segredo nao encontrado: $SecretFile"
        exit 2
    }
    $lines = @(Get-Content -Path $SecretFile | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -eq 0) {
        Write-Error "arquivo de segredo vazio: $SecretFile"
        exit 2
    }
    $Secret = $lines[0].Trim()
}
if (-not $Secret) {
    Write-Error "informe -Secret ou -SecretFile"
    exit 2
}
if ($Secret.Length -lt 16) {
    Write-Error "o segredo precisa ter ao menos 16 caracteres"
    exit 2
}

# ---------------------------------------------------------------- utilidades

function Write-GuaritaLog {
    param([string] $Message, [string] $Level = 'INFO')
    $line = ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message)
    Write-Host $line
    try {
        $dir = Split-Path -Parent $LogFile
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
        # Rotaciona em 5 MB.
        $fi = Get-Item $LogFile
        if ($fi.Length -gt 5MB) {
            $old = "$LogFile.1"
            if (Test-Path $old) { Remove-Item $old -Force }
            Move-Item $LogFile $old -Force
        }
    } catch {
        # Nunca deixa o log derrubar o agente.
    }
}

# Escapa uma string para JSON conforme RFC 8259. Feito a mao porque
# ConvertTo-Json so existe a partir do PowerShell 3.0.
function ConvertTo-JsonString {
    param([string] $Value)
    if ($null -eq $Value) { return '""' }
    # if/elseif em vez de switch: a semantica de switch com char/string e de
    # continue dentro de switch varia entre versoes do PowerShell, e este
    # codigo precisa rodar igual da 2.0 a 5.1 e no PowerShell 7.
    $sb = New-Object System.Text.StringBuilder
    [void] $sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int] $ch
        if     ($code -eq 34) { [void] $sb.Append('\"') }     # "
        elseif ($code -eq 92) { [void] $sb.Append('\\') }     # \
        elseif ($code -eq 8)  { [void] $sb.Append('\b') }
        elseif ($code -eq 12) { [void] $sb.Append('\f') }
        elseif ($code -eq 10) { [void] $sb.Append('\n') }
        elseif ($code -eq 13) { [void] $sb.Append('\r') }
        elseif ($code -eq 9)  { [void] $sb.Append('\t') }
        elseif ($code -lt 32 -or $code -gt 126) {
            [void] $sb.Append('\u')
            [void] $sb.Append($code.ToString('x4'))
        }
        else {
            [void] $sb.Append($ch)
        }
    }
    [void] $sb.Append('"')
    return $sb.ToString()
}

# Monta o corpo JSON do lote de eventos.
function Build-BatchJson {
    param([string] $AgentName, $Events)

    $sb = New-Object System.Text.StringBuilder
    [void] $sb.Append('{"agent":')
    [void] $sb.Append((ConvertTo-JsonString $AgentName))
    [void] $sb.Append(',"events":[')

    $first = $true
    foreach ($e in $Events) {
        if (-not $first) { [void] $sb.Append(',') }
        $first = $false
        [void] $sb.Append('{"type":')
        [void] $sb.Append((ConvertTo-JsonString $e.Type))
        [void] $sb.Append(',"user":')
        [void] $sb.Append((ConvertTo-JsonString $e.User))
        [void] $sb.Append(',"domain":')
        [void] $sb.Append((ConvertTo-JsonString $e.Domain))
        [void] $sb.Append(',"ip":')
        [void] $sb.Append((ConvertTo-JsonString $e.Ip))
        [void] $sb.Append(',"computer":')
        [void] $sb.Append((ConvertTo-JsonString $e.Computer))
        [void] $sb.Append(',"event_id":')
        [void] $sb.Append([string] [int] $e.EventId)
        [void] $sb.Append(',"time":')
        [void] $sb.Append((ConvertTo-JsonString ($e.Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))))
        [void] $sb.Append('}')
    }
    [void] $sb.Append(']}')
    return $sb.ToString()
}

# Assinatura HMAC-SHA256 de (timestamp + "\n" + corpo), em hexadecimal.
# Precisa casar exatamente com apiagent.Sign no lado do pfSense.
function Get-GuaritaSignature {
    param([string] $SecretKey, [long] $Timestamp, [byte[]] $BodyBytes)

    $enc = New-Object System.Text.UTF8Encoding $false
    $prefix = $enc.GetBytes(([string] $Timestamp) + "`n")

    $buf = New-Object byte[] ($prefix.Length + $BodyBytes.Length)
    [System.Array]::Copy($prefix, 0, $buf, 0, $prefix.Length)
    [System.Array]::Copy($BodyBytes, 0, $buf, $prefix.Length, $BodyBytes.Length)

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $enc.GetBytes($SecretKey)
        $hash = $hmac.ComputeHash($buf)
    } finally {
        # Dispose nao existe em HMACSHA256 no .NET 2.0; Clear existe.
        $hmac.Clear()
    }

    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $hash) { [void] $sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

# POST autenticado para o guaritad, usando HttpWebRequest (.NET 2.0).
function Send-ToGuarita {
    param([string] $Path, [string] $JsonBody)

    $scheme = 'http'
    if ($UseHttps) { $scheme = 'https' }
    $url = ('{0}://{1}:{2}{3}' -f $scheme, $Server, $Port, $Path)

    $enc = New-Object System.Text.UTF8Encoding $false
    $bodyBytes = $enc.GetBytes($JsonBody)
    $ts = [long] [Math]::Floor((Get-Date).ToUniversalTime().Subtract(
            (New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))).TotalSeconds)
    $sig = Get-GuaritaSignature -SecretKey $Secret -Timestamp $ts -BodyBytes $bodyBytes

    $req = [System.Net.WebRequest]::Create($url)
    $req.Method = 'POST'
    $req.ContentType = 'application/json; charset=utf-8'
    $req.ContentLength = $bodyBytes.Length
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000
    # Sem proxy: o DC fala direto com o firewall.
    $req.Proxy = $null
    $req.Headers.Add('X-Guarita-Agent', $env:COMPUTERNAME)
    $req.Headers.Add('X-Guarita-Timestamp', [string] $ts)
    $req.Headers.Add('X-Guarita-Signature', $sig)

    $stream = $req.GetRequestStream()
    try {
        $stream.Write($bodyBytes, 0, $bodyBytes.Length)
    } finally {
        $stream.Close()
    }

    $resp = $req.GetResponse()
    try {
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        try { return $sr.ReadToEnd() } finally { $sr.Close() }
    } finally {
        $resp.Close()
    }
}

# ------------------------------------------------------------------- estado

function Read-AgentState {
    $state = New-Object PSObject -Property @{
        LastRecordId = [long] 0
        LastTime     = (Get-Date).AddSeconds(-$BackfillSeconds)
    }
    try {
        if (Test-Path $StateFile) {
            $raw = Import-Clixml $StateFile
            if ($raw.LastRecordId) { $state.LastRecordId = [long] $raw.LastRecordId }
            if ($raw.LastTime)     { $state.LastTime     = [DateTime] $raw.LastTime }
        }
    } catch {
        Write-GuaritaLog ("estado ilegivel ({0}); recomecando com backfill de {1}s" -f $_.Exception.Message, $BackfillSeconds) 'WARN'
    }
    return $state
}

function Write-AgentState {
    param($State)
    try {
        $dir = Split-Path -Parent $StateFile
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $State | Export-Clixml -Path $StateFile -Force
    } catch {
        Write-GuaritaLog ("nao consegui gravar o estado: {0}" -f $_.Exception.Message) 'WARN'
    }
}

# -------------------------------------------------------- leitura de eventos

$script:HasGetWinEvent = $null

function Test-GetWinEvent {
    if ($null -ne $script:HasGetWinEvent) { return $script:HasGetWinEvent }
    $script:HasGetWinEvent = $false
    try {
        if (Get-Command Get-WinEvent -ErrorAction SilentlyContinue) {
            # Em alguns 2008 o cmdlet existe mas o provider falha; testamos de fato.
            Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null
            $script:HasGetWinEvent = $true
        }
    } catch {
        $script:HasGetWinEvent = $false
    }
    return $script:HasGetWinEvent
}

# Le os eventos de interesse desde o ultimo lido.
function Get-SecurityEvents {
    param($State)

    $ids = @(4624, 4634, 4647, 4768, 4769)
    $since = $State.LastTime.AddSeconds(-2)   # pequena sobreposicao
    $results = @()

    if (Test-GetWinEvent) {
        # Caminho rapido: filtro XPath no proprio log de eventos.
        $idClause = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
        $msSince = [long] ([DateTime]::UtcNow - $since.ToUniversalTime()).TotalMilliseconds
        if ($msSince -lt 0) { $msSince = 1000 }
        # Somente auditoria de SUCESSO. O bit 0x0020000000000000
        # (9007199254740992) do campo Keywords marca "Audit Success"; "Audit
        # Failure" e 0x0010000000000000. Sem este filtro, num dominio que
        # audita tambem as falhas, um pedido de ticket que FALHOU viraria uma
        # sessao: qualquer maquina pode pedir um ticket Kerberos em nome de
        # outro usuario, e o agente associaria esse usuario ao IP de quem
        # tentou, que herdaria a politica de acesso dele.
        $xpath = "*[System[($idClause) and band(Keywords,9007199254740992) and TimeCreated[timediff(@SystemTime) <= $msSince]]]"
        try {
            $results = @(Get-WinEvent -LogName Security -FilterXPath $xpath `
                          -MaxEvents $MaxEventsPerCycle -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -match 'No events were found|Nenhum evento') {
                return @()
            }
            throw
        }
    } else {
        # Caminho de compatibilidade para PowerShell 2.0 sem Get-WinEvent util.
        # Mesmo criterio do filtro XPath acima: so auditoria de sucesso.
        $results = @(Get-EventLog -LogName Security -After $since -ErrorAction Stop |
                     Where-Object { ($ids -contains $_.EventID) -and ($_.EntryType -eq 'SuccessAudit') } |
                     Select-Object -First $MaxEventsPerCycle)
    }
    return $results
}

# Extrai os campos relevantes de um evento, lidando com as duas formas
# (Get-WinEvent e Get-EventLog).
function Convert-EventToRecord {
    param($Ev)

    $isWinEvent = $null -ne (Get-Member -InputObject $Ev -Name 'Id' -MemberType Properties -ErrorAction SilentlyContinue)

    # Sucesso ou falha de auditoria, conferido de novo aqui alem do filtro da
    # leitura (defesa em profundidade: ver o comentario do filtro XPath).
    $success = $true
    if ($isWinEvent) {
        $id       = [int] $Ev.Id
        $when     = $Ev.TimeCreated
        $recordId = [long] $Ev.RecordId
        $props    = @()
        try { $props = @($Ev.Properties | ForEach-Object { [string] $_.Value }) } catch { $props = @() }
        $message  = ''
        try { $message = [string] $Ev.Message } catch { $message = '' }
        try {
            $kw = $Ev.Keywords
            # 0x8020000000000000 cabe num Int64 negativo; o -band funciona igual.
            if ($null -ne $kw) { $success = (([long] $kw) -band ([long] 9007199254740992)) -ne 0 }
        } catch { $success = $true }
    } else {
        $id       = [int] $Ev.EventID
        $when     = $Ev.TimeGenerated
        $recordId = [long] $Ev.Index
        $props    = @()
        try { $props = @($Ev.ReplacementStrings) } catch { $props = @() }
        $message  = ''
        try { $message = [string] $Ev.Message } catch { $message = '' }
        try { $success = ([string] $Ev.EntryType) -eq 'SuccessAudit' } catch { $success = $true }
    }

    $user     = ''
    $domain   = ''
    $ip       = ''
    $computer = ''
    $type     = ''
    $logonType = ''
    $kstatus  = ''

    switch ($id) {
        4768 {
            # 4768: TargetUserName(0), TargetDomainName(1), ..., Status(6), ..., IpAddress(9)
            $user    = Get-Field $props 0 $message 'Nome da Conta|Account Name'
            $domain  = Get-Field $props 1 $message 'Dominio da Conta|Dom.nio da Conta|Account Domain'
            $ip      = Get-IpField $props $message
            $kstatus = Get-StatusField $props 6
            $type    = 'logon'
        }
        4769 {
            # 4769: TargetUserName(0) (user@DOMINIO), TargetDomainName(1), ServiceName(2),
            #       ..., IpAddress(6), IpPort(7), Status(8)
            $user    = Get-Field $props 0 $message 'Nome da Conta|Account Name'
            $domain  = Get-Field $props 1 $message 'Dominio da Conta|Dom.nio da Conta|Account Domain'
            $ip      = Get-IpField $props $message
            $kstatus = Get-StatusField $props 8
            $type    = 'activity'
        }
        4624 {
            # 4624: ..., TargetUserName(5), TargetDomainName(6), ..., LogonType(8),
            #       WorkstationName(11), IpAddress(18)
            $user      = Get-Field $props 5 $message 'Nome da Conta|Account Name'
            $domain    = Get-Field $props 6 $message 'Dominio da Conta|Dom.nio da Conta|Account Domain'
            $logonType = Get-Field $props 8 $message 'Tipo de Logon|Logon Type'
            $computer  = Get-Field $props 11 $message 'Nome da Estacao de Trabalho|Nome da Esta..o de Trabalho|Workstation Name'
            $ip        = Get-IpField $props $message
            $type      = 'logon'
        }
        4634 {
            $user   = Get-Field $props 1 $message 'Nome da Conta|Account Name'
            $domain = Get-Field $props 2 $message 'Dominio da Conta|Dom.nio da Conta|Account Domain'
            $type   = 'logoff'
        }
        4647 {
            $user   = Get-Field $props 1 $message 'Nome da Conta|Account Name'
            $domain = Get-Field $props 2 $message 'Dominio da Conta|Dom.nio da Conta|Account Domain'
            $type   = 'logoff'
        }
    }

    return New-Object PSObject -Property @{
        EventId        = $id
        RecordId       = $recordId
        Time           = $when
        Type           = $type
        User           = $user
        Domain         = $domain
        Ip             = $ip
        Computer       = $computer
        LogonType      = $logonType
        Success        = $success
        KerberosStatus = $kstatus
    }
}

# Le o codigo de resultado do Kerberos (0x0 = sucesso). So confia no valor se
# ele tiver cara de codigo (0x...): se nesta versao do Windows o layout do
# evento for outro, o indice pode cair em outro campo, e ai a checagem e
# ignorada em vez de descartar eventos validos. A protecao principal contra
# eventos de falha e o filtro de auditoria de sucesso; esta e uma segunda.
function Get-StatusField {
    param($Props, [int] $Index)
    if ($null -eq $Props -or $Props.Count -le $Index) { return '' }
    $v = ([string] $Props[$Index]).Trim()
    if ($v -match '^0x[0-9a-fA-F]+$') { return $v.ToLower() }
    return ''
}

# Pega um campo pelo indice nas propriedades; se nao der, tenta achar pelo
# texto da mensagem (robusto para servidores em portugues ou ingles).
function Get-Field {
    param($Props, [int] $Index, [string] $Message, [string] $LabelPattern)

    if ($null -ne $Props -and $Props.Count -gt $Index) {
        $v = [string] $Props[$Index]
        if ($v -and $v -ne '-') { return $v.Trim() }
    }
    if ($Message -and $LabelPattern) {
        $m = [regex]::Match($Message, "(?im)^\s*(?:$LabelPattern)\s*:\s*(.+?)\s*$")
        if ($m.Success) {
            $v = $m.Groups[1].Value.Trim()
            if ($v -and $v -ne '-') { return $v }
        }
    }
    return ''
}

# Procura um endereco IP: primeiro nas propriedades (qualquer uma que pareca
# um IP), depois na mensagem.
function Get-IpField {
    param($Props, [string] $Message)

    if ($null -ne $Props) {
        foreach ($p in $Props) {
            $v = [string] $p
            if (-not $v) { continue }
            $v = $v.Trim()
            if ($v -eq '-' -or $v -eq '::1' -or $v -eq '127.0.0.1') { continue }
            if ($v.StartsWith('::ffff:')) { $v = $v.Substring(7) }
            if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { return $v }
            # IPv6 simples (tem ':' e caracteres validos)
            if ($v -match '^[0-9a-fA-F:]+$' -and $v.Contains(':') -and $v.Length -ge 3) { return $v }
        }
    }
    if ($Message) {
        $m = [regex]::Match($Message, '(?im)^\s*(?:Endere.o de Rede de Origem|Endere.o do Cliente|Source Network Address|Client Address)\s*:\s*(\S+)\s*$')
        if ($m.Success) {
            $v = $m.Groups[1].Value.Trim()
            if ($v.StartsWith('::ffff:')) { $v = $v.Substring(7) }
            if ($v -ne '-' -and $v -ne '::1' -and $v -ne '127.0.0.1') { return $v }
        }
    }
    return ''
}

# Decide se um registro deve ser enviado.
function Test-ShouldSend {
    param($Rec)

    if (-not $Rec.Type) { return $false }
    if (-not $Rec.User) { return $false }

    # So autenticacao bem-sucedida. Ver o comentario do filtro XPath em
    # Get-SecurityEvents: um evento de falha nao pode virar sessao.
    if (-not $Rec.Success) { return $false }
    if ($Rec.KerberosStatus -and ($Rec.KerberosStatus -ne '0x0')) { return $false }

    $u = $Rec.User.Trim()
    # Contas de maquina.
    if ($u.EndsWith('$')) { return $false }
    # Contas de servico/sistema.
    foreach ($ign in $IgnoreAccounts) {
        if ($u -eq $ign -or $u -ieq $ign) { return $false }
    }
    # UPN do Kerberos vem como "usuario@DOMINIO"; o servidor normaliza, mas
    # descartamos aqui o que claramente nao e conta de pessoa.
    if ($u -like '*$@*') { return $false }
    if ($u -like 'krbtgt*') { return $false }

    # Logoff nao traz IP: o servidor casa por usuario, entao deixamos passar
    # apenas quando houver IP, para nao derrubar sessao errada.
    if ($Rec.Type -eq 'logoff') { return $false }

    if (-not $Rec.Ip) { return $false }

    # Em 4624 so interessam logons de rede (3) e RDP (10); os outros sao
    # logons locais no proprio DC.
    if ($Rec.EventId -eq 4624) {
        if ($Rec.LogonType -ne '3' -and $Rec.LogonType -ne '10') { return $false }
    }

    foreach ($net in $IgnoreNetworks) {
        if ($net -and $Rec.Ip.StartsWith($net)) { return $false }
    }
    return $true
}

# ------------------------------------------------------------------- ciclo

function Invoke-Cycle {
    param($State)

    $events = @()
    try {
        $events = @(Get-SecurityEvents -State $State)
    } catch {
        Write-GuaritaLog ("falha ao ler o log de Seguranca: {0}" -f $_.Exception.Message) 'ERRO'
        return $State
    }

    if ($events.Count -eq 0) {
        return $State
    }

    $maxRecord = $State.LastRecordId
    $maxTime   = $State.LastTime
    $toSend    = @()

    foreach ($ev in $events) {
        $rec = $null
        try {
            $rec = Convert-EventToRecord -Ev $ev
        } catch {
            continue
        }
        if ($rec.Time -gt $maxTime)        { $maxTime = $rec.Time }
        if ($rec.RecordId -gt $maxRecord)  { $maxRecord = $rec.RecordId }

        # Evita reenviar o que ja foi processado (a janela tem sobreposicao).
        if ($State.LastRecordId -gt 0 -and $rec.RecordId -le $State.LastRecordId) { continue }
        if (-not (Test-ShouldSend -Rec $rec)) { continue }

        $toSend += $rec
    }

    # Deduplica por (tipo, usuario, ip): uma rajada de 4769 do mesmo usuario
    # vira um unico evento por ciclo.
    $seen = @{}
    $unique = @()
    foreach ($r in $toSend) {
        $key = ('{0}|{1}|{2}' -f $r.Type, $r.User.ToLower(), $r.Ip)
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $unique += $r
    }

    if ($unique.Count -gt 0) {
        if ($DryRun) {
            Write-GuaritaLog ("[dry-run] {0} evento(s) seriam enviados:" -f $unique.Count)
            foreach ($r in $unique) {
                Write-GuaritaLog ("  {0} {1} {2} (id {3})" -f $r.Type, $r.User, $r.Ip, $r.EventId)
            }
        } else {
            $json = Build-BatchJson -AgentName $env:COMPUTERNAME -Events $unique
            try {
                $resp = Send-ToGuarita -Path '/v1/events' -JsonBody $json
                Write-GuaritaLog ("{0} evento(s) enviados; resposta: {1}" -f $unique.Count, $resp)
            } catch {
                # Nao avanca o estado em caso de falha de envio: o proximo ciclo
                # tenta de novo os mesmos eventos.
                Write-GuaritaLog ("falha ao enviar: {0}" -f (Get-ErrorDetail $_)) 'ERRO'
                return $State
            }
        }
    }

    $State.LastRecordId = $maxRecord
    $State.LastTime     = $maxTime
    Write-AgentState -State $State
    return $State
}

function Get-ErrorDetail {
    param($ErrorRecord)
    $msg = $ErrorRecord.Exception.Message
    try {
        $we = $ErrorRecord.Exception -as [System.Net.WebException]
        if ($we -and $we.Response) {
            $sr = New-Object System.IO.StreamReader($we.Response.GetResponseStream())
            try {
                $body = $sr.ReadToEnd()
                if ($body) { $msg = ('{0} - {1}' -f $msg, $body.Trim()) }
            } finally { $sr.Close() }
        }
    } catch { }
    return $msg
}

function Invoke-ConnectivityTest {
    Write-GuaritaLog ("testando conexao com {0}:{1}" -f $Server, $Port)
    try {
        $resp = Send-ToGuarita -Path '/v1/ping' -JsonBody '{}'
        Write-GuaritaLog ("ok, o pfSense respondeu: {0}" -f $resp)
        return $true
    } catch {
        Write-GuaritaLog ("falha no teste: {0}" -f (Get-ErrorDetail $_)) 'ERRO'
        Write-GuaritaLog "verifique: 1) o servico Guarita esta rodando no pfSense;" 'ERRO'
        Write-GuaritaLog "           2) existe regra de firewall liberando este DC na porta $Port;" 'ERRO'
        Write-GuaritaLog "           3) o segredo e o mesmo configurado no pacote;" 'ERRO'
        Write-GuaritaLog "           4) a hora deste servidor e do firewall estao sincronizadas." 'ERRO'
        return $false
    }
}

# -------------------------------------------------------------------- main

Write-GuaritaLog ("agente Guarita iniciando em {0} (PowerShell {1})" -f $env:COMPUTERNAME, $PSVersionTable.PSVersion)

if ($TestOnly) {
    if (Invoke-ConnectivityTest) { exit 0 } else { exit 1 }
}

if (-not (Test-GetWinEvent)) {
    Write-GuaritaLog "Get-WinEvent indisponivel; usando Get-EventLog (mais lento)" 'WARN'
}

$state = Read-AgentState
Write-GuaritaLog ("estado inicial: ultimo registro {0}, desde {1:yyyy-MM-dd HH:mm:ss}" -f $state.LastRecordId, $state.LastTime)

if ($Once) {
    $state = Invoke-Cycle -State $state
    exit 0
}

# Modo loop (servico). Sai limpo em Ctrl+C / parada do servico.
while ($true) {
    try {
        $state = Invoke-Cycle -State $state
    } catch {
        Write-GuaritaLog ("erro no ciclo: {0}" -f $_.Exception.Message) 'ERRO'
    }
    Start-Sleep -Seconds $IntervalSeconds
}
