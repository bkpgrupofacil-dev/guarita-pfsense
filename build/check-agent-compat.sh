#!/bin/sh
# check-agent-compat.sh - reprova construcoes que quebram o agente no
# Windows Server 2008 R2 (PowerShell 2.0) ou num Windows que nao esta em ingles.
#
# Cada regra veio de uma falha vista no DC do laboratorio (2008 R2 SP1, pt-BR):
#   - $PSScriptRoot: vazio em scripts .ps1 no PowerShell 2.0;
#   - nomes de conta em ingles ('BUILTIN\Administrators', 'NT AUTHORITY\...'):
#     nao existem num Windows em portugues; use o SID;
#   - auditpol /subcategory:"Nome": o auditpol so aceita o nome no idioma do
#     Windows ("Erro 0x00000057"); use o GUID;
#   - cmdlets do PowerShell 3.0+ (ConvertTo-Json, Invoke-RestMethod...);
#   - & schtasks/auditpol direto: com $ErrorActionPreference = 'Stop', no PS 2.0
#     a saida de erro do programa derruba o script; use Invoke-Native;
#   - schtasks '/TR': no PS 2.0 as aspas do caminho com espaco chegam erradas
#     ao schtasks ("Argumento/opcao invalido"); crie a tarefa por /XML;
#   - bytes fora do ASCII: consoles antigos estragam os acentos.
# Linhas de comentario (comecando com #) sao ignoradas.
#
# Uso: sh build/check-agent-compat.sh agent/*.ps1

status=0
for f in "$@"; do
	# Numera as linhas e tira os comentarios: blocos <# ... #> e linhas "#".
	code=$(awk '
		/^[[:space:]]*<#/ { inblock = 1 }
		inblock { if (/#>/) inblock = 0; next }
		/^[[:space:]]*#/ { next }
		{ print NR ":" $0 }' "$f")
	bad=$(printf '%s\n' "$code" | grep -E \
		'\$PSScriptRoot|BUILTIN\\\\?[A-Za-z]|NT AUTHORITY|/subcategory:"([A-Za-z]|\$[A-Za-z])|(ConvertTo|ConvertFrom)-Json([^A-Za-z]|$)|Invoke-RestMethod|Invoke-WebRequest|\[ordered\]|[[:space:]]-(in|notin)[[:space:]]|&[[:space:]]*(schtasks|auditpol|icacls)|'"'"'/TR'"'"'')
	if [ -n "$bad" ]; then
		echo "$f: construcao incompativel com PowerShell 2.0 ou com Windows fora do ingles:" >&2
		echo "$bad" | sed 's/^/    linha /' >&2
		status=1
	fi
	if LC_ALL=C grep -n '[^[:print:][:space:]]' "$f" >/dev/null; then
		echo "$f: tem bytes fora do ASCII (acentos):" >&2
		LC_ALL=C grep -n '[^[:print:][:space:]]' "$f" | head -5 | sed 's/^/    linha /' >&2
		status=1
	fi
done
[ $status -eq 0 ] && echo "ok: $# script(s) do agente compativeis com PowerShell 2.0 e Windows em qualquer idioma"
exit $status
