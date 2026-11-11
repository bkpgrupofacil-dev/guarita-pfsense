#!/bin/sh
# check-page-globals.sh - impede que as paginas do pacote sobrescrevam as
# variaveis globais do pfSense.
#
# As paginas em /usr/local/www rodam no escopo GLOBAL do PHP. Nele, $g e o
# array de configuracao do sistema (lido por g_get()) e $config e a
# configuracao. Usar um desses nomes como variavel de laco ("foreach (...) as
# $g") ou atribuir a eles troca o global: no pfSense 2.9.0, o rodape
# (foot.inc -> print_credit() -> g_get()) quebrava com
#   "array_key_exists(): Argument #2 ($array) must be of type array, string given"
# na aba Sessoes, e o pfSense registrava um relatorio de falha.
#
# Uso: sh build/check-page-globals.sh <pagina.php>...

status=0
for f in "$@"; do
	hits=$(grep -nE 'as[[:space:]]+\$(g|config)\b|(^|[^$[:alnum:]_>])\$(g|config)[[:space:]]*(\[[^]]*\])?[[:space:]]*=[^=>]' "$f")
	if [ -n "$hits" ]; then
		echo "$f: sobrescreve uma global do pfSense (\$g ou \$config):" >&2
		echo "$hits" | sed 's/^/    /' >&2
		status=1
	fi
done
[ $status -eq 0 ] && echo "ok: $# pagina(s) sem sobrescrever \$g ou \$config"
exit $status
