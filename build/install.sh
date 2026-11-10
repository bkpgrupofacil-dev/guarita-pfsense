#!/bin/sh
# install.sh - instala o pacote Guarita no pfSense.
#
# Roda NO FIREWALL. Monta um pacote .pkg de verdade com o pkg do próprio
# sistema e o instala, de modo que o Guarita apareça em
# System > Package Manager > Installed Packages e possa ser removido de lá.
#
# Uso (como root, no shell do pfSense):
#   sh install.sh
#
# Para apenas gerar o .pkg sem instalar:
#   sh install.sh --build-only
#
# Para remover:
#   pkg delete -y pfSense-pkg-Guarita

set -eu

PKGNAME="pfSense-pkg-Guarita"
HERE=$(cd "$(dirname "$0")" && pwd)
VERSION=$(cat "$HERE/VERSION" 2>/dev/null || echo 0.1.0)
BUILD_ONLY=0

for arg in "$@"; do
	case "$arg" in
		--build-only) BUILD_ONLY=1 ;;
		-h|--help)
			echo "uso: sh install.sh [--build-only]"
			exit 0
			;;
		*)
			echo "argumento desconhecido: $arg" >&2
			exit 2
			;;
	esac
done

say()  { echo "[*] $*"; }
ok()   { echo "[ok] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

# ------------------------------------------------------------- verificações

[ "$(id -u)" = "0" ] || die "rode como root."

if [ ! -f /etc/version ]; then
	die "este script precisa rodar no pfSense (não encontrei /etc/version)."
fi
PFVER=$(cat /etc/version)
say "pfSense $PFVER"

case "$PFVER" in
	2.7*|2.8*|2.9*|3.*)
		;;
	*)
		warn "versão $PFVER não testada; o pacote foi feito para 2.7.x e 2.8.x."
		warn "continuando em 10 segundos (Ctrl+C para abortar)..."
		sleep 10
		;;
esac

command -v pkg >/dev/null 2>&1 || die "o comando pkg não foi encontrado."

for d in stage metadata; do
	[ -d "$HERE/$d" ] || die "diretório $d não encontrado; o tarball está incompleto."
done
[ -f "$HERE/plist" ] || die "arquivo plist não encontrado."

# Confere que o binário é do FreeBSD e roda nesta máquina.
BIN="$HERE/stage/usr/local/sbin/guaritad"
[ -f "$BIN" ] || die "binário guaritad não encontrado no tarball."
chmod 0755 "$BIN"
if ! "$BIN" -version >/dev/null 2>&1; then
	die "o binário guaritad não executou nesta máquina. Confira a arquitetura: $(uname -m) (o pacote é amd64)."
fi
ok "binário testado: $("$BIN" -version)"

# ------------------------------------------------------------ monta o .pkg

OUTDIR="$HERE/out"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

say "montando o pacote com o pkg do sistema"
# O ABI vem do próprio pkg desta máquina, então o pacote nasce com o ABI certo.
if ! pkg create \
		-m "$HERE/metadata" \
		-p "$HERE/plist" \
		-r "$HERE/stage" \
		-o "$OUTDIR" 2>"$OUTDIR/pkg-create.log"; then
	warn "saída do pkg create:"
	cat "$OUTDIR/pkg-create.log" >&2
	die "falha ao montar o pacote."
fi

PKGFILE=$(ls "$OUTDIR"/${PKGNAME}-*.pkg "$OUTDIR"/${PKGNAME}-*.txz 2>/dev/null | head -1 || true)
[ -n "$PKGFILE" ] || die "o pkg create não produziu nenhum arquivo em $OUTDIR."
ok "pacote gerado: $(basename "$PKGFILE") ($(ls -lh "$PKGFILE" | awk '{print $5}'))"

if [ "$BUILD_ONLY" = "1" ]; then
	echo ""
	echo "Pacote em: $PKGFILE"
	echo "Para instalar:  pkg add -f $PKGFILE"
	exit 0
fi

# ------------------------------------------------------------ instalação

# Se já havia uma versão instalada, o pkg add -f substitui. Antes disso,
# paramos o serviço para não deixar processo órfão com binário antigo.
if pkg info -e "$PKGNAME" 2>/dev/null; then
	INSTALLED=$(pkg query %v "$PKGNAME" 2>/dev/null || echo "?")
	say "versão $INSTALLED já instalada; atualizando para $VERSION"
	if [ -f /usr/local/etc/rc.d/guaritad.sh ]; then
		/usr/local/etc/rc.d/guaritad.sh stop >/dev/null 2>&1 || true
	fi
fi

say "instalando"
if ! pkg add -f "$PKGFILE"; then
	die "falha na instalação."
fi
ok "pacote instalado"

# O +POST_INSTALL já chamou o rc.packages, que registra o menu, o serviço e a
# configuração inicial em config.xml. Conferimos se deu certo.
say "verificando o registro no pfSense"
if ! pkg info -e "$PKGNAME"; then
	die "o pacote não aparece no banco do pkg."
fi

if [ ! -f /usr/local/pkg/guarita.xml ]; then
	die "guarita.xml não foi instalado em /usr/local/pkg."
fi
ok "arquivos no lugar"

# Checa se o menu entrou no config.xml.
if /usr/local/bin/php -r '
	require_once("config.inc");
	$found = false;
	foreach (config_get_path("installedpackages/menu", []) as $m) {
		if ($m["name"] === "Guarita") { $found = true; break; }
	}
	exit($found ? 0 : 1);
' 2>/dev/null; then
	ok "menu registrado em Services > Guarita"
else
	warn "o menu não apareceu no config.xml."
	warn "rode manualmente: /usr/local/bin/php -f /etc/rc.packages $PKGNAME POST-INSTALL"
fi

echo ""
echo "=============================================================="
echo " Guarita $VERSION instalado"
echo "=============================================================="
echo ""
echo "Próximos passos, na interface web do pfSense:"
echo ""
echo " 1. System > User Manager > Authentication Servers"
echo "    Cadastre o seu Active Directory como servidor LDAP, se ainda não"
echo "    cadastrou. Use uma conta de serviço do domínio, sem privilégios"
echo "    especiais: ela só precisa ler os grupos. Clique em \"Select a"
echo "    container\" para confirmar que a conexão funciona."
echo ""
echo " 2. Services > Guarita > Configurações"
echo "    Marque \"Habilitar\", escolha o servidor LDAP e salve."
echo "    Anote o segredo dos agentes (ou veja na aba Agentes)."
echo ""
echo " 3. Services > Guarita > Grupos"
echo "    Cadastre um grupo por política de acesso, informando os nomes"
echo "    dos grupos do AD correspondentes."
echo "    Cada grupo cria um alias chamado guarita_<nome curto>."
echo ""
echo " 4. Services > Guarita > Agentes"
echo "    Baixe os dois arquivos .ps1, copie para os controladores de"
echo "    domínio e rode o instalador como Administrador."
echo "    Crie também a regra de firewall liberando os DCs na porta do"
echo "    Guarita."
echo ""
echo " 5. Firewall > Rules"
echo "    Use os aliases guarita_<grupo> como ORIGEM das suas regras."
echo "    Veja exemplos em:"
echo "    /usr/local/share/pfSense-pkg-Guarita/docs/REGRAS.md"
echo ""
echo "Conferir: Services > Guarita > Status"
echo "Logs:     Status > System Logs > Guarita"
echo ""
echo "Para remover: pkg delete -y $PKGNAME"
echo ""
