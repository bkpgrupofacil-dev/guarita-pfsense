#!/bin/sh
# build.sh - monta o pacote distribuível do Guarita.
#
# Roda em qualquer máquina com Go instalado (Linux, macOS, FreeBSD). Produz:
#
#   dist/guarita-<versao>.tar.gz
#
# Esse tarball é o que você copia para o pfSense e descompacta. Dentro dele há
# um install.sh que monta e instala o .pkg de verdade, usando o pkg do próprio
# firewall — é por isso que o pacote aparece em System > Package Manager.
#
# Uso:
#   sh build/build.sh            # versão vem de VERSION
#   VERSION=0.2.0 sh build/build.sh

set -eu
# O pipefail nao e POSIX, mas precisamos que a falha do verificador pare o build.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=${VERSION:-$(cat VERSION 2>/dev/null || echo 0.1.0)}
PKGNAME="pfSense-pkg-Guarita"
STAGE="$ROOT/dist/stage"
OUT="$ROOT/dist"

echo "==> Guarita $VERSION"

# ---------------------------------------------------------------- limpeza
rm -rf "$STAGE"
mkdir -p "$STAGE" "$OUT"

# ------------------------------------------------------------ testes e vet
echo "==> go vet"
go vet ./...

echo "==> testes"
go test ./... >/dev/null
echo "    todos passaram"

echo "==> conferindo que os campos do config.xml sao ASCII"
if ! python3 build/check-config-ascii.py \
	pkg/pfsense/files/usr/local/pkg/guarita.xml \
	pkg/pfsense/files/usr/local/pkg/guaritagroups.xml \
	pkg/pfsense/files/usr/local/share/pfSense-pkg-Guarita/info.xml; then
	echo "build abortado: veja acima" >&2
	exit 1
fi

# -------------------------------------------------------- binário FreeBSD
echo "==> compilando guaritad para freebsd/amd64"
mkdir -p "$STAGE/usr/local/sbin"
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 \
	go build -trimpath \
		-ldflags "-s -w -X main.Version=$VERSION" \
		-o "$STAGE/usr/local/sbin/guaritad" \
		./cmd/guaritad
chmod 0755 "$STAGE/usr/local/sbin/guaritad"
echo "    $(ls -lh "$STAGE/usr/local/sbin/guaritad" | awk '{print $5}')"

# ---------------------------------------------------- arquivos do pacote
echo "==> copiando os arquivos do pacote"
# Estrutura do pfSense: /usr/local/pkg (XML e .inc), /usr/local/www (páginas),
# /etc/inc/priv (privilégios), /usr/local/share/<pkg> (info.xml e extras).
( cd "$ROOT/pkg/pfsense/files" && find . -type f -print | while read -r f; do
	dst="$STAGE/${f#./}"
	mkdir -p "$(dirname "$dst")"
	cp "$f" "$dst"
done )

# Grava a versão no info.xml e nos XMLs da interface.
for f in "$STAGE/usr/local/share/pfSense-pkg-Guarita/info.xml" \
         "$STAGE/usr/local/pkg/guarita.xml" \
         "$STAGE/usr/local/pkg/guaritagroups.xml"; do
	[ -f "$f" ] || continue
	sed -i.bak "s|%%PKGVERSION%%|$VERSION|g" "$f"
	rm -f "$f.bak"
done

# Agente do Windows, para download pela interface.
mkdir -p "$STAGE/usr/local/share/pfSense-pkg-Guarita/agent"
cp "$ROOT/agent/guarita-agent.ps1"  "$STAGE/usr/local/share/pfSense-pkg-Guarita/agent/"
cp "$ROOT/agent/install-agent.ps1"  "$STAGE/usr/local/share/pfSense-pkg-Guarita/agent/"

# Documentação.
mkdir -p "$STAGE/usr/local/share/pfSense-pkg-Guarita/docs"
for d in README.md docs/REGRAS.md docs/TESTES.md; do
	[ -f "$ROOT/$d" ] && cp "$ROOT/$d" "$STAGE/usr/local/share/pfSense-pkg-Guarita/docs/"
done

# Ajusta permissões: tudo legível, nada executável além do binário.
find "$STAGE" -type f -exec chmod 0644 {} \;
chmod 0755 "$STAGE/usr/local/sbin/guaritad"

# ------------------------------------------------------- lista de arquivos
echo "==> gerando a lista de arquivos (plist)"
# No formato de plist do FreeBSD, um caminho RELATIVO é resolvido a partir do
# prefix do pacote (/usr/local), e só um caminho ABSOLUTO vale como está. Então
# o que está sob stage/usr/local/ entra sem esse pedaço, e o resto entra com
# barra na frente. Os pacotes oficiais do pfSense fazem exatamente isso:
#
#     pkg/arping.xml                  -> /usr/local/pkg/arping.xml
#     /etc/inc/priv/arping.priv.inc   -> /etc/inc/priv/arping.priv.inc
#
# Listar "usr/local/pkg/guarita.xml" faria o pkg procurar o arquivo em
# /usr/local/usr/local/pkg/guarita.xml e a montagem do pacote falharia.
( cd "$STAGE" && find . -type f -print | sed 's|^\./||' | sort ) | while read -r f; do
	case "$f" in
		usr/local/*) echo "${f#usr/local/}" ;;
		*)           echo "/$f" ;;
	esac
done > "$OUT/plist"
NFILES=$(wc -l < "$OUT/plist" | tr -d ' ')
echo "    $NFILES arquivos"

# ------------------------------------------------------------- manifesto
echo "==> gerando o manifesto do pkg"
mkdir -p "$OUT/metadata"
cat > "$OUT/metadata/+MANIFEST" <<MANIFEST
name: $PKGNAME
version: "$VERSION"
origin: net/$PKGNAME
comment: "Controle de acesso a internet por usuario do Active Directory"
desc: <<EOD
Guarita identifica qual usuario do Active Directory esta atras de cada
endereco IP da rede e mantem uma tabela do firewall por grupo de usuarios.
Com isso as regras do pfSense passam a valer por usuario, e nao por IP.

Componentes:
  - guaritad: servico que recebe os eventos dos controladores de dominio,
    consulta os grupos no AD por LDAP e mantem as tabelas do pf
  - agente em PowerShell para os controladores de dominio, que le os eventos
    de autenticacao Kerberos do log de Seguranca
  - interface em Services > Guarita, com sessoes ativas, status e grupos

Este pacote nao e oficial nem homologado pela Netgate.
EOD
maintainer: admin@localhost
www: https://github.com/bkpgrupofacil-dev/guarita-pfsense
prefix: /usr/local
categories: [net]
licenselogic: single
licenses: [APACHE20]
MANIFEST

# Scripts do ciclo de vida. São eles que chamam o rc.packages do pfSense, que
# registra o menu, o serviço e a configuração em config.xml.
cat > "$OUT/metadata/+POST_INSTALL" <<'POSTINST'
#!/bin/sh
/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-Guarita POST-INSTALL
POSTINST

cat > "$OUT/metadata/+PRE_DEINSTALL" <<'PREDEINST'
#!/bin/sh
/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-Guarita DEINSTALL
PREDEINST

cat > "$OUT/metadata/+POST_DEINSTALL" <<'POSTDEINST'
#!/bin/sh
/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-Guarita POST-DEINSTALL
POSTDEINST

chmod 0755 "$OUT/metadata/"+*

# ------------------------------------------------------------- tarball
echo "==> montando o tarball"
TARDIR="$OUT/guarita-$VERSION"
rm -rf "$TARDIR"
mkdir -p "$TARDIR"

mv "$STAGE"            "$TARDIR/stage"
mv "$OUT/metadata"     "$TARDIR/metadata"
mv "$OUT/plist"        "$TARDIR/plist"
cp "$ROOT/build/install.sh" "$TARDIR/install.sh"
chmod 0755 "$TARDIR/install.sh"
echo "$VERSION" > "$TARDIR/VERSION"

[ -f "$ROOT/README.md" ] && cp "$ROOT/README.md" "$TARDIR/"

( cd "$OUT" && tar -czf "guarita-$VERSION.tar.gz" "guarita-$VERSION" )
rm -rf "$TARDIR"

echo ""
echo "Pronto: $OUT/guarita-$VERSION.tar.gz"
echo ""
echo "No pfSense:"
echo "  1) copie o arquivo para o firewall (scp, ou baixe com fetch)"
echo "  2) tar -xzf guarita-$VERSION.tar.gz"
echo "  3) cd guarita-$VERSION && sh install.sh"
echo ""
