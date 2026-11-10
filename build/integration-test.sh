#!/bin/bash
# integration-test.sh - teste ponta a ponta do guaritad.
#
# Sobe o daemon de verdade com um pfctl falso, manda eventos assinados como se
# fossem de um controlador de domínio e confere que:
#
#   - a assinatura HMAC é aceita (e a errada, recusada)
#   - a sessão usuário<->IP é criada
#   - o arquivo da tabela do grupo recebe o IP
#   - o pfctl é chamado com o nome certo da tabela
#   - a API local devolve o status e as sessões
#   - encerrar a sessão remove o IP da tabela
#   - o estado sobrevive a um reinício do serviço
#
# Roda em Linux (o daemon é compilado para o host). Não precisa de pfSense nem
# de Active Directory: o caminho sem LDAP exercita o grupo padrão.
#
# Uso: bash build/integration-test.sh

set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PASS=0
FAIL=0

cleanup() {
	if [ -n "${DAEMON_PID:-}" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
		kill -TERM "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { echo "  [ok] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FALHOU] $*"; FAIL=$((FAIL+1)); }
info() { echo "==> $*"; }

check() {
	# check <descrição> <esperado> <obtido>
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1 (esperado '$2', obtido '$3')"
	fi
}

# ------------------------------------------------------------------ preparo

info "compilando o daemon para o host"
cd "$ROOT"
if ! go build -o "$WORK/guaritad" ./cmd/guaritad; then
	echo "falha ao compilar" >&2
	exit 1
fi

SECRET="segredo-de-integracao-bem-longo-123"
PORT=18923

mkdir -p "$WORK/tables" "$WORK/db" "$WORK/bin"

# pfctl falso: registra cada chamada num log e copia o arquivo recebido.
cat > "$WORK/bin/pfctl" <<'FAKE'
#!/bin/bash
# Imita "pfctl -t <tabela> -T replace -f <arquivo>"
LOG="${PFCTL_LOG:?}"
table=""; action=""; file=""
while [ $# -gt 0 ]; do
	case "$1" in
		-t) table="$2"; shift 2 ;;
		-T) action="$2"; shift 2 ;;
		-f) file="$2";  shift 2 ;;
		*)  shift ;;
	esac
done
n=0
[ -f "$file" ] && n=$(grep -c . "$file" 2>/dev/null || echo 0)
echo "$action $table $n" >> "$LOG"
exit 0
FAKE
chmod +x "$WORK/bin/pfctl"
export PFCTL_LOG="$WORK/pfctl.log"
: > "$PFCTL_LOG"

cat > "$WORK/guarita.json" <<JSON
{
  "listen_agent": "127.0.0.1:$PORT",
  "listen_local": "$WORK/guarita.sock",
  "agent_secret": "$SECRET",
  "session_ttl": "1h",
  "group_refresh": "30m",
  "state_path": "$WORK/db/sessions.json",
  "table_dir": "$WORK/tables",
  "default_group": "padrao",
  "debug": true,
  "ldap": { "host": "" },
  "groups": [
    {"name": "Padrao",   "table": "padrao",   "ad_groups": ["GG_Padrao"],  "priority": 100},
    {"name": "Restrito", "table": "restrito", "ad_groups": ["GG_Restrito"], "priority": 0}
  ]
}
JSON

# Cliente assinador: monta o corpo e assina igual ao agente do Windows.
cat > "$WORK/send.py" <<'PY'
import hashlib, hmac, json, sys, urllib.request, time

secret, port, path, body = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
bad = len(sys.argv) > 5 and sys.argv[5] == 'bad'
ts = int(time.time())
key = (secret + ('x' if bad else '')).encode()
sig = hmac.new(key, ('%d\n' % ts).encode() + body.encode(), hashlib.sha256).hexdigest()
req = urllib.request.Request(
    'http://127.0.0.1:%s%s' % (port, path),
    data=body.encode(),
    headers={'Content-Type': 'application/json',
             'X-Guarita-Agent': 'DC-TESTE',
             'X-Guarita-Timestamp': str(ts),
             'X-Guarita-Signature': sig})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print(r.status)
        print(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code)
    print(e.read().decode())
PY

# Cliente da API local (socket unix).
cat > "$WORK/local.py" <<'PY'
import http.client, socket, sys, json

class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost')
        self.path_ = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self.path_)
        self.sock = s

c = UnixConn(sys.argv[1])
c.request('GET', sys.argv[2])
r = c.getresponse()
print(r.read().decode())
PY

# --------------------------------------------------------------- subir o daemon

info "subindo o guaritad"
"$WORK/guaritad" -config "$WORK/guarita.json" \
	-pfctl "$WORK/bin/pfctl" \
	-pid "$WORK/guaritad.pid" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do
	[ -S "$WORK/guarita.sock" ] && break
	sleep 0.1
done
if [ ! -S "$WORK/guarita.sock" ]; then
	echo "o daemon não subiu. Log:" >&2
	cat "$WORK/daemon.log" >&2
	exit 1
fi
ok "daemon no ar"

# ---------------------------------------------------------------- testes

info "1. autenticação dos agentes"

OUT=$(python3 -I "$WORK/send.py" "$SECRET" "$PORT" /v1/ping '{}')
check "ping com assinatura válida" "200" "$(echo "$OUT" | head -1)"

OUT=$(python3 -I "$WORK/send.py" "$SECRET" "$PORT" /v1/ping '{}' bad)
check "ping com assinatura inválida é recusado" "401" "$(echo "$OUT" | head -1)"

info "2. evento de logon cria sessão e popula a tabela"

BODY='{"agent":"DC-TESTE","events":[{"type":"logon","user":"joao","domain":"EMPRESA","ip":"10.10.20.50","computer":"PC-JOAO","event_id":4768}]}'
OUT=$(python3 -I "$WORK/send.py" "$SECRET" "$PORT" /v1/events "$BODY")
check "evento aceito" "200" "$(echo "$OUT" | head -1)"

# Sem LDAP configurado, o daemon cai no grupo padrão. Espera o debounce (750ms).
sleep 2

if [ -f "$WORK/tables/padrao.txt" ]; then
	ok "arquivo da tabela do grupo padrão foi criado"
else
	bad "arquivo $WORK/tables/padrao.txt não existe"
fi
check "IP está na tabela do grupo padrão" "10.10.20.50" "$(cat "$WORK/tables/padrao.txt" 2>/dev/null)"

if grep -q "replace guarita_padrao 1" "$PFCTL_LOG"; then
	ok "pfctl chamado com a tabela guarita_padrao e 1 entrada"
else
	bad "pfctl não foi chamado como esperado. Log: $(cat "$PFCTL_LOG" | tr '\n' ';')"
fi

# O grupo sem membros também precisa de arquivo, senão o alias do pfSense quebra.
if [ -f "$WORK/tables/restrito.txt" ] && [ ! -s "$WORK/tables/restrito.txt" ]; then
	ok "grupo sem membros tem arquivo vazio (alias não quebra)"
else
	bad "grupo sem membros deveria ter arquivo vazio"
fi

info "3. API local (usada pela interface do pfSense)"

SESSIONS=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /sessions)
USER=$(echo "$SESSIONS" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["user"])')
check "a sessão aparece na API local" "joao" "$USER"

IP=$(echo "$SESSIONS" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["ip"])')
check "IP correto na sessão" "10.10.20.50" "$IP"

STATUS=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /status)
NSESS=$(echo "$STATUS" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')
check "contador de sessões no status" "1" "$NSESS"

NGROUPS=$(echo "$STATUS" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["groups"]))')
check "os dois grupos aparecem no status" "2" "$NGROUPS"

SEEN=$(echo "$STATUS" | python3 -I -c 'import json,sys; print("DC-TESTE" in json.load(sys.stdin)["agents_last_seen"])')
check "o agente consta no último contato" "True" "$SEEN"

info "4. normalização de usuário e IP"

BODY='{"events":[
 {"type":"logon","user":"EMPRESA\\maria","ip":"::ffff:10.10.20.51","event_id":4768},
 {"type":"logon","user":"PC01$","ip":"10.10.20.52","event_id":4768},
 {"type":"logon","user":"ana@empresa.local","ip":"10.10.20.53","event_id":4768}
]}'
OUT=$(python3 -I "$WORK/send.py" "$SECRET" "$PORT" /v1/events "$BODY")
RES=$(echo "$OUT" | tail -n +2)
ACC=$(echo "$RES" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["accepted"])')
IGN=$(echo "$RES" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["ignored"])')
NWARN=$(echo "$RES" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin).get("warnings",[])))')
# Sem LDAP, os dois logons válidos são aplicados com ressalva (grupo padrão).
# Isso tem de contar como ACEITO: a sessão existe. Só a conta de máquina
# (PC01$) é de fato ignorada.
check "2 logons aplicados (ainda que com ressalva)" "2" "$ACC"
check "apenas a conta de máquina foi ignorada" "1" "$IGN"
check "2 avisos de grupo não resolvido" "2" "$NWARN"

sleep 2
SESSIONS=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /sessions)
USERS=$(echo "$SESSIONS" | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
print(",".join(sorted(s["user"] for s in d)))')
check "prefixo de domínio e UPN removidos" "ana,joao,maria" "$USERS"

IPS=$(echo "$SESSIONS" | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
print(",".join(sorted(s["ip"] for s in d)))')
check "IPv4 mapeado em IPv6 foi normalizado" "10.10.20.50,10.10.20.51,10.10.20.53" "$IPS"

check "tabela com os 3 IPs" "3" "$(grep -c . "$WORK/tables/padrao.txt")"

info "5. encerrar sessão pela interface"

python3 -I "$WORK/local.py" "$WORK/guarita.sock" "/session/remove?ip=10.10.20.51" >/dev/null
sleep 2
check "IP removido da tabela" "2" "$(grep -c . "$WORK/tables/padrao.txt")"
if grep -q "10.10.20.51" "$WORK/tables/padrao.txt"; then
	bad "o IP removido ainda está na tabela"
else
	ok "o IP removido saiu da tabela"
fi

info "6. sessão fixada e persistência entre reinícios"

python3 -I "$WORK/local.py" "$WORK/guarita.sock" "/session/sticky?ip=10.10.20.50&on=1" >/dev/null
STICKY=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /sessions | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
print([s["sticky"] for s in d if s["ip"]=="10.10.20.50"][0])')
check "sessão marcada como fixada" "True" "$STICKY"

# Encerra o daemon: ele salva o estado no SIGTERM.
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""

if [ -f "$WORK/db/sessions.json" ]; then
	ok "estado salvo em disco no encerramento"
else
	bad "estado não foi salvo"
fi

# Sobe de novo e confere que as sessões voltaram.
: > "$PFCTL_LOG"
"$WORK/guaritad" -config "$WORK/guarita.json" \
	-pfctl "$WORK/bin/pfctl" \
	-pid "$WORK/guaritad.pid" >> "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
	[ -S "$WORK/guarita.sock" ] && break
	sleep 0.1
done
sleep 2

NSESS=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /status | \
	python3 -I -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')
check "sessões restauradas depois do reinício" "2" "$NSESS"
check "tabela reescrita no boot" "2" "$(grep -c . "$WORK/tables/padrao.txt")"

if grep -q "replace guarita_padrao" "$PFCTL_LOG"; then
	ok "pfctl chamado no boot para reaplicar as tabelas"
else
	bad "pfctl não foi chamado no boot"
fi

info "7. recarga de configuração sem perder sessões (SIGHUP)"

# Troca o segredo no arquivo e manda SIGHUP.
NEWSECRET="outro-segredo-de-integracao-9876543"
sed -i "s|$SECRET|$NEWSECRET|" "$WORK/guarita.json"
kill -HUP "$DAEMON_PID"
sleep 1

OUT=$(python3 -I "$WORK/send.py" "$SECRET" "$PORT" /v1/ping '{}')
check "segredo antigo recusado depois do SIGHUP" "401" "$(echo "$OUT" | head -1)"

OUT=$(python3 -I "$WORK/send.py" "$NEWSECRET" "$PORT" /v1/ping '{}')
check "segredo novo aceito depois do SIGHUP" "200" "$(echo "$OUT" | head -1)"

NSESS=$(python3 -I "$WORK/local.py" "$WORK/guarita.sock" /status | \
	python3 -I -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')
check "sessões preservadas no SIGHUP" "2" "$NSESS"

# ---------------------------------------------------------------- resultado

echo ""
echo "=============================================="
echo " passaram: $PASS    falharam: $FAIL"
echo "=============================================="
if [ "$FAIL" -gt 0 ]; then
	echo ""
	echo "Log do daemon:"
	sed 's/^/  /' "$WORK/daemon.log"
	exit 1
fi
exit 0
