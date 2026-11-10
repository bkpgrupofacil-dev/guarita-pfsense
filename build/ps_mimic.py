#!/usr/bin/env python3
"""Replica, byte a byte, o que o guarita-agent.ps1 monta e assina.

Serve para conferir que o agente em PowerShell e o serviço em Go concordam
quanto ao formato do JSON e ao cálculo do HMAC, sem precisar de um Windows.
Qualquer divergência aqui apareceria em produção como "assinatura inválida".

Implementa:
  ConvertTo-JsonString  -> json_string()
  Build-BatchJson       -> build_batch()
  Get-GuaritaSignature  -> signature()
"""
import hashlib
import hmac
import json
import sys


def json_string(value):
    """Mesma lógica de ConvertTo-JsonString no .ps1."""
    if value is None:
        return '""'
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif code < 32 or code > 126:
            out.append('\\u%04x' % code)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def build_batch(agent, events):
    """Mesma lógica de Build-BatchJson no .ps1."""
    parts = ['{"agent":', json_string(agent), ',"events":[']
    first = True
    for e in events:
        if not first:
            parts.append(',')
        first = False
        parts.append('{"type":')
        parts.append(json_string(e['type']))
        parts.append(',"user":')
        parts.append(json_string(e['user']))
        parts.append(',"domain":')
        parts.append(json_string(e['domain']))
        parts.append(',"ip":')
        parts.append(json_string(e['ip']))
        parts.append(',"computer":')
        parts.append(json_string(e['computer']))
        parts.append(',"event_id":')
        parts.append(str(int(e['event_id'])))
        parts.append(',"time":')
        parts.append(json_string(e['time']))
        parts.append('}')
    parts.append(']}')
    return ''.join(parts)


def signature(secret, ts, body_bytes):
    """Mesma lógica de Get-GuaritaSignature no .ps1."""
    prefix = ('%d\n' % ts).encode('utf-8')
    mac = hmac.new(secret.encode('utf-8'), prefix + body_bytes, hashlib.sha256)
    return mac.hexdigest()


def main():
    secret = 'segredo-de-conformidade-123456789'
    ts = 1762800000
    events = [
        {'type': 'logon', 'user': 'joao', 'domain': 'EMPRESA',
         'ip': '10.10.20.50', 'computer': 'PC-JOAO', 'event_id': 4768,
         'time': '2026-11-10T18:00:00Z'},
        # Acentos: o agente escapa como \uXXXX, o Go tem de ler igual.
        {'type': 'activity', 'user': 'joão.conceição', 'domain': 'EMPRESA',
         'ip': '10.10.20.51', 'computer': 'PC-ÇÃO', 'event_id': 4769,
         'time': '2026-11-10T18:00:01Z'},
        # Caracteres que precisam de escape em JSON.
        {'type': 'logon', 'user': 'aspas"e\\barra', 'domain': 'LINHA\nNOVA',
         'ip': '10.10.20.52', 'computer': 'TAB\tAQUI', 'event_id': 4624,
         'time': '2026-11-10T18:00:02Z'},
    ]
    body = build_batch('DC01', events)
    body_bytes = body.encode('utf-8')

    # Confere que o que montamos à mão é JSON válido.
    parsed = json.loads(body)
    assert len(parsed['events']) == 3, parsed
    assert parsed['events'][1]['user'] == 'joão.conceição', parsed['events'][1]
    assert parsed['events'][2]['domain'] == 'LINHA\nNOVA', parsed['events'][2]

    out = {
        'secret': secret,
        'ts': ts,
        'body': body,
        'signature': signature(secret, ts, body_bytes),
    }
    json.dump(out, sys.stdout, ensure_ascii=False)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
