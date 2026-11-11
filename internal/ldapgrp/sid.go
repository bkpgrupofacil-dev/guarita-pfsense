package ldapgrp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// O grupo PRIMÁRIO de um usuário do AD não aparece no memberOf do usuário nem
// no member do grupo: o AD guarda só o RID dele no atributo primaryGroupID do
// usuário. É assim com "Usuários do domínio" (RID 513), o primário de quase
// todo mundo, e com qualquer grupo que o administrador marque como primário.
// Sem resolver isso, um grupo do Guarita que aponte para "Usuários do domínio"
// nunca casa com ninguém, e um usuário cujo único grupo é o primário fica sem
// grupo nenhum.
//
// O SID do grupo primário é o SID do domínio seguido do RID, e o SID do domínio
// é o SID do usuário sem a última subautoridade. Então basta trocar a última
// subautoridade do SID do usuário pelo primaryGroupID.

// primaryGroupSID devolve o SID binário do grupo primário a partir do SID
// binário do usuário (objectSid) e do primaryGroupID.
//
// Formato do SID binário: revisão (1 byte), quantidade de subautoridades
// (1 byte), autoridade (6 bytes, big-endian) e as subautoridades (4 bytes cada,
// little-endian).
func primaryGroupSID(userSID []byte, rid uint32) ([]byte, error) {
	if len(userSID) < 8 {
		return nil, fmt.Errorf("objectSid curto demais (%d bytes)", len(userSID))
	}
	n := int(userSID[1])
	if n < 1 || len(userSID) != 8+4*n {
		return nil, fmt.Errorf("objectSid inválido: %d subautoridades em %d bytes", n, len(userSID))
	}
	out := make([]byte, len(userSID))
	copy(out, userSID)
	binary.LittleEndian.PutUint32(out[len(out)-4:], rid)
	return out, nil
}

// escapeBinary escreve um valor binário no formato de filtro LDAP (RFC 4515),
// com cada byte como \hh. Serve para buscar por objectSid.
func escapeBinary(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "\\%02x", c)
	}
	return sb.String()
}

// sidString formata um SID binário como texto (S-1-5-21-...), para logs e
// mensagens de erro.
func sidString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	s := fmt.Sprintf("S-%d-%d", b[0], auth)
	for i := 8; i+4 <= len(b); i += 4 {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[i:i+4]))
	}
	return s
}
