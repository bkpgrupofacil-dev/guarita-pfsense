package ldapgrp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// sid monta um SID binário a partir das subautoridades, com autoridade 5 (NT).
func sid(sub ...uint32) []byte {
	b := []byte{1, byte(len(sub)), 0, 0, 0, 0, 0, 5}
	for _, s := range sub {
		var x [4]byte
		binary.LittleEndian.PutUint32(x[:], s)
		b = append(b, x[:]...)
	}
	return b
}

// Caso real do laboratório: os usuários de teste tinham o grupo do Guarita como
// grupo primário (primaryGroupID 1110), e o AD não lista o primário no
// memberOf. O SID do grupo tem de ser o do domínio com o RID trocado.
func TestPrimaryGroupSID(t *testing.T) {
	user := sid(21, 1111111111, 2222222222, 3333333333, 1105)
	got, err := primaryGroupSID(user, 1110)
	if err != nil {
		t.Fatal(err)
	}
	want := sid(21, 1111111111, 2222222222, 3333333333, 1110)
	if !bytes.Equal(got, want) {
		t.Fatalf("SID do grupo = %s, quero %s", sidString(got), sidString(want))
	}
	if sidString(got) != "S-1-5-21-1111111111-2222222222-3333333333-1110" {
		t.Fatalf("sidString = %s", sidString(got))
	}
	// "Usuários do domínio" é o RID 513.
	du, _ := primaryGroupSID(user, 513)
	if sidString(du) != "S-1-5-21-1111111111-2222222222-3333333333-513" {
		t.Fatalf("Usuários do domínio = %s", sidString(du))
	}
	// O SID do usuário não pode ser alterado.
	if !bytes.Equal(user, sid(21, 1111111111, 2222222222, 3333333333, 1105)) {
		t.Fatal("primaryGroupSID alterou o SID do usuário")
	}
}

func TestPrimaryGroupSIDRejectsInvalid(t *testing.T) {
	bad := map[string][]byte{
		"vazio":                   nil,
		"curto":                   {1, 1, 0, 0},
		"sem subautoridades":      {1, 0, 0, 0, 0, 0, 0, 5},
		"tamanho não bate":        append(sid(21, 1, 2), 0xff),
		"contagem maior que dado": {1, 5, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0},
	}
	for name, b := range bad {
		if _, err := primaryGroupSID(b, 513); err == nil {
			t.Errorf("%s: deveria dar erro", name)
		}
	}
}

func TestEscapeBinary(t *testing.T) {
	if got := escapeBinary([]byte{0x01, 0x05, 0x00, 0xff, '*', '('}); got != `\01\05\00\ff\2a\28` {
		t.Fatalf("escapeBinary = %s", got)
	}
}
