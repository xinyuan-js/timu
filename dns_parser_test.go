package main

import (
	"encoding/binary"
	"testing"
)

func TestParseCompressedPTR(t *testing.T) {
	var packet []byte
	packet = append(packet, 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
	name, _ := encodeName("_http._tcp.local")
	packet = append(packet, name...)
	packet = appendU16(packet, dnsTypePTR)
	packet = appendU16(packet, dnsClassINET)
	packet = appendU32(packet, 120)
	target, _ := encodeName("nas._http._tcp.local")
	packet = appendU16(packet, uint16(len(target)))
	packet = append(packet, target...)

	msg, err := parseDNSMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("answers=%d", len(msg.Answers))
	}
	if got := msg.Answers[0].Data.(string); got != "nas._http._tcp.local" {
		t.Fatalf("ptr=%q", got)
	}
}

func appendU16(out []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(out, value)
}

func appendU32(out []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(out, value)
}
