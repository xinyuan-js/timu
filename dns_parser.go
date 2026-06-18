package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type dnsMessage struct {
	Answers     []resourceRecord
	Authorities []resourceRecord
	Additionals []resourceRecord
}

type resourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  any
}

type srvRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (m dnsMessage) allRecords() []resourceRecord {
	out := make([]resourceRecord, 0, len(m.Answers)+len(m.Authorities)+len(m.Additionals))
	out = append(out, m.Answers...)
	out = append(out, m.Authorities...)
	out = append(out, m.Additionals...)
	return out
}

func parseDNSMessage(packet []byte) (dnsMessage, error) {
	if len(packet) < 12 {
		return dnsMessage{}, fmt.Errorf("dns packet too short")
	}
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	ns := int(binary.BigEndian.Uint16(packet[8:10]))
	ar := int(binary.BigEndian.Uint16(packet[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		_, off, err = readName(packet, off)
		if err != nil {
			return dnsMessage{}, err
		}
		if off+4 > len(packet) {
			return dnsMessage{}, fmt.Errorf("truncated question")
		}
		off += 4
	}

	var msg dnsMessage
	var err error
	msg.Answers, off, err = readRecords(packet, off, an)
	if err != nil {
		return dnsMessage{}, err
	}
	msg.Authorities, off, err = readRecords(packet, off, ns)
	if err != nil {
		return dnsMessage{}, err
	}
	msg.Additionals, _, err = readRecords(packet, off, ar)
	return msg, err
}

func readRecords(packet []byte, off int, count int) ([]resourceRecord, int, error) {
	records := make([]resourceRecord, 0, count)
	for i := 0; i < count; i++ {
		rr, next, err := readRecord(packet, off)
		if err != nil {
			return nil, off, err
		}
		records = append(records, rr)
		off = next
	}
	return records, off, nil
}

func readRecord(packet []byte, off int) (resourceRecord, int, error) {
	name, off, err := readName(packet, off)
	if err != nil {
		return resourceRecord{}, off, err
	}
	if off+10 > len(packet) {
		return resourceRecord{}, off, fmt.Errorf("truncated resource record")
	}
	rrType := binary.BigEndian.Uint16(packet[off : off+2])
	class := binary.BigEndian.Uint16(packet[off+2 : off+4])
	ttl := binary.BigEndian.Uint32(packet[off+4 : off+8])
	rdLen := int(binary.BigEndian.Uint16(packet[off+8 : off+10]))
	off += 10
	if off+rdLen > len(packet) {
		return resourceRecord{}, off, fmt.Errorf("truncated rdata")
	}
	rdataOff := off
	rdata := packet[off : off+rdLen]
	off += rdLen

	rr := resourceRecord{Name: name, Type: rrType, Class: class, TTL: ttl}
	switch rrType {
	case dnsTypeA:
		if len(rdata) == net.IPv4len {
			rr.Data = net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3])
		}
	case dnsTypeAAAA:
		if len(rdata) == net.IPv6len {
			rr.Data = net.IP(append([]byte(nil), rdata...))
		}
	case dnsTypePTR:
		value, _, err := readName(packet, rdataOff)
		if err == nil {
			rr.Data = value
		}
	case dnsTypeSRV:
		if len(rdata) >= 6 {
			target, _, err := readName(packet, rdataOff+6)
			if err == nil {
				rr.Data = srvRecord{
					Priority: binary.BigEndian.Uint16(rdata[0:2]),
					Weight:   binary.BigEndian.Uint16(rdata[2:4]),
					Port:     binary.BigEndian.Uint16(rdata[4:6]),
					Target:   target,
				}
			}
		}
	case dnsTypeTXT:
		rr.Data = readTXT(rdata)
	default:
		rr.Data = append([]byte(nil), rdata...)
	}
	return rr, off, nil
}

func readTXT(rdata []byte) []string {
	var out []string
	for off := 0; off < len(rdata); {
		length := int(rdata[off])
		off++
		if off+length > len(rdata) {
			break
		}
		out = append(out, string(rdata[off:off+length]))
		off += length
	}
	return out
}

func readName(packet []byte, off int) (string, int, error) {
	var labels []byte
	start := off
	jumped := false
	seen := 0
	for {
		if off >= len(packet) {
			return "", off, fmt.Errorf("truncated name")
		}
		length := int(packet[off])
		if length&0xc0 == 0xc0 {
			if off+1 >= len(packet) {
				return "", off, fmt.Errorf("truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(packet[off:off+2]) & 0x3fff)
			if ptr >= len(packet) {
				return "", off, fmt.Errorf("bad compression pointer")
			}
			if !jumped {
				start = off + 2
			}
			off = ptr
			jumped = true
			seen++
			if seen > len(packet) {
				return "", off, fmt.Errorf("compression loop")
			}
			continue
		}
		off++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 {
			return "", off, fmt.Errorf("unsupported label")
		}
		if off+length > len(packet) {
			return "", off, fmt.Errorf("truncated label")
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		labels = append(labels, packet[off:off+length]...)
		off += length
	}
	if jumped {
		return string(labels), start, nil
	}
	return string(labels), off, nil
}
