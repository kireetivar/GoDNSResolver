package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
)

type DNSHeader struct {
	ID      uint16
	FLAGS   uint16
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

type Flags struct {
	QR     bool
	OPCODE uint8
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	Z      uint8
	RCODE  uint8
}

type QuestionSection struct {
	QNAME  []byte
	QTYPE  uint16
	QClass uint16
}

type DNSResourceRecord struct {
	NAME     []byte
	TYPE  	 uint16
	CLASS 	 uint16
	TTL   	 uint32
	RDLENGTH uint16
	RDATA    []byte
}

type DNSPacket struct {
    Header      DNSHeader
    Questions   []QuestionSection
    Answers     []DNSResourceRecord
    Authorities []DNSResourceRecord
    Additionals []DNSResourceRecord
}

func (f *Flags) Pack() uint16 {
	var packed uint16 = 0

	if f.QR {
		packed |= (1 << 15)
	}

	packed |= (uint16(f.OPCODE&0x0F) << 11) // using & so we dont spillover

	if f.AA {
		packed |= (1 << 10)
	}

	if f.TC {
		packed |= (1 << 9)
	}

	if f.RD {
		packed |= (1 << 8)
	}

	if f.RA {
		packed |= (1 << 7)
	}

	packed |= (uint16(f.Z&0x07) << 4)
	packed |= (uint16(f.RCODE&0x0F) << 0)

	return packed
}

func Unpack(packed uint16) Flags {
	var f Flags

	f.QR = (packed >> 15) == 1
	f.OPCODE = uint8((packed >> 11) & 0x0F)
	f.AA = (packed >> 10) == 1
	f.TC = (packed >> 9) == 1
	f.RD = (packed >> 8) == 1
	f.RA = (packed >> 7) == 1
	f.Z = uint8((packed >> 4) & 0x07)
	f.RCODE = uint8((packed >> 0) & 0x0F)
	return f
}

func encodeDomainName(domain string) ([]byte, error) {
	var encodedDomain []byte
	s := strings.Split(domain, ".")

	for _, v := range s {
		l := len(v)
		if l > 63 {
			return nil, errors.New("field limit the label to 63 octets or less")
		}
		encodedDomain = append(encodedDomain, byte(l))
		encodedDomain = append(encodedDomain, v...)
	}
	encodedDomain = append(encodedDomain, byte(0))

	return encodedDomain, nil
}

// parseDomainName reads a (possibly compressed) domain name from the packet
// it takes the full packet and the starting offset
// it returns: decoded string, the *new* offset after the name, and an error
func parseDomainName(fullPacket []byte, offset int) (string, int, error) {
	var labels []string
	ptr := offset

	for {
		if ptr >= len(fullPacket) {
			return "", 0, errors.New("offset out of bounds")
		}

		b:= fullPacket[ptr]

		// 1. Check for Pointer (11xxxxxx)
		if (b & 0xC0) == 0xC0 {
			// Need atlest 2 bytes for a pointer
			if ptr+1 >= len(fullPacket) {
				return "", 0, errors.New("incomplete pointer")
			}

			b2 := fullPacket[ptr+1]

			// Calculate the offset to jump to
			pointerOffset := int(uint16(b&0x3F) << 8 | uint16(b2))

			// Jump to the pointer to parse the rest 
			// we don't care about the returned offset from the recursion,
			// because a pointer is always the END of this specific sequence
			restOfName, _,err := parseDomainName(fullPacket, pointerOffset)
			if err!= nil {
				return "", 0, err
			}

			labels = append(labels, restOfName)

			return strings.Join(labels, "."), ptr +2, nil
		} else if b == 0 {
			return strings.Join(labels, "."), ptr +1, nil
		} else {
			length := int(b)

			if ptr+1+length > len(fullPacket) {
				return "", 0, errors.New("label length out of bounds")
			}

			label := fullPacket[ptr+1: ptr+1+length]
			labels = append(labels, string(label))

			ptr += 1+ length
		}
	}
}

// parseResourceRecord parses a single Resource Record (RR) from the packet.
func parseResourceRecord(packet []byte, offset int) (DNSResourceRecord, int, error) {
	rr := DNSResourceRecord{}

	// 1. Parse the NAME
	s, newOffset, err := parseDomainName(packet, offset)
	if err != nil {
		return rr, offset, err
	}
	rr.NAME = []byte(s)
	offset = newOffset

	// 2. Check if we have enough bytes for the fixed header (Type+Class+TTL+Length = 10 bytes)
	if offset+10 > len(packet) {
		return rr, offset, errors.New("packet too short for RR header")
	}

	rr.TYPE = binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2

	rr.CLASS = binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2

	rr.TTL = binary.BigEndian.Uint32(packet[offset : offset+4])
	offset += 4

	rr.RDLENGTH = binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2

	// 3. Check if we have enough bytes for the RDATA
	// This is where your crash happened! We must check BEFORE slicing.
	if offset+int(rr.RDLENGTH) > len(packet) {
		return rr, offset, fmt.Errorf("packet too short for RDATA: need %d bytes, have %d", offset + int(rr.RDLENGTH), len(packet))	
	}

	rr.RDATA = packet[offset : offset+int(rr.RDLENGTH)]
	offset += int(rr.RDLENGTH)

	return rr, offset, nil
}

func parseDNSPacket(packet []byte) (DNSPacket, error) {
	result := DNSPacket{}
	
	// 1. Parse Header (First 12 bytes)
	buf := bytes.NewBuffer(packet[:12])
	err := binary.Read(buf, binary.BigEndian, &result.Header)
	if err != nil {
		return result, err
	}

	offset := 12 // Header is always 12 bytes

	// 2. Parse Questions
	for i := 0; i < int(result.Header.QDCOUNT); i++ {
		var qs QuestionSection
		var name string
		
		// Use your existing helper
		name, offset, err = parseDomainName(packet, offset)
		if err != nil {
			return result, err
		}
		qs.QNAME = []byte(name)
		
		if offset+4 > len(packet) {
			return result, errors.New("packet too short for Question")
		}
		qs.QTYPE = binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2
		qs.QClass = binary.BigEndian.Uint16(packet[offset : offset+2])
		offset += 2
		
		result.Questions = append(result.Questions, qs)
	}

	// 3. Parse Answers
	for i := 0; i < int(result.Header.ANCOUNT); i++ {
		// Use your existing helper
		rr, newOffset, err := parseResourceRecord(packet, offset)
		if err != nil {
			return result, err
		}
		offset = newOffset
		result.Answers = append(result.Answers, rr)
	}

	// 4. Parse Authorities
	for i := 0; i < int(result.Header.NSCOUNT); i++ {
		rr, newOffset, err := parseResourceRecord(packet, offset)
		if err != nil {
			return result, err
		}
		offset = newOffset
		result.Authorities = append(result.Authorities, rr)
	}

	// 5. Parse Additionals
	for i := 0; i < int(result.Header.ARCOUNT); i++ {
		rr, newOffset, err := parseResourceRecord(packet, offset)
		if err != nil {
			return result, err
		}
		offset = newOffset
		result.Additionals = append(result.Additionals, rr)
	}

	return result, nil
}

func buildQuery(s string) ([]byte, error) {
	f := Flags{
		QR:     false,
		OPCODE: 0,
		AA:     false,
		TC:     false,
		RD:     false, // We set RD: false because this is an iterative query from our resolver to an authoritative server
		RA:     false, // We set RA: false because this is a query, not a response
		Z:      0,
		RCODE:  0,
	}
	b := make([]byte, 2)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("ERROR: coild not generate random ID: %v\n", err)
		return nil, err
	}

	h := DNSHeader{
		ID:      binary.BigEndian.Uint16(b), // NEED TO GENERATE RANDNUMBER
		FLAGS:   f.Pack(),
		QDCOUNT: 1,
	}

	ed, err := encodeDomainName(s)
	if err != nil {
		return nil, err
	}

	qs := QuestionSection{
		QNAME:  ed,
		QTYPE:  1, // request for A record
		QClass: 1, // for IN
	}

	buffer := bytes.NewBuffer(nil) // A cleaner way to make an empty buffer
	err = binary.Write(buffer, binary.BigEndian, h.ID)
	if err != nil {
		log.Printf("ERROR: could not write header ID: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, h.FLAGS)
	if err != nil {
		log.Printf("ERROR: could not write header FLAGS: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, h.QDCOUNT)
	if err != nil {
		log.Printf("ERROR: could not write header QDCOUNT: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, h.ANCOUNT)
	if err != nil {
		log.Printf("ERROR: could not write header ANCOUNT: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, h.NSCOUNT)
	if err != nil {
		log.Printf("ERROR: could not write header NSCOUNT: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, h.ARCOUNT)
	if err != nil {
		log.Printf("ERROR: could not write header ARCOUNT: %v\n", err)
		return nil, err
	}

	_, err = buffer.Write(qs.QNAME)
	if err != nil {
		log.Printf("ERROR: could not write Question QNAME %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, qs.QTYPE)
	if err != nil {
		log.Printf("ERROR: could not write Question QTYPE: %v\n", err)
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, qs.QClass)
	if err != nil {
		log.Printf("ERROR: could not write Question QClass: %v\n", err)
		return nil, err
	}

	return buffer.Bytes(), nil

}
