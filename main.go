package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

func main() {
	rootHints, err := parseRootHints("root.hints")
	if err != nil {
		log.Printf("Error while parsing root hints file %v]n", err)
	}

	rootServer := rootHints[0].IP
	fmt.Printf("Querying Root Server: %s\n", rootServer)

	q, err := buildQuery("www.google.com")
	if err != nil {
		log.Printf("Error Coundn't build DNS Query: %v\n", err)
		return
	}

	serverAddr, err := net.ResolveUDPAddr("udp", rootServer+":53")
	if err != nil {
		log.Printf("Error: coudnt resolve UDP address: %v\n", err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Printf("Error: coudnt dail to server: %v\n", err)
	}
	defer conn.Close()

	_, err = conn.Write(q)
	if err != nil {
		log.Printf("Error writing query: %v\n", err)
		return
	}

	responseBytes := make([]byte, 512)
	resLen, err := conn.Read(responseBytes)
	if err != nil {
		log.Printf("ERROR from reading server response: %v\n", err)
		return
	}

	validResponse := responseBytes[:resLen]
	buf := bytes.NewBuffer(validResponse[:12])
	dnsHeader := DNSHeader{}
	err = binary.Read(buf, binary.BigEndian, &dnsHeader)
	if err != nil {
		log.Printf("Error: couldn't convert header %v\n", err)
	}

	offset := 12
	qs := QuestionSection{}

	var decodedName string
	decodedName, offset, err = parseDomainName(validResponse, offset)
	if err != nil {
		log.Printf("Error parsing domain name: %v\n", err)
		return
	}
	qs.QNAME = []byte(decodedName)

	if offset+2 > len(validResponse) {
		log.Println("Packet too short for QTYPE")
		return
	}
	qs.QTYPE = binary.BigEndian.Uint16(validResponse[offset:offset+2])
	offset += 2

	if offset+2 > len(validResponse) {
		log.Println("Packet too short for QCLASS")
		return
	}
	qs.QClass = binary.BigEndian.Uint16(validResponse[offset : offset+2])
	offset += 2

	

}
