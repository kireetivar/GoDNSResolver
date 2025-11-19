package main

import (
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

	q, err := buildQuery("www.google.com")
	if err != nil {
		log.Printf("Error Coundn't build DNS Query: %v\n", err)
		return
	}


	for {
		fmt.Printf("Querying Root Server: %s\n", rootServer)
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

		dp, err := parseDNSPacket(validResponse)
		if err != nil {
			log.Printf("ERROR parsing DNS Packet: %v\n", err)
			return
		}
		if len(dp.Answers) > 0 {
			for _, ans := range dp.Answers {
				if ans.TYPE == 1 { // A Record
					ip := net.IP(ans.RDATA)
					fmt.Printf("Answer found: %s -> %s\n", ans.NAME, ip.String())
				}
			}
			break
		}

		s := getIPFromPacket(dp)
		if s == "" {
			fmt.Println("Error: No glue records found.")
			break
		}
		rootServer = s
	}

}

// Helper to find an IPv4 address in the Additional section
func getIPFromPacket(packet DNSPacket) string {
	for _, rr := range packet.Additionals {
		// Type 1 is A record (IPv4)
		// RDATA length must be 4 bytes
		if rr.TYPE == 1 && len(rr.RDATA) == 4 {
			return net.IP(rr.RDATA).String()
		}
	}
	return "" // No IP found
}