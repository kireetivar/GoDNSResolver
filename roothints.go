package main

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type RootHint struct {
	Domain string
	TTL    int64
	Class  string
	Type   string
	IP     string
}

func parseRootHints(filePath string) ([]RootHint, error) {

	var rootHints []RootHint

	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error while reading roothints file %v\n", err)
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("Error closing file:", err)
		}
	}()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := scanner.Text()

		if strings.HasPrefix(s, ";") {
			continue
		}
		sl := strings.Fields(s)
		if len(sl) != 4 {
			continue
		}
		ttl, err := strconv.ParseInt(sl[1], 10, 64)
		if err != nil {
			log.Printf("ERROR while parsing str to int64: %v\n", err)
			return nil, err
		}

		roothint := RootHint{
			Domain: sl[0],
			TTL:    ttl,
			Class:  "IN",
			Type:   sl[2],
			IP:     sl[3],
		}
		rootHints = append(rootHints, roothint)
	}
	return rootHints, nil
}
