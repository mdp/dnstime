package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

// TimeToIP takes in time.Time and turns it into a IPv4 byte slice
func TimeToIP(t time.Time) [4]byte {
	ip := [4]byte{}
	unixTime := int32(t.Unix())
	ip[0] = byte(unixTime >> 24)
	ip[1] = byte((unixTime >> 16) & 255)
	ip[2] = byte((unixTime >> 8) & 255)
	ip[3] = byte(unixTime & 255)
	return ip
}

// TimeFromIP takes in a IPv4 byte slice, treats it as Unix Time and turns it into
// a time.Time object
func TimeFromIP(tb [4]byte) time.Time {
	i := int32(0)
	i = i + int32(tb[0])<<24
	i = i + int32(tb[1])<<16
	i = i + int32(tb[2])<<8
	i = i + int32(tb[3])
	t := time.Unix(int64(i), 0)
	return t
}

var privateKey *ecdsa.PrivateKey

func setPrivateKey() {
	privKeyEnv := os.Getenv("PRIVATE_KEY")

	if len(privKeyEnv) > 0 {
		key, err := base64.StdEncoding.DecodeString(privKeyEnv)
		if err != nil {
			fmt.Println("Unable to parse private key")
			panic(err)
		}

		privateKey, err = x509.ParseECPrivateKey(key)
		if err != nil {
			fmt.Println("Unable to unmarshall private key")
			panic(err)
		}

	} else {
		privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privateKeyMarshalled, _ := x509.MarshalECPrivateKey(privateKey)
		fmt.Println("Env: PRIVATE_KEY not found. Generating new key")
		fmt.Printf("New Key: %s\n", base64.StdEncoding.EncodeToString(privateKeyMarshalled))
	}
}

func main() {
	setPrivateKey()
	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: ":5553", Net: "udp"}
	log.Printf("DNS Serving to: %v", server.Addr)

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	m := new(dns.Msg)
	m.SetReply(r)

	switch q.Qtype {
	case dns.TypeA:
		now := TimeToIP(time.Now())
		m.Answer = make([]dns.RR, 1)
		m.Extra = make([]dns.RR, 1)
		ip := net.IPv4(now[0], now[1], now[2], now[3])
		fmt.Printf("Inbound time query for: %+v\n", m.Question[0].Name)
		m.Answer[0] = &dns.A{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: ip}

		// Extra field for holding signed time
		m.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: signTime(ip)}
	default:
		log.Println("Uhandled qtype")
	}
	w.WriteMsg(m)
}

// signTime signs the current time with an EC private key
func signTime(ip net.IP) []string {
	sig, _ := Sign(ip, privateKey)
	sigStr := base64.StdEncoding.EncodeToString(sig)
	sigStr = fmt.Sprintf("%s %s", ip.String(), sigStr)
	return []string{sigStr}
}
