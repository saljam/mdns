// command mdns queries for mdns services.
//
// https://datatracker.ietf.org/doc/html/rfc6762
// https://datatracker.ietf.org/doc/html/rfc6763
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	mdnsAddr4 = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("224.0.0.251:5353"))
	mdnsAddr6 = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[ff02::fb]:5353"))
)

func main() {
	timeout := flag.Duration("timeout", 2*time.Second, "how long to wait for answers, 0 means indefinitely")
	log.SetFlags(0)
	flag.Parse()

	ctx := context.Background()
	if *timeout != 0 {
		ctx, _ = context.WithTimeout(ctx, *timeout)
	}
	err := query(ctx, "_services._dns-sd._udp.local.")
	if err != nil {
		log.Fatalf("could not query: %v", err)
	}
}

func query(ctx context.Context, name string) error {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	servicesQueryID := dns.Id()
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: servicesQueryID},
		Question: []dns.Question{{
			Name:   name,
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET | 1<<15, // ask for a unicast response
		}},
	}
	bufq, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(bufq, mdnsAddr4)
	if err != nil {
		return err
	}

	buf := make([]byte, 0xffff)
	services := map[string]struct{}{}
	for {
		n, addr, err := conn.ReadFrom(buf)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		msg := &dns.Msg{}
		err = msg.Unpack(buf[:n])
		if err != nil {
			log.Printf("bad response from %v: %v", addr, err)
			continue
		}

		if msg.Id == servicesQueryID {
			// answer to initial services query
			for _, a := range msg.Answer {
				switch rr := a.(type) {
				case *dns.PTR:
					if _, ok := services[rr.Ptr]; ok {
						// we've already queried this service
						continue
					}
					services[rr.Ptr] = struct{}{}

					m := &dns.Msg{
						MsgHdr: dns.MsgHdr{Id: dns.Id()},
						Question: []dns.Question{{
							Name:   rr.Ptr,
							Qtype:  dns.TypePTR,
							Qclass: dns.ClassINET | 1<<15, // ask for a unicast response
						}},
					}
					buf, err := m.Pack()
					if err != nil {
						return err
					}
					_, err = conn.WriteTo(buf, mdnsAddr4)
					if err != nil {
						return err
					}
				}
			}
			continue
		}

		var (
			name    string
			host    string
			service string
			proto   string
			addrs   []string
		)

		for _, a := range append(msg.Answer, msg.Extra...) {
			switch rr := a.(type) {
			case *dns.PTR:
				name = strings.TrimSuffix(rr.Ptr, "."+rr.Hdr.Name)
				svcParts := strings.Split(strings.Trim(rr.Hdr.Name, "."), ".")
				if len(svcParts) == 3 && svcParts[2] == "local" {
					service = strings.Trim(svcParts[0], "_")
					proto = strings.Trim(svcParts[1], "_")
				}
			case *dns.SRV:
				host = fmt.Sprintf("%s:%d", strings.TrimSuffix(rr.Target, "."), rr.Port)
			case *dns.A:
				addrs = append(addrs, rr.A.String())
			case *dns.AAAA:
				addrs = append(addrs, rr.AAAA.String())
			case *dns.TXT:
			}
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", proto, service, host, name)
	}
}
