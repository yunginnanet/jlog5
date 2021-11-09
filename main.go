package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"inet.af/netaddr"
	// "sync"
)

var tcpflags = []string{"URG", "ACK", "PSH", "RST", "SYN", "FIN"}

var lines []string

func init() {
	if len(os.Args) < 2 {
		println("need file to read")
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	//goland:noinspection ALL
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "IPTABLES"):
			lines = append(lines, line)
		case strings.Contains(line, "IP DROP"):
			lines = append(lines, line)
		case strings.Contains(line, "UFW"):
			lines = append(lines, line)
		case strings.Contains(line, "DPT=") && strings.Contains(line, "SPT="):
			lines = append(lines, line)
		default:
		}
	}
	fmt.Println("loaded lines from log: ", len(lines))
}

// LogEntry represents a parsed netfilter block entry from syslog.
type LogEntry struct {
	Interface string
	Protocol  string
	MAC       string

	Window int
	Length int

	Destination netaddr.IPPort
	Source      netaddr.IPPort

	Loopback bool
	LAN      bool

	TCPFlags []string

	Time time.Time
}

// SrcStat represents the statistics of a given source address.
type SrcStat struct {
	Source string
	Length int
}

// Counts is a collection of our statistics.
type Counts []SrcStat

// Len returns the amount of source addresses we have.
func (c Counts) Len() int { return len(c) }

// Swap swaps the position of two indexed values within our source address statistics.
func (c Counts) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

// Less returns if an indexed item (i) in our source address statistics is of lesser value than (j).
func (c Counts) Less(i, j int) bool { return c[i].Length < c[j].Length }

func parseTime(split []string) time.Time {
	if len(split[1]) == 1 {
		split[1] = "0" + split[1]
	}
	tmp := strings.Join(split[:3], " ")
	stamp, err := time.Parse(time.Stamp, tmp)
	if err != nil {
		fmt.Println(err.Error())
		return time.Unix(0, 0)
	}
	return stamp.AddDate(time.Now().Year(), 0, 0)
}

func clean(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func truncate(item, substr string) string {
	if strings.Contains(item, substr) {
		return strings.TrimPrefix(item, substr)
	}
	return ""
}

func v6adapt(addr string) string {
	if strings.Contains(addr, ":") && !strings.Contains(addr, ".") {
		return "[" + addr + "]"
	}
	return addr
}

func mapValues(split []string) map[string]*string {

	var (
		ipinterface, srcaddr, srcport, dstaddr, dstport, proto, macaddr, tcpf, length string
	)

	var atlas = map[string]*string{
		"IN":    &ipinterface,
		"SRC":   &srcaddr,
		"SPT":   &srcport,
		"DPT":   &dstport,
		"DST":   &dstaddr,
		"PROTO": &proto,
		"MAC":   &macaddr,
		"FLAGS": &tcpf,
		"LEN":   &length,
	}

	for _, item := range split {
		for key, i := range atlas {
			if e := truncate(item, key+"="); len(e) > 1 {
				*i = e
			}
		}

		for _, f := range tcpflags {
			if strings.EqualFold(item, f) {
				comma := ""
				cur := *atlas["FLAGS"]
				if len(cur) > 0 {
					comma = ","
				}
				*atlas["FLAGS"] = cur + comma + f
			}
		}
	}

	return atlas
}

func process(line string) (l LogEntry) {
	split := strings.Split(line, " ")
	split = clean(split)
	l.Time = parseTime(split)
	atlas := mapValues(split)

	if len(*atlas["IN"]) > 0 {
		l.Interface = *atlas["IN"]
	}

	if sip := net.ParseIP(*atlas["SRC"]); sip != nil {
		l.Loopback = sip.IsLoopback()
		if sip.IsPrivate() || sip.IsLinkLocalMulticast() || sip.IsLinkLocalUnicast() {
			l.LAN = true
		}
	}

	if src, err := netaddr.ParseIPPort(v6adapt(*atlas["SRC"]) + ":" + *atlas["SPT"]); err == nil {
		l.Source = src
	} else {
		fmt.Println("SRC: " + v6adapt(*atlas["SRC"]) + ":" + *atlas["SPT"] + "(" + err.Error() + ")")
	}

	if dst, err := netaddr.ParseIPPort(v6adapt(*atlas["DST"]) + ":" + *atlas["DPT"]); err == nil {
		l.Destination = dst
	} else {
		fmt.Println("DST: " + v6adapt(*atlas["DST"]) + ":" + *atlas["DPT"] + "(" + err.Error() + ")")
	}

	l.Protocol = *atlas["PROTO"]
	l.MAC = *atlas["MAC"]

	return l
}

func main() {
	var mu = &sync.Mutex{}
	var source = make(map[string][]LogEntry)
	for _, line := range lines {
		entry := process(line)

		if entry.LAN || entry.Loopback {
			continue
		}

		mu.Lock()
		source[entry.Source.IP().String()] = append(source[entry.Source.IP().String()], entry)
		mu.Unlock()
		/*suffix := ""
		if entry.Protocol == "TCP" {
			suffix = "| Flags: " + strings.Join(entry.TCPFlags, ",")
		}
		fmt.Printf("\nProtocol: %s | Source: %s %s", entry.Protocol, entry.Source.String(), suffix)*/
	}
	fmt.Printf("\nProcessed %d unique IPs...\n", len(source))

	ct := make(Counts, len(source))
	i := 0
	for k, v := range source {
		ct[i] = SrcStat{Source: k, Length: len(v)}
		i++
	}

	sort.Sort(sort.Reverse(ct))

	for _, k := range ct {
		if k.Length > 5 {
			fmt.Printf("%v\t%v\n", k.Source, k.Length)
		}
	}

}
