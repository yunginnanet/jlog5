package main

import (
	"bufio"
	"fmt"
	"inet.af/netaddr"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
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
		case strings.Contains(line, "IP DROP"):
		case strings.Contains(line, "UFW"):
		case strings.Contains(line, "DPT=") && strings.Contains(line, "SPT="):
			lines = append(lines, line)
		}
	}
	fmt.Println("loaded lines from log: ", len(lines))
}

type LogEntry struct {
	Interface   string
	Destination netaddr.IPPort
	Protocol    string
	TCPFlags    []string
	Window      int
	Source      netaddr.IPPort
	Time        time.Time
	MAC         string
}

type SrcStat struct {
	Source string
	Length int
}

type Counts []SrcStat

func (c Counts) Len() int           { return len(c) }
func (c Counts) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
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
	} else {
		return ""
	}
}

func v6adapt(addr string) string {
	if strings.Contains(addr, ":") && !strings.Contains(addr, ".") {
		return "[" + addr + "]"
	}
	return addr
}

func process(line string) LogEntry {
	split := strings.Split(line, " ")
	split = clean(split)
	l := LogEntry{}
	l.Time = parseTime(split)

	var (
		srcaddr string
		srcport string
		dstaddr string
		dstport string
		proto   string
		macaddr string
	)

	var atlas = map[string]*string{
		"IN":    &l.Interface,
		"SRC":   &srcaddr,
		"SPT":   &srcport,
		"DPT":   &dstport,
		"DST":   &dstaddr,
		"PROTO": &proto,
		"MAC":   &macaddr,
	}

	for _, item := range split {
		for key, i := range atlas {
			if e := truncate(item, key+"="); len(e) > 1 {
				*i = e
			}
		}
		for _, f := range tcpflags {
			if strings.EqualFold(item, f) {
				l.TCPFlags = append(l.TCPFlags, f)
			}
		}
	}

	if len(*atlas["IN"]) > 0 {
		l.Interface = *atlas["IN"]
	}

	if src, err := netaddr.ParseIPPort(v6adapt(srcaddr) + ":" + *atlas["SPT"]); err != nil {
		fmt.Println("SRC: " + v6adapt(srcaddr) + ":" + *atlas["SPT"] + "(" + err.Error() + ")")
	} else {
		l.Source = src
	}

	if dst, err := netaddr.ParseIPPort(v6adapt(dstaddr) + ":" + *atlas["DPT"]); err != nil {
		fmt.Println("DST: " + v6adapt(dstaddr) + ":" + *atlas["DPT"] + "(" + err.Error() + ")")
	} else {
		l.Destination = dst
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
		mu.Lock()
		source[entry.Source.IP().String()] = append(source[entry.Source.IP().String()], entry)
		mu.Unlock()

		/*suffix := ""
		if entry.Protocol == "TCP" {
			suffix = "| Flags: " + strings.Join(entry.TCPFlags, ",")
		}
		fmt.Printf("\nProtocol: %s | Source: %s %s", entry.Protocol, entry.Source.String(), suffix)*/
	}
	fmt.Printf("\nProcessed %d unique IPs...\n")

	ct := make(Counts, len(source))
	i := 0
	for k, v := range source {
		ct[i] = SrcStat{Source: k, Length: len(v)}
		i++
	}

	sort.Sort(ct)

	for _, k := range ct {
		fmt.Printf("%v\t%v\n", k.Source, k.Length)
	}

}
