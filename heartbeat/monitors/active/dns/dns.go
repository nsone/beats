package dns

import (
	"github.com/elastic/beats/heartbeat/monitors"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/miekg/dns"
	"net"
	"strings"
)

func init() {
	monitors.RegisterActive("dns", create)
}

var debugf = logp.MakeDebug("dns")

func create(
	info monitors.Info,
	cfg *common.Config,
) ([]monitors.Job, error) {
	config := defaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, err
	}

	jobs := make([]monitors.Job, len(config.Questions)*len(config.NameServers))

	var (
		err   error
		index int
		qtype uint16
		isv6  bool
	)

	for _, nameserver := range config.NameServers {

		host, port, port_err := net.SplitHostPort(nameserver)

		if port_err != nil {
			host = nameserver
			IPAddr, rslv_err := net.ResolveIPAddr("ip", nameserver)

			if rslv_err != nil {
				continue
			}
			nameserver = IPAddr.String()
                        isv6 = isNsIPv6(nameserver)
			port = "53"

		} else {
			IPAddr, rslv_err := net.ResolveIPAddr("ip", host)

			if rslv_err != nil {
				continue
			}
			nameserver = IPAddr.String()
                        isv6 = isNsIPv6(nameserver)
		}

		for _, question := range config.Questions {

			query, qtypestr, qtype_err := net.SplitHostPort(question)

			if qtype_err != nil {
				query = question
				qtype = dns.TypeA

			} else {
				if k, ok := dns.StringToType[strings.ToUpper(qtypestr)]; ok {
					qtype = k
				} else {
					qtype = dns.TypeA
				}
			}

			jobs[index], err = newDNSMonitorHostJob(nameserver, host, port, isv6, query, qtype, &config)

			if err != nil {
				return nil, err
			}
			index++
		}
	}

	return jobs, nil
}

func isNsIPv6(nameserver string) bool {
     if strings.Contains(nameserver, ":") {
            return true
     } else {
	    return false
     }     
}