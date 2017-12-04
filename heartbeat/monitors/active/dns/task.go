package dns

import (
	"errors"
	"fmt"
	"github.com/elastic/beats/heartbeat/monitors"
	"github.com/elastic/beats/heartbeat/reason"
	"github.com/elastic/beats/libbeat/common"
	"github.com/miekg/dns"
)

func newDNSMonitorHostJob(
	nameserver string,
	host string,
	port string,
	isv6 bool,
	question string,
	qtype uint16,
	config *Config,
) (monitors.Job, error) {
	typ := config.Name
	qtypestr := dns.TypeToString[qtype]

	jobName := fmt.Sprintf("%v@%v@%v@%v", typ, nameserver, question, qtypestr)

	fields := common.MapStr{
		"host":       host,
		"question":   question,
		"ip":         nameserver,
		"qtype":      qtypestr,
		"port":       port,
	}

	return monitors.MakeSimpleJob(jobName, typ, func() (common.MapStr, error) {
		event, err := execQuery(nameserver, port, isv6, question, qtype)
		if event == nil {
			event = common.MapStr{}
		}
		event.Update(fields)
		return event, err
	}), nil
}

func execQuery(nameserver string, port string, isv6 bool, question string, qtype uint16) (common.MapStr, reason.Reason) {

	dns_msg := new(dns.Msg)
	dns_msg.Id = dns.Id()
	dns_msg.RecursionDesired = true
	dns_msg.Question = make([]dns.Question, 1)

	dns_msg.Question[0] = dns.Question{dns.Fqdn(question), qtype, dns.ClassINET}
	dns_client := new(dns.Client)
	var nameserver_port string

	if isv6 {
		dns_client.Net = "udp6"
                nameserver_port = "[" + nameserver + "]:" + port
	}else{
	        nameserver_port = nameserver + ":" + port
        }

	in, rtt, err := dns_client.Exchange(dns_msg, nameserver_port)

	event := common.MapStr{
		"response": common.MapStr{
			"in": in,
		},
		"nameserver": nameserver_port,
		"question":   question,
		"rtt":        rtt,
	}

	if len(in.Answer) == 0 {
		resp_err := errors.New("Zero Answers")
		return event, reason.IOFailed(resp_err)
	}

	if err != nil {
		return event, reason.IOFailed(err)
	}

	return event, nil
}
