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

	//	fmt.Printf("newDNSMonitorHostJob: nameserver[%v] host[%v] port[%v] question[%v] qtype[%v]\n", nameserver, host, port, question, qtype)

	fields := common.MapStr{
		"nameserver": nameserver,
		"question":   question,
		"ip":         host,
		"qtype":      qtypestr,
		"port":       port,
	}

	return monitors.MakeSimpleJob(jobName, typ, func() (common.MapStr, error) {
		event, err := execQuery(nameserver, isv6, question, qtype)
		if event == nil {
			event = common.MapStr{}
		}
		event.Update(fields)
		return event, err
	}), nil
}

func execQuery(nameserver string, isv6 bool, question string, qtype uint16) (common.MapStr, reason.Reason) {
	//     fmt.Printf("beginning: in:nameserver[%v] isv6[%v] question[%v] type[%v]\n", nameserver, isv6, question, qtype)
	dns_msg := new(dns.Msg)
	dns_msg.Id = dns.Id()
	dns_msg.RecursionDesired = true
	dns_msg.Question = make([]dns.Question, 1)

	dns_msg.Question[0] = dns.Question{dns.Fqdn(question), qtype, dns.ClassINET}
	dns_client := new(dns.Client)

	if isv6 {
		dns_client.Net = "udp6"
	}

	in, rtt, err := dns_client.Exchange(dns_msg, nameserver)

	event := common.MapStr{
		"response": common.MapStr{
			"in": in,
		},
		"nameserver": nameserver,
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
