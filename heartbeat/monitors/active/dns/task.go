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
		"host":     host,
		"question": question,
		"ip":       nameserver,
		"qtype":    qtypestr,
		"port":     port,
    }

	settings := monitors.MakeJobSetting(jobName).WithFields(fields)

	// return monitors.MakeSimpleJob(jobName, typ, func() (common.MapStr, error) {
	return monitors.MakeSimpleJob(settings, func() (common.MapStr, error) {
		event, err := execQuery(nameserver, port, isv6, question, qtype)
		if event == nil {
			event = common.MapStr{}
		}
		event.Update(fields)
		return event, err
	}), nil
}

func execQuery(nameserver string, port string, isv6 bool, question string, qtype uint16) (common.MapStr, reason.Reason) {

	dnsMsg := new(dns.Msg)
	dnsMsg.Id = dns.Id()
	dnsMsg.RecursionDesired = true
	dnsMsg.Question = make([]dns.Question, 1)

	dnsMsg.Question[0] = dns.Question{dns.Fqdn(question), qtype, dns.ClassINET}
	dnsClient := new(dns.Client)
	var nameserverPort string

	if isv6 {
		dnsClient.Net = "udp6"
		nameserverPort = "[" + nameserver + "]:" + port
	} else {
		nameserverPort = nameserver + ":" + port
	}

	in, rtt, err := dnsClient.Exchange(dnsMsg, nameserverPort)

	event := common.MapStr{
		"response": common.MapStr{
			"in": in,
		},
		"nameserver": nameserverPort,
		"question":   question,
		"rtt":        rtt,
	}

	if in != nil && len(in.Answer) == 0 {
		respErr := errors.New("Zero Answers")
		return event, reason.IOFailed(respErr)
	}

	if err != nil {
		return event, reason.IOFailed(err)
	}

	return event, nil
}
