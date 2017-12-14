package iptables

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/elastic/beats/libbeat/logp"
)

const (
	skip = errors.New("Skip this line")
)

// Iptables struct to handle parsing and reading out iptables metrics.
type Iptables struct {
	cmd  string
	args []string
}

func (ipt *Iptables) Run(table string) error {
	// Create the command to execute.
	cmd := exec.Command(ipt.cmd, "-t", table, ipt.args...)

	// Grab the stdout/stderr pipes so we can forward data to tcollectorbeat logs.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to obtain a lock on the stdout fd for command '%s': %s", ipt.cmd, err.Error())
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to obtain a lock on the stderr fd for command '%s': %s", ipt.cmd, err.Error())
	}

	// bufio readers are just simpler to work with, as the stdout/stderr readers can return incomplete lines from time to time, bufio ensures this doesn't happen.
	outReader := bufio.NewReader(stdout)
	errReader := bufio.NewReader(stderr)

	// Actually run the command now.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("the command '%s' failed to start: %s", ipt.cmd, err.Error())
	}

	// We need a wait group to async read from the stdout/stderr pipes.
	wg := sync.WaitGroup{}
	wg.Add(2)

	tbl := &Table{
		Name:   table,
		Chains: []*Chain{},
	}

	// Actually read the stderr data incase we have some info to tell the operator something is wrong.
	go func() {
		for {
			line, err := errReader.ReadString('\n')
			if err != nil {
				break
			}
			logp.Err("the command '%s' errored: %s", ipt.cmd, line)
		}
		wg.Done()
	}()

	// Actually read the stdout buffer and translate it into map objects and then append the data to the top level event.
	go func() {
		lastChain = &Chain{}
		for {
			line, err := outReader.ReadString('\n')
			if err != nil {
				break
			}

			chain, rule, err := parseLine(line)
			if err != nil && err != skip {
				logp.Err("the command '%s' returned invalid line data: '%s'", ipt.cmd, line)
				continue
			}

			switch {
			case chain != nil:
				if lastChain.Name != chain.Name {
					tbl.Chains = append(tbl.Chains, chain)
					lastChain = chain
				}
			case rule != nil:
				lastChain.Rules = append(lastChain.Rules, rule)
			}
		}
		wg.Done()
	}()

	// wait until stdout/stderr get EOF.
	wg.Wait()

	// clean up the command and pipes.
	if err := cmd.Wait(); err != nil {
		// log that we got a non 0 return code and skip writing this to es.
		return fmt.Errorf("the command '%s' exited with non-zero error code: %s", ipt.cmd, err.Error())
	}
}

// Table struct to handle the data contained in an individual iptables table.
type Table struct {
	Name   string
	Chains []*Chain
}

// Chain struct to hanlde the data contained in an individual iptables chain.
type Chain struct {
	Name       string
	Policy     string
	Packets    int64
	Bytes      int64
	References int64
	Rules      []*Rule
}

// Rule struct to handle the data contained in an individual iptables rule.
type Rule struct {
	Packets         int64
	Bytes           int64
	Target          string
	Protocol        string
	InterfaceIn     string
	InterfaceOut    string
	SourceAddr      net.IP
	DestinationAddr net.IP
	Comment         string
}

func parseLine(line string) (*Chain, *Rule, error) {
	switch {
	case strings.HasPrefix(line, "Chain"):
		chain, err := parseChain(line)
		if err != nil {
			return nil, nil, err
		}
		return chain, nil, nil
	case strings.HasPrefix(line, "pkts"):
		return nil, nil, skip
	default:
		rule, err := parseRule(line)
		if err != nil {
			return nil, nil, err
		}
		return nil, rule, nil
	}
}

func parseChain(line string) (*Chain, error) {
	builtInChainRE := regexp.MustCompile(`Chain (.*) \(policy (.*) ([0-9]+) packets, ([0-9]+) bytes\)`)
	customChainRE := regexp.MustCompile(`Chain (.*) \(([0-9]+) references\)`)

	if results := builtInChainRE.FindStringSubmatch(line); results != nil {
		pkts, err := strconv.ParseInt(results[3], 10, 64)
		if err != nil {
			return nil, err
		}

		bytes, err := strconv.ParseInt(results[4], 10, 64)
		if err != nil {
			return nil, err
		}

		return &Chain{
			Name:    results[1],
			Policy:  results[2],
			Packets: pkts,
			Bytes:   bytes,
		}, nil
	}

	if results := customChainRE.FindStringSubmatch(line); results != nil {
		refs, err := strconv.ParseInt(results[2], base, bitSize)
		if err != nil {
			return nil, err
		}

		return &Chain{
			Name:       results[1],
			References: refs,
		}, nil
	}

	return nil, skip
}

func parseRule(line string) (*Rule, error) {

}
