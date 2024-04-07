package record

import (
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

func GetKeyDomain(domain string) (string, error) {
	if _, ok := dns.IsDomainName(domain); !ok {
		err := errors.New("Invailid domain: " + domain)
		slog.Error(err.Error())
		return "", err
	}
	labels := dns.SplitDomainName(domain)

	// Reverse domain, starting from top-level domain
	slices.Reverse(labels)

	reverse_domain := strings.ToLower(strings.Join(labels, "."))
	return reverse_domain, nil
}

func GetKey(domain string, rtype uint16) (string, error) {
	reverse_domain, err := GetKeyDomain(domain)
	if err != nil {
		return "", err
	}

	r := strings.Join([]string{reverse_domain, dns.Type(rtype).String()}, "_")
	return r, nil
}
