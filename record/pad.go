package record

import (
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

var (
	errCNAMERecordIsExist = errors.New("CNAME record is exists")
	errRecordsIsExist     = errors.New("records is exists")
)

type pad struct {
	records map[string][]string
}

func NewPad(r map[string][]string) *pad {
	return &pad{
		records: r,
	}
}

func (s *pad) Records() map[string][]string {
	return s.records
}

func (s *pad) deleteRecords(domain string) error {
	prefix, err := GetKeyDomain(domain)
	if err != nil {
		return err
	}

	for key := range s.records {
		if strings.HasPrefix(key, prefix) {
			delete(s.records, key)
		}
	}

	return nil
}

func (s *pad) deleteRecord(domain string, rtype uint16) error {
	if rtype == dns.TypeANY {
		return s.deleteRecords(domain)
	}

	key, err := GetKey(domain, rtype)
	if err != nil {
		return err
	}

	delete(s.records, key)
	return nil
}

func (s *pad) hasRecords(domain string) (bool, error) {
	prefix, err := GetKeyDomain(domain)
	if err != nil {
		return false, err
	}

	for key := range s.records {
		if strings.HasPrefix(key, prefix) {
			return true, nil
		}
	}

	return false, nil
}

func (s *pad) storeRecord(rr dns.RR) error {
	// CNAME の場合、既存で同名レコードがあった場合は保存できない
	if rr.Header().Rrtype == dns.TypeCNAME {
		exist, err := s.hasRecords(rr.Header().Name)
		if err != nil {
			return err
		}
		if exist {
			return errRecordsIsExist
		}
	}

	// 同名の CNAME があった場合は保存できない
	key, err := GetKey(rr.Header().Name, dns.TypeCNAME)
	if err != nil {
		return nil
	}
	if _, ok := s.records[key]; ok {
		return errCNAMERecordIsExist
	}

	// ここから、保存
	key, err = GetKey(rr.Header().Name, rr.Header().Rrtype)
	if err != nil {
		return err
	}

	// gaurd dup.
	// Any duplicate RRs will be silently ignored by the primary master.
	if slices.Contains(s.records[key], rr.String()) {
		return nil
	}

	s.records[key] = append(s.records[key], rr.String())
	return nil
}

func (s *pad) omitRecord(rr dns.RR) error {
	key, err := GetKey(rr.Header().Name, rr.Header().Rrtype)
	if err != nil {
		return nil
	}

	values, ok := s.records[key]
	if !ok {
		return nil
	}

	newRWRecords := make([]string, 0)
	for _, v := range values {
		// RRを復元する
		tmp, err := dns.NewRR(v)
		if err != nil {
			return err
		}
		// この時、リクエストは ClassNONE、TTL=0としてやってくる。tmpの値を変更し、文字列比較する
		tmp.Header().Ttl = 0
		tmp.Header().Class = dns.ClassNONE
		if strings.ToLower(tmp.String()) == strings.ToLower(rr.String()) {
			slog.Info("omitRecord", "record", strings.ToLower(rr.String()))
			continue
		}

		// save original
		newRWRecords = append(newRWRecords, v)
	}

	s.records[key] = newRWRecords

	return nil
}

func (s *pad) UpdateRecord(r dns.RR, q *dns.Question) error {
	header := r.Header()

	slog.Info("updateRecord", "RR", r.String())

	if _, ok := dns.IsDomainName(header.Name); ok {
		if header.Class == dns.ClassANY {
			if header.Rdlength == 0 { // Delete record
				// RFC2136. 2.5.2 - Delete An RRset
				/*
					One RR is added to the Update Section whose NAME and TYPE are those
					of the RRset to be deleted.  TTL must be specified as zero (0) and is
					otherwise not used by the primary master.  CLASS must be specified as
					ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
					If no such RRsets exist, then this Update RR will be silently ignored
					by the primary master.
				*/
				/*
				   One RR is added to the Update Section whose NAME is that of the name
				   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
				   be specified as zero (0) and is otherwise not used by the primary
				   master.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
				   and RDATA must therefore be empty.  If no such RRsets exist, then
				   this Update RR will be silently ignored by the primary master.
				*/
				if err := s.deleteRecord(header.Name, header.Rrtype); err != nil {
					return err
				}
			}
		} else if header.Class == dns.ClassNONE {
			if header.Ttl == 0 {
				// RFC2136. 2.5.4 - Delete An RR From An RRset
				if err := s.omitRecord(r); err != nil {
					return err
				}
			}
		} else if header.Class == dns.ClassINET {
			// RFC2136. 2.5.1 - Add To An RRset
			/*
				RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
				and RDATA are those being added, and CLASS is the same as the zone
				class.  Any duplicate RRs will be silently ignored by the primary
				master.
			*/
			if err := s.storeRecord(r); err != nil {
				return err
			}
		}
	}
	return nil
}
