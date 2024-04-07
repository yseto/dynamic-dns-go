package zone

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yseto/dynamic-dns-go/record"
)

type Zone struct {
	zoneName  string
	nsName    string
	localAddr string

	filename string
	mtime    int64

	records map[string][]string

	mu sync.Mutex

	allowCIDR string
}

type Dic struct {
	Domain  string   `json:"domain"`
	Records []string `json:"records"`
}

func New(zoneName, nsName, filename, localAddr, allowCIDR string) (*Zone, error) {
	st, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	return &Zone{
		zoneName:  zoneName,
		nsName:    nsName,
		localAddr: localAddr,

		filename: filename,
		mtime:    st.ModTime().Unix(),

		records: map[string][]string{},

		allowCIDR: allowCIDR,
	}, nil
}

func (z *Zone) ReadDB() error {
	f, err := os.Open(z.filename)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		var v Dic
		if err := dec.Decode(&v); err == io.EOF {
			break // done decoding file
		} else if err != nil {
			return err
		}
		z.records[v.Domain] = v.Records
	}
	return nil
}

func (z *Zone) writeDB(content map[string][]string) error {
	f, err := os.Create(z.filename)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	for k, v := range content {
		b, err := json.Marshal(Dic{Domain: k, Records: v})
		if err != nil {
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if f.Close() != nil {
		return err
	}

	z.records = maps.Clone(content)
	z.mtime = time.Now().Unix()

	return nil
}

func (z *Zone) getRecord(qName string, qQtype uint16) ([]dns.RR, error) {
	var matchedRecords []string
	if qQtype == dns.TypeANY {
		// ANY 検索
		prefix, err := record.GetKeyDomain(qName)
		if err != nil {
			return nil, err
		}

		for key := range z.records {
			if strings.HasPrefix(key, prefix) {
				matchedRecords = append(matchedRecords, z.records[key]...)
			}
		}
	} else {
		// タイプ指定
		key, err := record.GetKey(qName, qQtype)
		if err != nil {
			return nil, err
		}
		matchedRecords = append(matchedRecords, z.records[key]...)
	}

	tmpqName := strings.ToLower(qName)

	if len(matchedRecords) == 0 {
		err := fmt.Errorf("Record not found, domain: %s, type: %s", tmpqName, dns.Type(qQtype).String())
		slog.Error("Record not found", "Name", tmpqName, "Type", dns.Type(qQtype).String())
		return nil, err
	}

	var rr []dns.RR
	for _, v := range matchedRecords {
		tmp, err := dns.NewRR(v)
		if err != nil {
			return nil, err
		}

		if strings.ToLower(tmp.Header().Name) == tmpqName {
			rr = append(rr, tmp)
		}
	}
	return rr, nil
}

func (z *Zone) axfrRecord() ([]dns.RR, error) {
	var matchedRecords []string
	for key := range z.records {
		matchedRecords = append(matchedRecords, z.records[key]...)
	}

	var rr []dns.RR

	nsRR, aRR := z.nsRR()
	rr = append(rr, z.soaRR(), nsRR, aRR)

	for _, v := range matchedRecords {
		tmp, err := dns.NewRR(v)
		if err != nil {
			return nil, err
		}

		rr = append(rr, tmp)
	}

	rr = append(rr, z.soaRR())

	return rr, nil
}

func (z *Zone) HandleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	defer w.WriteMsg(m) // nolint

	// tsig doc is rfc2845
	// TSIG 署名がない場合、TSIG 署名のエラーの場合、更新等を許可しない
	var invalidTsig = true
	if tsig := r.IsTsig(); tsig != nil && w.TsigStatus() == nil {
		defer m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
		invalidTsig = false
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			slog.Info("Question", "Name", strings.ToLower(q.Name), "Type", dns.Type(q.Qtype).String())

			qZone := strings.ToLower(q.Name) == strings.ToLower(z.zoneName)
			if qZone && q.Qtype == dns.TypeNS {
				nsRR, aRR := z.nsRR()
				m.Answer = append(m.Answer, nsRR)
				m.Extra = append(m.Extra, aRR)
				continue
			}

			if qZone && q.Qtype == dns.TypeSOA {
				m.Answer = append(m.Answer, z.soaRR())
				continue
			}

			// AXFR 転送は、TSIGを必要とする
			// CNAME 判定、個別のタイプによる判定の前に入れる
			if qZone && q.Qtype == dns.TypeAXFR {
				if invalidTsig {
					slog.Warn("TSIG Error")
					m.Rcode = dns.RcodeNotAuth
					return
				}
				// TODO https://www.rfc-editor.org/rfc/rfc8945#section-5.3.1-1
				m.Authoritative = true
				if rrs, e := z.axfrRecord(); e == nil {
					m.Answer = rrs
				}
				continue
			}

			if rrs, e := z.getRecord(q.Name, q.Qtype); e == nil {
				m.Answer = append(m.Answer, rrs...)
				continue
			}

			/*
				https://jprs.jp/tech/material/rfc/RFC1034-ja.txt

				CNAME RRは、DNSソフトウェアに特別な動作を生じさせる。ネームサーバーが
				ドメイン名に関連づけられたリソースの集合から要求されたRRを発見することに
				失敗した場合、リソースの集合がクラスの一致するCNAMEレコードで構成されて
				いないかを確認する。もしそうであれば、ネームサーバーは応答にCNAMEレコード
				を含め、CNAMEレコードのデータフィールドで指定されたドメイン名で問い合わせを
				再開する。このルールには例外が一つあり、タイプCNAMEに一致する問い合わせは
				再開しない。

				例えば、ネームサーバーはUSC-ISIC.ARPAのタイプAを要求する問い合わせを処理中で、
				以下のリソースレコードを持っていると仮定する。

				    USC-ISIC.ARPA   IN      CNAME   C.ISI.EDU

				    C.ISI.EDU       IN      A       10.0.0.52

				タイプAの問い合わせへの応答では、これら両方のRRが返されるだろう。一方、
				タイプCNAMEまたはタイプ*の問い合わせにはCNAMEだけが返されるべきである。
			*/
			if q.Qtype != dns.TypeCNAME {
				// 初回は、CNAME検索をする
				var qName = q.Name
				var qQtype = dns.TypeCNAME
			labelcname:
				if rrs, e := z.getRecord(qName, qQtype); e == nil {
					for _, rr := range rrs {
						// CNAME もしくは、問い合わせがあったタイプの結果でなければ、continue
						// CNAME多段の場合があるので、CNAME or 問い合わせた結果。で検索したいので、
						// 問い合わせがあったタイプの結果かどうかは、ANYで検索する
						if !slices.Contains([]uint16{dns.TypeCNAME, q.Qtype}, rr.Header().Rrtype) {
							continue
						}
						m.Answer = append(m.Answer, rr)

						// CNAME の時（初回） or 多段の時は、検索をもう一度行う
						if rr.Header().Rrtype == dns.TypeCNAME && strings.HasSuffix(rr.(*dns.CNAME).Target, z.zoneName) {
							qName = rr.(*dns.CNAME).Target
							qQtype = dns.TypeANY // ここで ANY で対応する
							goto labelcname
						}
					}
					continue
				}
			}
		}

	case dns.OpcodeUpdate:
		z.mu.Lock()
		defer z.mu.Unlock()

		if z.allowCIDR != "" {
			prefix := netip.MustParsePrefix(z.allowCIDR)

			if host, _, err := net.SplitHostPort(w.RemoteAddr().String()); err != nil || !prefix.Contains(netip.MustParseAddr(host)) {
				slog.Warn("Request Addr Error")
				m.Rcode = dns.RcodeRefused
				return
			}
		}

		if invalidTsig {
			// TSIG 署名がない場合、TSIG 署名のエラーの場合、更新許可しない
			slog.Warn("TSIG Error")
			m.Rcode = dns.RcodeNotAuth
			return
		}

		// padで作業する
		pad := record.NewPad(z.records)

		for _, question := range r.Question {
			for _, rr := range r.Ns {
				if err := pad.UpdateRecord(rr, &question); err != nil {
					slog.Error("Failed updateRecord", "detail", err.Error())
					m.Rcode = dns.RcodeRefused
					return
				}
			}
		}

		if err := z.writeDB(pad.Records()); err != nil {
			slog.Error("writeDB", "detail", err.Error())
			m.Rcode = dns.RcodeRefused
			return
		}

		slog.Info("updateed")
	}
}

func (z *Zone) soaRR() dns.RR {
	soaRR, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN SOA localhost. nobody.  %d 28800 7200 2419200 1200", z.zoneName, int32(z.mtime)))
	return soaRR
}

func (z *Zone) nsRR() (dns.RR, dns.RR) {
	nsRR, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN NS %s", z.zoneName, z.nsName))
	aRR, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A %s", z.nsName, z.localAddr))
	return nsRR, aRR
}
