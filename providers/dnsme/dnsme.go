package dnsme

import (
	"fmt"
	"os"
	"time"
  "strconv"

	"github.com/Sirupsen/logrus"
  api "github.com/soniah/dnsmadeeasy"
	"github.com/rancher/external-dns/providers"
	"github.com/rancher/external-dns/utils"
)

type DNSMEProvider struct {
  dnsmeDomainId string
  dnsmeZone string
	dnsmeServer  string
	dnsmeKey string
	dnsmeSecret  string
}

func init() {
	providers.RegisterProvider("dnsme", &DNSMEProvider{})
}

func (r *DNSMEProvider) Init(rootDomainName string) error {
	var domainId, keyName, secret, server, raw_sandbox string
  var sandBox bool

  if domainId = os.Getenv("DNSME_DOMAINID"); len(domainId) == 0 {
		return fmt.Errorf("DNSME_DOMAINID is not set")
	}

	if keyName = os.Getenv("DNSME_KEY"); len(keyName) == 0 {
		return fmt.Errorf("DNSME_KEY is not set")
	}

	if secret = os.Getenv("DNSME_SECRET"); len(secret) == 0 {
		return fmt.Errorf("DNSME_SECRET is not set")
	}


  raw_sandbox = os.Getenv("DNSME_SANDBOX")
  sandbox, err := strconv.ParseBool(raw_sandbox)
  if err != nil {
    return fmt.Errorf("DNSME_SANDBOX is not set")
  }

	if sandBox {
		server = "https://api.sandbox.dnsmadeeasy.com/V2.0/"
	} else {
    server = "https://api.dnsmadeeasy.com/V2.0/"
  }

//TODO Rate Limiting
//  This limit is 150 requests per 5 minute scrolling window

  r.dnsmeZone = rootDomainName
  r.dnsmeDomainId = domainId
	r.dnsmeServer = server
	r.dnsmeKey = keyName
	r.dnsmeSecret = secret

	logrus.Infof("Configured %s with domain id '%s' and nameserver '%s'",
		r.GetName(), r.domainId, r.dnsmeServer)

	return nil
}

func (*DNSMEProvider) GetName() string {
	return "DNS Made Easy"
}

func (r *DNSMEProvider) HealthCheck() error {
	_, err := r.GetRecords()
	return err
}

func (r *DNSMEProvider) AddRecord(record utils.DnsRecord) error {
  logrus.Debugf("Adding Record '%s %s'", record.Fqdn, record.Type)

  client, err := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
  	if err != nil {
  		logrus.Fatalf("err: %v", err)
  	}

    client.URL = r.dnsmeServer

    for _, rec := range record.Records {
      logrus.Debugf("Adding RR: '%s %d %s %s'", record.Fqdn, record.TTL, record.Type, rec)
      cr := map[string]interface{}{
		    "name":  record.Fqdn,
		    "type":  record.Type,
		    "value": rec,
		    "ttl":   record.TTL,
	    }

	    result, err2 := client.CreateRecord(r.dnsmeDomainId, cr)

	    if err2 != nil {
		    logrus.Fatalf("Result: '%s' Error: %s", result, err2)
      }

	    logrus.Printf("Result: '%s'", result)
    }

	return nil
}

func (r *DNSMEProvider) RemoveRecord(record utils.DnsRecord) error {
	logrus.Debugf("Removing Record '%s %s'", record.Fqdn, record.Type)

  client, err := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
    if err != nil {
      logrus.Fatalf("err: %v", err)
    }

    client.URL = r.dnsmeServer

  	err2 := client.DeleteRecord(r.dnsmeDomainId, record.Fqdn)
  	if err2 != nil {
  		logrus.Fatalf("DeleteRecord result: %v", err2)
  	}
  	logrus.Print("Record Removed")

	return nil
}

func (r *DNSMEProvider) UpdateRecord(record utils.DnsRecord) error {
	err := r.RemoveRecord(record)
	if err != nil {
		return err
	}

	return r.AddRecord(record)
}

func (r *DNSMEProvider) GetRecords() ([]utils.DnsRecord, error) {
	records := make([]utils.DnsRecord, 0)
	list, err := r.list()
	if err != nil {
		return records, err
	}

OuterLoop:
	for _, rr := range list {
		if rr.Header().Class != dns.ClassINET {
			continue
		}

		rrFqdn := rr.Header().Name
		rrTTL := int(rr.Header().Ttl)
		var rrType string
		var rrValues []string
		switch rr.Header().Rrtype {
		case dns.TypeCNAME:
			rrValues = []string{rr.(*dns.CNAME).Target}
			rrType = "CNAME"
		case dns.TypeA:
			rrValues = []string{rr.(*dns.A).A.String()}
			rrType = "A"
		case dns.TypeAAAA:
			rrValues = []string{rr.(*dns.AAAA).AAAA.String()}
			rrType = "AAAA"
		case dns.TypeTXT:
			rrValues = rr.(*dns.TXT).Txt
			rrType = "TXT"
		default:
			continue // Unhandled record type
		}

		for idx, existingRecord := range records {
			if existingRecord.Fqdn == rrFqdn && existingRecord.Type == rrType {
				records[idx].Records = append(records[idx].Records, rrValues...)
				continue OuterLoop
			}
		}

		record := utils.DnsRecord{
			Fqdn:    rrFqdn,
			Type:    rrType,
			TTL:     rrTTL,
			Records: rrValues,
		}

		records = append(records, record)
	}

	return records, nil
}

func (r *DNSMEProvider) sendMessage(msg *dns.Msg) error {
	c := new(dns.Client)
	c.TsigSecret = map[string]string{r.tsigKeyName: r.tsigSecret}
	c.SingleInflight = true
	msg.SetTsig(r.tsigKeyName, dns.HmacMD5, 300, time.Now().Unix())
	resp, _, err := c.Exchange(msg, r.nameserver)
	if err != nil {
		return err
	}

	if resp != nil && resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Bad return code: %s", dns.RcodeToString[resp.Rcode])
	}

	return nil
}

func (r *DNSMEProvider) list() ([]dns.RR, error) {
	logrus.Debugf("Fetching records for '%s'", r.zoneName)
	t := new(dns.Transfer)
	t.TsigSecret = map[string]string{r.tsigKeyName: r.tsigSecret}

	m := new(dns.Msg)
	m.SetAxfr(r.zoneName)
	m.SetTsig(r.tsigKeyName, dns.HmacMD5, 300, time.Now().Unix())

	env, err := t.In(m, r.nameserver)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch records via AXFR: %v", err)
	}

	records := make([]dns.RR, 0)
	for e := range env {
		if e.Error != nil {
			logrus.Errorf("AXFR envelope error: %v", e.Error)
			continue
		}
		records = append(records, e.RR...)
	}

	return records, nil
}
