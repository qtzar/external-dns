package dnsme

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	api "github.com/huguesalary/dnsmadeeasy"
	"github.com/juju/ratelimit"
	"github.com/rancher/external-dns/providers"
	"github.com/rancher/external-dns/utils"
)

// DNSMEProvider Structure
type DNSMEProvider struct {
	dnsmeDomainID uint32
	dnsmeZone     string
	dnsmeServer   string
	dnsmeKey      string
	dnsmeSecret   string
	limiter       *ratelimit.Bucket
}

func init() {
	providers.RegisterProvider("dnsme", &DNSMEProvider{})
}

// Init provider
func (r *DNSMEProvider) Init(rootDomainName string) error {
	var domainID, keyName, secret, server, rawSandbox string
	var sandBox bool

	if domainID = os.Getenv("DNSME_DOMAINID"); len(domainID) == 0 {
		return fmt.Errorf("DNSME_DOMAINID is not set")
	}

	if keyName = os.Getenv("DNSME_KEY"); len(keyName) == 0 {
		return fmt.Errorf("DNSME_KEY is not set")
	}

	if secret = os.Getenv("DNSME_SECRET"); len(secret) == 0 {
		return fmt.Errorf("DNSME_SECRET is not set")
	}

	rawSandbox = os.Getenv("DNSME_SANDBOX")
	sandBox, err := strconv.ParseBool(rawSandbox)
	if err != nil {
		return fmt.Errorf("DNSME_SANDBOX is not set")
	}

	if sandBox {
		server = "https://api.sandbox.dnsmadeeasy.com/V2.0/dns/managed/"
	} else {
		server = "https://api.dnsmadeeasy.com/V2.0/dns/managed/"
	}

	//  DNSMadeEasy limit is 150 requests per 5 minute scrolling window
	doqps := (float64)(150.0 / 300.0)
	r.limiter = ratelimit.NewBucketWithRate(doqps, 100)

	u64domainID, err := strconv.ParseUint(domainID, 10, 32)
	if err != nil {
		fmt.Println(err)
	}

	r.dnsmeZone = rootDomainName
	r.dnsmeServer = server
	r.dnsmeKey = keyName
	r.dnsmeSecret = secret

	r.dnsmeDomainID = uint32(u64domainID)

	logrus.Infof("DNS Made Easy Configured %s with domain id '%s' and nameserver '%s'",
		r.GetName(), fmt.Sprint(r.dnsmeDomainID), r.dnsmeServer)

	return nil
}

// GetName of provider
func (*DNSMEProvider) GetName() string {
	return "DNS Made Easy"
}

// HealthCheck for provider
func (r *DNSMEProvider) HealthCheck() error {
	_, err := r.GetRecords()
	return err
}

// AddRecord to provider
func (r *DNSMEProvider) AddRecord(record utils.DnsRecord) error {
	logrus.Debugf("DNSME Adding Records")

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	for _, rec := range record.Records {
		name := r.parseName(record)
		logrus.Debugf("DNSME Adding Record: '%s %d %s %s'", name, record.TTL, record.Type, rec)

		newRecord := &api.Record{}
		newRecord.Type = record.Type
		newRecord.Name = name
		newRecord.Value = rec
		newRecord.GtdLocation = "DEFAULT"
		newRecord.Ttl = record.TTL

		r.limiter.Wait(1)
		result := client.AddRecord(r.dnsmeDomainID, newRecord)
		if result != nil {
			logrus.Errorf("Error: %s", result)
		}
	}

	return nil
}

// RemoveRecord from provider
func (r *DNSMEProvider) RemoveRecord(record utils.DnsRecord) error {
	logrus.Debugf("DNSME Removing Record '%s %s'", record.Fqdn, record.Type)

	name := r.parseName(record)
	r.limiter.Wait(1)
	records, err := r.getDomainRecordsByName(name, record.Type)
	if err != nil {
		return err
	}

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer
	for _, rec := range records {
		logrus.Debugf("DNSME Removing Record: '%s %d %s %d'", rec.Name, record.TTL, record.Type, rec.Id)

		r.limiter.Wait(1)
		result := client.DelRecord(r.dnsmeDomainID, rec.Id)
		if result != nil {
			logrus.Errorf("DNSME Remove Record Error: %+v", result)
		}
	}
	return nil
}

// UpdateRecord provider
func (r *DNSMEProvider) UpdateRecord(record utils.DnsRecord) error {
	logrus.Debugf("DNSME Updating Record '%s %s'", record.Fqdn, record.Type)
	err := r.RemoveRecord(record)
	if err != nil {
		return err
	}
	return r.AddRecord(record)
}

// GetRecords from provider
func (r *DNSMEProvider) GetRecords() ([]utils.DnsRecord, error) {
	logrus.Debugf("DNSME Getting Records")
	records := make([]utils.DnsRecord, 0)

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	r.limiter.Wait(1)
	result, err2 := client.GetDomainRecords(r.dnsmeDomainID)
	if err2 != nil {
		return records, fmt.Errorf("DNSMadeEasy API Failed: %v", err2)
	}

	logrus.Debugf("DNSME Retrieved %d Records.", len(result))

	for _, rec := range result {
		logrus.Debugf("DNSME Processing Retrieved Record : %s", rec.Name)

		found := false
		recFQDN := fmt.Sprintf("%s.%s", rec.Name, r.dnsmeZone)

		if rec.Type == "TXT" {
			rec.Value = strings.Replace(rec.Value, "\"", "", -1)
		}

		for i, re := range records {
			if re.Fqdn == recFQDN {
				found = true
				cont := append(re.Records, rec.Value)
				records[i] = utils.DnsRecord{
					Fqdn:    recFQDN,
					Records: cont,
					Type:    rec.Type,
					TTL:     rec.Ttl,
				}
			}
		}
		if !found {
			r := utils.DnsRecord{
				Fqdn:    recFQDN,
				Records: []string{rec.Value},
				Type:    rec.Type,
				TTL:     rec.Ttl,
			}
			records = append(records, r)
		}
	}
	return records, nil

}

// GetDomainRecordByName from providers
func (r *DNSMEProvider) getDomainRecordsByName(recordName string, recordType string) ([]*api.Record, error) {
	logrus.Debugf("DNSME Getting Domain Records by Name and Type")

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	req, err := http.NewRequest("GET", fmt.Sprintf("%s%d/records?recordName=%s&type=%s", client.Url, r.dnsmeDomainID, recordName, recordType), nil)
	if err != nil {
		logrus.Errorf("Error http : %s", err)
	}

	domainRecords := &api.DomainRecords{}
	err2 := r.request(req, domainRecords)
	if err2 != nil {
		logrus.Errorf("Error request : %s", err2)
	}

	logrus.Debugf("DNSME Record %+v", domainRecords.Records)

	return domainRecords.Records, err

}

func (r *DNSMEProvider) request(req *http.Request, object interface{}) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: transport}

	req.Header.Add("x-dnsme-apikey", r.dnsmeKey)
	requestDate := time.Now().UTC().Format(time.RFC1123)
	req.Header.Add("x-dnsme-requestdate", requestDate)

	h := hmac.New(sha1.New, []byte(r.dnsmeSecret))
	h.Write([]byte(requestDate))
	req.Header.Add("x-dnsme-hmac", fmt.Sprintf("%x", h.Sum(nil)))

	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Error Doing Request : %s", err)
		return err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	if resp.StatusCode >= 400 {
		apierr := &APIError{}
		json.Unmarshal(buf.Bytes(), apierr)
		apierr.Code = resp.StatusCode
		logrus.Errorf("API Error : %+v", apierr)
		return apierr
	}

	if buf.Len() > 0 {
		return json.Unmarshal(buf.Bytes(), object)
	}

	return nil
}

// APIError Represents an API Error. Code corresponds to the HTTP Status Code returned by the API.
// Messages is a list of error messages returned by the DNS Made Easy API
type APIError struct {
	Code     int      `json:"-"`
	Messages []string `json:"error"`
}

func (a *APIError) Error() string {
	return fmt.Sprintf("API Error. Code:%d Message:%s", a.Code, strings.Join(a.Messages, " "))
}

// parseName will remove the domain name and trailing . as DNSMadeEasy Does not want this
func (r *DNSMEProvider) parseName(record utils.DnsRecord) string {

	noDomain := strings.Replace(record.Fqdn, "."+r.dnsmeZone, "", -1)
	logrus.Infof("DNSME : Parsed Name : %s", noDomain)

	return noDomain
}
