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

	//TODO Rate Limiting
	//  This limit is 150 requests per 5 minute scrolling window

	// Convert the domainID in to a uint
	u64domainID, err := strconv.ParseUint(domainID, 10, 32)
	if err != nil {
		fmt.Println(err)
	}

	r.dnsmeZone = rootDomainName
	r.dnsmeDomainID = uint32(u64domainID)
	r.dnsmeServer = server
	r.dnsmeKey = keyName
	r.dnsmeSecret = secret

	logrus.Infof("Configured %s with domain id '%s' and nameserver '%s'",
		r.GetName(), r.dnsmeDomainID, r.dnsmeServer)

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
	logrus.Debugf("Adding Record '%s %s'", record.Fqdn, record.Type)

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)

	client.Url = r.dnsmeServer

	for _, rec := range record.Records {
		logrus.Debugf("Adding RR: '%s %d %s %s'", record.Fqdn, record.TTL, record.Type, rec)

		newRecord := &api.Record{}
		newRecord.Type = record.Type
		newRecord.Name = record.Fqdn
		newRecord.Value = rec
		newRecord.GtdLocation = "DEFAULT"
		newRecord.Ttl = record.TTL

		result := client.AddRecord(r.dnsmeDomainID, newRecord)

		if result != nil {
			logrus.Fatalf("Error: %s", result)
		}

		logrus.Printf("Record Added")
	}

	return nil
}

// RemoveRecord from provider
func (r *DNSMEProvider) RemoveRecord(record utils.DnsRecord) error {
	logrus.Debugf("Removing Record '%s %s'", record.Fqdn, record.Type)

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	recordID, err := r.GetDomainRecordByName(record.Fqdn, record.Type)
	if err != nil {
		logrus.Fatalf("Error: %s", err)
	}

	result := client.DelRecord(r.dnsmeDomainID, recordID)
	if result != nil {
		logrus.Fatalf("DeleteRecord result: %v", result)
	}
	logrus.Print("Record Removed")

	return nil
}

// UpdateRecord provider
func (r *DNSMEProvider) UpdateRecord(record utils.DnsRecord) error {
	logrus.Debugf("Updating Record '%s %s'", record.Fqdn, record.Type)

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)

	client.Url = r.dnsmeServer

	for _, rec := range record.Records {
		logrus.Debugf("Updating RR: '%s %d %s %s'", record.Fqdn, record.TTL, record.Type, rec)

		newRecord := &api.Record{}
		newRecord.Type = record.Type
		newRecord.Name = record.Fqdn
		newRecord.Value = rec
		newRecord.GtdLocation = "DEFAULT"
		newRecord.Ttl = record.TTL

		result := client.UpdRecord(r.dnsmeDomainID, newRecord)

		if result != nil {
			logrus.Fatalf("Error: %s", result)
		}

		logrus.Printf("TRecord Updated")
	}

	return nil
}

// GetRecords from provider
func (r *DNSMEProvider) GetRecords() ([]utils.DnsRecord, error) {
	logrus.Debugf("Getting Records")
	records := make([]utils.DnsRecord, 0)

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	result, err2 := client.GetDomainRecords(r.dnsmeDomainID)
	if err2 != nil {
		return records, fmt.Errorf("DNSMadeEasy API Failed: %v", err2)
	}

	for _, rec := range result {

		recFQDN := utils.Fqdn(rec.Name)
		recTTL := rec.Ttl
		recType := rec.Type
		var recValueArray = []string{}
		recValueArray = append(recValueArray, rec.Value)

		record := utils.DnsRecord{Fqdn: recFQDN, Records: recValueArray, Type: recType, TTL: recTTL}
		records = append(records, record)
	}
	return records, nil

}

// GetDomainRecordByName from providers
func (r *DNSMEProvider) GetDomainRecordByName(recordName string, recordType string) (uint32, error) {
	logrus.Debugf("Getting Record ID by Name and Type")

	client := api.NewClient(r.dnsmeKey, r.dnsmeSecret)
	client.Url = r.dnsmeServer

	req, err := http.NewRequest("GET", fmt.Sprintf("%s%d/records?recordName=%s&type=%s", client.Url, r.dnsmeDomainID, recordName, recordType), nil)
	if err != nil {
		logrus.Fatalf("Error: %s", err)
	}

	record := &api.Record{}
	err = r.request(req, record)

	return record.Id, err
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
		return err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	if resp.StatusCode >= 400 {
		apierr := &APIError{}
		json.Unmarshal(buf.Bytes(), apierr)
		apierr.Code = resp.StatusCode

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
