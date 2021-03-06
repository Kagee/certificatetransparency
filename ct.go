// Package certificatetransparency implements some helper functions for reading
// and processing log entries from a Certificate Transparency log.
//
// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-12
package certificatetransparency

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

const (
	logVersion           = 0
	certificateTimestamp = 0
	treeHash             = 1
	hashSHA256           = 4
	sigECDSA             = 3
)

// Log represents a public log.
type Log struct {
	Root string
	Key  *ecdsa.PublicKey
}

// NewLog creates a new Log given the base URL of a public key and its public
// key in PEM format.
func NewLog(url, pemPublicKey string) (*Log, error) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil {
		return nil, errors.New("certificatetransparency: no PEM block found in public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificatetransparency: only ECDSA keys supported at the current time")
	}

	return &Log{url, ecdsaKey}, nil
}

const pilotKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT
DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==
-----END PUBLIC KEY-----`

const DigiCertLogServerPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCF
RkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==
-----END PUBLIC KEY-----
`

// PilotLog is a *Log representing the pilot log run by Google.
var PilotLog *Log
var DigiCertLogServerLog *Log

func init() {
	PilotLog, _ = NewLog("http://ct.googleapis.com/pilot", pilotKeyPEM)
	DigiCertLogServerLog, _ = NewLog("https://ct1.digicert-ct.com/log", DigiCertLogServerPEM)
}

// SignedTreeHead contains a parsed signed tree-head structure.
type SignedTreeHead struct {
	Size      uint64    `json:"tree_size"`
	Time      time.Time `json:"-"`
	Hash      []byte    `json:"sha256_root_hash"`
	Signature []byte    `json:"tree_head_signature"`
	Timestamp uint64    `json:"timestamp"`
}

type LogOperator struct {
	Name	string	`json:"name"`
	Id	uint64	`json:"id"`
}

type LogData struct {
	Desc	string	`json:"description"` // "description": "Google 'Pilot' log",
	Key	string	`json:"key"` // "key": "MFkwEwYHKoZIzj0C....o==",
	URL	string	`json:"url"` // "url": "ct.googleapis.com/pilot",
	MMD	uint64	`json:"maximum_merge_delay"`// "maximum_merge_delay": 86400,
	OperatorId []uint64 `json:"operated_by"` // "operated_by": [0]
	OperatorName	string
	PublicLog	*Log
	SafeFileName	string
}

type LogList struct {
	OperatorList	[]LogOperator	`json:"operators"`
	Logs		[]LogData		`json:"logs"`
	OperatorMap	map[uint64]string
}

func GetAllLogsList() (*LogList, error) {
	resp, err := http.Get("https://www.certificate-transparency.org/known-logs/all_logs_list.json?attredirects=0&d=1")
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                return nil, errors.New("certificatetransparency:GetAllLogsList() error from server")
        }
        if resp.ContentLength == 0 {
                return nil, errors.New("certificatetransparency:GetAllLogsList() body unexpectedly missing")
        }
        if resp.ContentLength > 1<<16 {
                return nil, errors.New("certificatetransparency:GetAllLogsList() body too large")
        }
        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                return nil, err
        }
        logs := new(LogList)
        if err := json.Unmarshal(data, &logs); err != nil {
                return nil, err
        }

        const BEGIN = `-----BEGIN PUBLIC KEY-----
`
        const END = `
-----END PUBLIC KEY-----`

	logs.OperatorMap = make(map[uint64]string)
	for _, operator := range logs.OperatorList {
		logs.OperatorMap[operator.Id] = operator.Name
	}
	SafeNameRe := regexp.MustCompile("[^0-9A-Za-z\\.]") 
	//for _, log := range logs.Logs {
	//	log.SafeFileName = SafeNameRe.ReplaceAllString(log.URL, "_") + ".log"
	//}
	for i, _ := range logs.Logs {
	//for i := 0; i < len(logs.Logs); i++ {
		logs.Logs[i].SafeFileName = SafeNameRe.ReplaceAllString(logs.Logs[i].URL, "_") + ".log"
		operatorNames := []string{}
		for _, Id := range logs.Logs[i].OperatorId {
			operatorNames = append(operatorNames, logs.OperatorMap[Id])
		}
		logs.Logs[i].OperatorName = strings.Join(operatorNames, ", ")
		logPEM := BEGIN + logs.Logs[i].Key + END
		logs.Logs[i].PublicLog, _ = NewLog("https://" + logs.Logs[i].URL, logPEM)
	}
	return logs, nil
}

// GetSignedTreeHead fetches a signed tree-head and verifies the signature.
func (log *Log) GetSignedTreeHead() (*SignedTreeHead, error) {
	// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-4.3
	var resp *http.Response
	var err error
	if strings.HasPrefix("https://ct.gdca.com.cn", log.Root) ||
		strings.HasPrefix("https://ctlog.gdca.com.cn", log.Root) ||
		strings.HasPrefix("https://ct.izenpe.com", log.Root) {
		// Skip verification of HTTPS certificates for these logs
		fmt.Printf("certificatetransparency:WARNING: Not verifying HTTPs certificate for any downloads from log %s\n", log.Root)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
		}
		InsecureClient := &http.Client{Transport: tr}
		resp, err = InsecureClient.Get(log.Root + "/ct/v1/get-sth")
	} else {
		resp, err = http.Get(log.Root + "/ct/v1/get-sth")
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("certificatetransparency: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("certificatetransparency: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<16 {
		return nil, errors.New("certificatetransparency: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	head := new(SignedTreeHead)
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}

	head.Time = time.Unix(int64(head.Timestamp/1000), int64(head.Timestamp%1000))

	// See https://tools.ietf.org/html/rfc5246#section-4.7
	if len(head.Signature) < 4 {
		return nil, errors.New("certificatetransparency: signature truncated")
	}
	if head.Signature[0] != hashSHA256 {
		return nil, errors.New("certificatetransparency: unknown hash function")
	}
	if head.Signature[1] != sigECDSA {
		return nil, errors.New("certificatetransparency: unknown signature algorithm")
	}

	signatureBytes := head.Signature[4:]
	var sig struct {
		R, S *big.Int
	}

	if signatureBytes, err = asn1.Unmarshal(signatureBytes, &sig); err != nil {
		return nil, errors.New("certificatetransparency: failed to parse signature: " + err.Error())
	}
	if len(signatureBytes) > 0 {
		return nil, errors.New("certificatetransparency: trailing garbage after signature")
	}

	// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5
	signed := make([]byte, 2+8+8+32)
	x := signed
	x[0] = logVersion
	x[1] = treeHash
	x = x[2:]
	binary.BigEndian.PutUint64(x, head.Timestamp)
	x = x[8:]
	binary.BigEndian.PutUint64(x, head.Size)
	x = x[8:]
	copy(x, head.Hash)

	h := sha256.New()
	h.Write(signed)
	digest := h.Sum(nil)

	if !ecdsa.Verify(log.Key, digest, sig.R, sig.S) {
		return nil, errors.New("certificatetransparency: signature verification failed")
	}

	return head, nil
}

type LogEntryType uint16

const (
	X509Entry    LogEntryType = 0
	PreCertEntry LogEntryType = 1
)

type RawEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

func (ent *RawEntry) writeTo(out io.Writer) error {
	var buf bytes.Buffer
	z, err := flate.NewWriter(&buf, 8)
	if err != nil {
		return err
	}
	if err := binary.Write(z, binary.LittleEndian, uint32(len(ent.LeafInput))); err != nil {
		return err
	}
	if _, err := z.Write(ent.LeafInput); err != nil {
		return err
	}
	if err := binary.Write(z, binary.LittleEndian, uint32(len(ent.ExtraData))); err != nil {
		return err
	}
	if _, err := z.Write(ent.ExtraData); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}

	bytes := buf.Bytes()
	if err := binary.Write(out, binary.LittleEndian, uint32(len(bytes))); err != nil {
		return err
	}
	if _, err := out.Write(bytes); err != nil {
		return err
	}

	return nil
}

type entries struct {
	Entries []RawEntry `json:"entries"`
}

// GetEntries returns a series of consecutive log entries from the starting
// index up to, at most, the end index (which may be included). The log may
// choose to return fewer than the requested number of log entires and this is
// not considered an error.
func (log *Log) GetEntries(start, end uint64) ([]RawEntry, error) {
	var resp *http.Response
        var err error
        if strings.HasPrefix("https://ct.gdca.com.cn", log.Root) ||
                strings.HasPrefix("https://ctlog.gdca.com.cn", log.Root) ||
                strings.HasPrefix("https://ct.izenpe.com", log.Root) {
                // Skip verification of HTTPS certificates for these logs
		// Not printing warning, should have been printed by GetSignedTreeHead
                fmt.Printf("certificatetransparency:WARNING: Not verifying HTTPs certificate for log %s", log.Root)
                tr := &http.Transport{
                        TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
                }
                InsecureClient := &http.Client{Transport: tr}
                resp, err = InsecureClient.Get(fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", log.Root, start, end))
        } else {
                resp, err = http.Get(fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", log.Root, start, end))
        }

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("certificatetransparency: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("certificatetransparency: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<31 {
		return nil, errors.New("certificatetransparency: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ents entries
	if err := json.Unmarshal(data, &ents); err != nil {
		return nil, err
	}

	return ents.Entries, nil
}

// OperationStatus contains the current state of a large operation (i.e.
// download or tree hash).
type OperationStatus struct {
	// Start contains the requested starting index of the operation.
	Start uint64
	// Current contains the greatest index that has been processed.
	Current uint64
	// Length contains the total number of entries.
	Length uint64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// will be compressed and written to out in a format suitable for using with
// EntriesFile. It returns the new starting index (i.e.  start + the number of
// entries downloaded).
func (log *Log) DownloadRange(out io.Writer, status chan<- OperationStatus, start, upTo uint64) (uint64, error) {
	if status != nil {
		defer close(status)
	}

	done := start
	for done < upTo {
		if status != nil {
			status <- OperationStatus{start, done, upTo}
		}

		max := done + 2000
		if max >= upTo {
			max = upTo - 1
		}
		ents, err := log.GetEntries(done, max)
		if err != nil {
			return done, err
		}

		for _, ent := range ents {
			if err := ent.writeTo(out); err != nil {
				return done, err
			}
			done++
		}
	}

	return done, nil
}
