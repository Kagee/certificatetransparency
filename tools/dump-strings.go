// This program prints most strings from certificates in a log entries file.

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"github.com/agl/certificatetransparency"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	in, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer in.Close()

	entriesFile := certificatetransparency.EntriesFile{in}

	outputLock := new(sync.Mutex)

	entriesFile.Map(func(ent *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}

		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}
		// we output all "string" fields in the Certificate-struct and substructs
		output := cert.Subject.CommonName + "\n"
		for _, san := range cert.Subject.Organization {
			output += san + "\n"
		}
		for _, san := range cert.Subject.OrganizationalUnit {
                        output += san + "\n"
                }
		for _, san := range cert.Subject.Names {
			if str, ok := san.Value.(string); ok {
			    output += str + "\n"
			}
		}

		output += cert.Issuer.CommonName + "\n"
                for _, san := range cert.IssuingCertificateURL {
                        output += san + "\n"
                }
                for _, san := range cert.OCSPServer {
                        output += san + "\n"
                }
		for _, san := range cert.DNSNames {
			output += san + "\n"
		}
		for _, san := range cert.EmailAddresses {
                        output += san + "\n"
                }
		for _, san := range cert.PermittedDNSDomains {
                        output += san + "\n"
                }
		for _, san := range cert.CRLDistributionPoints {
                        output += san + "\n"
                }
		outputLock.Lock()
		fmt.Print(output)
		outputLock.Unlock()
	})
}
