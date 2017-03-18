// This program prints most strings from certificates in a log entries file.

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"sync"
    "strings"
	"github.com/agl/certificatetransparency"
)

var (
    version string = "0.2-no-only"
)

// returnStringIfDotNO
func ifno(strToTest string) string {
  if strings.Contains(strToTest, ".no") {
    return strToTest;
  }
  return "";
}

func main() {
	if len(os.Args) != 2 {
        fmt.Fprintf(os.Stderr, "%s version %s\n", os.Args[0], version)
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
		output := ""
		output += ifno(cert.Subject.CommonName + "\n")
		for _, san := range cert.Subject.Organization {
			output += ifno(san + "\n")
		}
		for _, san := range cert.Subject.OrganizationalUnit {
			output += ifno(san + "\n")
		}
		for _, san := range cert.Subject.Names {
			if str, ok := san.Value.(string); ok {
			    output += ifno(str + "\n")
			}
		}

		output += ifno(cert.Issuer.CommonName + "\n")
		for _, san := range cert.IssuingCertificateURL {
			output += ifno(san + "\n")
		}
		for _, san := range cert.OCSPServer {
			output += ifno(san + "\n")
		}
		for _, san := range cert.DNSNames {
			output += ifno(san + "\n")
		}
		for _, san := range cert.EmailAddresses {
			 output += ifno(san + "\n")
		}
		for _, san := range cert.PermittedDNSDomains {
			output += ifno(san + "\n")
		}
		for _, san := range cert.CRLDistributionPoints {
			output += ifno(san + "\n")
		}
		outputLock.Lock()
		fmt.Print(output)
		outputLock.Unlock()
	})
}
