// This utility program synchronises a file containing compressed log entries
// to disk. It will download any new log entries and check the tree hash.

package main

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"time"
	"strconv"
	"path"
	//"regexp"
	"github.com/agl/certificatetransparency"
)

func clearLine() {
	fmt.Printf("\x1b[80D\x1b[2K")
}

func displayProgress(statusChan chan certificatetransparency.OperationStatus, wg *sync.WaitGroup) {
	wg.Add(1)

	go func() {
		defer wg.Done()
		symbols := []string{"|", "/", "-", "\\"}
		symbolIndex := 0

		status, ok := <-statusChan
		if !ok {
			return
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case status, ok = <-statusChan:
				if !ok {
					return
				}
			case <-ticker.C:
				symbolIndex = (symbolIndex + 1) % len(symbols)
			}

			clearLine()
			fmt.Printf("%s %.1f%% (%d of %d)", symbols[symbolIndex], status.Percentage(), status.Current, status.Length)
		}
	}()
}

func usage(logs *certificatetransparency.LogList) {
	fmt.Fprintf(os.Stderr, "Usage: %s <log> <log entries folder>\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "These logs are based on all_logs_list.json from https://www.certificate-transparency.org/known-logs, and may include logs that are no longer in operation")
	fmt.Fprintf(os.Stderr, "<log> is one of 0-%d fro mthe following dynamic list:\n", len(logs.Logs)-1)
	for i, log := range logs.Logs {
		fmt.Fprintf(os.Stderr, "[%d] %s (URL: https://%s, operator: %s)\n",
			i, log.Desc, log.URL, log.OperatorName)
	}
	os.Exit(2)
}

func main() {


	logs, err := certificatetransparency.GetAllLogsList()
	if err != nil {
                fmt.Fprintf(os.Stderr, "Failed to get log list: %s\n", err)
                os.Exit(1)
        }

        if len(os.Args) != 3 {
                usage(logs)
        }


	logNum, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s could no be converted to int", os.Args[1])
		usage(logs)
	}

	if logNum >= len(logs.Logs) {
                fmt.Fprintf(os.Stderr, "%d is not a valid log number", os.Args[1])
                usage(logs)
        }

        folder := os.Args[2]
	fileName := path.Join(folder, logs.Logs[logNum].SafeFileName)

	fmt.Printf("Selected log: %s (https://%s)\n", logs.Logs[logNum].Desc, logs.Logs[logNum].URL)
	fmt.Printf("Path to entries file: %s\n", fileName)

	out, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer out.Close()

	entriesFile := certificatetransparency.EntriesFile{out}
	fmt.Printf("Counting existing entries... ")
	count, err := entriesFile.Count()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to read entries file: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d\n", count)

	fmt.Printf("Fetching signed tree head... ")
	sth, err := logs.Logs[logNum].PublicLog.GetSignedTreeHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	fmt.Printf("%d total entries at %s\n", sth.Size, sth.Time.Format(time.ANSIC))
	if count == sth.Size {
		fmt.Printf("Nothing to do\n")
		return
	}

	statusChan := make(chan certificatetransparency.OperationStatus, 1)
	wg := new(sync.WaitGroup)
	displayProgress(statusChan, wg)
	_, err = logs.Logs[logNum].PublicLog.DownloadRange(out, statusChan, count, sth.Size)
	wg.Wait()

	clearLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while downloading: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Hashing tree\n")
	entriesFile.Seek(0, 0)
	statusChan = make(chan certificatetransparency.OperationStatus, 1)
	wg = new(sync.WaitGroup)
	displayProgress(statusChan, wg)
	treeHash, err := entriesFile.HashTree(statusChan, sth.Size)
	wg.Wait()

	clearLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing tree: %s\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(treeHash[:], sth.Hash) {
		fmt.Fprintf(os.Stderr, "Hashes do not match! Calculated: %x, STH contains %x\n", treeHash, sth.Hash)
		os.Exit(1)
	}

}
