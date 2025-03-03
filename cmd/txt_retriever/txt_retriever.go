package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsLog "github.com/Motmedel/dns_utils/pkg/log"
	dnsUtilsClient "github.com/Motmedel/dns_utils/pkg/types/client"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"golang.org/x/sync/semaphore"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
)

func main() {
	logger := motmedelLog.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Handler: slog.NewJSONHandler(os.Stderr, nil),
				Extractors: []motmedelLog.ContextExtractor{
					dnsUtilsLog.DnsContextExtractor,
					motmedelLog.ErrorContextExtractor,
				},
			},
		),
	}

	var inPath string
	flag.StringVar(&inPath, "in", "", "The path of the input file.")

	var numConcurrent int
	flag.IntVar(&numConcurrent, "num", 50, "The number of concurrent requests.")

	var dnsServerAddress string
	flag.StringVar(&dnsServerAddress, "dns-server", "", "The DNS server to use.")

	var prefix string
	flag.StringVar(&prefix, "prefix", "", "The TXT prefix.")

	flag.Parse()

	var input *os.File
	if inPath == "" {
		input = os.Stdin
	} else {
		var err error
		input, err = os.Open(inPath)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when opening the input file.",
				motmedelErrors.New(fmt.Errorf("os open (input file): %w", err), inPath),
			)
		}
	}

	if dnsServerAddress == "" {
		dnsServers, err := dns_utils.GetDnsServers()
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when getting DNS server addresses.",
				fmt.Errorf("get dns servers: %w", err),
			)
		}

		if len(dnsServers) == 0 {
			logger.FatalWithExitingMessage("No DNS servers could be obtained and none was provided.", nil)
		}
		dnsServerAddress = dnsServers[0] + ":53"
	}

	dnsClient, err := dnsUtilsClient.NewWithAddress(dnsServerAddress)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when creating a DNS client.",
			motmedelErrors.New(
				fmt.Errorf("dns utils client new with address: %w", err),
				dnsServerAddress,
			),
		)
	}

	weightedSemaphore := semaphore.NewWeighted(int64(numConcurrent))
	var waitGroup sync.WaitGroup
	var printLock sync.Mutex

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		var acquireWeight int64 = 1
		if err := weightedSemaphore.Acquire(context.Background(), acquireWeight); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when acquiring the weighted semaphore.",
				motmedelErrors.New(fmt.Errorf("sempaphore acquire: %w", err), acquireWeight),
			)
		}

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()

			ctx := dnsUtilsContext.WithDnsContext(context.Background())
			rawRecordStrings, err := dnsClient.GetPrefixedTxtRecordStrings(ctx, domain, prefix)
			weightedSemaphore.Release(acquireWeight)
			if err != nil {
				logger.WarnContext(
					motmedelErrors.WithErrorContextValue(
						ctx,
						motmedelErrors.New(
							fmt.Errorf("get prefixed txt record strings: %w", err),
							domain, dnsServerAddress,
						),
					),
					"An error occurred when retrieving SPF TXT records.",
				)
				return
			}

			quotedRecordStrings := make([]string, len(rawRecordStrings))
			for i, s := range rawRecordStrings {
				quotedRecordStrings[i] = strconv.Quote(s)
			}

			printLock.Lock()
			fmt.Printf("%s:%s\n", domain, strings.Join(quotedRecordStrings, ","))
			printLock.Unlock()
		}()
	}

	waitGroup.Wait()

	if err := scanner.Err(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when scanning.",
			fmt.Errorf("scanner: %w", err),
		)
	}
}
