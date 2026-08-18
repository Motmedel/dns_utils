package client

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"iter"
	"strings"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/dns/dkim"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/miekg/dns"
)

//go:embed common_selectors.txt
var CommonDkimSelectorsData []byte

func CommonDkimSelectors() iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		scanner := bufio.NewScanner(bytes.NewReader(CommonDkimSelectorsData))
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				if !yield(line, nil) {
					return
				}
			}
		}

		if err := scanner.Err(); err != nil {
			yield("", fmt.Errorf("scanner: %w", err))
		}
	}
}

func (c *Client) GetDkimRecordStringWithDomainName(
	ctx context.Context,
	domainName string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if domainName == "" {
		return "", nil
	}

	answers, err := c.GetDnsAnswers(ctx, domainName, dns.TypeTXT)
	if rcodeError, ok := errors.AsType[*dnsUtilsErrors.RcodeError](err); err != nil && (!ok || rcodeError.Rcode != dns.RcodeNameError) {
		return "", altshiftErrors.New(
			fmt.Errorf("get dns answers: %w", err),
			domainName,
		)
	}

	var answerStrings []string
	for _, answer := range answers {
		if txtAnswer, ok := answer.(*dns.TXT); ok && txtAnswer.Txt != nil {
			if answerString := strings.Join(txtAnswer.Txt, ""); answerString != "" {
				answerStrings = append(answerStrings, answerString)
			}
		}
	}

	if len(answerStrings) == 0 {
		return "", nil
	}
	if len(answerStrings) > 1 {
		return "", &dnsUtilsErrors.MultipleRecordsError{Records: answerStrings}
	}

	return answerStrings[0], nil
}

func (c *Client) GetDkimRecordString(
	ctx context.Context,
	domain string,
	selector string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if domain == "" {
		return "", nil
	}

	domainName := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	recordString, err := c.GetDkimRecordStringWithDomainName(ctx, domainName)
	if err != nil {
		return "", altshiftErrors.New(
			fmt.Errorf("get record string with domain name: %w", err),
			domainName, c,
		)
	}

	return recordString, nil
}

func (c *Client) GetDkimRecord(
	ctx context.Context,
	domain string,
	selector string,
) (*dkim.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if domain == "" {
		return nil, nil
	}

	recordString, err := c.GetDkimRecordString(ctx, domain, selector)
	if err != nil {
		return nil, fmt.Errorf("get record string: %w", err)
	}

	if recordString == "" {
		return nil, nil
	}

	recordBytes := []byte(recordString)
	record, err := dkim.ParseRecord(recordBytes)
	if err != nil {
		record = &dkim.Record{Raw: recordString, Domain: domain}
		return record, altshiftErrors.New(fmt.Errorf("parse dkim record: %w", err), recordBytes)
	}
	if record == nil {
		return nil, nil
	}

	record.Domain = domain
	record.Selector = selector

	return record, nil
}
