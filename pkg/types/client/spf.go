package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	spfParsing "github.com/Motmedel/utils_go/pkg/dns/parsing/spf"
	dnsTypes "github.com/Motmedel/utils_go/pkg/dns/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
)

func (c *Client) GetSpfRecordString(ctx context.Context, domain string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if domain == "" {
		return "", nil
	}

	var rcodeError *dnsUtilsErrors.RcodeError

	prefix := dnsTypes.SpfPrefix
	recordStrings, err := c.GetPrefixedTxtRecordStrings(ctx, domain, prefix)
	if err != nil && !(errors.As(err, &rcodeError) && rcodeError.Rcode == dns.RcodeNameError) {
		return "", motmedelErrors.New(
			fmt.Errorf("get prefixed txt record strings: %w", err),
			domain, prefix,
		)
	}
	if len(recordStrings) == 0 {
		return "", nil
	}
	if len(recordStrings) > 1 {
		return "", &dnsUtilsErrors.MultipleRecordsError{Records: recordStrings}
	}

	return recordStrings[0], nil
}

func (c *Client) GetSpfRecord(ctx context.Context, domain string) (*dnsTypes.SpfRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if domain == "" {
		return nil, nil
	}

	domain = strings.ToLower(domain)

	recordString, err := c.GetSpfRecordString(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("get record string: %w", err)
	}
	if recordString == "" {
		return nil, nil
	}

	recordBytes := []byte(recordString)
	record, err := spfParsing.ParseSpfRecord(recordBytes)
	if err != nil {
		record = &dnsTypes.SpfRecord{Raw: recordString, Domain: domain}
		return record, motmedelErrors.New(fmt.Errorf("parse spf record: %w", err), recordBytes)
	}
	if record == nil {
		return nil, nil
	}

	record.Domain = domain

	return record, nil
}
