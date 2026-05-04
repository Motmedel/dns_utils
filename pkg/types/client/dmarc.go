package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dmarcParsing "github.com/Motmedel/utils_go/pkg/dns/parsing/dmarc"
	dnsTypes "github.com/Motmedel/utils_go/pkg/dns/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
)

// DmarcLookup is the minimal interface DMARC analysis needs to look up report
// authorization records. *Client satisfies it; tests can supply an in-memory
// fake.
type DmarcLookup interface {
	GetDmarcRecordStringWithSubdomain(ctx context.Context, subdomain string) (string, error)
}

func (c *Client) GetDmarcRecordStringWithSubdomain(
	ctx context.Context,
	subdomain string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if subdomain == "" {
		return "", nil
	}

	var rcodeError *dnsUtilsErrors.RcodeError

	prefix := dnsTypes.DmarcPrefix
	recordStrings, err := c.GetPrefixedTxtRecordStrings(ctx, subdomain, prefix)
	if err != nil && !(errors.As(err, &rcodeError) && rcodeError.Rcode == dns.RcodeNameError) {
		return "", motmedelErrors.New(
			fmt.Errorf("get prefixed txt record strings: %w", err),
			subdomain, prefix,
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

func (c *Client) GetDmarcRecordWithSubdomain(
	ctx context.Context,
	subdomain string,
) (*dnsTypes.DmarcRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if subdomain == "" {
		return nil, nil
	}

	recordString, err := c.GetDmarcRecordStringWithSubdomain(ctx, subdomain)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("get record string with subdomain: %w", err),
			subdomain,
		)
	}
	if recordString == "" {
		return nil, nil
	}

	recordBytes := []byte(recordString)
	record, err := dmarcParsing.ParseDmarcRecord(recordBytes)
	if err != nil {
		record = &dnsTypes.DmarcRecord{Raw: recordString}
		return record, motmedelErrors.New(fmt.Errorf("parse dmarc record: %w", err), recordBytes)
	}

	return record, nil
}

func (c *Client) GetDmarcRecord(
	ctx context.Context,
	domain string,
) (*dnsTypes.DmarcRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if domain == "" {
		return nil, nil
	}

	domain = strings.ToLower(domain)
	subdomain := "_dmarc." + domain

	record, err := c.GetDmarcRecordWithSubdomain(ctx, subdomain)
	if err != nil {
		if record != nil {
			record.Domain = domain
		}
		return record, motmedelErrors.New(fmt.Errorf("get record with subdomain: %w", err), subdomain)
	}
	if record == nil {
		return nil, nil
	}

	record.Domain = domain

	return record, nil
}
