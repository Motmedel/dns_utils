package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsQuicErrors "github.com/Motmedel/dns_utils/pkg/quic/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"io"
	"log/slog"
	"time"
)

func Exchange(
	ctx context.Context,
	message *dns.Msg,
	serverAddress string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*dns.Msg, error) {
	if message == nil {
		return nil, nil
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{NextProtos: []string{"doq"}}
	}

	dnsContext := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if dnsContext != nil {
		dnsContext.QuestionMessage = message
	}

	messageBytes, err := message.Pack()
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("request pack: %w", err))
	}

	connection, err := quic.DialAddr(ctx, serverAddress, tlsConfig, quicConfig)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("quic dial addr: %w", err))
	}
	if dnsContext != nil {
		var localAddrString string
		if localAddr := connection.LocalAddr(); localAddr != nil {
			localAddrString = localAddr.String()
		}

		var remoteAddrString string
		var transport string
		if remoteAddr := connection.RemoteAddr(); remoteAddr != nil {
			remoteAddrString = remoteAddr.String()
			transport = remoteAddr.Network()
		}

		dnsContext.ClientAddress = localAddrString
		dnsContext.ServerAddress = remoteAddrString
		dnsContext.Transport = transport

		// TODO: Not sure if I can obtain TLS information? Maybe if I call something other than `quic.DialAddr`?
	}

	closeStreamInDefer := true
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("connection open stream sync: %w", err), connection)
	}
	defer func() {
		if closeStreamInDefer {
			if err := stream.Close(); err != nil {
				slog.WarnContext(
					motmedelContext.WithErrorContextValue(
						ctx,
						motmedelErrors.NewWithTrace(fmt.Errorf("stream close: %w", err)),
					),
					"An error occurred when closing a stream.",
				)
			}
		}
	}()

	rawMessageLength := len(messageBytes)
	if rawMessageLength > 0xFFFF {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("%w (%d)", dnsUtilsQuicErrors.ErrMessageLengthOverflow, rawMessageLength),
			rawMessageLength,
		)
	}
	messageLength := uint16(rawMessageLength)

	if err := binary.Write(stream, binary.BigEndian, messageLength); err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("binary write (message length): %w", err),
			stream, messageLength,
		)
	}
	if _, err := stream.Write(messageBytes); err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("binary write (message bytes): %w", err),
			stream, messageBytes,
		)
	}

	if err := stream.Close(); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("stream close: %w", err), stream)
	}
	closeStreamInDefer = false

	var responseLength uint16
	if err := binary.Read(stream, binary.BigEndian, &responseLength); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("binary read (response length): %w", err), stream)
	}

	responseBuffer := make([]byte, responseLength)
	if _, err := io.ReadFull(stream, responseBuffer); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("io read full (response): %w", err), stream)
	}

	var response dns.Msg
	if err := response.Unpack(responseBuffer); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("response unpack: %w", err), responseBuffer)
	}

	if dnsContext != nil {
		// TODO: Maybe I can obtain an earlier time?
		t := time.Now()
		dnsContext.Time = &t
		dnsContext.AnswerMessage = &response
	}

	return &response, nil
}
