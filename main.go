package main

// References
// https://kana.me/entry/dnssec-rfc2136-delegation
// https://qiita.com/binzume/items/698d12779b8ad5cda423
// https://mkaczanowski.com/golang-build-dynamic-dns-service-go/

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/yseto/dynamic-dns-go/config"
	"github.com/yseto/dynamic-dns-go/zone"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	var (
		port     = flag.Int("port", 1053, "server port")
		confFile = flag.String("config", "config.json", "")
	)
	flag.Parse()

	conf, err := config.Load(*confFile)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	for _, i := range conf.Zone {
		z, err := zone.New(i.ZoneName, i.NsName, i.DBFile, conf.LocalAddr, i.AllowCIDR)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
		if err := z.ReadDB(); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		// Attach request handler func
		dns.HandleFunc(i.ZoneName, z.HandleRequest)
	}

	addr := net.JoinHostPort("", strconv.Itoa(*port))

	udpServer := createServer(addr, "udp", conf.TsigSecret)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			slog.Error(err.Error())
			cancel()
		}
	}()

	tcpServer := createServer(addr, "tcp", conf.TsigSecret)
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			slog.Error(err.Error())
			cancel()
		}
	}()

	<-ctx.Done()
	slog.Info("Server stopping")

	cT, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		if err := udpServer.ShutdownContext(ctx); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}(cT)

	wg.Add(1)
	go func(ctx context.Context) {
		defer wg.Done()
		if err := tcpServer.ShutdownContext(ctx); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}(cT)

	wg.Wait()
	slog.Info("Server gracefully stopped")
}

func createServer(addr, proto string, tsigSecret map[string]string) *dns.Server {
	server := &dns.Server{
		Addr: addr,
		Net:  proto,
		NotifyStartedFunc: func() {
			slog.Info("Server starting", "address", addr, "proto", proto)
		},
		// https://mkaczanowski.com/golang-build-dynamic-dns-service-go/#comment-5823504001
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			// defaultMsgAcceptFunc does reject UPDATE queries
			opcode := int(dh.Bits>>11) & 0xF
			if opcode == dns.OpcodeUpdate {
				return dns.MsgAccept
			}

			return dns.DefaultMsgAcceptFunc(dh)
		},
	}

	if len(tsigSecret) > 0 {
		server.TsigSecret = tsigSecret
	}
	return server
}
