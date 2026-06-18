package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	Version   = "1.0.0-oss"
	Commit    = "nogit"
	BuildDate = "unknown"
)

func main() {
	var (
		mode       = flag.String("mode", "", "operation mode: master | client")
		bootstrap  = flag.Bool("bootstrap", false, "initialize a new Root CA (master only)")
		promote    = flag.Bool("promote-to-master", false, "disaster-recovery promotion (client)")
		token      = flag.String("token", "", "24-word BIP-39 recovery seed phrase")
		configPath = flag.String("config", "/etc/natssl/config.yaml", "path to config.yaml")
		issue      = flag.String("issue", "", "issue a certificate for the given domain/IP")
		localhost  = flag.Bool("localhost", false, "issue a Same-PC-only localhost certificate")
		decryptKey = flag.String("decrypt-key", "", "decrypt an encrypted private key (.key.enc) to stdout")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[natssl] ")

	if *showVer {
		fmt.Printf("NATSSL %s (commit %s, built %s)\n", Version, Commit, BuildDate)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil && !*bootstrap {
		log.Fatalf("config: %v", err)
	}
	if cfg == nil {
		cfg = DefaultConfig()
		cfg.path = *configPath
	}

	switch *mode {
	case "master":
		if *bootstrap {
			if err := RunBootstrap(cfg); err != nil {
				log.Fatalf("bootstrap failed: %v", err)
			}
			return
		}
		if *issue != "" {
			if err := RunIssueCLI(cfg, *issue, *localhost); err != nil {
				log.Fatalf("issue failed: %v", err)
			}
			return
		}
		if err := RunMaster(cfg); err != nil {
			log.Fatalf("master failed: %v", err)
		}

	case "client":
		if *promote {
			if *token == "" {
				log.Fatal("--promote-to-master requires --token=\"<24 words>\"")
			}
			if err := RunPromote(cfg, *token); err != nil {
				log.Fatalf("PROMOTE BLOCKED: %v", err)
			}
			return
		}
		if *decryptKey != "" {
			if err := RunDecryptKey(*decryptKey); err != nil {
				log.Fatalf("decrypt failed: %v", err)
			}
			return
		}
		if *issue != "" {
			// Клиент выписывает СЕБЕ сертификат через CSR-flow к мастеру.
			if err := RunClientIssue(cfg, *issue, *localhost); err != nil {
				log.Fatalf("issue failed: %v", err)
			}
			return
		}
		if err := RunClient(cfg); err != nil {
			log.Fatalf("client failed: %v", err)
		}

	default:
		fmt.Fprintln(os.Stderr, "usage: natssl --mode=master|client [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
}
