package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	Version   = "1.0.7-oss"
	Commit    = "nogit"
	BuildDate = "unknown"
)

func usage() {
	fmt.Fprintf(os.Stderr, `NATSSL %s — Zero-Configuration Distributed TLS for Private Infrastructure

USAGE:
  natssl --mode=master [flags]
  natssl --mode=client [flags]

MASTER MODE:
  --mode=master --bootstrap          Initialize a new Root CA (10y) and print the 24-word seed once
  --mode=master                      Run the master (bootstrap API :443, mTLS control plane :8443)
  --mode=master --issue "<target>"   Issue a certificate locally (CLI-only; the master generates the key)
                                     Add --localhost for a Same-PC-only localhost cert (1 year)
  --mode=master --revoke "<serial>"  Revoke a certificate by its hex serial

CLIENT MODE:
  --mode=client                      Run the client (install Root CA, enroll, pull cache over mTLS)
  --mode=client --issue "<target>"   Issue a LOOPBACK cert for yourself via CSR-flow over mTLS
  --mode=client --decrypt-key=FILE   Decrypt an encrypted private key (.key.enc) to stdout
  --mode=client --promote-to-master --token="<24 words>"
                                     Disaster-recovery promotion of this client into a new master

FLAGS:
`, Version)
	flag.PrintDefaults()
}

func main() {
	var (
		mode       = flag.String("mode", "", "operation mode: master | client")
		bootstrap  = flag.Bool("bootstrap", false, "initialize a new Root CA (master only)")
		promote    = flag.Bool("promote-to-master", false, "disaster-recovery promotion (client)")
		token      = flag.String("token", "", "24-word BIP-39 recovery seed phrase")
		configPath = flag.String("config", "/etc/natssl/config.yaml", "path to config.yaml")
		issue      = flag.String("issue", "", "issue a certificate for the given domain/IP")
		revoke     = flag.String("revoke", "", "revoke a certificate by hex serial (master)")
		localhost  = flag.Bool("localhost", false, "issue a Same-PC-only localhost certificate (1 year)")
		decryptKey = flag.String("decrypt-key", "", "decrypt an encrypted private key (.key.enc) to stdout")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
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
		if *revoke != "" {
			if err := RunRevoke(cfg, *revoke); err != nil {
				log.Fatalf("revoke failed: %v", err)
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
			if err := RunDecryptKey(cfg, *decryptKey); err != nil {
				log.Fatalf("decrypt failed: %v", err)
			}
			return
		}
		if *issue != "" {
			if err := RunClientIssue(cfg, *issue, *localhost); err != nil {
				log.Fatalf("issue failed: %v", err)
			}
			return
		}
		if err := RunClient(cfg); err != nil {
			log.Fatalf("client failed: %v", err)
		}

	default:
		usage()
		os.Exit(2)
	}
}
