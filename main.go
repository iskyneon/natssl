package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	Version   = "1.0.9"
	Commit    = "nogit"
	BuildDate = "20062026"
)

func usage() {
	fmt.Fprintf(os.Stderr, `NATSSL %s — Zero-Configuration Distributed TLS for Private Infrastructure

USAGE:
  natssl --mode=master [flags]
  natssl --mode=client [flags]

MASTER MODE:
  --mode=master --bootstrap            Initialize a new Root CA (10y) and print the 24-word seed once
  --mode=master                        Run the master (ACME API on :443, mTLS management on :8443)
  --mode=master --issue "<dom/IP>"     Issue a certificate; the master generates the private key
                                       Add --localhost for a Same-PC-only localhost cert (1 year)
  --mode=master --reissue "<dom/IP>"   Revoke the current certificate for the subject and issue a fresh one
  --mode=master --revoke "<serial>"    Revoke a certificate by its hex serial (regenerates the CRL)
  --mode=master --list-certs           List issued certificates (serial, subject, expiry, status)
  --mode=master --list-revoked         List revoked certificates
  --mode=master --list-clients         List registered clients (IP, registered-at)
  --mode=master --deregister "<IP>"    Remove a registered client from the push list
  --mode=master --block "<IP>"         Blacklist a client IP (denies future registration); add --block-reason
  --mode=master --unblock "<IP>"       Remove a client IP from the blacklist
  --mode=master --list-blocked         List blacklisted client IPs

CLIENT MODE:
  --mode=client                        Run the client (install Root CA, ping master, receive cache)
  --mode=client --issue "<localhost>"  Issue a certificate for yourself via CSR-flow
                                       (private key is generated locally and never leaves this machine)
                                       Add --localhost for a Same-PC-only localhost cert (1 year)
  --mode=client --decrypt-key=FILE     Decrypt an encrypted private key (.key.enc) to stdout
  --mode=client --promote-to-master --token="<24 words>"
                                       Disaster-recovery promotion of this client into a new master

FLAGS:
`, Version)
	flag.PrintDefaults()
}

func main() {
	var (
		mode        = flag.String("mode", "", "operation mode: master | client")
		bootstrap   = flag.Bool("bootstrap", false, "initialize a new Root CA (master only)")
		promote     = flag.Bool("promote-to-master", false, "disaster-recovery promotion (client)")
		token       = flag.String("token", "", "24-word BIP-39 recovery seed phrase")
		configPath  = flag.String("config", "/etc/natssl/config.yaml", "path to config.yaml")
		issue       = flag.String("issue", "", "issue a certificate for the given domain/IP")
		reissue     = flag.String("reissue", "", "master: revoke the current cert for the subject and issue a new one")
		revoke      = flag.String("revoke", "", "master: revoke a certificate by hex serial")
		localhost   = flag.Bool("localhost", false, "issue a Same-PC-only localhost certificate (1 year)")
		decryptKey  = flag.String("decrypt-key", "", "decrypt an encrypted private key (.key.enc) to stdout")
		listCerts   = flag.Bool("list-certs", false, "master: list issued certificates")
		listRevoked = flag.Bool("list-revoked", false, "master: list revoked certificates")
		listClients = flag.Bool("list-clients", false, "master: list registered clients")
		listBlocked = flag.Bool("list-blocked", false, "master: list blacklisted clients")
		deregister  = flag.String("deregister", "", "master: remove a registered client by IP")
		block       = flag.String("block", "", "master: blacklist a client IP")
		blockReason = flag.String("block-reason", "", "optional reason stored alongside --block")
		unblock     = flag.String("unblock", "", "master: remove a client IP from the blacklist")
		showVer     = flag.Bool("version", false, "print version and exit")
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
		if *issue != "" {
			if err := RunIssueCLI(cfg, *issue, *localhost); err != nil {
				log.Fatalf("issue failed: %v", err)
			}
			return
		}
		if *reissue != "" {
			if err := RunReissueCert(cfg, *reissue, *localhost); err != nil {
				log.Fatalf("reissue failed: %v", err)
			}
			return
		}
		if *revoke != "" {
			if err := RunRevokeCert(cfg, *revoke); err != nil {
				log.Fatalf("revoke failed: %v", err)
			}
			return
		}
		if *listCerts {
			if err := RunListCerts(cfg); err != nil {
				log.Fatalf("list-certs failed: %v", err)
			}
			return
		}
		if *listRevoked {
			if err := RunListRevoked(cfg); err != nil {
				log.Fatalf("list-revoked failed: %v", err)
			}
			return
		}
		if *listClients {
			if err := RunListClients(cfg); err != nil {
				log.Fatalf("list-clients failed: %v", err)
			}
			return
		}
		if *listBlocked {
			if err := RunListBlocked(cfg); err != nil {
				log.Fatalf("list-blocked failed: %v", err)
			}
			return
		}
		if *deregister != "" {
			if err := RunDeregisterClient(cfg, *deregister); err != nil {
				log.Fatalf("deregister failed: %v", err)
			}
			return
		}
		if *block != "" {
			if err := RunBlockClient(cfg, *block, *blockReason); err != nil {
				log.Fatalf("block failed: %v", err)
			}
			return
		}
		if *unblock != "" {
			if err := RunUnblockClient(cfg, *unblock); err != nil {
				log.Fatalf("unblock failed: %v", err)
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
			if err := RunDecryptKey(cfg, *decryptKey); err != nil { // FIX: was RunDecryptKey(*decryptKey)
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
