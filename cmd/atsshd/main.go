// example sshd
package main

import (
	"flag"
	"io"
	"log"
	"os"
	"strconv"

	"github.com/mllken/atsshd"
)

const (
	DefPort   = 22
	DefBanner = "SSH-2.0-OpenSSH_7.4p1"
)

func main() {
	var (
		listenPort = flag.Int("p", DefPort, "`port` to listen on")
		logFile    = flag.String("l", "", "output log `file`")
		attackMode = flag.Bool("A", false, "enable attack mode")
		bannerLine = flag.String("b", DefBanner, "SSH server `banner`")
		sourceIP   = flag.String("s", "", "`source` IP of interface to bind to")

		hostKeyFiles []string
	)
	flag.Func("k", "SSH server host key PEM `file`s", func(s string) error {
		hostKeyFiles = append(hostKeyFiles, s)
		return nil
	})
	flag.Parse()

	config := &atsshd.Config{
		Banner:       *bannerLine,
		EnableAttack: *attackMode,
		PEMFiles:     hostKeyFiles,
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("ERROR: unable to open logfile: %s\n", *logFile)
		}
		log.Printf("Logging output to: %s\n", *logFile)
		config.Output = io.MultiWriter(f, os.Stderr)
	}

	srv, err := atsshd.New(config)
	if err != nil {
		log.Fatal(err)
	}

	err = srv.ListenAndServe(*sourceIP + ":" + strconv.Itoa(*listenPort))
	if err != nil {
		log.Fatal(err)
	}
}
