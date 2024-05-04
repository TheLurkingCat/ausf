package context

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"time"

	"github.com/free5gc/ausf/internal/logger"
)

type TLSContext struct {
	net.Conn
	Done     bool
	Readbuf  chan string
	Writebuf chan string
}

func (c TLSContext) Read(p []byte) (int, error) {
	temp := <-c.Readbuf
	n := copy(p, temp)
	if len(temp) > n {
		c.Readbuf <- temp[n:]
	}
	return n, nil
}

func (c TLSContext) Write(p []byte) (int, error) {
	n := len(p)
	c.Writebuf <- string(p)
	return n, nil
}

func (c TLSContext) Close() error {
	close(c.Writebuf)
	return nil
}

func (c TLSContext) SetDeadline(t time.Time) error {
	return nil
}

func (c TLSContext) SetReadDeadline(t time.Time) error {
	return nil
}

func (c TLSContext) SetWriteDeadline(t time.Time) error {
	return nil
}

func HandleTLSHandshake(ue *AusfUeContext) {
	cert, err := tls.LoadX509KeyPair("servercert.pem", "serverkey.pem")
	if err != nil {
		logger.AuthELog.Errorf("Failed to load server key pair: %s", err.Error())
		return
	}
	cacert, err := os.ReadFile("cacert.pem")
	if err != nil {
		logger.AuthELog.Errorf("Failed to read CA certificate: %s", err.Error())
		return
	}
	p, _ := pem.Decode(cacert)
	crt, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		logger.AuthELog.Errorf("Failed to parse CA certificate: %s", err.Error())
		return
	}

	pool := x509.NewCertPool()
	pool.AddCert(crt)

	serv := tls.Server(ue.TLScontext, &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	})
	defer serv.Close()
	err = serv.Handshake()
	if err != nil {
		logger.AuthELog.Errorf("Handshake failed: %s", err.Error())
		return
	}
	// Handshake complete - derive Kausf
	cs := serv.ConnectionState()
	keyMaterial, err := cs.ExportKeyingMaterial("client EAP encryption", nil, 128)
	if err != nil {
		logger.AuthELog.Errorf("Failed to export keying material: %s", err.Error())
		return
	}
	ue.Kausf = hex.EncodeToString(keyMaterial[64:96])
	ue.TLScontext.Done = true
}
