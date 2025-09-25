package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	//"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/yggdrasil-network/yggquic"
	//"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const (
	version     = 1
	cmdAnnounce = 0
	cmdGetAddrs = 1
)

const keyFile = "tracker.key"

// record stored for each user
type record struct {
	nodePub   [32]byte // key that announced
	signature [64]byte // signature of this addr
	priority  byte
	clientID  uint32
	expires   time.Time
	prevTtl   int
}

var (
	records   = make(map[[32]byte][]record) // userPub -> []record
	recordsMu sync.RWMutex
)

func main() {
	var (
		keyHex string
		peers  []string
	)
	fs := flag.NewFlagSet("tracker", flag.ExitOnError)
	fs.StringVar(&keyHex, "key", "", "hex-encoded 32-byte private key (optional)")
	fs.Func("peer", "bootstrap peer (can be given multiple times)", func(s string) error {
		peers = append(peers, s)
		return nil
	})
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	if len(peers) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage:\n  %s -peer PEER1 [-peer PEER2 ...] [-key PRIV]\n", os.Args[0])
		os.Exit(1)
	}

	loadGob("records.gob", &records)
	defer saveGob("records.gob", records)

	var priv ed25519.PrivateKey
	if len(keyHex) > 0 {
		// second argument is hex private key
		var err error
		priv, err = hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			log.Fatalf("Invalid private key: %v", err)
		}
	} else {
		// generate or load persistent key
		priv = loadOrGenKey()
	}

	// 1.  build a self-signed certificate
	pub := priv.Public().(ed25519.PublicKey)
	certDER, err := createSelfSignedCert(pub, priv)
	if err != nil {
		log.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER}, // ← required
		PrivateKey:  priv,
	}

	// 2.  use it everywhere
	node, err := core.New(&cert, nil)
	if err != nil {
		log.Fatal(err)
	}
	m, err := yggquic.NewWithNode(node, &cert, peers)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Tracker started, listening for requests…")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// catch Ctrl+C
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		log.Println("Shutting down...")
		cancel()
	}()

	// accept loop that respects context
	for {
		select {
		case <-ctx.Done():
			_ = m.Close()
			log.Println("Tracker stopped")
			return
		default:
		}
		conn, err := m.Accept()
		if err != nil {
			continue // listener closed by context
		}
		go handle(ctx, conn)
	}
}

// loadOrGenKey returns a private key from file or creates + stores a new one.
func loadOrGenKey() ed25519.PrivateKey {
	if b, err := os.ReadFile(keyFile); err == nil && len(b) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(b)
		log.Printf("Loaded tracker key from %s - private: %x… public : %x\n",
			keyFile, priv[:min(4, len(priv))], priv.Public())
		return priv
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, priv, 0600); err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated new tracker key (saved to %s) - private: %x… public : %x\n",
		keyFile, priv[:min(4, len(priv))], priv.Public())
	return priv
}

func createSelfSignedCert(pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, template, template, pub, priv)
}

func handle(ctx context.Context, conn *yggquic.Conn) {
	defer conn.Stream.Close()
	//log.Printf("Handling request…")

	var hdr [38]byte // version(1) + nonce(4) + cmd(1) + userPub(32)
	if _, err := io.ReadFull(conn.Stream, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version {
		return
	}
	nonce := binary.BigEndian.Uint32(hdr[1:5])
	cmd := hdr[5]
	userPub := ([32]byte)(hdr[6:])

	switch cmd {
	case cmdGetAddrs:
		getAddrs(conn, nonce, userPub)
	case cmdAnnounce:
		announce(conn, nonce, userPub)
	default:
	}
	time.Sleep(3 * time.Second)
}

func announce(conn *yggquic.Conn, nonce uint32, userPub [32]byte) {
	//log.Printf("Handling announce request…")
	var body [37]byte // priority(1)+clientID(4)+addrPub(32)+sig(64)  -- read below
	if _, err := io.ReadFull(conn.Stream, body[:37]); err != nil {
		return
	}
	priority := body[0]
	clientID := binary.BigEndian.Uint32(body[1:5])
	addrPub := ([32]byte)(body[5:37])
	var signature [64]byte
	if _, err := io.ReadFull(conn.Stream, signature[:64]); err != nil {
		return
	}
	log.Printf("Got addr: %x… from user: %x…", addrPub[:min(2, len(addrPub))], userPub[:min(2, len(addrPub))])

	// verify signature
	if !ed25519.Verify(userPub[:], addrPub[:], signature[:]) {
		log.Printf("Wrong signature")
		//conn.Close()
		return
	}

	recordsMu.Lock()

	prevTtl := 2
	for _, r := range records[userPub] {
		if r.clientID == clientID && r.nodePub == addrPub {
			prevTtl = r.prevTtl
		}
	}
	newTtl := min(prevTtl*2, 16)

	// keep the slice without the old record (if any)
	filtered := records[userPub][:0] // reuse backing array
	// insert the new one to be the first
	filtered = append(filtered, record{
		nodePub:   addrPub,
		signature: signature,
		priority:  priority,
		clientID:  clientID,
		expires:   time.Now().Add(time.Duration(newTtl+1) * time.Minute),
		prevTtl:   newTtl,
	})
	for _, r := range records[userPub] {
		if r.clientID != clientID {
			filtered = append(filtered, r)
		}
	}

	records[userPub] = filtered
	recordsMu.Unlock()

	// ACK
	resp := make([]byte, 13)
	binary.BigEndian.PutUint32(resp, nonce)
	resp[4] = cmdAnnounce
	binary.BigEndian.PutUint64(resp[5:], uint64(time.Duration(newTtl)*time.Minute/time.Second))
	_, err := conn.Stream.Write(resp)
	if err != nil {
		log.Printf("Write error: %v", err)
		return
	}
	//log.Printf("Sent announce response…")
}

func getAddrs(conn *yggquic.Conn, nonce uint32, userPub [32]byte) {
	recordsMu.RLock()
	recs := records[userPub]
	recordsMu.RUnlock()
	log.Printf("Search for %x…", userPub[:min(2, len(userPub))])

	buf := make([]byte, 9+len(recs)*(32+64+1+4+8)+8) // header + each record + ttl
	off := 0
	buf[off] = byte(nonce >> 24)
	buf[off+1] = byte(nonce >> 16)
	buf[off+2] = byte(nonce >> 8)
	buf[off+3] = byte(nonce)
	off += 4
	buf[off] = cmdGetAddrs
	off++
	buf[off] = byte(len(recs))
	off++

	now := time.Now()
	for _, r := range recs {
		if now.After(r.expires) {
			buf[5] = buf[5] - 1
			continue // skip expired
		}
		copy(buf[off:], r.nodePub[:])
		off += 32
		copy(buf[off:], r.signature[:])
		off += 64
		buf[off] = r.priority
		off++
		binary.BigEndian.PutUint32(buf[off:], r.clientID)
		off += 4
		binary.BigEndian.PutUint64(buf[off:], uint64(r.expires.Sub(now)/time.Millisecond))
		off += 8
	}

	if _, err := conn.Stream.Write(buf[:off]); err != nil {
		log.Println("Write:", err)
	}
}

func saveGob(path string, data interface{}) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		log.Fatal("encode:", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		log.Fatal("write:", err)
	}
}

func loadGob(path string, data interface{}) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	} // first run – nothing to load
	if err != nil {
		log.Fatal("read:", err)
	}
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(data); err != nil {
		log.Fatal("decode:", err)
	}
}
