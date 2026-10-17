package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultPort = "8443"
	shareDir    = "./shared"
	certDirName = ".localshare"
	certFile    = "server.crt"
	keyFile     = "server.key"
	clockSkew   = time.Hour
)

func certDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}

	if strings.TrimSpace(home) == "" {
		return "", errors.New("home directory is empty")
	}

	home = filepath.Clean(home)

	root := filepath.Clean(
		filepath.VolumeName(home) + string(os.PathSeparator),
	)

	if home == root || !filepath.IsAbs(home) {
		return "", fmt.Errorf("unsafe home directory: %q", home)
	}

	return filepath.Join(home, certDirName), nil
}

func localIPv4s() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var ips []net.IP
	seen := make(map[string]bool)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			default:
				continue
			}

			ip = ip.To4()
			if ip == nil ||
				ip.IsLoopback() ||
				ip.IsLinkLocalUnicast() {
				continue
			}

			if !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, append(net.IP(nil), ip...))
			}
		}
	}

	return ips, nil
}

func primaryIP() net.IP {
	conn, err := net.DialTimeout(
		"udp",
		"1.1.1.1:80",
		2*time.Second,
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}

	return addr.IP
}

func generateCertificate(
	certPath string,
	keyPath string,
	ips []net.IP,
) error {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localshare"
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	dnsNames := []string{
		host,
		host + ".local",
		"localhost",
	}

	seen := make(map[string]bool)
	uniqueDNS := make([]string, 0, len(dnsNames))

	for _, name := range dnsNames {
		if name != "" && !seen[name] {
			seen[name] = true
			uniqueDNS = append(uniqueDNS, name)
		}
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: now.Add(-clockSkew),
		NotAfter:  now.AddDate(10, 0, 0),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		DNSNames:              uniqueDNS,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("encoding private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}

	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("setting private key permissions: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	return nil
}

func loadOrCreateCertificate(
	dir string,
	ips []net.IP,
) (tls.Certificate, *x509.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf(
			"creating certificate directory: %w", err,
		)
	}

	if err := os.Chmod(dir, 0700); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf(
			"setting certificate directory permissions: %w", err,
		)
	}

	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	pair, pairErr := tls.LoadX509KeyPair(certPath, keyPath)

	if pairErr == nil && len(pair.Certificate) > 0 {
		leaf, parseErr := x509.ParseCertificate(pair.Certificate[0])

		if parseErr == nil {
			now := time.Now()

			switch {
			case now.After(leaf.NotAfter):
				fmt.Fprintf(
					os.Stderr,
					"⚠ Existing certificate expired at %s; regenerating.\n"+
						"  Previously paired clients must rescan.\n",
					leaf.NotAfter.Format(time.RFC3339),
				)

			case now.Before(leaf.NotBefore):
				fmt.Fprintf(
					os.Stderr,
					"⚠ Existing certificate not valid until %s "+
						"(server time: %s).\n"+
						"  If this repeats, check your system clock.\n"+
						"  Regenerating.\n",
					leaf.NotBefore.Format(time.RFC3339),
					now.Format(time.RFC3339),
				)

			default:
				if err := os.Chmod(keyPath, 0600); err != nil {
					return tls.Certificate{}, nil, fmt.Errorf(
						"setting private key permissions: %w", err,
					)
				}

				pair.Leaf = leaf
				return pair, leaf, nil
			}
		} else {
			fmt.Fprintf(
				os.Stderr,
				"⚠ Existing certificate is unparseable (%v); regenerating.\n",
				parseErr,
			)
		}
	} else if pairErr != nil {
		if !errors.Is(pairErr, fs.ErrNotExist) {
			fmt.Fprintf(
				os.Stderr,
				"⚠ Existing certificate/key pair is unreadable (%v); regenerating.\n",
				pairErr,
			)
		} else {
			_, certErr := os.Stat(certPath)
			_, keyErr := os.Stat(keyPath)

			switch {
			case errors.Is(certErr, fs.ErrNotExist) &&
				errors.Is(keyErr, fs.ErrNotExist):

			case errors.Is(certErr, fs.ErrNotExist):
				fmt.Fprintln(
					os.Stderr,
					"⚠ Existing certificate missing; regenerating.",
				)

			case errors.Is(keyErr, fs.ErrNotExist):
				fmt.Fprintln(
					os.Stderr,
					"⚠ Existing private key missing; regenerating.",
				)

			default:
				fmt.Fprintln(
					os.Stderr,
					"⚠ Existing certificate/key pair is incomplete; regenerating.",
				)
			}
		}
	}

	if err := generateCertificate(certPath, keyPath, ips); err != nil {
		return tls.Certificate{}, nil, err
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf(
			"loading generated certificate: %w", err,
		)
	}

	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New(
			"generated certificate contains no certificates",
		)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf(
			"parsing generated certificate: %w", err,
		)
	}

	pair.Leaf = leaf
	return pair, leaf, nil
}

func fingerprint(
	leaf *x509.Certificate,
) (hexForm, colonForm string) {
	sum := sha256.Sum256(leaf.Raw)
	hexForm = hex.EncodeToString(sum[:])

	var buf strings.Builder
	for i := 0; i < len(hexForm); i += 2 {
		if i > 0 {
			buf.WriteByte(':')
		}
		buf.WriteString(strings.ToUpper(hexForm[i : i+2]))
	}

	return hexForm, buf.String()
}

func main() {
	if err := os.MkdirAll(shareDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Creating shared directory: %v\n", err)
		os.Exit(1)
	}

	absShareDir, err := filepath.Abs(shareDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Resolving shared directory: %v\n", err)
		os.Exit(1)
	}

	ips, err := localIPv4s()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Detecting local IPs: %v\n", err)
		os.Exit(1)
	}

	dir, err := certDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Locating certificate directory: %v\n", err)
		os.Exit(1)
	}

	cert, leaf, err := loadOrCreateCertificate(dir, ips)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Loading TLS certificate: %v\n", err)
		os.Exit(1)
	}

	hexForm, colonForm := fingerprint(leaf)

	fmt.Printf("Sharing directory: %s\n", absShareDir)
	fmt.Printf("Certificate directory: %s\n", dir)
	fmt.Printf("Certificate expires: %s\n",
		leaf.NotAfter.Format(time.RFC3339))

	fmt.Println("Cert SHA-256:")
	fmt.Printf("  %s\n", colonForm)
	fmt.Printf("  %s\n", hexForm)

	fmt.Println("\nHTTPS URLs:")

	primary := primaryIP()
	if primary != nil {
		fmt.Printf("  https://%s:%s\n", primary, defaultPort)
	}

	for _, ip := range ips {
		if primary != nil && ip.Equal(primary) {
			continue
		}
		fmt.Printf("  https://%s:%s\n", ip, defaultPort)
	}

	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localshare"
	}

	fmt.Printf("  https://localhost:%s (this device only)\n", defaultPort)
	fmt.Printf("  https://%s.local:%s (if resolvable)\n",
		host, defaultPort)
	fmt.Printf("  https://%s:%s (hostname; if resolvable)\n",
		host, defaultPort)

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(absShareDir)))

	server := &http.Server{
		Addr:              ":" + defaultPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	fmt.Printf("\nHTTPS server listening on :%s\n", defaultPort)
	err = server.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "HTTPS server error: %v\n", err)
		os.Exit(1)
	}
}
