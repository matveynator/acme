// acme-compat-renewer
// Renew TLS certificates on old systems (e.g., Debian 9) by reading ~/.acme.sh/*/*.conf
// and obtaining new certs via lego (Go ACME client), only HTTP-01 webroot.
// Writes acme.sh-like outputs: <main>.key, <main>.cer, fullchain.cer, ca.cer.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
)

// ----- parse acme.sh conf -----

type acmeConf struct {
	MainDomain string
	AltDomains []string
	Webroot    string
	KeyLenRaw  string
	API        string
	Email      string
	CA         string
	EABKid     string
	EABHmac    string
}

var reKV = regexp.MustCompile(`(?m)^([A-Za-z0-9_]+)='([^']*)'\s*$`)

func parseAcmeConf(path string) (*acmeConf, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	m := map[string]string{}
	for _, g := range reKV.FindAllStringSubmatch(string(b), -1) {
		m[g[1]] = g[2]
	}
	c := &acmeConf{}
	c.MainDomain = firstNonEmpty(m["Le_Domain"], m["DOMAIN"], m["Le_DomainNo"])
	alts := firstNonEmpty(m["Le_Alt"], m["Le_AltNames"], m["Le_SAN_Domains"])
	if alts != "" {
		for _, d := range strings.Split(alts, ",") {
			d = strings.TrimSpace(d)
			if d != "" { c.AltDomains = append(c.AltDomains, d) }
		}
	}
	c.Webroot = firstNonEmpty(m["Le_Webroot"], m["Le_Webroot_0"])
	c.KeyLenRaw = firstNonEmpty(m["Le_Keylength"], m["Le_Keylength_0"])
	c.API = firstNonEmpty(m["Le_API"], m["CA_URL"])
	c.Email = firstNonEmpty(m["Le_Email"], m["ACCOUNT_EMAIL"], m["AccountEmail"])
	c.CA = firstNonEmpty(m["Le_CA"], m["CA"])
	c.EABKid = m["Le_Eab_Kid"]
	c.EABHmac = m["Le_Eab_HmacKey"]
	if c.MainDomain == "" {
		return nil, fmt.Errorf("%s: Le_Domain not found", path)
	}
	return c, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss { if strings.TrimSpace(s) != "" { return s } }
	return ""
}

// ----- lego user -----

type accountUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *accountUser) GetEmail() string                        { return u.email }
func (u *accountUser) GetRegistration() *registration.Resource { return u.registration }
func (u *accountUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ----- keys & domains -----

func chooseKeyType(raw string) (certcrypto.KeyType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "2048", "rsa2048", "":
		return certcrypto.RSA2048, nil
	case "3072", "rsa3072":
		return certcrypto.RSA3072, nil
	case "4096", "rsa4096":
		return certcrypto.RSA4096, nil
	case "ec-256", "ecdsa256", "p256":
		return certcrypto.EC256, nil
	case "ec-384", "ecdsa384", "p384":
		return certcrypto.EC384, nil
	default:
		return certcrypto.RSA2048, fmt.Errorf("unknown key length '%s', defaulting to RSA2048", raw)
	}
}

func uniqueSorted(in []string) []string {
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" { continue }
		if _, ok := m[d]; ok { continue }
		m[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func accountKeyPath(dirURL, email string) (string, error) {
	host := dirHost(dirURL)
	if host == "" { return "", fmt.Errorf("bad directory URL: %s", dirURL) }
	home, err := os.UserHomeDir()
	if err != nil { return "", err }
	return filepath.Join(home, ".acme-go-accounts", host, email, "account.key"), nil
}

func dirHost(u string) string {
	u = strings.TrimSpace(u)
	if u == "" { return "" }
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return strings.Split(u, "/")[0]
}

func loadOrCreateAccountKey(path string, kt certcrypto.KeyType) (crypto.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil { return nil, fmt.Errorf("%s: invalid PEM", path) }
		switch blk.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(blk.Bytes)
		default:
			return nil, fmt.Errorf("%s: unknown key type %s", path, blk.Type)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { return nil, err }
	var priv crypto.PrivateKey
	switch kt {
	case certcrypto.EC256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); if err != nil { return nil, err }
		priv = k
	case certcrypto.EC384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader); if err != nil { return nil, err }
		priv = k
	default:
		bits := 2048
		if kt == certcrypto.RSA3072 { bits = 3072 }
		if kt == certcrypto.RSA4096 { bits = 4096 }
		k, err := rsa.GenerateKey(rand.Reader, bits); if err != nil { return nil, err }
		priv = k
	}
	var blk *pem.Block
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		blk = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k); if err != nil { return nil, err }
		blk = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil, fmt.Errorf("unexpected key type")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil { return nil, err }
	defer f.Close()
	if err := pem.Encode(f, blk); err != nil { return nil, err }
	return priv, nil
}

// ----- util -----

func infof(format string, a ...any) { fmt.Printf("[+] "+format+"\n", a...) }
func warnf(format string, a ...any) { fmt.Printf("[!] "+format+"\n", a...) }
func fatal(err error)               { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

// ----- main -----

var (
	flagAll     = flag.Bool("all", false, "Process all ~/.acme.sh/*/*.conf")
	flagDomain  = flag.String("domain", "", "Process only this main domain")
	flagDry     = flag.Bool("dry", false, "Dry run (no writes)")
	flagTimeout = flag.Duration("timeout", 5*time.Minute, "Overall timeout per certificate (unused)")
)

func main() {
	flag.Parse()
	if !*flagAll && *flagDomain == "" {
		fmt.Println("Usage: acme -all | -domain <main-domain> [-dry]")
		os.Exit(2)
	}

	confs, err := findConfs()
	if err != nil { fatal(err) }

	processed := 0
	for _, p := range confs {
		c, err := parseAcmeConf(p)
		if err != nil { warnf("%s: %v", p, err); continue }
		if *flagDomain != "" && c.MainDomain != *flagDomain { continue }

		if c.Webroot == "" || strings.HasPrefix(strings.ToLower(c.Webroot), "dns_") {
			warnf("%s: unsupported challenge (Webroot='%s'), skipping", c.MainDomain, c.Webroot)
			continue
		}
		if _, err := os.Stat(c.Webroot); err != nil {
			warnf("%s: webroot '%s' not accessible: %v", c.MainDomain, c.Webroot, err)
			continue
		}

		kt, ktErr := chooseKeyType(c.KeyLenRaw)
		if ktErr != nil { warnf("%s", ktErr) }

		dirURL := pickDirectoryURL(c)
		if dirURL == "" {
			warnf("%s: cannot determine ACME directory URL; set Le_API in conf", c.MainDomain)
			continue
		}

		// ZeroSSL без EAB — бессмысленно: сервер вернёт externalAccountRequired.
		if strings.Contains(strings.ToLower(dirURL), "zerossl.com") &&
			(strings.TrimSpace(c.EABKid) == "" || strings.TrimSpace(c.EABHmac) == "") {
			warnf("%s: ZeroSSL requires EAB; Le_Eab_Kid/Le_Eab_HmacKey not found — skipping", c.MainDomain)
			continue
		}

		email := c.Email
		if email == "" { email = "noc@" + c.MainDomain }
		acctKeyPath, err := accountKeyPath(dirURL, email)
		if err != nil { warnf("%s: %v", c.MainDomain, err); continue }
		priv, err := loadOrCreateAccountKey(acctKeyPath, kt)
		if err != nil { warnf("%s: %v", c.MainDomain, err); continue }

		user := &accountUser{email: email, key: priv}
		cfg := lego.NewConfig(user)
		cfg.CADirURL = dirURL
		cfg.Certificate = lego.CertificateConfig{KeyType: kt}

		client, err := lego.NewClient(cfg)
		if err != nil { warnf("%s: lego client: %v", c.MainDomain, err); continue }

		// HTTP-01 provider via webroot
		prov, err := webroot.NewHTTPProvider(c.Webroot)
		if err != nil { warnf("%s: webroot: %v", c.MainDomain, err); continue }
		if err := client.Challenge.SetHTTP01Provider(prov); err != nil {
			warnf("%s: http-01 set: %v", c.MainDomain, err); continue
		}

		// Register account (без явного EAB вызова — lego v4.26 API)
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			// ZeroSSL потребует EAB — заранее отлавливаем
			if strings.Contains(strings.ToLower(dirURL), "zerossl.com") &&
				strings.Contains(strings.ToLower(err.Error()), "externalaccountrequired") {
				warnf("%s: ZeroSSL requires EAB; entry skipped", c.MainDomain)
				continue
			}
			// if already registered — ок
			if !isAlreadyRegistered(err) {
				warnf("%s: register: %v", c.MainDomain, err)
				continue
			}
		}
		if reg != nil { user.registration = reg }

		// domains: unique + sorted, and ≤100 SAN
		domains := uniqueSorted(append([]string{c.MainDomain}, c.AltDomains...))
		if len(domains) > 100 {
			warnf("%s: %d names > 100 SAN limit; trimming to 100", c.MainDomain, len(domains))
			domains = domains[:100]
		}
		infof("%s: requesting certificate via %s for %v", c.MainDomain, dirHost(dirURL), domains)

		if *flagDry {
			infof("%s: DRY RUN — skipping request and write", c.MainDomain)
			processed++
			continue
		}

		certRes, err := obtainOrRenew(client, c, domains)
		if err != nil { warnf("%s: obtain/renew: %v", c.MainDomain, err); continue }
		if err := writeOut(c, certRes); err != nil { warnf("%s: write files: %v", c.MainDomain, err); continue }
		infof("%s: renewed and wrote certs", c.MainDomain)
		processed++
	}

	if processed == 0 {
		warnf("No matching/valid entries processed.")
	}
}

func findConfs() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil { return nil, err }
	root := filepath.Join(home, ".acme.sh")
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil { return nil }
		if d == nil || d.IsDir() { return nil }
		if strings.HasSuffix(path, ".conf") {
			base := filepath.Base(path)
			parent := filepath.Base(filepath.Dir(path))
			if base == parent+".conf" { out = append(out, path) }
		}
		return nil
	})
	sort.Strings(out)
	return out, nil
}

func pickDirectoryURL(c *acmeConf) string {
	if c.API != "" { return c.API }
	ca := strings.ToLower(c.CA)
	if strings.Contains(ca, "letsencrypt") || ca == "" {
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
	if strings.Contains(ca, "zerossl") {
		return "https://acme.zerossl.com/v2/DV90"
	}
	return ""
}

func isAlreadyRegistered(err error) bool {
	if err == nil { return false }
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already registered") || strings.Contains(s, "account exists")
}

func obtainOrRenew(client *lego.Client, _ *acmeConf, domains []string) (*certificate.Resource, error) {
	req := certificate.ObtainRequest{Domains: domains, Bundle: true}
	return client.Certificate.Obtain(req)
}

func writeOut(c *acmeConf, res *certificate.Resource) error {
	if res == nil { return errors.New("nil cert resource") }
	home, err := os.UserHomeDir(); if err != nil { return err }
	dir := filepath.Join(home, ".acme.sh", c.MainDomain)
	if err := os.MkdirAll(dir, 0700); err != nil { return err }

	leafPath := filepath.Join(dir, c.MainDomain+".cer")
	fullPath := filepath.Join(dir, "fullchain.cer")
	caPath   := filepath.Join(dir, "ca.cer")
	keyPath  := filepath.Join(dir, c.MainDomain+".key")

	if err := writeFile(leafPath, 0644, res.Certificate); err != nil { return err }
	if err := writeFile(caPath,   0644, res.IssuerCertificate); err != nil { return err }
	full := append([]byte{}, res.Certificate...)
	full = append(full, res.IssuerCertificate...)
	if err := writeFile(fullPath, 0644, full); err != nil { return err }
	if err := writeFile(keyPath,  0600, res.PrivateKey); err != nil { return err }
	return nil
}

func writeFile(path string, mode fs.FileMode, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil { return err }
	defer f.Close()
	_, err = f.Write(data)
	return err
}
