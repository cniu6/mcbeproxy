package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var secureIdentityID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type SecureIdentityInfo struct {
	ServerName string    `json:"server_name"`
	CertPEM    string    `json:"trusted_cert_pem"`
	SHA256     string    `json:"cert_sha256"`
	Expires    time.Time `json:"expires"`
}
type secureIdentityFile struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}
type SecureIdentityStore struct {
	root string
	mu   sync.Mutex
}

func NewSecureIdentityStore(dataDir string) *SecureIdentityStore {
	return &SecureIdentityStore{root: filepath.Join(dataDir, "secure-identities")}
}
func (s *SecureIdentityStore) Create(id string) (SecureIdentityInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !secureIdentityID.MatchString(id) {
		return SecureIdentityInfo{}, errors.New("身份ID无效")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	name := id + ".proxy.internal"
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	file := secureIdentityFile{Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	raw, err := json.Marshal(file)
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	if err := os.MkdirAll(s.root, 0700); err != nil {
		return SecureIdentityInfo{}, err
	}
	// 显式创建且禁止覆盖；正常启动只读取，损坏也不能静默更换身份。
	path := filepath.Join(s.root, id+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return SecureIdentityInfo{}, err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return SecureIdentityInfo{}, err
	}
	_, info, err := decodeSecureIdentity(file)
	return info, err
}
func (s *SecureIdentityStore) Load(id string) (tls.Certificate, SecureIdentityInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !secureIdentityID.MatchString(id) {
		return tls.Certificate{}, SecureIdentityInfo{}, errors.New("身份ID无效")
	}
	raw, err := os.ReadFile(filepath.Join(s.root, id+".json"))
	if err != nil {
		return tls.Certificate{}, SecureIdentityInfo{}, err
	}
	var file secureIdentityFile
	if json.Unmarshal(raw, &file) != nil {
		return tls.Certificate{}, SecureIdentityInfo{}, errors.New("服务身份文件损坏")
	}
	return decodeSecureIdentity(file)
}
func decodeSecureIdentity(file secureIdentityFile) (tls.Certificate, SecureIdentityInfo, error) {
	pair, err := tls.X509KeyPair([]byte(file.Cert), []byte(file.Key))
	if err != nil {
		return pair, SecureIdentityInfo{}, errors.New("服务身份密钥不匹配")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return pair, SecureIdentityInfo{}, err
	}
	if len(cert.DNSNames) != 1 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return pair, SecureIdentityInfo{}, errors.New("服务身份名称或有效期无效")
	}
	pair.Leaf = cert
	hash := sha256.Sum256(cert.Raw)
	return pair, SecureIdentityInfo{ServerName: cert.DNSNames[0], CertPEM: file.Cert, SHA256: hex.EncodeToString(hash[:]), Expires: cert.NotAfter}, nil
}
