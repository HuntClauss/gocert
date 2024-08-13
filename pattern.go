package gocert

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type CertConfig struct {
	Metadata Metadata
	Subject  Subject
	DNS      DNS
}

type Metadata struct {
	IsCa       bool
	CaCertPath string `toml:"ca-cert"`
	CaKeyPath  string `toml:"ca-key"`
	Expiration struct {
		Years, Months, Days int
	}
}

type Subject struct {
	CommonName    string `toml:"common-name"`
	Organization  []string
	Country       []string
	Province      []string
	Locality      []string
	StreetAddress []string `toml:"street-address"`
	PostalCode    []string `toml:"posta-code"`
}

type DNS struct {
	Domains []string
	IPs     []string
}

func LoadCertConfig(path string) (CertConfig, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return CertConfig{}, fmt.Errorf("cannot open cert config file: %w", err)
	}
	defer f.Close()

	var result CertConfig
	if err := toml.NewDecoder(f).Decode(&result); err != nil {
		return CertConfig{}, fmt.Errorf("cannot decode toml cert config: %w", err)
	}
	return result, nil
}
