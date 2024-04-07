package config

import (
	"encoding/json"
	"io"
	"os"
)

type Config struct {
	Zone       []ConfZone        `json:"zones"`
	TsigSecret map[string]string `json:"tsig-secret"`
	LocalAddr  string            `json:"local-addr"`
}

type ConfZone struct {
	DBFile    string `json:"db-file"`
	ZoneName  string `json:"zone-name"`
	NsName    string `json:"ns-name"`
	AllowCIDR string `json:"allow-cidr"`
}

func Load(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var c Config
	err = json.Unmarshal(b, &c)
	return &c, err
}
