package agent

import "time"

type ConfigTemplate struct {
	JSON string `json:"base" yaml:"base"`

	Issuer string `json:"issuer" yaml:"issuer"`
	Scopes string `json:"scopes" yaml:"scopes"`
}

type ConfigPrivateKey struct {
	NotAfter time.Time `json:"not_after" yaml:"not_after"`

	File struct {
		Path string `json:"path" yaml:"path"`

		Format   string `json:"format" yaml:"format"`
		Encoding string `json:"encoding" yaml:"encoding"`
	} `json:"file" yaml:"file"`

	KMS string `json:"aws_kms" yaml:"aws_kms"`
}

type ConfigAttestation struct {
	ExpiresAfter time.Duration  `json:"expires_after" yaml:"expires_after"`
	Template     ConfigTemplate `json:"template" yaml:"template"`

	PrivateKeys map[string]ConfigPrivateKey `json:"private_keys" yaml:"private_keys"`
}

func (c *ConfigAttestation) DefaultPrivateKey() (string, *ConfigPrivateKey) {
	for k, v := range c.PrivateKeys {
		return k, &v
	}

	return "", nil
}

type Config struct {
	Attestation map[string]ConfigAttestation `json:"attestation" yaml:"attestation"`
}

func (c *Config) DefaultAttestationConfig() (string, *ConfigAttestation) {
	for k, v := range c.Attestation {
		return k, &v
	}

	return "", nil
}
