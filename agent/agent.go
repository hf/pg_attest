package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/pg_attest/message"
	"github.com/hf/pg_attest/server"
)

type Agent struct {
	config *Config
	server *server.Server
}

func NewAgent(config *Config) (*Agent, error) {
	agent := &Agent{
		config: config,
		server: &server.Server{},
	}

	agent.server.Attest = agent.Attest

	return agent, nil
}

func (a *Agent) Run(ctx context.Context) error {
	return a.server.Run(ctx, "")
}

func (a *Agent) Attest(ctx context.Context, req message.RequestAttestation) (message.ResponseAttestation, error) {
	format, config := a.config.DefaultAttestationConfig()

	switch strings.ToLower(format) {
	case "oidc":
		return a.attestOIDC(ctx, req, config)

	default:
		panic(fmt.Sprintf("agent: unsupported attestation format %q", format))
	}
}

func (a *Agent) attestOIDC(ctx context.Context, req message.RequestAttestation, config *ConfigAttestation) (message.ResponseAttestation, error) {
	var res message.ResponseAttestation

	kid, keySpec := config.DefaultPrivateKey()
	if "" == kid {
		panic("agent: no private key found for OIDC attestation")
	}

	signer, err := keySpec.Load(ctx)
	if err != nil {
		return res, err
	}

	var alg string
	switch signer.(type) {
	case *rsa.PrivateKey:
		alg = "RS256"

	case *ecdsa.PrivateKey:
		alg = "ES256"

	case ed25519.PrivateKey:
		alg = "EdDSA"

	case *kmsPrivateKey:
		switch signer.(*kmsPrivateKey).keySpec {
		case kmstypes.KeySpecRsa2048, kmstypes.KeySpecRsa3072, kmstypes.KeySpecRsa4096:
			alg = "RS256"

		case kmstypes.KeySpecEccNistP256:
			alg = "ES256"

		case kmstypes.KeySpecHmac256:
			alg = "HS256"

		default:
			panic(fmt.Sprintf("agent: unable to determine OIDC attestation alg from AWS KMS key spec %q", signer.(*kmsPrivateKey).keySpec))
		}

	default:
		panic(fmt.Sprintf("agent: unsupported private key type %t", signer))
	}

	header, err := json.Marshal(map[string]any{
		"typ": "JWT",
		"alg": alg,
		"kid": kid,
	})
	if err != nil {
		panic(err.Error())
	}

	body := make(map[string]any)
	if config.Template.JSON != "" {
		if err := json.Unmarshal([]byte(config.Template.JSON), body); err != nil {
			panic(err.Error())
		}
	}

	if config.Template.Issuer != "" {
		body["iss"] = config.Template.Issuer
	}

	now := time.Now()
	exp := req.Timestamp.Add(config.ExpiresAfter)

	body["nbf"] = now.Unix()
	body["exp"] = exp.Unix()

	body["sub"] = req.Proofs["session_user"]
	body["role"] = req.Proofs["current_user"]

	proofs := make(map[string]json.RawMessage, len(req.Proofs))
	for k, v := range req.Proofs {
		proofs[k] = v
	}

	delete(proofs, "current_user")
	delete(proofs, "session_user")

	if len(proofs) > 0 {
		body["proofs"] = proofs
	}

	headerJWT := base64.RawURLEncoding.EncodeToString(header)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return res, err
	}

	bodyJWT := base64.RawURLEncoding.EncodeToString(bodyBytes)
	unsignedJWT := headerJWT + "." + bodyJWT

	var h crypto.Hash
	var digest []byte

	switch signer.(type) {
	case ed25519.PrivateKey:
		// Ed25519 hashes the input on its own
		h = crypto.Hash(0)
		digest = []byte(unsignedJWT)

	case *kmsPrivateKey:
		switch signer.(*kmsPrivateKey).keySpec {
		case kmstypes.KeySpecHmac256:
			// AWS KMS HMAC keys hash on their own
			h = crypto.Hash(0)
			digest = []byte(unsignedJWT)
		}
	}

	if digest == nil {
		// all other algorithms require a hash
		h = crypto.SHA256

		hs := sha256.New()
		hs.Write([]byte(unsignedJWT))
		digest = hs.Sum(nil)
	}

	var signature []byte
	if _, ok := signer.(SignerWithContext); ok {
		sig, err := signer.(SignerWithContext).SignWithContext(ctx, rand.Reader, digest, h)
		if err != nil {
			return res, err
		}
		signature = sig
	} else {
		sig, err := signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return res, err
		}
		signature = sig
	}

	signatureJWT := base64.RawURLEncoding.EncodeToString(signature)

	res.Type = message.TypeResponseAttestation
	res.Attestation = unsignedJWT + "." + signatureJWT
	res.Format = "oidc"
	res.NotBefore = now
	res.NotAfter = exp

	return res, nil
}
