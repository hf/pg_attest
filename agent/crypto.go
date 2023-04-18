package agent

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func (c *ConfigPrivateKey) Load(ctx context.Context) (crypto.Signer, error) {
	if c.File.Path != "" {
		return c.loadFile()
	}

	if c.KMS != "" {
		return c.loadKMS(ctx)
	}

	return nil, errors.New("agent: private key not specified in config")
}

func parsePKCS8(der []byte) (crypto.Signer, error) {
	pk, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	switch pk.(type) {
	case crypto.Signer:
		return pk.(crypto.Signer), nil

	default:
		panic(fmt.Sprintf("agent: PKCS8 private key of type %t does not implement crypto.Signer", pk))
	}
}

func parsePrivateKey(contents []byte, path, encoding, format string) (crypto.Signer, error) {
	switch strings.ToLower(encoding) {
	case "", "pem":
		block, rest := pem.Decode(contents)
		if len(rest) > 0 {
			return nil, fmt.Errorf("agent: unable fully decode PEM file %q", path)
		}

		switch block.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)

		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)

		case "PRIVATE KEY":
			return parsePKCS8(block.Bytes)

		default:
			return nil, fmt.Errorf("agent: unrecognized PEM block type %q in file %q", block.Type, path)
		}

	case "der", "ber", "base64", "asn1":
		if "base64" == encoding {
			decoded := make([]byte, 0, len(contents))
			n, err := base64.StdEncoding.Decode(decoded, contents)
			if err != nil {
				return nil, fmt.Errorf("agent: unable to decode Base64 private key file %q: %w", path, err)
			}

			contents = decoded[:n]
		}

		switch strings.ToLower(format) {
		case "", "pkcs8":
			return parsePKCS8(contents)

		case "ec":
			return x509.ParseECPrivateKey(contents)

		case "pkcs1", "rsa":
			return x509.ParsePKCS1PrivateKey(contents)

		case "hmac":
			// TODO
			return nil, fmt.Errorf("agent: private key format %q not implemented", format)

		default:
			return nil, fmt.Errorf("agent: private key format %q not supported", format)
		}

	default:
		return nil, fmt.Errorf("agent: private key encoding %q not supported", encoding)
	}
}

func (c *ConfigPrivateKey) loadFile() (crypto.Signer, error) {
	file, err := os.Open(c.File.Path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return parsePrivateKey(contents, c.File.Path, c.File.Encoding, c.File.Format)
}

type SignerWithContext interface {
	SignWithContext(context.Context, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

type kmsPrivateKey struct {
	client *kms.Client

	arn     string
	keySpec kmstypes.KeySpec
}

func (c *kmsPrivateKey) Public() crypto.PublicKey {
	panic("agent: public key extraction not supported at this time")
}

func (c *kmsPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.SignWithContext(context.Background(), rand, digest, opts)
}

func (c *kmsPrivateKey) SignWithContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch c.keySpec {
	case kmstypes.KeySpecHmac256:
		output, err := c.client.GenerateMac(ctx, &kms.GenerateMacInput{
			KeyId:        &c.arn,
			MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256,
			Message:      digest,
		})
		if err != nil {
			return nil, err
		}

		return output.Mac, nil

	default:
		var signingAlgorithm kmstypes.SigningAlgorithmSpec

		switch c.keySpec {
		case kmstypes.KeySpecRsa2048, kmstypes.KeySpecRsa3072, kmstypes.KeySpecRsa4096:
			signingAlgorithm = kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256

		case kmstypes.KeySpecEccNistP256:
			signingAlgorithm = kmstypes.SigningAlgorithmSpecEcdsaSha256

		default:
			panic(fmt.Sprintf("agent: unsupported key spec %q for kms:Sign APIs", c.keySpec))
		}

		output, err := c.client.Sign(ctx, &kms.SignInput{
			KeyId:            &c.arn,
			SigningAlgorithm: signingAlgorithm,
			Message:          digest,
			MessageType:      kmstypes.MessageTypeDigest,
		})
		if err != nil {
			return nil, err
		}

		return output.Signature, nil
	}
}

func (c *ConfigPrivateKey) loadKMS(ctx context.Context) (crypto.Signer, error) {
	privateKey := &kmsPrivateKey{
		client: kms.NewFromConfig(aws.NewConfig().Copy()),
	}

	output, err := privateKey.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: &c.KMS,
	})
	if err != nil {
		return nil, err
	}

	switch output.KeyMetadata.KeyState {
	case kmstypes.KeyStateEnabled:
		// ok

	default:
		return nil, fmt.Errorf("agent: AWS KMS key %q in %q state", output.KeyMetadata.KeyState)
	}

	switch output.KeyMetadata.KeyUsage {
	case kmstypes.KeyUsageTypeEncryptDecrypt:
		return nil, fmt.Errorf("agent: AWS KMS key %q can't be used for signatures", *output.KeyMetadata.Arn)
	}

	switch output.KeyMetadata.KeySpec {
	case kmstypes.KeySpecRsa2048, kmstypes.KeySpecRsa3072, kmstypes.KeySpecRsa4096, kmstypes.KeySpecEccNistP256, kmstypes.KeySpecHmac256:
		// ok

	default:
		return nil, fmt.Errorf("agent: AWS KMS key %q has unsupported algorithm %q", *output.KeyMetadata.Arn, output.KeyMetadata.KeySpec)
	}

	privateKey.arn = *output.KeyMetadata.Arn
	privateKey.keySpec = output.KeyMetadata.KeySpec

	return privateKey, nil
}
