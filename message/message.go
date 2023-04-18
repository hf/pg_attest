package message

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	TypeRequestAttestation  = "request_attestation"
	TypeResponseAttestation = "response_attestation"
	TypeError               = "error"
)

const (
	FormatJWT = "jwt"
)

type Message struct {
	Type string `json:"type"`
}

type RequestAttestation struct {
	Type      string                     `json:"type"`
	Timestamp time.Time                  `json:"timestamp,unix"`
	Proofs    map[string]json.RawMessage `json:"proofs"`
}

type ResponseAttestation struct {
	Type        string    `json:"type"`
	Attestation string    `json:"attestation"`
	Format      string    `json:"format"`
	NotBefore   time.Time `json:"issued_at,unix"`
	NotAfter    time.Time `json:"not_after,unix"`
}

type Error struct {
	Type  string `json:"type"`
	Error string `json:"error"`
}

func Marshal(msg any) []byte {
	switch msg.(type) {
	case error:
		msg = Error{
			Type:  TypeError,
			Error: msg.(error).Error(),
		}
	}

	bytes, err := json.Marshal(msg)
	if err != nil {
		panic(err.Error())
	}

	return bytes
}

func Parse(buf []byte) (any, error) {
	var message Message
	if err := json.Unmarshal(buf, &message); err != nil {
		return nil, err
	}

	var parsed any

	switch message.Type {
	case TypeRequestAttestation:
		parsed = &RequestAttestation{}

	case TypeResponseAttestation:
		parsed = &ResponseAttestation{}

	case TypeError:
		parsed = &Error{}

	default:
		return nil, fmt.Errorf("unsupported message type %q", message.Type)
	}

	if err := json.Unmarshal(buf, parsed); err != nil {
		return nil, err
	}

	return parsed, nil
}
