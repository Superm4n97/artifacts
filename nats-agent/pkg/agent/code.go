package agent

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Code returns the code the platform derives from an identity: the lower-case,
// unpadded base32 of the first 16 bytes of SHA-256(identity). 26 characters.
func Code(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return strings.ToLower(codeEncoding.EncodeToString(sum[:16]))
}

// AgentIdentity is the identity the platform gives a datacenter agent.
func AgentIdentity(uuid string) string { return "service_account:" + uuid }
