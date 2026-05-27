package identity_provider

import "time"

// IdentityType uses string constants for explicit JSON serialization across the QUIC mesh
type IdentityType string

const (
	IdentityHuman   IdentityType = "human"
	IdentityMachine IdentityType = "machine" // Aligns with TPM 2.0 / Service Key terminology
)

// Identity acts as the universal passport across the mesh and policy engines
type Identity struct {
	Subject       string            `json:"sub"`
	Type          IdentityType      `json:"type"`
	Attributes    map[string]string `json:"attr,omitempty"`
	HardwareBound bool              `json:"hw_bound"` // Indicates if identity is backed by TPM/Passkey
	ExpiresAt     time.Time         `json:"exp"`
	SessionID     string            `json:"sid,omitempty"`
}

// Application represents a registered integration in your Zero-Trust catalog
type Application struct {
	ID             string `json:"app_id"`
	Name           string `json:"name"`
	TargetURL      string `json:"target_url"`
	AuthProtocol   string `json:"auth_protocol"`
	RequiredPolicy string `json:"required_policy"`
	SCIMEndpoint   string `json:"scim_endpoint,omitempty"`
	SCIMToken      string `json:"scim_token,omitempty"`
}
