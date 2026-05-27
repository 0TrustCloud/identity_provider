package identity_provider

import "time"

type IdentityType int

const (
	IdentityHuman IdentityType = iota
	IdentityService
)

// Identity acts as the universal passport across the mesh and policy engines
type Identity struct {
	Subject    string            `json:"sub"`
	Type       IdentityType      `json:"type"`
	Attributes map[string]string `json:"attr"`
	ExpiresAt  time.Time         `json:"exp"`
	SessionID  string            `json:"sid"`
}

// Application represents a registered integration in your Okta-like catalog
type Application struct {
	ID             string `json:"app_id"`
	Name           string `json:"name"`
	TargetURL      string `json:"target_url"`
	AuthProtocol   string `json:"auth_protocol"`
	RequiredPolicy string `json:"required_policy"`
	SCIMEndpoint   string `json:"scim_endpoint,omitempty"`
	SCIMToken      string `json:"scim_token,omitempty"`
}
