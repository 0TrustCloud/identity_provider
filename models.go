package identity_provider

import (
	"time"
	"github.com/0TrustCloud/ultimate_db"
)

// AppRegistryPageID safely isolates the IAM application registry from orchid_sync's Index (10) and Metadata (11) pages.
const AppRegistryPageID ultimate_db.PageID = 20

// IdentityType uses string constants for explicit JSON serialization across the QUIC mesh
type IdentityType string

const (
	IdentityHuman   IdentityType = "human"
	IdentityMachine IdentityType = "machine" // Aligns with TPM 2.0 / Service Key terminology
)

// Identity acts as the universal passport across the mesh and policy engines,
// now expanded to support polymorphic SDF verification tracking.
type Identity struct {
	Subject       string            `json:"sub" yaml:"sub"`
	Type          IdentityType      `json:"type" yaml:"type"`
	Attributes    map[string]string `json:"attr,omitempty" yaml:"attr,omitempty"`
	HardwareBound bool              `json:"hw_bound" yaml:"hw_bound"`
	ExpiresAt     time.Time         `json:"exp" yaml:"exp"`
	SessionID     string            `json:"sid,omitempty" yaml:"sid,omitempty"`
	SDFToken      string            `json:"sdf_token,omitempty" yaml:"sdf_token,omitempty"`
	StateRootHash string            `json:"state_root_hash,omitempty" yaml:"state_root_hash,omitempty"`
}

// ToSDFArgs extracts identity context dimensions into a canonical argument map for the SDF compilation engine
func (i Identity) ToSDFArgs() map[string]interface{} {
	args := map[string]interface{}{
		"subject":        i.Subject,
		"identity_type":  string(i.Type),
		"hardware_bound": i.HardwareBound,
		"session_id":     i.SessionID,
		"expires_at":     i.ExpiresAt.Unix(),
	}
	for k, v := range i.Attributes {
		args["attr_"+k] = v
	}
	return args
}

// Application represents a registered integration in your Zero-Trust catalog,
// now integrated with structural registry identity fields.
type Application struct {
	ID             string `json:"app_id" yaml:"app_id"`
	Name           string `json:"name" yaml:"name"`
	TargetURL      string `json:"target_url" yaml:"target_url"`
	AuthProtocol   string `json:"auth_protocol" yaml:"auth_protocol"`
	RequiredPolicy string `json:"required_policy" yaml:"required_policy"`
	SCIMEndpoint   string `json:"scim_endpoint,omitempty" yaml:"scim_endpoint,omitempty"`
	SCIMToken      string `json:"scim_token,omitempty" yaml:"scim_token,omitempty"`
	RegistryToken  string `json:"registry_token,omitempty" yaml:"registry_token,omitempty"`
}

// ToSDFArgs normalizes the application catalog specifications into a standardized schema mapping context
func (a Application) ToSDFArgs() map[string]interface{} {
	return map[string]interface{}{
		"app_id":          a.ID,
		"name":            a.Name,
		"target_url":      a.TargetURL,
		"auth_protocol":   a.AuthProtocol,
		"required_policy": a.RequiredPolicy,
		"scim_configured": a.SCIMEndpoint != "",
	}
}
