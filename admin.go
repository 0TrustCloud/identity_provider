package identity_provider

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/ultimate_db"
)

type AdminController struct {
	DB           *ultimate_db.DB
	PolicyEngine *secure_policy.PolicyEngine
	LocalBus     chan secure_network.SystemEvent
	Logger       *logger.LogDispatcher
	SDFEngine    *secure_data_format.SecureDataEngine // Unified SDF compilation engine
}

// NewAdminController instantiates the controller with fully integrated SDF capability
func NewAdminController(db *ultimate_db.DB, pe *secure_policy.PolicyEngine, bus chan secure_network.SystemEvent, log *logger.LogDispatcher, sdf *secure_data_format.SecureDataEngine) *AdminController {
	return &AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
		Logger:       log,
		SDFEngine:    sdf,
	}
}

// RegisterApp compiles a structural application registration schema via SDF
// and appends an immutable record to the ledger state.
func (a *AdminController) RegisterApp(app Application, actor string) error {
	// 1. Generate declarative configuration script for the SDF parser
	script := fmt.Sprintf(`
		service:catalog.register#%s(
			name("%s")
			target_url("%s")
			auth_protocol("%s")
			required_policy("%s")
		)
	`, app.ID, app.Name, app.TargetURL, app.AuthProtocol, app.RequiredPolicy)

	// 2. Marshal baseline app data for token argument inclusion
	appBytes, err := json.Marshal(app)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error("Failed to serialize application configuration payload: " + err.Error())
		}
		return err
	}

	var args map[string]interface{}
	if err := json.Unmarshal(appBytes, &args); err != nil {
		return err
	}
	args["registered_by"] = actor

	tx := secure_data_format.DataInvocation{
		TargetAddress: fmt.Sprintf("mesh:catalog:app:%s", app.ID),
		Caller:        actor,
		Nonce:         nonceFromAppID(app.ID),
		Method:        "EMIT",
		Profile:       secure_data_format.ProfileStructuredLog, // Use 10-year archival lifecycle profile
		Args:          args,
	}

	// 3. Compile structural graph token and execute 2PL transactional storage commit
	token, err := a.SDFEngine.CompileSecureData(script, tx)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error(fmt.Sprintf("Application catalog registration failed via SDF: %v", err))
		}
		return err
	}

	if err := a.saveApp(app); err != nil {
		return err
	}

	if a.Logger != nil {
		a.Logger.Audit(actor, "DEPLOY_SERVICE", fmt.Sprintf("Successfully registered application tile %s using contract token signature hash: %s", app.ID, token[len(token)-15:]))
	}

	return nil
}

func (a *AdminController) saveApp(app Application) error {
	if a.DB == nil {
		return fmt.Errorf("database not initialized")
	}
	appBytes, err := json.Marshal(app)
	if err != nil {
		return err
	}
	txn := a.DB.BeginTxn()
	if err := a.DB.Write(AppRegistryPageID, txn, []byte(app.ID), appBytes, 0); err != nil {
		return err
	}
	a.DB.CommitTxn(txn)
	return nil
}

func (a *AdminController) GetApp(appID string) (Application, error) {
	if a.DB == nil {
		return Application{}, fmt.Errorf("database not initialized")
	}
	txn := a.DB.BeginTxn()
	raw, err := a.DB.Read(AppRegistryPageID, txn, []byte(appID))
	a.DB.CommitTxn(txn)
	if err != nil || len(raw) == 0 {
		return Application{}, fmt.Errorf("application not found")
	}
	var app Application
	return app, json.Unmarshal(raw, &app)
}

func (a *AdminController) UpdateAppSCIM(appID, endpoint, token, actor string) error {
	app, err := a.GetApp(appID)
	if err != nil {
		return err
	}
	app.SCIMEndpoint = endpoint
	if token != "" {
		app.SCIMToken = token
	}
	if err := a.saveApp(app); err != nil {
		return err
	}
	if a.Logger != nil {
		a.Logger.Audit(actor, "SCIM_CONFIGURE", fmt.Sprintf("Updated SCIM endpoint for app %s", appID))
	}
	return nil
}

func (a *AdminController) EmitSCIMProvision(appID string, identity Identity) error {
	if a.LocalBus == nil {
		return fmt.Errorf("event bus not initialized")
	}
	payload, err := json.Marshal(map[string]interface{}{
		"app_id":   appID,
		"identity": identity,
	})
	if err != nil {
		return err
	}
	a.LocalBus <- secure_network.SystemEvent{Topic: "scim_provision", Payload: payload}
	return nil
}

// AssignUserToApp evaluates the entitlement rule through the SDF script token synthesis layer,
// updates the active policy engine, and safely triggers the outbound async SCIM daemon provisioning pipeline.
func (a *AdminController) AssignUserToApp(identity Identity, appID string, actor string) error {
	// 1. Enforce rule expression via precise grammatical constraints matching the engine parser
	script := fmt.Sprintf(`
		grant:mesh.access#%s(
			scope("access")
			subject("%s")
			identity_type("%s")
			hardware_bound:enforced("%t")
		)
	`, appID, identity.Subject, string(identity.Type), identity.HardwareBound)

	// 2. Map standard identity contextual dimensions into execution namespace arguments
	args := map[string]interface{}{
		"subject":        identity.Subject,
		"identity_type":  string(identity.Type),
		"hardware_bound": identity.HardwareBound,
		"session_id":     identity.SessionID,
	}
	for k, v := range identity.Attributes {
		args["attr_"+k] = v
	}

	tx := secure_data_format.DataInvocation{
		TargetAddress: fmt.Sprintf("mesh:policy:grant:%s", appID),
		Caller:        actor,
		Nonce:         uint64(time.Now().UnixNano()),
		Method:        "DELEGATE",
		Profile:       secure_data_format.ProfileGrant, // Enforces explicit short-term credential window bounds
		Args:          args,
	}

	// 3. Compile cryptographic polymorphic token
	_, err := a.SDFEngine.CompileSecureData(script, tx)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error(fmt.Sprintf("Access assignment token compilation aborted by SDF engine: %v", err))
		}
		return err
	}

	// 4. Update the structural policy matrix state machine
	resource := appID
	if !strings.HasPrefix(resource, "app:") {
		resource = "app:" + appID
	}
	err = a.PolicyEngine.AddPolicy([]byte(identity.Subject), "access", resource, "ALLOW", nil)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error("Policy matrix failure applying newly validated assignment: " + err.Error())
		}
		return err
	}

	// 5. Package state envelope cleanly and dispatch across the background system event bus
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"app_id":   appID,
		"identity": identity,
	})

	a.LocalBus <- secure_network.SystemEvent{
		Topic:   "scim_provision",
		Payload: eventPayload,
	}

	if a.Logger != nil {
		a.Logger.Audit(actor, "GRANT_ACCESS", fmt.Sprintf("Assigned zero-trust identity token assertion for subject %s to target endpoint application %s", identity.Subject, appID))
	}

	return nil
}

// SynthesizeIdentityToken acts as a bridge for HTTP handlers to dynamically compile ad-hoc SDF tokens
func (a *AdminController) SynthesizeIdentityToken(script, targetAddress, actor string, nonce uint64, profile secure_data_format.TokenProfile, args map[string]interface{}) (string, error) {
	if a.SDFEngine == nil {
		return "", fmt.Errorf("SDF engine is not initialized on this controller")
	}

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        actor,
		Nonce:         nonce,
		Method:        "ASSERT",
		Profile:       profile,
		Args:          args,
	}

	return a.SDFEngine.CompileSecureData(script, tx)
}

// ListApps returns IAM catalog applications registered via RegisterApp.
func (a *AdminController) ListApps() ([]Application, error) {
	if a.DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	var apps []Application
	txn := a.DB.BeginTxn()
	defer a.DB.CommitTxn(txn)
	_ = a.DB.Scan(AppRegistryPageID, txn, nil, func(key, value []byte) bool {
		if len(value) == 0 {
			return true
		}
		var app Application
		if json.Unmarshal(value, &app) == nil && app.ID != "" {
			app.SCIMToken = ""
			apps = append(apps, app)
		}
		return true
	})
	return apps, nil
}

func nonceFromAppID(id string) uint64 {
	if id == "" {
		return uint64(time.Now().UnixNano())
	}
	return uint64(id[0])
}
