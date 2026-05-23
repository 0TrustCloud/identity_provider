package identity_provider

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
)

// --- Helper: Mock HTTP Transport for SCIM ---
type MockRoundTripper struct {
	RoundTripFunc func(req *http.Request) *http.Response
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req), nil
}

// --- Helper: DB Setup ---
func setupTestDB(t *testing.T) (*ultimate_db.DB, string) {
	dir, err := os.MkdirTemp("", "iam_test_db")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(dir, "test.db")
	dm, _ := ultimate_db.NewDiskManager(dbPath)
	bp := ultimate_db.NewBufferPool(dm, 1024)
	wal, _ := ultimate_db.NewBatchingWAL(dbPath + "_wal.log")
	db := ultimate_db.NewDB(bp, wal)
	ultimate_db.RecoverDB(dbPath+"_wal.log", db)

	return db, dir
}

func TestAdminController_AppLifecycle(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)

	pe := secure_policy.NewPolicyEngine(db)
	bus := make(chan secure_network.SystemEvent, 10)

	admin := AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
	}

	// 1. Test App Registration
	testApp := Application{
		ID:           "app_okta_sim",
		Name:         "Google Workspace SCIM",
		TargetURL:    "https://workspace.google.com",
		SCIMEndpoint: "https://admin.google.com/scim/v2",
		SCIMToken:    "mock_token_123",
	}

	err := admin.RegisterApp(testApp)
	if err != nil {
		t.Fatalf("Failed to register app: %v", err)
	}

	// Verify DB Write
	txn := db.BeginTxn()
	data, err := db.Read(AppRegistryPageID, txn, []byte("app_okta_sim"))
	db.CommitTxn(txn)
	if err != nil || len(data) == 0 {
		t.Fatal("App was not written to database")
	}

	// 2. Test User Assignment
	testUser := Identity{
		Subject: "user_777",
		Type:    IdentityHuman,
		Attributes: map[string]string{
			"email":       "gregory@example.mesh",
			"given_name":  "Gregory",
			"family_name": "Disney",
		},
	}

	err = admin.AssignUserToApp(testUser, testApp.ID)
	if err != nil {
		t.Fatalf("Failed to assign user to app: %v", err)
	}

	// Verify Policy Engine was updated
	if !pe.Evaluate([]byte("user_777"), "access", "app_okta_sim", nil) {
		t.Fatal("Policy engine did not grant access after assignment")
	}

	// Verify LocalBus received the provisioning event
	select {
	case event := <-bus:
		if event.Topic != "scim_provision" {
			t.Errorf("Expected scim_provision event, got %s", event.Topic)
		}
	default:
		t.Fatal("No event was published to the LocalBus")
	}
}

func TestSCIMDaemon_Provisioning(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)

	// Pre-load an app into the DB for the Daemon to find
	testApp := Application{
		ID:           "app_scim_target",
		Name:         "Target App",
		SCIMEndpoint: "https://api.target.app/scim",
		SCIMToken:    "secret_token",
	}
	appData, _ := json.Marshal(testApp)
	txn := db.BeginTxn()
	db.Write(AppRegistryPageID, txn, []byte("app_scim_target"), appData, 0)
	db.CommitTxn(txn)

	bus := make(chan secure_network.SystemEvent, 1)

	// Setup Mock HTTP Client to intercept the SCIM POST request
	mockTransport := &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.String() != "https://api.target.app/scim/Users" {
				t.Errorf("Expected URL https://api.target.app/scim/Users, got %s", req.URL.String())
			}
			if req.Header.Get("Authorization") != "Bearer secret_token" {
				t.Errorf("Missing or invalid Auth header")
			}

			// Read and verify the SCIM payload
			bodyBytes, _ := io.ReadAll(req.Body)
			var scimUser SCIMUser
			json.Unmarshal(bodyBytes, &scimUser)

			if scimUser.UserName != "gregory@example.mesh" {
				t.Errorf("Expected UserName gregory@example.mesh, got %s", scimUser.UserName)
			}
			if scimUser.Name.GivenName != "Gregory" {
				t.Errorf("Expected GivenName Gregory, got %s", scimUser.Name.GivenName)
			}

			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(bytes.NewBufferString(`{"id": "remote_scim_id_999"}`)),
				Header:     make(http.Header),
			}
		},
	}

	daemon := NewSCIMDaemon(db, bus)
	daemon.Client.Transport = mockTransport

	// Start daemon in background
	go daemon.Start()

	// Fire an event into the bus (simulating AdminController)
	testUser := Identity{
		Subject: "user_888",
		Attributes: map[string]string{
			"email":       "gregory@example.mesh",
			"given_name":  "Gregory",
			"family_name": "Disney",
		},
	}
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"app_id":   "app_scim_target",
		"identity": testUser,
	})

	bus <- secure_network.SystemEvent{
		Topic:   "scim_provision",
		Payload: eventPayload,
	}

	// Allow a moment for the goroutine to process the HTTP mock
	time.Sleep(100 * time.Millisecond)
}

func TestEnforcePolicyMiddleware(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)

	pe := secure_policy.NewPolicyEngine(db)
	
	// Pre-authorize user_trusted
	pe.AddPolicy([]byte("user_trusted"), "access", "secure_app", "ALLOW", nil)

	// Create the protected handler
	protectedHandler := EnforcePolicy(pe, "access", "secure_app")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Access Granted"))
	})

	// Scenario 1: No Cookie
	req1 := httptest.NewRequest("GET", "/app", nil)
	rr1 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing cookie, got %d", rr1.Code)
	}

	// Scenario 2: Cookie exists, but user is NOT authorized (user_untrusted)
	req2 := httptest.NewRequest("GET", "/app", nil)
	req2.AddCookie(&http.Cookie{Name: "session_id", Value: "user_session_user_untrusted"})
	rr2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for unauthorized user, got %d", rr2.Code)
	}

	// Scenario 3: Cookie exists AND user IS authorized (user_trusted)
	req3 := httptest.NewRequest("GET", "/app", nil)
	req3.AddCookie(&http.Cookie{Name: "session_id", Value: "user_session_user_trusted"})
	rr3 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for authorized user, got %d", rr3.Code)
	}
}
