package identity_provider

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
)

type MockRoundTripper struct {
	RoundTripFunc func(req *http.Request) *http.Response
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req), nil
}

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

func getRealLogger(t *testing.T, walPath string) *logger.RPCLogger {
	rpc := secure_network.NewRPCManager(nil)
	l, err := logger.NewRPCLogger(rpc, "test_svc", 10, walPath)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return l
}

func TestAdminController_AppLifecycle(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)

	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))
	defer sysLog.Close()

	pe := secure_policy.NewPolicyEngine(db)
	bus := make(chan secure_network.SystemEvent, 10)

	admin := AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
		Logger:       sysLog,
	}

	testApp := Application{
		ID:           "app_okta_sim",
		Name:         "Google Workspace SCIM",
		TargetURL:    "https://workspace.google.com",
		SCIMEndpoint: "https://admin.google.com/scim/v2",
		SCIMToken:    "mock_token_123",
	}

	err := admin.RegisterApp(testApp, "test_admin")
	if err != nil {
		t.Fatalf("Failed to register app: %v", err)
	}

	testUser := Identity{
		Subject: "user_777",
		Type:    IdentityHuman,
		Attributes: map[string]string{
			"email":       "gregory@example.mesh",
			"given_name":  "Gregory",
			"family_name": "Disney",
		},
	}

	err = admin.AssignUserToApp(testUser, testApp.ID, "test_admin")
	if err != nil {
		t.Fatalf("Failed to assign user: %v", err)
	}

	if !pe.Evaluate([]byte("user_777"), "access", "app_okta_sim", nil) {
		t.Fatal("Policy engine did not grant access")
	}
}

func TestSCIMDaemon_Provisioning(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)
	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))
	defer sysLog.Close()

	bus := make(chan secure_network.SystemEvent, 1)

	daemon := NewSCIMDaemon(db, bus, sysLog)
	daemon.Client.Transport = &MockRoundTripper{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(bytes.NewBufferString(`{"id": "remote_scim_id_999"}`)),
				Header:     make(http.Header),
			}
		},
	}

	go daemon.Start()
	time.Sleep(100 * time.Millisecond)
}

func TestEnforcePolicyMiddleware(t *testing.T) {
	db, dir := setupTestDB(t)
	defer os.RemoveAll(dir)

	pe := secure_policy.NewPolicyEngine(db)
	sm := secure_policy.NewSessionManager(db, nil)
	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))
	defer sysLog.Close()

	pe.AddPolicy([]byte("user_trusted"), "access", "secure_app", "ALLOW", nil)

	protectedHandler := EnforcePolicy(pe, sm, sysLog, "access", "secure_app")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/app", nil)
	rr := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
	}
}
