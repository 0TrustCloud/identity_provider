package identity_provider

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/ultimate_db"
)

// =============================================================================
// Test Storage Mocks for SDF Engine Fulfillment
// =============================================================================

type mockTxnHandle struct {
	id uint64
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { return nil }
func (m *mockTxnHandle) Abort() error  { return nil }

type mockKVStore struct {
	records map[string][]byte
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	return &mockTxnHandle{id: 1}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

type mockLockManager struct{}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	return nil
}

// =============================================================================
// Test Environment Setup Helpers
// =============================================================================

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
	
	device, err := ultimate_db.NewOSFileDevice(dbPath)
	if err != nil {
		t.Fatalf("Failed to open VFS device: %v", err)
	}

	dm := ultimate_db.NewDiskManager(device)
	evictor := ultimate_db.NewLRUEvictionPolicy()
	metrics := ultimate_db.NewAtomicMetrics()

	bp := ultimate_db.NewBufferPool(dm, 1024, evictor, metrics)
	wal, _ := ultimate_db.NewBatchingWAL(dbPath + "_wal.log")
	db := ultimate_db.NewDB(bp, wal, metrics)
	
	err = ultimate_db.PerformRecovery(db, dbPath+"_wal.log")
	if err != nil {
		t.Fatalf("ARIES Recovery failed: %v", err)
	}

	return db, dir
}

func getRealLogger(t *testing.T, walPath string) *logger.LogDispatcher {
	// For these unit tests, we return nil to bypass the logging pipeline dependency.
	return nil
}

func setupTestSDFEngine(t *testing.T) *secure_data_format.SecureDataEngine {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA private key: %v", err)
	}
	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{}

	engine, err := secure_data_format.New(storeMock, lockMock, "test-identity-provider", privKey)
	if err != nil {
		t.Fatalf("failed to initialize test SDF engine: %v", err)
	}
	return engine
}

// =============================================================================
// Operational Test Cases
// =============================================================================

func TestAdminController_AppLifecycle(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()
	defer os.RemoveAll(dir)

	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))

	sdfEngine := setupTestSDFEngine(t)
	pe := secure_policy.NewPolicyEngine(sdfEngine)
	bus := make(chan secure_network.SystemEvent, 10)

	admin := AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
		Logger:       sysLog,
		SDFEngine:    sdfEngine,
	}

	testApp := Application{
		ID:             "app_okta_sim",
		Name:           "Google Workspace SCIM",
		TargetURL:      "https://workspace.google.com",
		RequiredPolicy: "enforce",
		SCIMEndpoint:   "https://admin.google.com/scim/v2",
		SCIMToken:      "mock_token_123",
	}

	err := admin.RegisterApp(testApp, "test_admin")
	if err != nil {
		t.Fatalf("Failed to register app through SDF pipeline: %v", err)
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
		t.Fatalf("Failed to assign user through SDF pipeline: %v", err)
	}

	if !pe.Evaluate([]byte("user_777"), "access", "app_okta_sim", nil) {
		t.Fatal("Policy engine matrix did not register permission grant state")
	}
}

func TestSCIMDaemon_Provisioning(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()
	defer os.RemoveAll(dir)
	
	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))
	bus := make(chan secure_network.SystemEvent, 1)
	sdfEngine := setupTestSDFEngine(t)

	daemon := NewSCIMDaemon(db, bus, sysLog, sdfEngine)
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

	testApp := Application{
		ID:           "app_scim_target",
		Name:         "Target Integration",
		SCIMEndpoint: "https://api.target.com/scim",
		SCIMToken:    "secret",
	}
	appBytes, _ := json.Marshal(testApp)
	txn := db.BeginTxn()
	_ = db.Write(AppRegistryPageID, txn, []byte(testApp.ID), appBytes, 0)
	db.CommitTxn(txn)

	eventPayload, _ := json.Marshal(map[string]interface{}{
		"app_id": "app_scim_target",
		"identity": Identity{
			Subject: "user_scim_test",
			Attributes: map[string]string{
				"email":       "test@example.mesh",
				"given_name":  "Test",
				"family_name": "User",
			},
		},
	})

	bus <- secure_network.SystemEvent{
		Topic:   "scim_provision",
		Payload: eventPayload,
	}

	time.Sleep(100 * time.Millisecond)
}

func TestEnforcePolicyMiddleware(t *testing.T) {
	db, dir := setupTestDB(t)
	defer db.Close()
	defer os.RemoveAll(dir)

	sdfEngine := setupTestSDFEngine(t)
	pe := secure_policy.NewPolicyEngine(sdfEngine)
	sm := secure_policy.NewSessionManager(sdfEngine, nil)
	
	sysLog := getRealLogger(t, filepath.Join(dir, "test.wal"))

	pe.AddPolicy([]byte("user_trusted"), "access", "secure_app", "ALLOW", nil)

	protectedHandler := EnforcePolicy(pe, sm, sdfEngine, sysLog, "access", "secure_app")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/app", nil)
	rr := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
	}
}
