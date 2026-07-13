package identity_provider

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/orchid_sync"
)

// LogDisplay is used specifically to format logs for the GML frontend UI.
type LogDisplay struct {
	LevelClass string
	Level      string
	Time       string
	Service    string
	Message    string
	TokenHash  string // Captures the cryptographic signature trailing segment for active verification checks
}

type AuditController struct {
	SearchEngine *orchid_sync.Engine
	UI           *guikit.GUIKit
	SDFEngine    *secure_data_format.SecureDataEngine // Integrated polymorphic engine
	recentLogs   []LogDisplay
	logsMu       sync.RWMutex
}

// NewAuditController initializes the UI, Search, and SDF controller for audit logs.
func NewAuditController(search *orchid_sync.Engine, ui *guikit.GUIKit, sdf *secure_data_format.SecureDataEngine) *AuditController {
	return &AuditController{
		SearchEngine: search,
		UI:           ui,
		SDFEngine:    sdf,
		recentLogs:   make([]LogDisplay, 0, 100), // Ring buffer capped at 100
	}
}

// Export satisfies the logger.Exporter interface. 
// The LogDispatcher calls this automatically AFTER safely persisting the log to ultimate_db.
func (a *AuditController) Export(item logger.LogItem) error {
	// 1. Normalize and escape message quotes to ensure strict parsing compatibility with the SDF recursive grammar engine
	cleanMsg := strings.ReplaceAll(item.Message, `"`, `\"`)

	script := fmt.Sprintf(`
		log:system.audit(
			service("%s")
			level("%s")
			message("%s")
		)
	`, item.Service, item.Level, cleanMsg)

	tx := secure_data_format.DataInvocation{
		TargetAddress: fmt.Sprintf("mesh:audit:service:%s", item.Service),
		Caller:        item.Service,
		Nonce:         uint64(item.Timestamp),
		Method:        "EMIT", // Formally maps semantic method execution to logging contexts
		Profile:       secure_data_format.ProfileStructuredLog, // Enforces the 10-year archival lifecycle window configuration
		Args: map[string]interface{}{
			"level":     item.Level,
			"message":   item.Message,
			"timestamp": item.Timestamp,
		},
	}

	var tokenStr string
	var tokenHash string
	if a.SDFEngine != nil {
		var err error
		tokenStr, err = a.SDFEngine.CompileSecureData(script, tx)
		if err != nil {
			tokenStr = ""
		} else if len(tokenStr) > 30 {
			tokenHash = tokenStr[len(tokenStr)-30:]
		}
	}

	// 2. Index for Threat Hunting Search, passing along the token hash to match verification proofs
	indexableText := strings.ToLower(item.Level + " " + item.Service + " " + item.Message + " " + tokenHash)
	
	logID := fmt.Sprintf("%d", item.Timestamp) 
	if a.SearchEngine != nil {
		_ = a.SearchEngine.Index(logID, indexableText)
	}

	// 3. Format for GUIKit UI
	levelClass := "level-info"
	if item.Level == "ERROR" || item.Level == "FATAL" {
		levelClass = "level-error"
	} else if item.Level == "WARN" {
		levelClass = "level-warn"
	} else if item.Level == "AUDIT" {
		levelClass = "level-warn" // Gives audits a distinct visual pop in the UI
	}

	newLog := LogDisplay{
		LevelClass: levelClass,
		Level:      item.Level,
		Time:       time.Unix(0, item.Timestamp).Format("15:04:05"),
		Service:    item.Service,
		Message:    item.Message,
		TokenHash:  tokenHash,
	}

	// 4. Update In-Memory Ring Buffer for quick page loads
	a.logsMu.Lock()
	a.recentLogs = append([]LogDisplay{newLog}, a.recentLogs...)
	if len(a.recentLogs) > 100 {
		a.recentLogs = a.recentLogs[:100]
	}
	a.logsMu.Unlock()

	// 5. Broadcast via WebSockets for live-tail UI
	if a.UI != nil {
		a.UI.Broadcast("new_log", newLog)
	}

	return nil
}

func (a *AuditController) RecentLogs() []LogDisplay {
	a.logsMu.RLock()
	defer a.logsMu.RUnlock()
	recent := make([]LogDisplay, len(a.recentLogs))
	copy(recent, a.recentLogs)
	return recent
}
