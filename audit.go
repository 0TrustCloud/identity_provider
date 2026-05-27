package identity_provider

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gddisney/guikit"
	"github.com/gddisney/logger"
	"github.com/gddisney/orchid_sync"
)

// LogDisplay is used specifically to format logs for the GML frontend UI.
type LogDisplay struct {
	LevelClass string
	Level      string
	Time       string
	Service    string
	Message    string
}

type AuditController struct {
	SearchEngine *orchid_sync.Engine
	UI           *guikit.GUIKit
	recentLogs   []LogDisplay
	logsMu       sync.RWMutex
}

// NewAuditController initializes the UI and Search controller for audit logs.
func NewAuditController(search *orchid_sync.Engine, ui *guikit.GUIKit) *AuditController {
	return &AuditController{
		SearchEngine: search,
		UI:           ui,
		recentLogs:   make([]LogDisplay, 0, 100), // Ring buffer capped at 100
	}
}

// Export satisfies the logger.Exporter interface. 
// The LogDispatcher calls this automatically AFTER safely persisting the log to ultimate_db.
func (a *AuditController) Export(item logger.LogItem) error {
	// 1. Index for Threat Hunting Search
	indexableText := strings.ToLower(item.Level + " " + item.Service + " " + item.Message)
	
	// Using Timestamp as a unique document ID for Orchid Sync
	logID := fmt.Sprintf("%d", item.Timestamp) 
	if a.SearchEngine != nil {
		_ = a.SearchEngine.Index(logID, indexableText)
	}

	// 2. Format for GUIKit UI
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
	}

	// 3. Update In-Memory Ring Buffer for quick page loads
	a.logsMu.Lock()
	a.recentLogs = append([]LogDisplay{newLog}, a.recentLogs...)
	if len(a.recentLogs) > 100 {
		a.recentLogs = a.recentLogs[:100]
	}
	a.logsMu.Unlock()

	// 4. Broadcast via WebSockets for live-tail UI
	if a.UI != nil {
		a.UI.Broadcast("new_log", newLog)
	}

	return nil
}
