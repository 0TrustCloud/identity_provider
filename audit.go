package identity_provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gddisney/guikit"
	"github.com/gddisney/orchid_sync"
	"github.com/gddisney/ultimate_db"
)

const AuditLogPageID ultimate_db.PageID = 5 // Reserving Page 5 for Audit Logs

type LogPayload struct {
	Level   string `json:"level"`
	Service string `json:"service"`
	Message string `json:"message"`
}

type LogDisplay struct {
	LevelClass string
	Level      string
	Time       string
	Service    string
	Message    string
}

type AuditController struct {
	DB           *ultimate_db.DB
	SearchEngine *orchid_sync.Engine
	UI           *guikit.GUIKit
	recentLogs   []LogDisplay
	logsMu       sync.RWMutex
}

func NewAuditController(db *ultimate_db.DB, search *orchid_sync.Engine, ui *guikit.GUIKit) *AuditController {
	return &AuditController{
		DB:           db,
		SearchEngine: search,
		UI:           ui,
		recentLogs:   make([]LogDisplay, 0, 100),
	}
}

func generateLogID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// RecordLog securely stores, indexes, and broadcasts a system event
func (a *AuditController) RecordLog(level, service, message string) {
	logID := generateLogID()
	logData := LogPayload{Level: level, Service: service, Message: message}
	payload, _ := json.Marshal(logData)

	txnID := a.DB.BeginTxn()
	_ = a.DB.WriteCompressed(AuditLogPageID, txnID, []byte(logID), payload, 720*time.Hour)
	a.DB.CommitTxn(txnID)

	indexableText := strings.ToLower(level + " " + service + " " + message)
	_ = a.SearchEngine.Index(logID, indexableText)

	levelClass := "level-info"
	if level == "ERROR" || level == "FATAL" {
		levelClass = "level-error"
	} else if level == "WARN" {
		levelClass = "level-warn"
	}

	newLog := LogDisplay{
		LevelClass: levelClass,
		Level:      level,
		Time:       time.Now().Format("15:04:05"),
		Service:    service,
		Message:    message,
	}

	a.logsMu.Lock()
	a.recentLogs = append([]LogDisplay{newLog}, a.recentLogs...)
	if len(a.recentLogs) > 100 {
		a.recentLogs = a.recentLogs[:100]
	}
	a.logsMu.Unlock()

	if a.UI != nil {
		a.UI.Broadcast("new_log", newLog)
	}

	log.Printf("[AUDIT] %s %s: %s", level, service, message)
}
