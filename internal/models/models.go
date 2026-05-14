package models

import "time"

// SecurityEvent représente un événement loggué
type SecurityEvent struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	UserAgent string    `json:"user_agent"`
	Country   string    `json:"country"`
	EventType string    `json:"event_type"` // request | honeypot | ratelimit | error
}

// BlacklistedIP représente une IP blacklistée
type BlacklistedIP struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DailyStat représente les stats d'une journée
type DailyStat struct {
	ID          int64     `json:"id"`
	Date        time.Time `json:"date"`
	TotalReq    int       `json:"total_req"`
	UniqueIPs   int       `json:"unique_ips"`
	Errors4xx   int       `json:"errors_4xx"`
	Errors5xx   int       `json:"errors_5xx"`
	HoneypotHit int       `json:"honeypot_hit"`
}

// DashboardStats regroupe toutes les stats pour le dashboard
type DashboardStats struct {
	TotalEvents    int             `json:"total_events"`
	TotalBlacklist int             `json:"total_blacklist"`
	Events24h      int             `json:"events_24h"`
	Honeypots24h   int             `json:"honeypots_24h"`
	Errors24h      int             `json:"errors_24h"`
	TopIPs         []IPCount       `json:"top_ips"`
	TopPaths       []PathCount     `json:"top_paths"`
	RecentEvents   []SecurityEvent `json:"recent_events"`
	EventsByHour   []HourCount     `json:"events_by_hour"`
}

// IPCount — IP avec son nombre de requêtes
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// PathCount — path avec son nombre de requêtes
type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// HourCount — heure avec son nombre d'événements
type HourCount struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}
