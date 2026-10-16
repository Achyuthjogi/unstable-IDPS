package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
)

// Role defines user authorization levels.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// RoleLevel hierarchy
var roleHierarchy = map[Role]int{
	RoleAdmin:   3,
	RoleAnalyst: 2,
	RoleViewer:  1,
}

// User represents an authenticated identity.
type User struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
}

// Manager handles API key and role authentication.
type Manager struct {
	mu         sync.RWMutex
	apiKeys    map[string]User // key -> User
	masterKey  string
}

var (
	defaultManager *Manager
	once           sync.Once
)

// NewManager creates a new authentication manager with specific keys.
func NewManager(adminKey, analystKey, viewerKey string) *Manager {
	m := &Manager{
		apiKeys:   make(map[string]User),
		masterKey: adminKey,
	}

	if adminKey != "" {
		m.apiKeys[adminKey] = User{Username: "Administrator", Role: RoleAdmin}
	}
	if analystKey != "" {
		m.apiKeys[analystKey] = User{Username: "Security Analyst", Role: RoleAnalyst}
	}
	if viewerKey != "" {
		m.apiKeys[viewerKey] = User{Username: "Dashboard Viewer", Role: RoleViewer}
	}

	// Fallback demo key if no keys set
	if len(m.apiKeys) == 0 {
		m.apiKeys["idps_demo_key"] = User{Username: "Default Admin", Role: RoleAdmin}
	}

	return m
}

// Init initializes the default authentication manager.
func Init(adminKey, analystKey, viewerKey string) *Manager {
	defaultManager = NewManager(adminKey, analystKey, viewerKey)
	return defaultManager
}

// Get returns the default authentication manager.
func Get() *Manager {
	if defaultManager == nil {
		return Init("", "", "")
	}
	return defaultManager
}

// Authenticate extracts and verifies an API key from an HTTP request.
func (m *Manager) Authenticate(r *http.Request) (User, bool) {
	var key string

	// 1. Header: X-API-Key
	if h := r.Header.Get("X-API-Key"); h != "" {
		key = strings.TrimSpace(h)
	}

	// 2. Header: Authorization: Bearer <key>
	if key == "" {
		if auth := r.Header.Get("Authorization"); auth != "" {
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				key = strings.TrimSpace(parts[1])
			}
		}
	}

	// 3. Query param: ?api_key= or ?key= (useful for WebSocket handshake)
	if key == "" {
		key = r.URL.Query().Get("api_key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}
	}

	// 4. WebSocket Sec-WebSocket-Protocol token
	if key == "" {
		if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
			for _, p := range strings.Split(proto, ",") {
				p = strings.TrimSpace(p)
				if p != "" && !strings.HasPrefix(p, "vite") {
					key = p
					break
				}
			}
		}
	}

	if key == "" {
		return User{}, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for storedKey, user := range m.apiKeys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(key)) == 1 {
			return user, true
		}
	}

	return User{}, false
}

// Authorize checks if the user possesses the required role.
func (m *Manager) Authorize(user User, requiredRole Role) bool {
	userLevel := roleHierarchy[user.Role]
	reqLevel := roleHierarchy[requiredRole]
	return userLevel >= reqLevel
}
