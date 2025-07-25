package middleware

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SecurityConfig holds security configuration
type SecurityConfig struct {
	RecaptchaSecretKey string
	MaxSignupAttempts  int
	RateLimitWindow    time.Duration
	BlockDuration      time.Duration
}

// SecurityMiddleware provides various security features
type SecurityMiddleware struct {
	config     SecurityConfig
	blockedIPs map[string]time.Time
	mu         sync.RWMutex
	emailRegex *regexp.Regexp
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(config SecurityConfig) *SecurityMiddleware {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	return &SecurityMiddleware{
		config:     config,
		blockedIPs: make(map[string]time.Time),
		emailRegex: emailRegex,
	}
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		RecaptchaSecretKey: os.Getenv("RECAPTCHA_SECRET_KEY"),
		MaxSignupAttempts:  5,
		RateLimitWindow:    15 * time.Minute,
		BlockDuration:      1 * time.Hour,
	}
}

// IsIPBlocked checks if an IP is currently blocked
func (sm *SecurityMiddleware) IsIPBlocked(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if blockedUntil, exists := sm.blockedIPs[ip]; exists {
		if time.Now().Before(blockedUntil) {
			return true
		}
		// Clean up expired blocks
		delete(sm.blockedIPs, ip)
	}
	return false
}

// BlockIP blocks an IP for a specified duration
func (sm *SecurityMiddleware) BlockIP(ip string, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.blockedIPs[ip] = time.Now().Add(duration)
}

// ValidateEmail validates email format and checks for disposable domains
func (sm *SecurityMiddleware) ValidateEmail(email string) error {
	// Basic format validation
	if !sm.emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	// Check for disposable email domains
	if sm.isDisposableEmail(email) {
		return fmt.Errorf("disposable email addresses are not allowed")
	}

	return nil
}

// isDisposableEmail checks if email is from a disposable domain
func (sm *SecurityMiddleware) isDisposableEmail(email string) bool {
	disposableDomains := []string{
		"10minutemail.com", "guerrillamail.com", "mailinator.com",
		"tempmail.org", "throwaway.email", "temp-mail.org",
		"yopmail.com", "maildrop.cc", "getnada.com",
		"sharklasers.com", "guerrillamailblock.com",
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(parts[1])
	return slices.Contains(disposableDomains, domain)
}

// SanitizeInput sanitizes user input
func (sm *SecurityMiddleware) SanitizeInput(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

// ContainsSuspiciousContent checks for suspicious patterns in input
func (sm *SecurityMiddleware) ContainsSuspiciousContent(input string) bool {
	suspiciousPatterns := []string{
		"<script", "javascript:", "data:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"eval(", "document.cookie", "window.location",
		"<iframe", "<object", "<embed",
	}

	lower := strings.ToLower(input)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// VerifyCaptcha verifies reCAPTCHA response
func (sm *SecurityMiddleware) VerifyCaptcha(response string) bool {
	if sm.config.RecaptchaSecretKey == "" {
		// If no secret key is configured, skip verification
		return true
	}

	verifyURL := "https://www.google.com/recaptcha/api/siteverify"

	resp, err := http.PostForm(verifyURL, url.Values{
		"secret":   {sm.config.RecaptchaSecretKey},
		"response": {response},
	})
	if err != nil {
		return false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("Error closing response body", "error", err)
		}
	}()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	return result.Success
}

// ValidateSignupForm performs comprehensive signup form validation
func (sm *SecurityMiddleware) ValidateSignupForm(c *fiber.Ctx) error {
	// Check IP blocking first
	if sm.IsIPBlocked(c.IP()) {
		return c.Status(429).JSON(fiber.Map{
			"error": "Too many failed attempts. Please try again later.",
		})
	}

	// Check honeypot field
	if c.FormValue("website") != "" {
		// Bot detected, silently reject and block IP
		sm.BlockIP(c.IP(), sm.config.BlockDuration)
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request",
		})
	}

	// Verify CAPTCHA if configured
	recaptchaResponse := c.FormValue("g-recaptcha-response")
	if !sm.VerifyCaptcha(recaptchaResponse) {
		return c.Status(400).JSON(fiber.Map{
			"error": "CAPTCHA verification failed",
		})
	}

	// Get and sanitize inputs
	email := sm.SanitizeInput(c.FormValue("email"))
	password := sm.SanitizeInput(c.FormValue("password"))

	// Validate email
	if err := sm.ValidateEmail(email); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Validate input lengths
	if len(email) > 254 || len(password) > 128 {
		return c.Status(400).JSON(fiber.Map{
			"error": "Input too long",
		})
	}

	// Check for suspicious content
	if sm.ContainsSuspiciousContent(email) || sm.ContainsSuspiciousContent(password) {
		sm.BlockIP(c.IP(), sm.config.BlockDuration)
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid input detected",
		})
	}

	// Store sanitized values back to context
	c.Locals("sanitized_email", email)
	c.Locals("sanitized_password", password)

	return c.Next()
}

// IPBlockMiddleware blocks requests from blocked IPs
func (sm *SecurityMiddleware) IPBlockMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if sm.IsIPBlocked(c.IP()) {
			return c.Status(429).JSON(fiber.Map{
				"error": "Your IP has been temporarily blocked due to suspicious activity",
			})
		}
		return c.Next()
	}
}
