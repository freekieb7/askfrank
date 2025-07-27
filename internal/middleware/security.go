package middleware

import (
	"askfrank/internal/config"
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

// SecurityHeadersMiddleware adds security headers to responses
func SecurityHeadersMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Content Security Policy
		c.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data: https:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"form-action 'self';")

		// X-Content-Type-Options
		c.Set("X-Content-Type-Options", "nosniff")

		// X-Frame-Options
		c.Set("X-Frame-Options", "DENY")

		// X-XSS-Protection
		c.Set("X-XSS-Protection", "1; mode=block")

		// Referrer Policy
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Strict Transport Security (only for HTTPS)
		if c.Protocol() == "https" {
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Permissions Policy
		c.Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=()")

		return c.Next()
	}
}

// InputSanitizationMiddleware sanitizes user input
func InputSanitizationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Sanitize form data
		if c.Method() == "POST" || c.Method() == "PUT" || c.Method() == "PATCH" {
			body := c.Body()
			if len(body) > 0 {
				// Parse form data if content type is form-encoded
				contentType := c.Get("Content-Type")
				if strings.Contains(contentType, "application/x-www-form-urlencoded") {
					values, err := url.ParseQuery(string(body))
					if err == nil {
						sanitizedValues := url.Values{}
						for key, vals := range values {
							sanitizedKey := sanitizeInput(key)
							for _, val := range vals {
								sanitizedVal := sanitizeInput(val)
								sanitizedValues.Add(sanitizedKey, sanitizedVal)
							}
						}
						c.Request().SetBody([]byte(sanitizedValues.Encode()))
					}
				}
			}
		}

		return c.Next()
	}
}

// sanitizeInput removes potentially dangerous characters and HTML tags
func sanitizeInput(input string) string {
	// HTML escape
	escaped := html.EscapeString(input)

	// Remove script tags and their content
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	escaped = scriptRegex.ReplaceAllString(escaped, "")

	// Remove other potentially dangerous tags
	dangerousTagsRegex := regexp.MustCompile(`(?i)<(script|iframe|object|embed|form|input|textarea|select|button)[^>]*>`)
	escaped = dangerousTagsRegex.ReplaceAllString(escaped, "")

	return strings.TrimSpace(escaped)
}

// IPWhitelistMiddleware allows only whitelisted IPs for admin endpoints
func IPWhitelistMiddleware(allowedIPs []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientIP := c.IP()

		// Check if IP is in whitelist
		for _, allowedIP := range allowedIPs {
			if clientIP == allowedIP {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Access denied",
		})
	}
}

// PasswordStrengthValidator validates password strength
type PasswordStrengthValidator struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSpecial   bool
}

func NewPasswordStrengthValidator(cfg config.AuthConfig) *PasswordStrengthValidator {
	return &PasswordStrengthValidator{
		MinLength:        cfg.PasswordMinLength,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
	}
}

func (v *PasswordStrengthValidator) Validate(password string) []string {
	var errors []string

	if len(password) < v.MinLength {
		errors = append(errors, "Password must be at least 8 characters long")
	}

	if v.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}

	if v.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}

	if v.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one number")
	}

	if v.RequireSpecial && !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
		errors = append(errors, "Password must contain at least one special character")
	}

	// Check for common weak passwords
	weakPasswords := []string{
		"password", "123456", "123456789", "qwerty", "abc123",
		"password123", "admin", "letmein", "welcome", "monkey",
	}

	lowerPassword := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if lowerPassword == weak {
			errors = append(errors, "Password is too common")
			break
		}
	}

	return errors
}
