package middleware

import (
	"askfrank/internal/config"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
)

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
