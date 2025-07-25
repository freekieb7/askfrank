# Security Features Documentation

This application implements multiple layers of security to protect against signup abuse and malicious attacks.

## Implemented Security Measures

### 1. Rate Limiting
- **Sign-up Rate Limiting**: Maximum 5 sign-up attempts per IP address within 15 minutes
- **IP-based Blocking**: Temporary IP blocks for suspicious activity
- Automatic cleanup of expired blocks

### 2. CSRF Protection
- CSRF tokens are automatically generated and validated for all form submissions
- Protects against Cross-Site Request Forgery attacks
- Token expires after 1 hour

### 3. Input Validation & Sanitization
- **Email Validation**: Proper email format validation with regex
- **Disposable Email Protection**: Blocks common disposable email domains
- **HTML Sanitization**: All user inputs are escaped to prevent XSS
- **Length Limits**: Email max 254 chars, password max 128 chars
- **Suspicious Content Detection**: Blocks inputs containing script tags, JavaScript, etc.

### 4. reCAPTCHA Integration (Optional)
- Google reCAPTCHA v2 integration
- Only displays if `RECAPTCHA_SITE_KEY` environment variable is set
- Verifies user is human before allowing signup

### 5. Honeypot Field
- Hidden form field that catches automated bots
- Legitimate users won't fill this field
- Automatically blocks IPs that fill the honeypot field

### 6. Password Security
- Minimum 8 character requirement
- bcrypt hashing with default cost
- No plaintext password storage

### 7. Duplicate Registration Prevention
- Checks for existing users with the same email
- Prevents multiple accounts with same email address

### 8. IP Blocking System
- Tracks and blocks suspicious IP addresses
- Configurable block duration (default: 1 hour)
- Automatic cleanup of expired blocks
- In-memory storage (can be extended to Redis for production)

## Configuration

### Environment Variables

```bash
# reCAPTCHA (optional)
RECAPTCHA_SITE_KEY=your_site_key_here
RECAPTCHA_SECRET_KEY=your_secret_key_here

# Server
PORT=8080
```

### Security Configuration

The security middleware can be configured in `main.go`:

```go
securityConfig := middleware.SecurityConfig{
    RecaptchaSecretKey: os.Getenv("RECAPTCHA_SECRET_KEY"),
    MaxSignupAttempts:  5,              // attempts per window
    RateLimitWindow:    15 * time.Minute,  // rate limit window
    BlockDuration:      1 * time.Hour,     // IP block duration
}
```

## How It Works

### Sign-up Flow Security

1. **IP Check**: First checks if the IP is blocked
2. **Rate Limit**: Validates IP hasn't exceeded signup attempts
3. **Honeypot**: Checks if bot filled hidden field
4. **CSRF**: Validates CSRF token
5. **reCAPTCHA**: Verifies CAPTCHA response (if configured)
6. **Input Validation**: Sanitizes and validates all inputs
7. **Email Check**: Ensures email format is valid and not disposable
8. **Duplicate Check**: Verifies user doesn't already exist
9. **Content Filter**: Checks for suspicious/malicious content

### Attack Mitigation

- **Brute Force**: Rate limiting prevents rapid sign-up attempts
- **Bot Attacks**: Honeypot and reCAPTCHA stop automated bots
- **XSS**: Input sanitization prevents script injection
- **CSRF**: Tokens prevent cross-site request forgery
- **Email Bombing**: Disposable email blocking and rate limiting
- **IP-based Attacks**: Automatic IP blocking for suspicious behavior

## Monitoring & Logging

The application logs security events:

```go
slog.Info("New user signup", "email", email, "ip", c.IP())
slog.Error("Suspicious activity detected", "ip", c.IP(), "reason", "honeypot")
```

## Production Recommendations

1. **Configure reCAPTCHA**: Set up proper reCAPTCHA keys
2. **Use Redis**: Replace in-memory IP blocking with Redis for multi-server setups
3. **Monitor Logs**: Set up log monitoring for security events
4. **Adjust Limits**: Fine-tune rate limits based on your traffic patterns
5. **Database Logging**: Consider logging security events to database
6. **Email Verification**: Current setup generates codes but doesn't send emails
7. **SSL/TLS**: Ensure HTTPS is properly configured
8. **WAF**: Consider using a Web Application Firewall
9. **GeoIP**: Block sign-ups from high-risk countries if needed
10. **2FA**: Consider adding two-factor authentication

## Testing Security

To test the security features:

1. **Rate Limiting**: Try rapid sign-up attempts
2. **Honeypot**: Fill the hidden "website" field
3. **Invalid Email**: Test with malformed emails
4. **Disposable Email**: Try with throwaway email addresses
5. **XSS Attempts**: Include script tags in form fields
6. **CSRF**: Try submitting form without valid token

## Updating Disposable Domain List

The disposable email domain list is in `internal/middleware/security.go`. Update the `disposableDomains` slice to add new domains:

```go
disposableDomains := []string{
    "10minutemail.com",
    "guerrillamail.com",
    // Add new domains here
}
```
