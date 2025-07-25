#!/bin/bash

# Security Testing Script for AskFrank Sign-up
echo "🔒 Testing AskFrank Security Features"
echo "======================================"

BASE_URL="http://localhost:8080"
SIGNUP_URL="$BASE_URL/auth/sign-up/create-user"

echo ""
echo "1. Testing Rate Limiting (sending 6 rapid requests)..."
echo "Expected: First 5 should work, 6th should be rate limited"

for i in {1..6}; do
    echo -n "Request $i: "
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
        -d "email=test$i@example.com" \
        -d "password=testpassword123" \
        -d "terms=on")
    echo "HTTP $response"
    if [ $i -eq 6 ]; then
        if [ "$response" = "429" ]; then
            echo "✅ Rate limiting working correctly!"
        else
            echo "❌ Rate limiting may not be working"
        fi
    fi
    sleep 1
done

echo ""
echo "2. Testing Honeypot Field..."
echo "Expected: Should be blocked when honeypot field is filled"

response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
    -d "email=bot@example.com" \
    -d "password=testpassword123" \
    -d "terms=on" \
    -d "website=http://spam.com")

echo "Response with honeypot filled: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Honeypot protection working!"
else
    echo "❌ Honeypot protection may not be working"
fi

echo ""
echo "3. Testing Email Validation..."
echo "Expected: Should reject invalid email formats"

response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
    -d "email=invalid-email" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with invalid email: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Email validation working!"
else
    echo "❌ Email validation may not be working"
fi

echo ""
echo "4. Testing Disposable Email Protection..."
echo "Expected: Should reject disposable email domains"

response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
    -d "email=test@10minutemail.com" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with disposable email: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Disposable email protection working!"
else
    echo "❌ Disposable email protection may not be working"
fi

echo ""
echo "5. Testing XSS Protection..."
echo "Expected: Should sanitize and reject suspicious content"

response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
    -d "email=<script>alert('xss')</script>@example.com" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with XSS attempt: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ XSS protection working!"
else
    echo "❌ XSS protection may not be working"
fi

echo ""
echo "6. Testing CSRF Protection..."
echo "Expected: Should reject requests without CSRF token"

response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SIGNUP_URL" \
    -d "email=test@example.com" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response without CSRF token: HTTP $response"
if [ "$response" = "403" ] || [ "$response" = "400" ]; then
    echo "✅ CSRF protection working!"
else
    echo "⚠️  CSRF protection response: $response (may need CSRF token)"
fi

echo ""
echo "🔒 Security Test Summary Complete!"
echo "Check the application logs for more details."
