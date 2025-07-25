#!/bin/bash

# Advanced Security Testing Script with CSRF handling
echo "🔒 Advanced AskFrank Security Testing"
echo "====================================="

BASE_URL="http://localhost:8080"
SIGNUP_URL="$BASE_URL/auth/sign-up/create-user"

# Function to get CSRF token from the form page
get_csrf_token() {
    curl -s -c cookies.txt "$SIGNUP_URL" | grep -o 'csrf_token" value="[^"]*' | cut -d'"' -f3
}

echo ""
echo "1. Testing CSRF Protection..."
echo "Getting CSRF token from signup page..."

# Get CSRF token
CSRF_TOKEN=$(get_csrf_token)
if [ -n "$CSRF_TOKEN" ]; then
    echo "✅ CSRF token obtained: ${CSRF_TOKEN:0:20}..."
    
    # Test with valid CSRF token
    echo "Testing with valid CSRF token..."
    response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
        -d "csrf_token=$CSRF_TOKEN" \
        -d "email=test@example.com" \
        -d "password=testpassword123" \
        -d "terms=on")
    echo "Response with valid CSRF: HTTP $response"
    
    if [ "$response" != "403" ]; then
        echo "✅ CSRF protection allows valid tokens!"
    else
        echo "❌ Valid CSRF token was rejected"
    fi
else
    echo "❌ Could not obtain CSRF token"
fi

echo ""
echo "2. Testing Honeypot Protection..."

CSRF_TOKEN=$(get_csrf_token)
response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
    -d "csrf_token=$CSRF_TOKEN" \
    -d "email=bot@example.com" \
    -d "password=testpassword123" \
    -d "terms=on" \
    -d "website=http://spam.com")

echo "Response with honeypot filled: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Honeypot protection working!"
else
    echo "⚠️  Honeypot response: $response"
fi

echo ""
echo "3. Testing Rate Limiting..."
echo "Sending multiple requests quickly..."

for i in {1..6}; do
    CSRF_TOKEN=$(get_csrf_token)
    echo -n "Request $i: "
    response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
        -d "csrf_token=$CSRF_TOKEN" \
        -d "email=ratetest$i@example.com" \
        -d "password=testpassword123" \
        -d "terms=on")
    echo "HTTP $response"
    
    if [ "$response" = "429" ]; then
        echo "✅ Rate limiting triggered at request $i"
        break
    fi
    sleep 0.5
done

echo ""
echo "4. Testing Email Validation..."

CSRF_TOKEN=$(get_csrf_token)
response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
    -d "csrf_token=$CSRF_TOKEN" \
    -d "email=invalid-email-format" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with invalid email: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Email validation working!"
else
    echo "⚠️  Email validation response: $response"
fi

echo ""
echo "5. Testing Disposable Email Protection..."

CSRF_TOKEN=$(get_csrf_token)
response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
    -d "csrf_token=$CSRF_TOKEN" \
    -d "email=test@10minutemail.com" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with disposable email: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Disposable email protection working!"
else
    echo "⚠️  Disposable email response: $response"
fi

echo ""
echo "6. Testing XSS/Content Protection..."

CSRF_TOKEN=$(get_csrf_token)
response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
    -d "csrf_token=$CSRF_TOKEN" \
    -d "email=<script>alert('xss')</script>@example.com" \
    -d "password=testpassword123" \
    -d "terms=on")

echo "Response with suspicious content: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Content protection working!"
else
    echo "⚠️  Content protection response: $response"
fi

echo ""
echo "7. Testing Password Requirements..."

CSRF_TOKEN=$(get_csrf_token)
response=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt -X POST "$SIGNUP_URL" \
    -d "csrf_token=$CSRF_TOKEN" \
    -d "email=shortpass@example.com" \
    -d "password=123" \
    -d "terms=on")

echo "Response with short password: HTTP $response"
if [ "$response" = "400" ]; then
    echo "✅ Password validation working!"
else
    echo "⚠️  Password validation response: $response"
fi

# Cleanup
rm -f cookies.txt

echo ""
echo "🔒 Advanced Security Test Complete!"
echo ""
echo "Summary of Security Features Tested:"
echo "• CSRF Protection"
echo "• Rate Limiting" 
echo "• Honeypot Bot Detection"
echo "• Email Format Validation"
echo "• Disposable Email Blocking"
echo "• XSS/Content Filtering"
echo "• Password Requirements"
echo ""
echo "Check application logs for detailed security events."
