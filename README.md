# Security Headers — Complete Implementation Guide

**Production-ready HTTP security headers for Apache, Nginx, Node.js, and more.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Rating: A+](https://img.shields.io/badge/Security-A+-brightgreen.svg)](https://securityheaders.com)

---

## Why Security Headers Matter

Security headers are your first line of defense against:

- **XSS (Cross-Site Scripting)** — malicious scripts injected into your site
- **Clickjacking** — invisible frames tricking users into clicking malicious content
- **Data leaks** — unauthorized access to cross-origin resources
- **MIME-type attacks** — browsers executing malicious content
- **Referrer leaks** — sensitive URL data exposed to third parties

**Result:** Setting proper headers can boost your security rating from F to A+ in minutes, with zero code changes to your application.

---

## Quick Start

### Test your current security
```bash
curl -I https://yoursite.com | grep -i "x-frame\|content-security\|strict-transport"

# Or use online tools:
# https://securityheaders.com
# https://observatory.mozilla.org
```

### Choose your platform
- [Apache (.htaccess)](#apache-configuration)
- [Nginx](#nginx-configuration)
- [Node.js / Express](#nodejs--express)
- [Docker / Containers](#docker-containers)
- [Cloudflare Workers](#cloudflare-workers)
- [WordPress](#wordpress-specific)

---

## Apache Configuration

### Complete .htaccess example

Add this to your `.htaccess` or Apache virtual host config:

```apache
# ============================================
# Security Headers — Production Config
# ============================================

# Hide PHP version (if using PHP)
php_flag expose_php off

<IfModule mod_headers.c>
    # Isolation headers
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    Header always set Cross-Origin-Embedder-Policy "require-corp"
    
    # Content Security Policy
    # OPTION 1: Strict (recommended for new sites)
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    
    # OPTION 2: Relaxed (for sites with inline scripts/styles)
    # Header always set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline'; connect-src 'self'"
    
    # Frame protection
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # XSS protection
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
    
    # Download handling
    Header always set X-Download-Options "noopen"
    
    # Feature policies
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()"
    
    # Referrer policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # HTTPS enforcement (only if you have SSL!)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Adobe policy restrictions
    Header always set X-Permitted-Cross-Domain-Policies "none"
</IfModule>

# ============================================
# Additional Security Measures
# ============================================

# Disable directory browsing
Options -Indexes

# Disable server signature
ServerSignature Off

# Block suspicious request methods
<LimitExcept GET POST HEAD>
    deny from all
</LimitExcept>
```

### Enable required Apache modules
```bash
# Enable mod_headers
sudo a2enmod headers
sudo systemctl restart apache2
```

---

## Nginx Configuration

Add to your `nginx.conf` or site-specific config in `/etc/nginx/sites-available/`:

```nginx
server {
    listen 443 ssl http2;
    server_name yoursite.com;
    
    # Hide Nginx version
    server_tokens off;
    
    # Security headers
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    
    # Content Security Policy
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'" always;
    
    # Frame protection
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # XSS protection
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Referrer policy
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # HTTPS enforcement
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Permissions policy
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;
    
    # Adobe policies
    add_header X-Permitted-Cross-Domain-Policies "none" always;
    
    # Your site config continues here...
    root /var/www/html;
    index index.html;
}
```

### Test and reload
```bash
# Test configuration
sudo nginx -t

# Reload if successful
sudo systemctl reload nginx
```

---

## Node.js / Express

### Using Helmet.js (recommended)

```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Apply all security headers with sensible defaults
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

app.get('/', (req, res) => {
    res.send('Secured with Helmet!');
});

app.listen(3000);
```

### Manual implementation (without Helmet)

```javascript
app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});
```

---

## Docker Containers

### Nginx in Docker

Create `nginx-security.conf`:

```nginx
# Include this in your Nginx Docker image
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Dockerfile:**
```dockerfile
FROM nginx:alpine
COPY nginx-security.conf /etc/nginx/conf.d/security.conf
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80 443
```

---

## Cloudflare Workers

Add headers via Workers or Transform Rules:

```javascript
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
    const response = await fetch(request)
    
    // Clone response to modify headers
    const newResponse = new Response(response.body, response)
    
    // Add security headers
    newResponse.headers.set('Cross-Origin-Opener-Policy', 'same-origin')
    newResponse.headers.set('Cross-Origin-Resource-Policy', 'same-origin')
    newResponse.headers.set('Content-Security-Policy', "default-src 'self'")
    newResponse.headers.set('X-Frame-Options', 'SAMEORIGIN')
    newResponse.headers.set('X-Content-Type-Options', 'nosniff')
    newResponse.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
    
    return newResponse
}
```

---

## WordPress Specific

### Common issues with WordPress

WordPress often requires relaxed CSP due to:
- Inline scripts in themes/plugins
- Third-party assets (fonts, analytics, CDNs)
- Admin panel dynamic content

### Recommended WordPress .htaccess

```apache
<IfModule mod_headers.c>
    # Isolation headers (safe for WordPress)
    Header always set Cross-Origin-Opener-Policy "same-origin-allow-popups"
    Header always set Cross-Origin-Resource-Policy "cross-origin"
    
    # Relaxed CSP for WordPress
    Header always set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:; font-src 'self' https: data:; connect-src 'self' https:"
    
    # Frame protection (allows same-origin for admin)
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # XSS and MIME protection
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
    
    # Referrer policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Permissions policy
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    
    # HSTS (only if SSL is configured)
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
```

### WordPress plugin alternative

If `.htaccess` doesn't work, use this in `functions.php`:

```php
// Add security headers via PHP
function add_security_headers() {
    header('Cross-Origin-Opener-Policy: same-origin-allow-popups');
    header('Cross-Origin-Resource-Policy: cross-origin');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'");
}
add_action('send_headers', 'add_security_headers');
```

---

## Header Breakdown

### Critical Headers (Must Have)

#### Content-Security-Policy (CSP)
**Purpose:** Controls which resources can be loaded  
**Strict:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
```
**Relaxed (for legacy sites):**
```
Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline'
```

**Common CSP issues:**
- Inline scripts blocked → Move to external `.js` files or use nonces
- Google Analytics blocked → Add `script-src 'self' https://www.google-analytics.com`
- Fonts not loading → Add `font-src 'self' https://fonts.gstatic.com`

#### Strict-Transport-Security (HSTS)
**Purpose:** Forces HTTPS for all connections  
**Configuration:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
**⚠️ Warning:** Only enable if your entire site uses SSL. Once set, browsers will refuse HTTP for the specified duration.

#### X-Frame-Options
**Purpose:** Prevents clickjacking attacks  
**Options:**
- `DENY` — Never allow framing
- `SAMEORIGIN` — Allow framing from same domain only
- `ALLOW-FROM https://example.com` — (deprecated, use CSP instead)

### Important Headers

#### X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
Prevents browsers from MIME-sniffing responses away from declared content-type.

#### Referrer-Policy
**Options:**
- `no-referrer` — Never send referrer
- `strict-origin-when-cross-origin` — (recommended) Full URL for same-origin, origin only for cross-origin
- `same-origin` — Only send for same-origin requests

#### Permissions-Policy (formerly Feature-Policy)
```
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()
```
Disables powerful browser features unless explicitly needed.

### Advanced Headers

#### Cross-Origin-Opener-Policy (COOP)
**Purpose:** Isolates browsing context from cross-origin documents  
**Options:**
- `same-origin` — Strictest, breaks pop-ups
- `same-origin-allow-popups` — Allows pop-ups (better for WordPress)

#### Cross-Origin-Resource-Policy (CORP)
**Purpose:** Prevents resources from being loaded by other origins  
**Options:**
- `same-origin` — Only same domain
- `same-site` — Same site (includes subdomains)
- `cross-origin` — Allow all (least secure)

#### Cross-Origin-Embedder-Policy (COEP)
**Purpose:** Required for advanced features like SharedArrayBuffer  
**Configuration:**
```
Cross-Origin-Embedder-Policy: require-corp
```
**⚠️ Warning:** Can break third-party integrations if not configured carefully.

---

## Testing & Validation

### Online Tools
1. **Security Headers** — https://securityheaders.com  
   Quick grade (A+ to F) with actionable recommendations

2. **Mozilla Observatory** — https://observatory.mozilla.org  
   Comprehensive scan with detailed explanations

3. **CSP Evaluator** — https://csp-evaluator.withgoogle.com  
   Validates Content-Security-Policy syntax

### Command Line Testing
```bash
# Check all security headers
curl -I https://yoursite.com | grep -iE "content-security|x-frame|strict-transport|x-content|referrer"

# Test specific header
curl -I https://yoursite.com | grep -i "x-frame-options"

# Check from different location (for CDN testing)
curl -H "Host: yoursite.com" -I https://cdn-ip-address/
```

### Browser DevTools
1. Open DevTools (F12)
2. Go to **Network** tab
3. Refresh page
4. Click on main document
5. Check **Response Headers** section

---

## Common Issues & Solutions

### Issue: CSP blocks everything
**Symptom:** Site appears broken, console shows CSP violations  
**Solution:** Start with a relaxed policy, then tighten:
```apache
# Phase 1: Report-only mode (doesn't block)
Header set Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report"

# Phase 2: After reviewing violations, enable blocking
Header set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline'"
```

### Issue: HSTS locks users out after SSL expires
**Symptom:** Users can't access site even after fixing SSL  
**Solution:** 
1. Renew SSL immediately
2. Reduce `max-age` initially: `max-age=300` (5 minutes)
3. Gradually increase after confirming stability

### Issue: WordPress admin breaks with strict headers
**Symptom:** Can't save posts, plugins fail to update  
**Solution:** Use WordPress-specific config (see [WordPress section](#wordpress-specific))

### Issue: Third-party embeds don't load
**Symptom:** YouTube videos, Google Maps, etc. blocked  
**Solution:** Adjust CSP frame-src:
```apache
Header set Content-Security-Policy "default-src 'self'; frame-src 'self' https://www.youtube.com https://www.google.com"
```

---

### Best Practices

#### 1. Start conservatively
Begin with relaxed policies, monitor for issues, then tighten gradually.

#### 2. Test in staging first
Never deploy security headers directly to production without testing.

#### 3. Monitor CSP violations
Implement CSP reporting to catch issues:
```javascript
Content-Security-Policy: default-src 'self'; report-uri /csp-report
```

#### 4. Version control your configs
Keep `.htaccess` / `nginx.conf` in Git to track changes.

#### 5. Document exceptions
If you must use `'unsafe-inline'`, document WHY in comments.

#### 6. Regular audits
Re-scan with securityheaders.com monthly to catch regressions.

---

### Platform-Specific Guides

#### Apache + WordPress + SSL
```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

#### Nginx + Static Site + Cloudflare
```nginx
# Cloudflare already provides some headers, avoid duplication
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
```

#### Node.js API (No Frontend)
```javascript
app.use(helmet({
    contentSecurityPolicy: false, // Not needed for APIs
    frameguard: { action: 'deny' },
    hsts: { maxAge: 31536000 }
}));
```

---

### Resources

#### Official Documentation
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy Reference](https://content-security-policy.com/)

#### Tools
- [CSP Generator](https://report-uri.com/home/generate)
- [HSTS Preload List](https://hstspreload.org/)
- [Security Headers Scanner](https://securityheaders.com/)

#### Further Reading
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Google Web Fundamentals — Security](https://web.dev/secure/)
- [Scott Helme's Security Headers Blog](https://scotthelme.co.uk/)

---

### Contributing

Improvements welcome!

1. Fork repository
2. Add your platform-specific config
3. Test thoroughly
4. Submit PR with documentation

---

### License

MIT License — Use freely, modify as needed, no warranty provided.

---

### Author
[@volkansah](https://github.com/volkansah)

---

## Support

Found this useful?

- ⭐ Star this repository
- 🐛 Report issues
- 💡 Suggest improvements
- 💖 [Sponsor development](https://github.com/sponsors/volkansah)

---

**Stay secure. Stay paranoid. 🔒**
