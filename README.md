
# Security Headers Explained 
#### A Simple Guide for Beginners


Security headers are HTTP response headers that help protect your website or API from common web vulnerabilities like cross-site scripting (XSS), clickjacking, and data leaks. Adding the right security headers can boost your site's security score (e.g., on securityheaders.com) to A+ and help keep your users safe.

Why Security Headers Matter:

Security headers are your website’s frontline defense against common attacks like XSS, clickjacking, and data leaks. Setting them right is the fastest way to get an A+ on security scanners and keep your users safe — no fancy plugins needed, just hardcore config.

Here is a **perfect, minimal paranoid set** of security headers that you can add to your Apache `.htaccess` or server config to secure your site:

```apache
# BEGIN Customs
php_flag expose_php off
<IfModule mod_headers.c>
    Header set Cross-Origin-Opener-Policy "same-origin"
    Header set Cross-Origin-Resource-Policy "same-origin"
    Header set Content-Security-Policy "default-src https: 'self' data:; connect-src 'self'"
    Header set Cross-Origin-Embedder-Policy "require-corp"
    Header set X-Permitted-Cross-Domain-Policies "none"
    Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header set Referrer-Policy "no-referrer-when-downgrade"
    Header set X-Content-Type-Options "nosniff"
    Header set X-Download-Options "noopen"
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-XSS-Protection "1; mode=block"
</IfModule>
# END Customs
```

---

### What these headers do:

* **Cross-Origin-Opener-Policy: same-origin**
  Isolates your browsing context to prevent other sites from accessing your window or tab.

* **Cross-Origin-Resource-Policy: same-origin**
  Ensures only resources from your own origin are loaded, protecting against data leaks.

* **Content-Security-Policy**
  Controls which sources your page can load resources from (scripts, images, data, etc.). This example allows only HTTPS, your own domain (`self`), and inline data URLs.

* **Cross-Origin-Embedder-Policy: require-corp**
  Requires cross-origin resources to grant explicit permission to be loaded, important for advanced web features.

* **X-Permitted-Cross-Domain-Policies: none**
  Prevents Adobe Flash and Acrobat from loading cross-domain policies, reducing risk.

* **Permissions-Policy**
  Controls access to powerful features like geolocation, microphone, and camera — here they are all disabled.

* **Referrer-Policy: no-referrer-when-downgrade**
  Sends the referrer header only on secure connections to avoid leaking sensitive URLs.

* **X-Content-Type-Options: nosniff**
  Prevents browsers from guessing content types, helping to stop certain types of attacks.

* **X-Download-Options: noopen**
  Stops files from being opened automatically after download (Internet Explorer/Edge).

* **X-Frame-Options: SAMEORIGIN**
  Prevents your site from being embedded in frames or iframes on other domains, protecting against clickjacking.

* **X-XSS-Protection: 1; mode=block**
  Enables the browser’s built-in cross-site scripting filter.

---

### Important Notes:

* **WordPress users beware:**
  The `Content-Security-Policy` line can sometimes cause issues with plugins, store updates, or admin features because it restricts loading resources too strictly. You may need to customize this policy depending on your setup.

* **There are many other headers and configurations possible**, but this set balances strong security with broad compatibility.

* Always test your site after adding headers, and adjust according to your platform’s needs.

---

Feel free to copy and paste this snippet to harden your server security today — no paid plugins required! 😎


