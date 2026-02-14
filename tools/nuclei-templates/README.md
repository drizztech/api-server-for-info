# Custom Nuclei Templates

This directory contains custom Nuclei templates developed for White Fatalis Framework, focusing on less common vulnerability variants and rigorous logic testing.

## Categories

### 1. IDOR (`idor/`)
*   `hpp-idor.yaml`: HTTP Parameter Pollution (e.g., `id=1&id=2`).
*   `type-juggling-idor.yaml`: Testing wildcards (`*`), booleans, and other types.
*   `wrapper-idor.yaml`: Testing JSON array/object wrapping bypasses (e.g., `{"id": [1]}`).

### 2. Cross-Site (`cross-site/`)
*   `cors-null.yaml`: CORS `Origin: null` check with credentials.
*   `cors-bypass.yaml`: CORS Origin validation bypasses (special chars).
*   `csrf-spoofing.yaml`: Content-Type spoofing (Text/Plain) for CSRF.

### 3. HTTP Smuggling (`smuggling/`)
*   `cl-te.yaml`: Content-Length vs Transfer-Encoding.
*   `te-cl.yaml`: Transfer-Encoding vs Content-Length.
*   `te-te.yaml`: Obfuscated TE headers.

### 4. XSS (`xss/`)
*   `header-polyglot.yaml`: Polyglot payloads in multiple headers.
*   `svg-xss.yaml`: XSS via SVG/XML namespaces.
*   `framework-csti.yaml`: Client-Side Template Injection for Angular/Vue.

### 5. Blind XSS (`blind-xss/`)
*   `ua-blind.yaml`: User-Agent injection with OOB interaction.
*   `referer-blind.yaml`: Referer injection with OOB interaction.
*   `headers-blind.yaml`: Custom headers (X-Forwarded-For, API Keys) injection.

### 6. API Logic (`api-logic/`)
*   `mass-assignment.yaml`: Privilege escalation via mass assignment (`role: admin`).
*   `integer-logic.yaml`: Integer overflows and negative quantity checks.
*   `method-override.yaml`: HTTP Method Override bypass testing.

## Usage

To use these templates with Nuclei:

```bash
nuclei -u https://target.com -t tools/nuclei-templates/
```

Or target specific categories:

```bash
nuclei -u https://target.com -t tools/nuclei-templates/idor/
```
