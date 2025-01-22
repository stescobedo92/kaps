# Security Policy

## Supported Versions
| Version | Supported          |
|---------| ------------------ |
| 0.1.0   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting Vulnerabilities

**Please report any security issues to**: security@yourdomain.com

### Security Assumptions
- AES-256-CBC with proper key derivation
- Random IV generation for each file
- Salt storage with encrypted vault
- Password complexity enforcement

## Best Practices
- Rotate encryption keys periodically
- Store salt files securely
- Use environment variables for passwords in production