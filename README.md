# WPGuard v1.0.0

![Screenshot_1](https://github.com/msxsec1337/WPGuard/blob/main/wpg.png)

> This program is designed to scan WordPress sites and detect various vulnerabilities, such as the version used, vulnerable plugins, weak login settings, and other security issues. Using HTTP requests, the program collects data from the website and provides information about potential security holes.


## Installation

Scripts are written for Python 3.6+.

```bash
git clone https://github.com/msxsec1337/WPGuard
cd WPGuard
pip install -r requirements.txt
```

## Run script

```bash
python3 wpguard.py
python wpguard.py 
```

## Program features
- WordPress Version Detection:
Uses meta tags or the presence of WordPress-specific content to detect the version of WordPress a site is running.

- Vulnerable Plugin Detection:
Compares links on the site against a dictionary of known vulnerabilities to flag potential risks.

- Login Bruteforce Vulnerability Check:
Checks for the presence of wp-login.php, which could indicate susceptibility to brute-force attacks.

- SSL Verification:
Verifies if the site uses HTTPS for secure communication.

- HTTP Header Security Check:
Checks for the presence of important HTTP security headers like Strict-Transport-Security, X-Content-Type-Options, etc.

- wp-admin Access Check:
Verifies whether sensitive admin URLs (/wp-admin and /wp-login.php) are exposed.

- Sensitive File Exposure:
Looks for publicly accessible files like wp-config.php, .htaccess, readme.html, and license.txt.

## Contact

[@mousexeploitsec](https://www.instagram.com/mousexeploitsec/)

Project Link: https://github.com/msxsec1337/WPGuard
