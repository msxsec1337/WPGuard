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
- Detect WordPress version using meta tag generator.
- Identify vulnerable WordPress plugins based on URL and page information.
- Check brute-force login vulnerability on wp-login.php.
- Validate SSL/TLS (HTTPS) presence.
- Check HTTP header security such as Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and X-XSS-Protection.
- Detect open administrative pages, such as wp-admin and wp-login.php.
- Check sensitive files such as wp-config.php, .htaccess, readme.html, and license.txt.
- Detect WordPress theme used based on information on the page.
- Identify WordPress REST API to exploit potential user data.
- Check WordPress JSON to access user list.

## Contact

[@mousexeploitsec](https://www.instagram.com/mousexeploitsec/)

Project Link: https://github.com/msxsec1337/WPGuard
