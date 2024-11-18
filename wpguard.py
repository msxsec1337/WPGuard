import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from threading import Semaphore
from colorama import init, Fore
import random
import time
from tqdm import tqdm

init(autoreset=True)

def get_wordpress_version(url, checked_sites, semaphore):
    if url in checked_sites:
        return None
    try:
        headers = {'User-Agent': random.choice(["Mozilla/5.0", "Mozilla/4.0", "Chrome/91.0"])}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tag = soup.find('meta', {'name': 'generator'})
        if meta_tag and 'WordPress' in meta_tag.get('content', ''):
            version = meta_tag.get('content').split('WordPress ')[-1]
            print(f"{Fore.GREEN}WordPress Version Detected for {url}: {version}")
            checked_sites.add(url)
            return version
        else:
            if 'wp-admin' in response.text or 'wp-content' in response.text:
                print(f"{Fore.YELLOW}Looks like a WordPress site but version not detected for {url}")
            else:
                print(f"{Fore.RED}This does not appear to be a WordPress site: {url}")
            checked_sites.add(url)
            return None
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching WordPress version for {url}: {e}")
        checked_sites.add(url)
        return None

def check_vulnerable_plugins(url, known_vulnerabilities, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        headers = {'User-Agent': random.choice(["Mozilla/5.0", "Mozilla/4.0", "Chrome/91.0"])}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for plugin, bug_info in known_vulnerabilities.items():
                if plugin in href:
                    print(f"{Fore.YELLOW}Possible vulnerable plugin detected on {url}: {plugin}")
                    print(f"{Fore.RED}Bug Information: {bug_info}")
                    checked_sites.add(url)
                    return
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking vulnerable plugins for {url}: {e}")
        checked_sites.add(url)

def check_login_bruteforce(url, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        login_url = f"{url}/wp-login.php"
        response = requests.get(login_url, timeout=10)
        if "wp-login.php" in response.text:
            print(f"{Fore.RED}Warning: {url} could be vulnerable to brute-force attacks at {login_url}")
        else:
            print(f"{Fore.GREEN}{url} login page seems secure.")
        checked_sites.add(url)
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking brute-force vulnerability for {url}: {e}")
        checked_sites.add(url)

def check_ssl(url, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        if url.startswith("https://"):
            print(f"{Fore.GREEN}SSL is enabled for {url}.")
        else:
            print(f"{Fore.RED}Warning: {url} is not using SSL (HTTPS).")
        checked_sites.add(url)
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking SSL for {url}: {e}")
        checked_sites.add(url)

def check_http_headers(url, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        if 'Strict-Transport-Security' not in headers:
            print(f"{Fore.RED}Warning: {url} is missing 'Strict-Transport-Security' header.")
        if 'X-Content-Type-Options' not in headers:
            print(f"{Fore.RED}Warning: {url} is missing 'X-Content-Type-Options' header.")
        if 'X-Frame-Options' not in headers:
            print(f"{Fore.RED}Warning: {url} is missing 'X-Frame-Options' header.")
        if 'X-XSS-Protection' not in headers:
            print(f"{Fore.RED}Warning: {url} is missing 'X-XSS-Protection' header.")
        checked_sites.add(url)
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking HTTP headers for {url}: {e}")
        checked_sites.add(url)

def check_wp_admin(url, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        wp_admin_url = f"{url}/wp-admin"
        wp_login_url = f"{url}/wp-login.php"
        response_admin = requests.get(wp_admin_url, timeout=10)
        response_login = requests.get(wp_login_url, timeout=10)
        if response_admin.status_code == 200:
            print(f"{Fore.RED}Warning: {url} has wp-admin open.")
        if response_login.status_code == 200:
            print(f"{Fore.RED}Warning: {url} has wp-login.php open.")
        checked_sites.add(url)
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking wp-admin for {url}: {e}")
        checked_sites.add(url)

def check_sensitive_files(url, checked_sites, semaphore):
    if url in checked_sites:
        return
    try:
        files = ['/wp-config.php', '/.htaccess', '/readme.html', '/license.txt']
        for file in files:
            file_url = f"{url}{file}"
            response = requests.get(file_url, timeout=10)
            if response.status_code == 200:
                print(f"{Fore.RED}Critical: {file_url} is publicly accessible on {url}.")
            else:
                print(f"{Fore.GREEN}No exposure for {file_url}.")
        checked_sites.add(url)
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking sensitive files for {url}: {e}")
        checked_sites.add(url)

def main():
    print(Fore.CYAN + '''
      _      _____  _____                 __
     | | /| / / _ \/ ___/_ _____ ________/ /
     | |/ |/ / ___/ (_ / // / _ `/ __/ _  /
     |__/|__/_/   \___/\_,_/\_,_/_/  \_,_/  
      >> MouseExplotSec
    ''')
    file_name = input(f"{Fore.CYAN}Masukkan nama file yang berisi daftar URL (misalnya, 'file.txt'): ").strip()
    try:
        with open(file_name, 'r') as f:
            urls = f.readlines()
            urls = [url.strip() for url in urls]
    except FileNotFoundError:
        print(f"{Fore.RED}File '{file_name}' tidak ditemukan!")
        return

    known_vulnerabilities = {
        'elementor': "Elementor plugin versions <= 3.5.0 is vulnerable to Remote Code Execution (RCE) via malicious input.",
        'wpml': "WPML versions <= 4.5.6 have SQL injection vulnerability allowing attackers to access sensitive data.",
        'jetpack': "Jetpack versions <= 10.7 have a privilege escalation vulnerability.",
    }
    semaphore = Semaphore(5)
    checked_sites = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        for url in tqdm(urls, desc="Checking sites", unit="site"):
            executor.submit(get_wordpress_version, url, checked_sites, semaphore)
            executor.submit(check_vulnerable_plugins, url, known_vulnerabilities, checked_sites, semaphore)
            executor.submit(check_login_bruteforce, url, checked_sites, semaphore)
            executor.submit(check_ssl, url, checked_sites, semaphore)
            executor.submit(check_http_headers, url, checked_sites, semaphore)
            executor.submit(check_wp_admin, url, checked_sites, semaphore)
            executor.submit(check_sensitive_files, url, checked_sites, semaphore)

if __name__ == "__main__":
    main()
