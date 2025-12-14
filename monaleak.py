import os
import sys
import re
import logging
import requests
from colorama import Fore, Style, Back
from concurrent.futures import ThreadPoolExecutor, as_completed
import math
from bs4 import BeautifulSoup
import urllib.parse
from ddgs import DDGS

# Logger setup
logger = logging.getLogger("monaleak")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(console_handler)

# Constants
POSTMAN_HOST = "https://www.postman.com"
GLOBAL_SEARCH_ENDPOINT = "/_api/ws/proxy"
GET_REQUEST_ENDPOINT = "/_api/request/"
MAX_SEARCH_RESULTS = 25
MAX_OFFSET = 200

GITHUB_API_URL = "https://api.github.com/search/code"
GITHUB_TOKEN = ""  # GitHub Personal Access Token

# Display a graphical banner
def display_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}

███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ██╗     ███████╗ █████╗ ██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██║     ██╔════╝██╔══██╗██║ ██╔╝
██╔████╔██║██║   ██║██╔██╗ ██║███████║██║     █████╗  ███████║█████╔╝ 
██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║██║     ██╔══╝  ██╔══██║██╔═██╗ 
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║███████╗███████╗██║  ██║██║  ██╗
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                                                                      
{Style.RESET_ALL}
"""
    print(banner)

# Improved print_colored function
def print_colored(message, color=Fore.WHITE, background=Back.BLACK, style=Style.NORMAL):
    """
    Prints a message with specified color, background, and style.

    Args:
        message (str): The message to print.
        color (str): The text color (default: Fore.WHITE).
        background (str): The background color (default: Back.BLACK).
        style (str): The text style (default: Style.NORMAL).
    """
    print(f"{style}{color}{background}{message}{Style.RESET_ALL}")

def google_dork_search(search_term, num_results=30):
    """
    Perform Dork searches using DuckDuckGo and Yandex.
    Only returns URLs where the search term is confirmed to exist in the page content.

    Args:
        search_term (str): The search term to use in the dork queries.
        num_results (int): Number of results to fetch for each dork query (default: 30).

    Returns:
        list: A list of URLs from the search results that contain the search term.
    """
    # Optimized dork queries - using OR operators to reduce search count
    dork_queries = [
        # Code hosting platforms combined
        f'(site:gist.github.com OR site:pastebin.com OR site:gitlab.com OR site:bitbucket.org) "{search_term}"',
        
        # Config and env files combined
        f'"{search_term}" (filetype:env OR filetype:json OR filetype:yaml OR filetype:yml OR filetype:xml OR filetype:config OR filetype:conf OR filetype:sql OR filetype:ini OR  filetype:bak OR filetype:log OR filetype:txt)',

        f'"{search_term}" (intitle:"index of" OR inurl:admin OR inurl:login OR inurl:dashboard)',
    ]

    urls = []
    verified_urls = []
    
    # Domains to exclude from results (ads, tracking, etc.)
    excluded_domains = ['bing.com',  'facebook.com', 'twitter.com', 'yandex.com', 'yandex.ru', 'duckduckgo.com', 'amazon.com', 'linkedin.com', 'pinterest.com', 'instagram.com']
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    try:
        # DuckDuckGo search
        ddgs = DDGS()
        for dork_query in dork_queries:
            logger.info(f"Running DuckDuckGo Dork: {dork_query}")
            try:
                results = ddgs.text(dork_query, max_results=num_results)
                for result in results:
                    if 'href' in result:
                        url = result['href']
                        if not any(domain in url for domain in excluded_domains):
                            urls.append(url)
            except Exception as e:
                logger.debug(f"DuckDuckGo error for query '{dork_query}': {str(e)}")
        
        # Yandex search
        for dork_query in dork_queries:
            logger.info(f"Running Yandex Dork: {dork_query}")
            try:
                encoded_query = urllib.parse.quote_plus(dork_query)
                yandex_url = f"https://yandex.com/search/?text={encoded_query}&numdoc={num_results}"
                
                response = requests.get(yandex_url, headers=headers, timeout=15)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find Yandex search result links
                    for link in soup.find_all('a', class_='Link'):
                        href = link.get('href')
                        if href and href.startswith('http'):
                            if not any(domain in href for domain in excluded_domains):
                                urls.append(href)
                    
                    # Alternative selector for Yandex results
                    for link in soup.find_all('a', {'class': re.compile(r'organic__url|Link_theme_outer')}):
                        href = link.get('href')
                        if href and href.startswith('http'):
                            if not any(domain in href for domain in excluded_domains):
                                urls.append(href)
            except Exception as e:
                logger.debug(f"Yandex error for query '{dork_query}': {str(e)}")
        
        # Remove duplicates
        urls = list(set(urls))
        logger.info(f"Found {len(urls)} unique URLs from DuckDuckGo and Yandex")
        
        # Print all found URLs
        print_colored(f"\n[+] Found {len(urls)} URLs before verification:", Fore.YELLOW)
        for i, url in enumerate(urls, 1):
            print_colored(f"  [{i}] {url}", Fore.CYAN)
        
        # Verify each URL contains the search term
        if urls:
            logger.info(f"Verifying URLs contain '{search_term}'...")
            for url in urls:
                try:
                    response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
                    if response.status_code == 200:
                        if search_term.lower() in response.text.lower():
                            verified_urls.append(url)
                            logger.info(f"Verified: {url}")
                except Exception as e:
                    logger.debug(f"Could not verify URL {url}: {str(e)}")
            
            logger.info(f"Verified {len(verified_urls)} URLs containing '{search_term}'")
    except Exception as e:
        logger.error(f"Error during Dork search: {str(e)}")
    
    return verified_urls

def github_search(query, num_results=100):
    """
    Search GitHub for code matching the query using GitHub Search API.

    Args:
        query (str): The search query (e.g., "endpoint language:python").
        num_results (int): Number of results to fetch (default: 50).

    Returns:
        list: A list of dictionaries containing file URLs and repository information.
    """
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"q": query, "per_page": num_results}

    try:
        response = requests.get(GITHUB_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            items = response.json().get("items", [])
            return [
                {
                    "file_url": item.get("html_url"),
                    "repository": item.get("repository", {}).get("full_name"),
                    "file_name": item.get("name")
                }
                for item in items
            ]
        else:
            logger.error(f"GitHub search failed with status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Error during GitHub search: {str(e)}")
    return []

regex_patterns={
    "Cloudinary": "cloudinary://.*",
    "Firebase URL": ".*firebaseio\\.com",
    "Slack Token": "(?i)xox[a-zA-Z]-[0-9a-zA-Z]{10,48}",
    "Slack Access Token": "(?i)xox[a-zA-Z]-[0-9a-zA-Z]{10,48}",
    "Slack Webhook": "(?i)hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon AWS Access Key ID": "AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "Discord Token": "\\b[MN][A-Za-z0-9]{23}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}\\b",
    "Telegram Bot Token": "\\b\\d{9}:[A-Za-z0-9_-]{35}\\b",
    "GitHub Token": "\\bghp_[A-Za-z0-9_]{36}\\b",
    "FCM Token": "\\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\\b",
    "JWT Token": "\\beyJ[A-Za-z0-9-_=]+?\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*\\b",
    "SAML Token": "<saml:Assertion.*?</saml:Assertion>",
    "SAML Response": "<samlp:Response.*?</samlp:Response>",
    "SAML Assertion": "<saml:Assertion.*?</saml:Assertion>",
    "SAML Signature": "<ds:Signature.*?</ds:Signature>",
    "SAML Encrypted Assertion": "<saml:EncryptedAssertion.*?</saml:EncryptedAssertion>",
    "SAML Encrypted Key": "<xenc:EncryptedKey.*?</xenc:EncryptedKey>",
    "SAML Encrypted Data": "<xenc:EncryptedData.*?</xenc:EncryptedData>",
    "SAML Encrypted Key Name": "<xenc:KeyName.*?</xenc:KeyName>",
    "SAML Encrypted Key Value": "<xenc:CipherValue.*?</xenc:CipherValue>",
    "SAML Encrypted Key Algorithm": "<xenc:EncryptionMethod.*?</xenc:EncryptionMethod>",
    "JWT Header": '{"alg":"[A-Za-z0-9\\-_]+","typ":"JWT"}',
    "JWT Payload": '{"sub":"[A-Za-z0-9\\-_]+","iat":\\d+,"exp":\\d+}',
    "OAuth2 Access Token": "\\bya29\\.[0-9A-Za-z\\-_]+\\b",
    "Basic Auth Credentials": "\\bbasic [A-Za-z0-9=:_\\+\\/\\-]{5,100}\\b",
    "Bearer Auth Token": "\\bbearer [A-Za-z0-9_\\-\\.=:_\\+\\/]{5,100}\\b",
    "Session ID": "\\bsession_id=[0-9A-Za-z]{32}\\b",
    "Session Token": "\\bsession_token=[0-9A-Za-z]{32}\\b",
    "Cookie Value": "(?<=Set-Cookie:\\s)[^;]+",
    "MongoDB Connection String": "\\bmongodb(\\+srv)?:\\/\\/[^\\s]+\\b",
    "MongoDB URI": "\\bmongodb:\\/\\/[^\\s]+\\b",
    "MongoDB Atlas Connection String": "\\bmongodb\\+srv:\\/\\/[^\\s]+\\b",
    "PostgreSQL Connection String": "\\bpostgresql:\\/\\/[^\\s]+\\b",
    "PostgreSQL URI": "\\bpostgres:\\/\\/[^\\s]+\\b",
    "MySQL Connection String": "\\bmysql:\\/\\/[^\\s]+\\b",
    "Redis Connection String": "\\bredis:\\/\\/[^\\s]+\\b",
    "FTP Connection String": "\\bftp:\\/\\/[^\\s]+\\b",
    "SFTP Connection String": "\\bsftp:\\/\\/[^\\s]+\\b",
    "SSH Connection String": "\\bssh:\\/\\/[^\\s]+\\b",
    "SQL Server Connection String": "\\bsqlserver:\\/\\/[^\\s]+\\b",
    "SQLite Connection String": "\\bsqlite:\\/\\/[^\\s]+\\b",
    "Oracle Connection String": "\\boracle:\\/\\/[^\\s]+\\b",
    "Cassandra URI": "\\bcassandra:\\/\\/[^\\s]+\\b",
    "Cassandra Connection String": "\\bcassandra:\\/\\/[^\\s]+\\b",
    "Azure Storage Account Key": "\\b[A-Za-z0-9+\\/]{88}==\\b",
    "Azure Storage Connection String": "\\bStorageAccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+\\/=]+;\\b",
    "Google Cloud Service Account Key": "\"private_key\":\\s*\"-----BEGIN PRIVATE KEY-----[A-Za-z0-9\\\\n\\/+=]*-----END PRIVATE KEY-----\"",
    "DigitalOcean Token": "\\bdo_[A-Fa-f0-9]{64}\\b",
    "Linode Personal Access Token": "\\blinode_[A-Za-z0-9-_]{64}\\b",
    "Email Address": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    "IPv4 Address": "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\b",
    "JSON Web Token": "\\bey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*\\b",
    "UUID": "\\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\b",
    "Password in Code": r"(?i)(?:password|secret|passwd|pwd|contraseña|passwort|motdepasse|senha|hasło|пароль|رمزعبور|clave|parola)\s*[:=]+\s*[^\s]+"
}
def check_regex(data, regex_patterns):
    """
    Scans the given data for matches against a set of regex patterns.

    Args:
        data (str): The input data to scan.
        regex_patterns (dict): A dictionary of regex patterns where keys are pattern names.

    Returns:
        list: A list of tuples containing the pattern name and the matched content.
    """
    matches = []
    for pattern_name, pattern in regex_patterns.items():
        matches.extend([(pattern_name, match) for match in re.findall(pattern, data)])
    return matches

def process_url(url, regex_patterns):
    """
    Fetches the content of a URL and scans it for sensitive data using regex patterns.

    Args:
        url (str): The URL to process.
        regex_patterns (dict): A dictionary of regex patterns to scan for.

    Returns:
        list: A list of matches found in the URL content.
    """
    if not url.startswith("http"):
        logger.error(f"Invalid URL: {url}. Expected a valid HTTP/HTTPS URL.")
        return []

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return check_regex(response.text, regex_patterns)
        else:
            logger.error(f"Failed to fetch URL {url}. HTTP status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Error processing URL {url}: {str(e)}")
    return []

def fetch_urls_and_descriptions_swagger(search_term):
    """
    Fetches API URLs and descriptions from SwaggerHub based on a search term.

    Args:
        search_term (str): The term to search for in SwaggerHub.

    Returns:
        list: A list of dictionaries containing API URLs and descriptions.
    """
    base_url = "https://app.swaggerhub.com/apiproxy/specs?sort=BEST_MATCH&order=DESC&query={}&page={}&limit=100"  # Limit set to 100
    apis = []
    try:
        session = requests.Session()
        page = 0
        total_apis = None  # Initialize total_apis to None
        results = []  # To store results for saving to a file

        while True:
            response = session.get(base_url.format(search_term, page), headers={"accept": "application/json"})
            if response.status_code != 200:
                logger.error(f"SwaggerHub API request failed with status code: {response.status_code}")
                break

            data = response.json()
            if total_apis is None:
                total_apis = int(data.get("totalCount", 0))  # Fetch totalCount only once
                if total_apis == 0:
                    logger.warning("No APIs found on SwaggerHub for the given search term.")
                    break

            if not data.get("apis"):
                logger.info("No more APIs to fetch from SwaggerHub.")
                break  # Exit loop if no more results

            logger.info(f"Fetched {len(data['apis'])} APIs from page {page + 1} of SwaggerHub.")
            for api in data.get("apis", []):
                description = api.get("description", "No description provided.")
                for prop in api.get("properties", []):
                    if "url" in prop:
                        api_data = {"url": prop["url"], "description": description}
                        apis.append(api_data)
                        # Print each API to the terminal
                        print_colored(f"[SwaggerHub API] URL: {api_data['url']}", Fore.CYAN)
                        print_colored(f"[SwaggerHub API] Description: {api_data['description']}", Fore.WHITE)
                        # Add to results for saving
                        results.append(f"URL: {api_data['url']}\nDescription: {api_data['description']}\n")

            page += 1  # Move to the next page
            if len(apis) >= total_apis:
                logger.info("Fetched all available APIs from SwaggerHub.")
                break

        # Save results to a file
        output_dir = "results"
        os.makedirs(output_dir, exist_ok=True)
        filename = f"swagger_results_{search_term}.txt".replace(" ", "_")
        filepath = os.path.join(output_dir, filename)
        
        save_results_to_file(filepath, results)
        print_colored(f"\n[+] SwaggerHub results saved to {filename}", Fore.MAGENTA)

        logger.info(f"Total APIs fetched from SwaggerHub: {len(apis)}")
    except Exception as e:
        logger.error(f"Error connecting to SwaggerHub: {str(e)}")
        print_colored(f"Error connecting to SwaggerHub: {str(e)}", Fore.RED)
    return apis

def fetch_postman_explore(search_term):
    """
    Fetches API data from Postman Explore based on a search term and checks for sensitive data.

    Args:
        search_term (str): The term to search for in Postman Explore.

    Returns:
        list: A list of flattened API data from Postman Explore.
    """
    logger.info(f"Searching Postman Explore for term: '{search_term}'")
    session = requests.Session()

    try:
        response = session.post(
            POSTMAN_HOST + GLOBAL_SEARCH_ENDPOINT,
            json=format_search_request_body(search_term, 0, MAX_SEARCH_RESULTS)
        )
        if response.status_code != 200:
            logger.error(f"Postman Explore search failed with status code: {response.status_code}")
            return []

        data = response.json().get("data", [])
        apis = []
        for item in data:
            document = item.get("document", {})
            url = document.get("url", "")
            base_url = document.get("baseUrl", "")
            publisher_handle = document.get("publisherHandle", "unknown-publisher")
            workspace_slug = document.get("workspaces", [{}])[0].get("slug", "unknown-workspace")
            request_id = document.get("id", "")

            # Resolve {{baseUrl}} placeholders
            if "{{baseUrl}}" in url:
                if base_url:
                    url = url.replace("{{baseUrl}}", base_url)
                else:
                    logger.warning(f"Unresolved placeholder in URL: {url}")
                    continue

            real_url = f"https://www.postman.com/{publisher_handle}/{workspace_slug}/request/{request_id}/{url}" if url else "N/A"

            sensitive_data = {}
            if real_url != "N/A":
                sensitive_data = fetch_request_details(real_url, session)

            if url:
                apis.append({
                    "id": request_id,
                    "url": url,
                    "explore_url": real_url,
                    "name": document.get("name", "No name provided"),
                    "description": document.get("description", "No description provided"),
                    "publisher": document.get("publisherName", "Unknown Publisher"),
                    "sensitive_data": sensitive_data
                })
            else:
                logger.warning(f"No valid URL found for document ID: {request_id}")

        if not apis:
            logger.warning("No valid APIs found in Postman Explore results.")
        return apis
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Postman Explore: {str(e)}")
        return []

def fetch_request_details(explore_url, session):
    """
    Fetches details of a Postman request.

    Args:
        explore_url (str): The Postman Explore URL.
        session (requests.Session): The session object for making requests.

    Returns:
        dict: A dictionary containing the URL and explore URL.
    """
    try:
        response = session.get(explore_url, timeout=10)
        if response.status_code != 200:
            logger.warning(f"Failed to fetch details from Explore URL: {explore_url} (HTTP {response.status_code})")
            return {"error": "Failed to fetch details"}

        return {"url": explore_url, "explore_url": explore_url}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching request details from {explore_url}: {str(e)}")
        return {"error": str(e)}

def format_search_request_body(keyword, offset, size):
    """
    Formats the request body for Postman Explore API search.

    Args:
        keyword (str): The search keyword.
        offset (int): The offset for pagination.
        size (int): The number of results to fetch.

    Returns:
        dict: The formatted request body.
    """
    return {
        "service": "search",
        "method": "POST",
        "path": "/search-all",
        "body": {
            "queryIndices": ["runtime.request"],
            "queryText": keyword,
            "size": size,
            "from": offset,
            "requestOrigin": "srp",
            "mergeEntities": "true",
            "nonNestedRequests": "true"
        }
    }

def parse_search_response(response):
    """
    Parses the response from Postman Explore API search.

    Args:
        response (requests.Response): The API response.

    Returns:
        set: A set of request IDs extracted from the response.
    """
    ids = set()
    data = response.json().get("data", [])
    for item in data:
        request_id = item.get("document", {}).get("id")
        if request_id:
            ids.add(request_id)
    return ids

def flatten_postman_request(request_data):
    """
    Flattens the Postman request data into a simplified dictionary.

    Args:
        request_data (dict): The raw request data from Postman.

    Returns:
        dict: A flattened dictionary containing key details of the request.
    """
    request_id = request_data.get("id", "")
    if not request_id:
        logger.warning("Request ID is missing in the Postman data.")
        return {}

    return {
        "id": request_id,
        "url": request_data.get("url", ""),
        "method": request_data.get("method", ""),
        "auth": request_data.get("auth", {}),
        "queryParams": request_data.get("queryParams", []),
        "headerData": request_data.get("headerData", []),
        "data": request_data.get("data", []),
        "description": request_data.get("description", ""),
        "name": request_data.get("name", ""),
        "explore_url": f"{POSTMAN_HOST}/collections/{request_id}"  # Corrected Postman Explore URL
    }

def validate_postman_url(url):
    """
    Validates if a Postman Explore URL is accessible.

    Args:
        url (str): The Postman Explore URL to validate.

    Returns:
        bool: True if the URL is accessible, False otherwise.
    """
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return True
        else:
            logger.warning(f"Postman Explore URL validation failed with status code: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error validating Postman Explore URL {url}: {str(e)}")
        return False

def save_results_to_file(filename, results):
    """
    Saves the results to a file.

    Args:
        filename (str): The name of the file to save the results.
        results (list): The results to save.
    """
    try:
        with open(filename, "w", encoding="utf-8") as file:
            for result in results:
                file.write(f"{result}\n")
        logger.info(f"Results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving results to file {filename}: {str(e)}")

def scan_urls_for_sensitive_data(urls, regex_patterns):
    """
    Sends requests to URLs and detects sensitive data using regex patterns.

    Args:
        urls (list): List of URLs to scan.
        regex_patterns (dict): Dictionary of regex patterns to scan for.

    Returns:
        dict: Dictionary containing URLs and detected sensitive data matches.
    """
    results = {}
    skipped_domains = set()

    def process_url(url):
        try:
            domain = url.split("/")[2]  # Extract domain from URL
            if domain in skipped_domains:
                print_colored(f"[!] Skipping domain {domain} due to 429 errors.", Fore.YELLOW)
                return

            print_colored(f"[+] Sending request to {url}...", Fore.CYAN)
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                print_colored(f"[+] Successfully fetched content from {url}.", Fore.GREEN)
                matches = check_regex(response.text, regex_patterns)
                if matches:
                    results[url] = matches
                    print_colored(f"[!] Sensitive data found in {url}:", Fore.RED)
                    for match in matches:
                        print_colored(f"    - {match[0]}: {match[1]}", Fore.RED)
                else:
                    print_colored(f"[!] No sensitive data found in {url}.", Fore.YELLOW)
            elif response.status_code == 429:
                print_colored(f"[!] Received 429 error for domain {domain}. Skipping further requests.", Fore.YELLOW)
                skipped_domains.add(domain)
            else:
                print_colored(f"[!] Failed to access {url} (HTTP {response.status_code}).", Fore.RED)
        except Exception as e:
            print_colored(f"[!] Error while processing {url}: {str(e)}", Fore.RED)

    with ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(process_url, urls)

    return results

def enhanced_main(search_term, mode):
    """
    Main function to fetch APIs from various sources, scan them for sensitive data, and display results.

    Args:
        search_term (str): The search term to use for API discovery.
        mode (str): The mode of operation ('-s', '-p', '-g', '-gh', '-a', '-explore', '-e').
    """
    display_banner()  # Display the banner at the start
    print_colored("Starting API discovery and scanning process...", Fore.MAGENTA, style=Style.BRIGHT)
    logger.info("Fetching APIs...")

    apis_swagger, apis_postman, google_dork_urls, github_results = [], [], [], []

    try:
        if mode in ["-s", "-a", "-explore", "-e"]:
            apis_swagger = fetch_urls_and_descriptions_swagger(search_term)
        if mode in ["-p", "-a", "-explore", "-e"]:
            apis_postman = fetch_postman_explore(search_term)
        if mode in ["-g", "-a", "-explore", "-e"]:
            google_dork_urls = google_dork_search(search_term)
        if mode in ["-gh", "-a", "-explore", "-e"]:
            github_query = f'"{search_term}" in:file language:python'
            github_results = github_search(github_query)
    except Exception as e:
        logger.error(f"Error during API discovery: {str(e)}")
        print_colored("An error occurred during the discovery process. Check logs for details.", Fore.RED)

    total_apis = len(apis_swagger) + len(apis_postman) + len(google_dork_urls) + len(github_results)
    if not total_apis:
        print_colored("[!] No APIs found. Please refine your search term.", Fore.YELLOW)
        return

    print_colored(f"[+] Found {total_apis} API(s). Scanning for sensitive data...\n", Fore.GREEN)

    # Prepare results for saving
    results = []

    # Display and collect Swagger results
    for api in apis_swagger:
        url = api.get('url', 'N/A')
        description = api.get('description', 'No description provided')
        results.append(f"Swagger URL: {url}")
        results.append(f"Description: {description}")
        print_colored(f"\n[Swagger URL] {url}", Fore.CYAN)
        print_colored(f"[Description] {description}", Fore.CYAN)

    # Display and collect Postman results
    for api in apis_postman:
        url = api.get('url', 'N/A')
        explore_url = api.get('explore_url', 'N/A')
        results.append(f"Postman URL: {url}")
        results.append(f"Postman Explore URL: {explore_url}")
        print_colored(f"\n[Postman URL] {url}", Fore.CYAN)
        print_colored(f"[Explore URL] {explore_url}", Fore.CYAN)

    # Display and collect Dork results
    if google_dork_urls:
        print_colored("\n[+] Dork Results:", Fore.MAGENTA)
        for url in google_dork_urls:
            results.append(f"Dork URL: {url}")
            print_colored(f"  [URL] {url}", Fore.CYAN)

    # Display and collect GitHub results
    if github_results:
        print_colored("\n[+] GitHub Search Results:", Fore.MAGENTA)
        for result in github_results:
            file_url = result['file_url']
            repository = result['repository']
            file_name = result['file_name']
            results.append(f"GitHub File: {file_name}, Repository: {repository}, URL: {file_url}")
            print_colored(f"  [File] {file_name}", Fore.CYAN)
            print_colored(f"  [Repository] {repository}", Fore.CYAN)
            print_colored(f"  [URL] {file_url}", Fore.CYAN)

    # If '-explore' or '-e' mode is selected, scan for sensitive data
    if mode in ["-explore", "-e"]:
        logger.info("-explore mode detected. Starting URL detection and sensitive data scan.")
        detected_urls = [api.get('url', 'N/A') for api in apis_swagger + apis_postman] + google_dork_urls + [result['file_url'] for result in github_results]
        logger.info(f"Total detected URLs: {len(detected_urls)}")
        print_colored(f"[+] Total {len(detected_urls)} URLs detected. Starting sensitive data scan...\n", Fore.GREEN)

        sensitive_data_results = scan_urls_for_sensitive_data(detected_urls, regex_patterns)

        if sensitive_data_results:
            logger.info("Sensitive data found during scan.")
            for url, matches in sensitive_data_results.items():
                results.append(f"\n[URL] {url}")
                for match in matches:
                    results.append(f"  [Sensitive Data] {match[0]}: {match[1]}")
            print_colored("\n[+] Sensitive data scan completed.", Fore.MAGENTA)
        else:
            logger.info("No sensitive data found during scan.")
            print_colored("[!] No sensitive data found in the scanned URLs.", Fore.YELLOW)

    # Determine filename based on mode
    mode_mapping = {
        "-a": "full",
        "-p": "postman",
        "-g": "google",
        "-gh": "github",
        "-s": "swagger",
        "-explore": "explore",
        "-e": "explore"
    }
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)
    
    filename_prefix = mode_mapping.get(mode, "results")
    filename = f"{filename_prefix}_{search_term}.txt".replace(" ", "_")
    filepath = os.path.join(output_dir, filename)
    # Save results to file
    save_results_to_file(filepath, results)

    print_colored("\n[+] Scan completed successfully.", Fore.MAGENTA)
    logger.info("Scan completed.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        display_banner()  # Display the banner for incorrect usage
        print_colored("\nUsage: python3 monaleak.py <parameter> <search_term>", Fore.RED, style=Style.BRIGHT)
        print_colored("Parameters:\n  -s : Search only SwaggerHub\n  -p : Search only Postman\n  -g : Perform Dork search\n  -gh : Perform GitHub search\n  -a : Search all\n  -e/-explore : Find all secret in URLS ", Fore.RED)
        sys.exit(1)

    mode = sys.argv[1]
    term = sys.argv[2]
    enhanced_main(term, mode)
