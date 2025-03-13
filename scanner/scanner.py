import requests
from bs4 import BeautifulSoup
import nmap
from urllib.parse import urljoin, urlparse
import re

def scan_website(url):
    results = {
        "headers": {},
        "technology": [],
        "vulnerabilities": [],
        "open_ports": []
    }

    # Ensure URL is correctly formatted
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Retrieve headers
    try:
        response = requests.get(url)
        results["headers"] = response.headers
    except requests.RequestException as e:
        results["vulnerabilities"].append(f"Failed to retrieve headers: {e}")
        return results

    # Detect technology using headers and meta tags
    detect_technology(url, results)

    # Detect common vulnerabilities
    detect_vulnerabilities(url, results)

    # Detect open ports
    detect_open_ports(url, results)

    return results

def detect_technology(url, results):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Detect using meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            results["technology"].append(meta_generator['content'])

        # Detect using headers
        server_header = results["headers"].get('Server')
        if server_header:
            results["technology"].append(server_header)

        # Simple checks for common technologies
        if 'x-powered-by' in results["headers"]:
            results["technology"].append(results["headers"]['x-powered-by'])
        if 'wordpress' in response.text.lower():
            results["technology"].append('WordPress')
        if 'wp-content' in response.text.lower():
            results["technology"].append('WordPress')
        if 'shopify' in response.text.lower():
            results["technology"].append('Shopify')
    except requests.RequestException as e:
        results["vulnerabilities"].append(f"Failed to detect technology: {e}")

def detect_vulnerabilities(url, results):
    try:
        response = requests.get(url)

        xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
        for payload in xss_payloads:
            test_url = urljoin(url, f"?q={payload}")
            test_response = requests.get(test_url)
            if payload in test_response.text:
                results["vulnerabilities"].append("Cross-site Scripting (XSS) detected")
                break
        else:
            results["vulnerabilities"].append("Cross-site Scripting (XSS) not detected")

       
        sql_injection_payloads = ["'", '"', '1=1', "' OR '1'='1"]
        for payload in sql_injection_payloads:
            test_url = f"{url}?id={payload}"
            test_response = requests.get(test_url)
            if "SQL" in test_response.text or "sql" in test_response.text:
                results["vulnerabilities"].append(f"Potential SQL Injection vulnerability with payload: {payload}")
                break
        else:
            results["vulnerabilities"].append("SQL Injection not detected")

        
        cmd_injection_payloads = [";ls", "&& ls", "| ls"]
        for payload in cmd_injection_payloads:
            test_url = f"{url}?cmd={payload}"
            test_response = requests.get(test_url)
            if "bin" in test_response.text or "usr" in test_response.text:
                results["vulnerabilities"].append(f"Potential Command Injection vulnerability with payload: {payload}")
                break
        else:
            results["vulnerabilities"].append("Command Injection not detected")

     
        ssrf_payload = "http://localhost:8080"
        ssrf_response = requests.get(urljoin(url, f"?url={ssrf_payload}"))
        if "localhost" in ssrf_response.text:
            results["vulnerabilities"].append('SSRF detected with payload : http://localhost:8080')
        else:
            results["vulnerabilities"].append('SSRF not detected')

        
        rfi_payload = "http://example.com/shell.txt"
        rfi_response = requests.get(urljoin(url, f"?file={rfi_payload}"))
        if "shell" in rfi_response.text:
            results["vulnerabilities"].append('RFI detected using payload http://example.com/shell.txt')
        else:
            results["vulnerabilities"].append('RFI not detected')

        
        lfi_payload = "../../../../etc/passwd"
        lfi_response = requests.get(urljoin(url, f"?file={lfi_payload}"))
        if "root:" in lfi_response.text:
            results["vulnerabilities"].append('LFI detected with payload ../../../../etc/passwd')
        else:
            results["vulnerabilities"].append('LFI not detected')

       
        rce_payload = "; echo 'rce_test'"
        rce_response = requests.get(urljoin(url, f"?cmd={rce_payload}"))
        if "rce_test" in rce_response.text:
            results["vulnerabilities"].append('RCE detected with payload ; echo rce_test')
        else:
            results["vulnerabilities"].append('RCE not detected')

        
        crlf_payload = "%0d%0aSet-Cookie:crlf=injection"
        crlf_response = requests.get(urljoin(url, f"?q={crlf_payload}"))
        if "crlf=injection" in crlf_response.headers.get('Set-Cookie', ''):
            results["vulnerabilities"].append('CRLF Injection detected with payload %0d%0aSet-Cookie:crlf=injection')
        else:
            results["vulnerabilities"].append('CRLF Injection not detected')

       
        url_access_test = urljoin(url, "/admin")
        url_access_response = requests.get(url_access_test)
        if url_access_response.status_code == 200:
            results["vulnerabilities"].append('Failure to restrict URL Access detected')
        else:
            results["vulnerabilities"].append('Failure to restrict URL Access not detected')

        
        if not url.startswith("https"):
            results["vulnerabilities"].append('Insufficient Transport Layer Protection detected')
        else:
            results["vulnerabilities"].append('Insufficient Transport Layer Protection not detected')

        
        redirect_payload = "http://evil.com"
        redirect_response = requests.get(urljoin(url, f"?next={redirect_payload}"), allow_redirects=False)
        if redirect_response.status_code in [301, 302] and redirect_response.headers.get('Location') == redirect_payload:
            results["vulnerabilities"].append('Unvalidated Redirects and Forwards detected')
        else:
            results["vulnerabilities"].append('Unvalidated Redirects and Forwards not detected')

        
        if 'Set-Cookie' in results["headers"] and 'Secure' not in results["headers"]['Set-Cookie']:
            results["vulnerabilities"].append('Insecure Cryptographic Storage detected')
        else:
            results["vulnerabilities"].append('Insecure Cryptographic Storage not detected')

        
        if 'X-Frame-Options' not in results["headers"]:
            results["vulnerabilities"].append('Security Misconfiguration detected')
        else:
            results["vulnerabilities"].append('Security Misconfiguration not detected')

        
        xml_payload = "<test><value>1</value></test>"
        xml_response = requests.post(url, data=xml_payload, headers={'Content-Type': 'application/xml'})
        if "<value>1</value>" in xml_response.text:
            results["vulnerabilities"].append('XML Injection detected')
        else:
            results["vulnerabilities"].append('XML Injection not detected')
   

    except requests.RequestException as e:
        results["vulnerabilities"].append(f"Failed to detect vulnerabilities: {e}")

def detect_open_ports(url, results):
    nm = nmap.PortScanner()
    hostname = urlparse(url).hostname
    try:
        scan_result = nm.scan(hostname, '1-1024')  
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    results["open_ports"].append(f"Port {port}: {nm[host][proto][port]['state']}")
    except Exception as e:
        results["vulnerabilities"].append(f"Failed to detect open ports: {e}")
