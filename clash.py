import yaml
import re
import requests

# Function to fetch web content from the given URL
def fetch_proxies_from_url(url):
    """Fetches the web content from the given URL."""
    try:
        response = requests.get(url, timeout=10) # Set a timeout for the request
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None

# Function to parse web content and extract proxies
def get_proxies_from_content(content):
    """Parses the web content and extracts the proxies."""
    try:
        data = yaml.safe_load(content)
        return data.get('proxies', [])
    except yaml.YAMLError as e:
        print(f"Error parsing YAML content: {e}")
        return []

# Function to filter out failed nodes
def filter_failed_nodes(proxies, speed_threshold_mb=5.0):
    """Filters out proxies based on a speed threshold in their name."""
    filtered_proxies = []
    for proxy in proxies:
        name = proxy.get('name', '')
        match = re.search(r'\|([\d.]+)Mb', name)
        if match:
            speed_mb = float(match.group(1))
            if speed_mb >= speed_threshold_mb:
                filtered_proxies.append(proxy)
            else:
                print(f"Excluding proxy '{name}' due to low speed: {speed_mb} Mb < {speed_threshold_mb} Mb")
        else:
            # If no speed information, include it by default or exclude it based on policy
            print(f"Including proxy '{name}' (no speed information found).")
            filtered_proxies.append(proxy)
    return filtered_proxies

# Function to write the complete Clash configuration to a YAML file
def write_clash_config(filtered_proxies, filename="config.yaml"): # {{ edit_1 }}
    """Generates a complete Clash YAML configuration and writes it to a file."""
    
    # Base Clash configuration template
    base_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:53',
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'fake-ip-filter': [
                '+.stun.*.*',
                '+.specht.run',
                '+.olcs.com'
            ],
            'default-nameserver': [
                '114.114.114.114',
                '8.8.8.8'
            ],
            'nameserver': [
                'https://dns.google/dns-query',
                'https://cloudflare-dns.com/dns-query'
            ]
        },
        'proxies': [], # This will be filled with filtered_proxies
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['自动选择', 'DIRECT'] # Will add filtered proxy names here
            },
            {
                'name': '💡 故障转移',
                'type': 'fallback',
                'url': 'http://www.google.com/generate_204',
                'interval': 300,
                'proxies': ['自动选择', 'DIRECT']
            },
            {
                'name': '🔯 自动选择',
                'type': 'url-test',
                'url': 'http://www.google.com/generate_204',
                'interval': 300,
                'proxies': ['DIRECT'] # Will add filtered proxy names here
            },
            {
                'name': '🌍 国外媒体',
                'type': 'select',
                'proxies': ['自动选择', 'DIRECT']
            },
            {
                'name': '🎯 全球直连',
                'type': 'select',
                'proxies': ['DIRECT', '🚀 节点选择']
            }
        ],
        'rules': [
            'DOMAIN-SUFFIX,google.com,🚀 节点选择',
            'DOMAIN-SUFFIX,youtube.com,🚀 节点选择',
            'DOMAIN-SUFFIX,netflix.com,🚀 节点选择',
            'DOMAIN-SUFFIX,twitter.com,🚀 节点选择',
            'DOMAIN-SUFFIX,facebook.com,🚀 节点选择',
            'DOMAIN-SUFFIX,telegram.org,🚀 节点选择',
            'GEOSITE,CN,DIRECT',
            'GEOIP,CN,DIRECT',
            'MATCH,🚀 节点选择'
        ]
    }

    # Add filtered proxies to the 'proxies' section
    base_config['proxies'] = filtered_proxies

    # Get the names of the filtered proxies
    filtered_proxy_names = [p['name'] for p in filtered_proxies]

    # Add filtered proxy names to relevant proxy groups
    for group in base_config['proxy-groups']:
        if group['name'] in ['🚀 节点选择', '🔯 自动选择']:
            group['proxies'].extend(filtered_proxy_names)

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(base_config, f, allow_unicode=True, sort_keys=False)
        print(f"Complete Clash configuration successfully written to '{filename}'")
    except IOError as e:
        print(f"Error writing to file '{filename}': {e}")

if __name__ == "__main__":
    url = "https://proxypool.dmit.dpdns.org/clash/proxies?type=ss,vmess,trojan,hysteria2"
    web_content = fetch_proxies_from_url(url)

    if web_content:
        all_proxies = get_proxies_from_content(web_content)
        if all_proxies:
            print(f"Found {len(all_proxies)} proxies from the source.")
            filtered_proxies = filter_failed_nodes(all_proxies, speed_threshold_mb=5.0)
            print(f"Filtered down to {len(filtered_proxies)} proxies.")
            write_clash_config(filtered_proxies) # {{ edit_2 }}
        else:
            print("No proxies found or an error occurred during parsing.")
    else:
        print("Failed to fetch web content. Exiting.")
