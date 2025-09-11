import yaml
import re
import requests
import socket # 新增：导入 socket 模块

# Function to fetch web content from the given URL
def fetch_proxies_from_url(url):
    """Fetches the web content from the given URL."""
    try:
        response = requests.get(url, timeout=10)  # Set a timeout for the request
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
        return data.get("proxies", [])
    except yaml.YAMLError as e:
        print(f"Error parsing YAML content: {e}")
        return []


def test_proxy_tcp_reachability(host, port, timeout=3):
    """
    Tests if the given host and port are TCP reachable.
    Returns True if reachable, False otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout) as sock:
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def filter_unreachable_proxies(proxies, timeout=5):
    """
    Filters out proxies whose server and port are not TCP reachable.
    """
    reachable_proxies = []
    for proxy in proxies:
        server = proxy.get("server")
        port = proxy.get("port")
        name = proxy.get("name", "Unknown Proxy")

        if not server or not port:
            print(f"Skipping TCP connectivity test for '{name}' due to missing server or port.")
            reachable_proxies.append(proxy) # 如果信息缺失，暂时不进行过滤
            continue

        # Convert port to int if it's a string
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                print(f"Skipping TCP connectivity test for '{name}' due to invalid port format: {port}.")
                reachable_proxies.append(proxy)
                continue

        if test_proxy_tcp_reachability(server, port, timeout):
            print(f"Proxy '{name}' ({server}:{port}) is TCP reachable.")
            reachable_proxies.append(proxy)
        else:
            print(f"Excluding proxy '{name}' ({server}:{port}) as it is NOT TCP reachable.")
    return reachable_proxies


# Function to write the complete Clash configuration to a YAML file
def write_clash_config(filtered_proxies, filename="config.yaml"):  # {{ edit_1 }}
    """Generates a complete Clash YAML configuration and writes it to a file."""

    # Base Clash configuration template
    base_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "Rule",
        "log-level": "info",
        "external-controller": ":9090",
        "proxies": [],
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": [],
                "url": "https://www.google.com/generate_204",
                # "timeout": 5000,
            }
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }

    # Add filtered proxies to the 'proxies' section
    base_config["proxies"] = filtered_proxies

    # Get the names of the filtered proxies
    filtered_proxy_names = [p["name"] for p in filtered_proxies]

    # Add filtered proxy names to relevant proxy groups
    for group in base_config["proxy-groups"]:
        if group["name"] in ["🚀 节点选择"]:
            group["proxies"].extend(filtered_proxy_names)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            yaml.dump(base_config, f, allow_unicode=True, sort_keys=False)
        print(f"Complete Clash configuration successfully written to '{filename}'")
    except IOError as e:
        print(f"Error writing to file '{filename}': {e}")


if __name__ == "__main__":
    url = "https://proxypool.dmit.dpdns.org/clash/proxies?type=vmess,hysteria2"
    web_content = fetch_proxies_from_url(url)

    if web_content:
        all_proxies = get_proxies_from_content(web_content)
        if all_proxies:
            print(f"Found {len(all_proxies)} proxies from the source.")
            # Apply TCP reachability filtering
            final_proxies = filter_unreachable_proxies(all_proxies, timeout=5)
            print(f"Filtered to {len(final_proxies)} proxies after TCP reachability check.")
            write_clash_config(final_proxies)
        else:
            print("No proxies found or an error occurred during parsing.")
    else:
        print("Failed to fetch web content. Exiting.")
