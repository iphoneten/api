import base64
import json
import yaml
import uuid
import re
import urllib.parse

proxy_links = [
    "vmess://eyJ2IjoiMiIsInBzIjoiU0NQVVMyIiwiYWRkIjoidGVzdDMuZmxoYS5ydSIsInBvcnQiOjgwLCJpZCI6IjA3MzBkNGUxLTNjODQtNGUwNi04YjJjLTIyYWI0ZjU5MWZmNiIsImFpZCI6MCwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0Ijoic2ltcy1tdXNldW0tbWVudGFsLWxpc3RlbmluZy50cnljbG91ZGZsYXJlLmNvbSIsInBhdGgiOiIvMDczMGQ0ZTEtM2M4NC00ZTA2LThiMmMtMjJhYjRmNTkxZmY2LXZtP2VkPTIwNDgifQ==",
    "vmess://eyAidiI6ICIyIiwgInBzIjogIlNDUFVTMiIsICJhZGQiOiAiMTA0LjE2LjAuMCIsICJwb3J0IjogIjQ0MyIsICJpZCI6ICI1OGI3OGQ0MC1hYWFmLTQzYTUtODI2My1kOGMzYTA3ZTI0MWUiLCAiYWlkIjogIjAiLCAic2N5IjogImF1dG8iLCAibmV0IjogIndzIiwgInR5cGUiOiAibm9uZSIsICJob3N0IjogIm1hbmFnZWQtbHVjeS1ib29raW5nLXN0YW5kYXJkLnRyeWNsb3VkZmxhcmUuY29tIiwgInBhdGgiOiAiLzU4Yjc4ZDQwLWFhYWYtNDNhNS04MjYzLWQ4YzNhMDdlMjQxZS12bT9lZD0yMDQ4IiwgInRscyI6ICJ0bHMiLCAic25pIjogIm1hbmFnZWQtbHVjeS1ib29raW5nLXN0YW5kYXJkLnRyeWNsb3VkZmxhcmUuY29tIiwgImFscG4iOiAiIiwgImZwIjogIiJ9Cg==",
    "hysteria2://435e90c0-bfeb-45b7-bcc4-cad22a4ceb63@9jclv1.225313.xyz:32525?sni=9jclv1.225313.xyz#%F0%9F%87%BA%F0%9F%87%B8%20United%20States%2001",
]

# 初始化Clash配置
clash_config = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "external-controller": ":9090",
    "proxies": [],
    "proxy-groups": [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": [],
            "url": "https://www.google.com/generate_204",
            # "timeout": 5000,
        }
    ],
    "rules": ["GEOIP,CN,DIRECT", "MATCH,Proxy"],
}


def parse_vmess_link(link_str):
    base64_str = link_str.replace("vmess://", "", 1)
    vmess_json = json.loads(base64.b64decode(base64_str).decode("utf-8"))

    node_name = vmess_json.get("ps", "UnnamedNode")
    server = vmess_json.get("add", "")
    port = int(vmess_json.get("port", 80))
    uuid_str = vmess_json.get("id", "")
    alter_id = int(vmess_json.get("aid", 0))
    cipher = vmess_json.get("scy", "auto")
    network = vmess_json.get("net", "tcp")
    ws_path = vmess_json.get("path", "")
    ws_host = vmess_json.get("host", "")
    tls = vmess_json.get("tls", False)
    sni = vmess_json.get("sni", "")

    proxy = {
        "name": node_name,
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid_str,
        "alterId": alter_id,
        "cipher": cipher,
        "udp": True,
    }

    if network == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": ws_path, "headers": {"Host": ws_host}}

    if tls:
        proxy["tls"] = True
        if sni:
            proxy["servername"] = sni
        elif ws_host:
            proxy["servername"] = ws_host

    return proxy


def parse_shadowsocks_link(link_str):
    try:
        parts = link_str.replace("ss://", "", 1).split("#", 1)
        encoded_credentials = parts[0]
        node_name = parts[1] if len(parts) > 1 else "Unnamed SS Node"

        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")

        match = re.match(r"([^:]+):([^@]+)@([^:]+):(\d+)", decoded_credentials)
        if not match:
            raise ValueError("Invalid Shadowsocks credentials format")

        method, password, server, port_str = match.groups()
        port = int(port_str)

        proxy = {
            "name": node_name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
        return proxy
    except Exception as e:
        print(f"Error parsing Shadowsocks link {link_str}: {e}")
        return None


def parse_hysteria2_link(link_str):
    try:
        # hy2://password@server:port?param=value#name

        if link_str.startswith("hy2://"):
            link_str.replace("hy2://", "", 1)
        elif link_str.startswith("hysteria2://"):
            link_str.replace("hysteria2://", "", 1)

        # Split into auth_server_port and params_name
        if "#" in link_str:
            core_part, node_name = link_str.split("#", 1)
            node_name = urllib.parse.unquote(node_name)
        else:
            core_part = link_str
            node_name = "Hysteria2"

        if "?" in core_part:
            auth_server_port, query_string = core_part.split("?", 1)
            params = urllib.parse.parse_qs(query_string)
        else:
            auth_server_port = core_part
            params = {}

        # Parse password@server:port
        if "@" in auth_server_port:
            password, server_port = auth_server_port.split("@", 1)
        else:
            password = ""
            server_port = auth_server_port

        server, port_str = server_port.split(":", 1)
        port = int(port_str)

        proxy = {
            "name": node_name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,  # or auth-str depending on Clash version
            "udp": True,  # Hysteria2 is UDP-based
        }

        # Add optional parameters
        if "tls" in params:
            proxy["tls"] = params["tls"][0].lower() == "true"
        if "sni" in params:
            proxy["sni"] = params["sni"][0]
        if "skip-cert-verify" in params:
            proxy["skip-cert-verify"] = params["skip-cert-verify"][0].lower() == "true"
        if "insecure" in params:  # Handle insecure parameter
            proxy["skip-cert-verify"] = params["insecure"][0] == "1"
        if "alpn" in params:
            proxy["alpn"] = params["alpn"][0].split(",")
        if "obfs" in params:
            proxy["obfs"] = params["obfs"][0]
        if "obfs-password" in params:
            proxy["obfs-password"] = params["obfs-password"][0]
        if "up" in params:
            proxy["up"] = int(params["up"][0])
        if "down" in params:
            proxy["down"] = int(params["down"][0])

        return proxy
    except Exception as e:
        print(f"Error parsing Hysteria2 link {link_str}: {e}")
        return None


# 解析并转换每个代理链接
for link in proxy_links:
    try:
        proxy = None
        if link.startswith("vmess://"):
            proxy = parse_vmess_link(link)
        elif link.startswith("ss://"):
            proxy = parse_shadowsocks_link(link)
        elif link.startswith("hy2://") or link.startswith("hysteria2://"):
            proxy = parse_hysteria2_link(link)
        else:
            print(f"Unsupported protocol for link: {link}")
            continue

        if proxy:
            original_node_name = proxy["name"]
            counter = 1
            node_name = original_node_name
            while any(p.get("name") == node_name for p in clash_config["proxies"]):
                node_name = f"{original_node_name}_{counter}"
                counter += 1
            proxy["name"] = node_name

            clash_config["proxies"].append(proxy)
            clash_config["proxy-groups"][0]["proxies"].append(node_name)

    except Exception as e:
        print(f"Error processing link {link}: {e}")
        continue

# 保存为config.yaml文件
with open("config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

print("Clash YAML配置已生成：config.yaml")
