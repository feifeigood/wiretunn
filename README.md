# Wiretunn
This project aims to provides a cross-platform, asynchronous(with [Tokio](https://tokio.rs/)) [WireGuard](https://www.wireguard.com/) implementation.

# Usage

Create a Wiretunn's configuration file. Example
```code
# interface_name = "en0"
external_controller = "127.0.0.1:9090"
# Only effect Windows
nameservers = ["8.8.8.8", "1.1.1.1"]
# Exclude IPs like this https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/
excluded_ips = [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "239.255.255.250/32",
    "255.255.255.255/32",
    "fe80::/10",
    "fd00::/8",
    "ff01::/16",
    "ff02::/16",
    "ff03::/16",
    "ff04::/16",
    "ff05::/16",
    "fc00::/7",
]

[log]
level = "debug"

[wireguard.wg0]
private_key = "your private key"
address = "10.0.0.2/24"
mtu = 1420

[[wireguard.wg0.peer]]
public_key = "your public key"
allowed_ips = "0.0.0.0/0"
endpoint = "your wireguard endpoint"
persistent_keepalive = 15
```

Start Wiretunn application by command line
```code
# required root or administrator privilege
# on Windows, you need download wintun driver in current dir
$ wiretunn-cli run -c example.toml
```

# Supported Platforms

- Windows
- Linux
- MacOS
- Android
- iOS

# License
This project is licensed under the [MIT License](LICENSE)
