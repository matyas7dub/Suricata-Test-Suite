# Parameter template example

suri_yaml_params = {
    "dpdk.interfaces[0].interface": ["PCIEaddr"],
    "dpdk.interfaces[0].mtu": [2500, 3000],
}

capture_modes = ["dpdk"]
suri_cmd_params = {"capture-mode": ["dpdk"]}

filter = {"dpdk": [lambda x: x["dpdk.interfaces[0].mtu"] <= 3000]}
