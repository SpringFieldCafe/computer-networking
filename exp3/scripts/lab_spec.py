"""课件实验三的静态拓扑与理论预期；这里的连通矩阵不是 eNSP 实测结果。"""
from ipaddress import IPv4Address, IPv4Network


EXP1_HOSTS = {
    "PC1": {"ip": "192.168.1.2", "mask": "255.255.255.0", "gateway": "", "switch": "S1", "port": 1, "vlan": 1},
    "PC2": {"ip": "192.168.1.3", "mask": "255.255.255.0", "gateway": "", "switch": "S1", "port": 2, "vlan": 1},
    "PC3": {"ip": "192.168.1.4", "mask": "255.255.255.0", "gateway": "", "switch": "S1", "port": 13, "vlan": 2},
    "PC4": {"ip": "192.168.1.5", "mask": "255.255.255.0", "gateway": "", "switch": "S1", "port": 14, "vlan": 2},
}
EXP2_HOSTS = {
    "PC1": {"ip": "192.168.100.1", "mask": "255.255.255.0", "gateway": "192.168.100.254", "switch": "S2", "port": 1, "vlan": 100},
    "PC2": {"ip": "192.168.200.2", "mask": "255.255.255.0", "gateway": "192.168.200.254", "switch": "S2", "port": 2, "vlan": 200},
    "PC3": {"ip": "192.168.100.3", "mask": "255.255.255.0", "gateway": "192.168.100.254", "switch": "S3", "port": 1, "vlan": 100},
    "PC4": {"ip": "192.168.200.4", "mask": "255.255.255.0", "gateway": "192.168.200.254", "switch": "S3", "port": 2, "vlan": 200},
}
EXP1_LINKS = (("S1", 1, "PC1", 1), ("S1", 2, "PC2", 1),
              ("S1", 13, "PC3", 1), ("S1", 14, "PC4", 1))
EXP2_LINKS = (("S1", 1, "S2", 3), ("S1", 2, "S3", 3),
              ("S2", 1, "PC1", 1), ("S2", 2, "PC2", 1),
              ("S3", 1, "PC3", 1), ("S3", 2, "PC4", 1))
TOPOLOGY_FILES = {"part1": "实验3-部分1.topo", "part2": "实验3-部分2.topo"}
CONSOLE_PORTS = {"part1": {"S1": 2100}, "part2": {"S1": 2200, "S2": 2201, "S3": 2202}}
EXPERIMENTS = {
    "part1": {"switches": CONSOLE_PORTS["part1"], "hosts": EXP1_HOSTS, "links": EXP1_LINKS,
             "positions": {"S1": (550, 100), "PC1": (100, 380), "PC2": (400, 380), "PC3": (700, 380), "PC4": (1000, 380)},
             "source_pages": (8, 9, 10, 11)},
    "part2": {"switches": CONSOLE_PORTS["part2"], "hosts": EXP2_HOSTS, "links": EXP2_LINKS,
             "positions": {"S1": (550, 80), "S2": (280, 270), "S3": (820, 270),
                           "PC1": (100, 500), "PC2": (400, 500), "PC3": (700, 500), "PC4": (1000, 500)},
             "source_pages": (13, 14, 15, 16, 17, 18, 19)},
}
STAGES = {
    "part1-default": {"experiment": "part1", "description": "全部端口默认 VLAN1，配置前", "optional": False, "source_pages": (9,)},
    "part1-vlan2": {"experiment": "part1", "description": "Ethernet0/0/13—22 改为 access VLAN2", "optional": False, "source_pages": (10, 11), "pending_decision": "part1_interface_name"},
    "part2-access": {"experiment": "part2", "description": "S2/S3 配置完成，S1 保持默认", "optional": False, "source_pages": (15, 16)},
    "part2-l2-optional": {"experiment": "part2", "description": "补充验证：S1 配置 VLAN/trunk，暂不配置 Vlanif", "optional": True, "source_pages": ()},
    "part2-routing": {"experiment": "part2", "description": "S1 VLAN/trunk/Vlanif 均配置完成", "optional": False, "source_pages": (17, 18, 19)},
}
PING_TARGETS = ("PC2", "PC3", "PC4")


def validate_spec(experiment, spec=None):
    """校验静态数据；端口号按课件一基编号，拓扑 XML 中才减一。"""
    spec = EXPERIMENTS[experiment] if spec is None else spec
    switches, hosts = spec["switches"], spec["hosts"]
    names = set(switches) | set(hosts)
    if len(names) != len(switches) + len(hosts):
        raise ValueError("交换机与主机名称重复")
    if set(spec["positions"]) != names:
        raise ValueError("设备坐标与名称不一致")
    if len(set(switches.values())) != len(switches):
        raise ValueError("Console 端口重复")
    if any(not isinstance(p, int) or not 1 <= p <= 65535 for p in switches.values()):
        raise ValueError("Console 端口越界")
    used, edges = set(), set()
    for a, ap, b, bp in spec["links"]:
        if a not in names or b not in names or a == b:
            raise ValueError("链路包含未知设备或自身回环")
        for name, port in ((a, ap), (b, bp)):
            limit = 22 if name in switches else 1
            if not isinstance(port, int) or not 1 <= port <= limit:
                raise ValueError(f"{name} 端口越界")
            if (name, port) in used:
                raise ValueError(f"{name} 端口 {port} 被复用")
            used.add((name, port))
        edge = frozenset(((a, ap), (b, bp)))
        edges.add(edge)
    if len(edges) != len(spec["links"]):
        raise ValueError("链路重复")
    ips = set()
    for name, host in hosts.items():
        ip = IPv4Address(host["ip"])
        network = IPv4Network(f'{ip}/{host["mask"]}', strict=False)
        if ip in ips or ip in (network.network_address, network.broadcast_address):
            raise ValueError("主机 IP 重复或使用网络/广播地址")
        ips.add(ip)
        if host["gateway"]:
            gateway = IPv4Address(host["gateway"])
            if gateway not in network or gateway == ip:
                raise ValueError("网关地址与主机网段不匹配")
        expected = frozenset(((name, 1), (host["switch"], host["port"])))
        if expected not in edges:
            raise ValueError(f"{name} 的连接与地址表不一致")
    return True


def theoretical_matrix(stage):
    """所有有向 PC 对的理论预期；要求设备正常且已完成该阶段配置。"""
    experiment = STAGES[stage]["experiment"]
    hosts = EXPERIMENTS[experiment]["hosts"]
    result = {}
    for a, ha in hosts.items():
        for b, hb in hosts.items():
            if a == b:
                continue
            if stage == "part1-default":
                reachable = True
            elif stage == "part1-vlan2":
                reachable = ha["vlan"] == hb["vlan"]
            elif stage == "part2-access":
                # S1 默认不接收两条上联上的 VLAN100/200 帧。
                reachable = ha["switch"] == hb["switch"] and ha["vlan"] == hb["vlan"]
            elif stage == "part2-l2-optional":
                reachable = ha["vlan"] == hb["vlan"]
            else:
                reachable = True
            result[(a, b)] = reachable
    return result


def expected_pc1(stage):
    matrix = theoretical_matrix(stage)
    return {target: matrix[("PC1", target)] for target in PING_TARGETS}


def reference_configs():
    """返回阶段增量 CLI 参考，不连接设备；所有阶段都从 user-view 开始。"""
    start = ["undo terminal monitor", "system-view"]
    configs = {"part1-vlan2": {"S1": start + [
        "sysname S1", "vlan 2", "quit", "port-group g2",
        "group-member Ethernet 0/0/13 to Ethernet 0/0/22", "port link-type access",
        "port default vlan 2", "quit", "return"]}}
    access = {}
    for switch in ("S2", "S3"):
        access[switch] = start + [f"sysname {switch}", "vlan batch 100 200",
            "interface Ethernet0/0/3", "port link-type trunk", "port trunk allow-pass vlan 100 200", "quit",
            "interface Ethernet0/0/1", "port link-type access", "port default vlan 100", "quit",
            "interface Ethernet0/0/2", "port link-type access", "port default vlan 200", "quit", "return"]
    configs["part2-access"] = access
    l2 = start + ["sysname S1", "vlan batch 100 200",
        "interface Ethernet0/0/1", "port link-type trunk", "port trunk allow-pass vlan 100 200", "quit",
        "interface Ethernet0/0/2", "port link-type trunk", "port trunk allow-pass vlan 100 200", "quit"]
    configs["part2-l2-optional"] = {"S1": l2 + ["return"]}
    configs["part2-routing"] = {"S1": l2 + [
        "interface Vlanif 100", "ip address 192.168.100.254 255.255.255.0", "quit",
        "interface Vlanif 200", "ip address 192.168.200.254 255.255.255.0", "quit", "return"]}
    return configs
