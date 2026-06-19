import os.path
from pathlib import Path
from typing import List, Tuple


pcap_path_prefix = str(Path(__file__).parent / "pcaps")

def join_pcaps_with_cps_times_multiplier(pcaps_with_cps: List[Tuple[str, int]], multiplier: float) -> List[Tuple[str, float]]:
    joined_values: List[Tuple[str, float]] = []

    for value in pcaps_with_cps:
        pcap_name, cps = value
        joined_values.append((os.path.join(pcap_path_prefix, pcap_name), cps * multiplier))

    return joined_values
