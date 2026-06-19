#import lbr_trex_client.paths

from lbr_testsuite import trex
from .util_trex_profile import join_pcaps_with_cps_times_multiplier

def create_profile(multiplier: float) -> trex.TRexProfilePcap:
    return trex.TRexProfilePcap(pcap_files=
                                join_pcaps_with_cps_times_multiplier(
                                    [
                                    ("genericEBay_730P_1069B_3.pcap", 800),
                                    ("DNS_3P_83B.pcap", 200),
                                    ("http-p52728.pcap", 190)
                                    ],
                                    multiplier),
                                client_net="10.0.0.0/24",
                                server_net="10.0.0.0/26",
                                )
