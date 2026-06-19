#import lbr_trex_client.paths

from lbr_testsuite import trex
from .util_trex_profile import join_pcaps_with_cps_times_multiplier

def create_profile(multiplier: float) -> trex.TRexProfilePcap:
    return trex.TRexProfilePcap(pcap_files=
                                join_pcaps_with_cps_times_multiplier(
                                    [
                                    ("https.pcap", 1500),
                                    ("https_web.pcap", 1800),
                                    ("https_info.pcap", 700),
                                    ("https_bbc.pcap",1800),
                                    ("https_info_user.pcap",1400),
                                    ],
                                    multiplier),
                                client_net="16.0.0.0/24",
                                server_net="48.0.0.0/16",
                                )

