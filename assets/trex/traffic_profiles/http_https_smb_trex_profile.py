# import lbr_trex_client.paths

from lbr_testsuite import trex
from .util_trex_profile import join_pcaps_with_cps_times_multiplier


def create_profile(multiplier: float) -> trex.TRexProfilePcap:
    return trex.TRexProfilePcap(
        pcap_files=join_pcaps_with_cps_times_multiplier(
            [
                ("dark_reader.pcap", 120),
                ("genericEBay_730P_1069B_3.pcap", 80),
                ("cisco.pcap", 80),
                ("kerberos.pcap", 120),
                ("jpg_download.pcap", 120),
                ("google_maps.pcap", 120),
                ("youtube.pcap", 80),
                ("netflix.pcap", 50),
                ("reddit.pcap", 60),
                ("my_liftor.pcap", 70),
                ("smbtorture_1.pcap", 50),
                ("smbtorture_4.pcap", 100),
            ],
            multiplier,
        ),
        client_net="16.0.0.0/24",
        server_net="48.0.0.0/16",
    )
