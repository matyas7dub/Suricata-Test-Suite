#import lbr_trex_client.paths

from lbr_testsuite import trex
from .util_trex_profile import join_pcaps_with_cps_times_multiplier

def create_profile(multiplier: float) -> trex.TRexProfilePcap:
    return trex.TRexProfilePcap(pcap_files=
                                join_pcaps_with_cps_times_multiplier(
                                    [
                                    ("nfsv2.pcap", 40),
                                    ("nfsv3.pcap", 40),
                                    ("nfsv4.pcap", 40),
                                    ("nfs_simple.pcap", 25),
                                    ("nfs_50MB_file.pcap", 17),
                                    ("smbtorture_1.pcap", 25),
                                    ("smbtorture_2.pcap", 20),
                                    ("smbtorture_3.pcap", 25),
                                    ("smbtorture_4.pcap", 25),
                                    ("smbtorture_5.pcap", 25),
                                    ("smbtorture_6.pcap", 20)
                                    ],
                                    multiplier),
                                client_net="16.0.0.0/24",
                                server_net="48.0.0.0/16",
                                )

