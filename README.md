# OvS-DPDK with TSO
This repository consists of the patched version of OvS to enable TSO (TCP Segmentation Offload) feature. Moreover, wiki of this repository provides a step by step guide for beginners to experiment Inter-VM Communication using OvS-DPDK.

**Note (as per the status quo on 04/09/2019)**: As communicated in a [thread](https://mail.openvswitch.org/pipermail/ovs-discuss/2019-May/048671.html) at OvS mailing list, TSO is not supported currently in OvS-DPDK. TSO essentially requires the 
enablement of multi segment mbuf in OVS as well as TSO enablement. There were patches proposed previously to enable both of these but they have not made it upstream to date due to concerns around their impact for non TSO usecases as well as some of the fundamental changes introduced with respect to the mbuf itself.
