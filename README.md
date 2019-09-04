## OvS-DPDK with TSO (TCP Segmentation Offload) feature
This repository consists of the patched version of OvS to enable TSO (TCP Segmentation Offload) feature. Moreover, [wiki](https://github.com/harshgondaliya/ovs-dpdk-with-tso/wiki) of this repository provides a step by step guide for beginners to experiment Inter-VM Communication using OvS-DPDK.

The repository provides an already patched version of OvS code. Patches were applied on top of [adb3f0b ("python: Avoid flake8 warning for unused variables.")](https://github.com/openvswitch/ovs/commits?author=blp&since=2019-01-01&until=2019-01-23) commit. Further, [DPDK stable version 18.11.2](https://core.dpdk.org/download/) is used to have the user-space datapath.  

**Note (as per the status quo on 15/05/2019)**: As communicated in a [thread](https://mail.openvswitch.org/pipermail/ovs-discuss/2019-May/048671.html) at OvS mailing list, TSO is not supported currently in OvS-DPDK. TSO essentially requires the 
enablement of multi segment mbuf in OVS as well as TSO enablement. There were patches proposed previously to enable both of these but they have not made it upstream to date due to concerns around their impact for non TSO usecases as well as some of the fundamental changes introduced with respect to the mbuf itself.

**Credit:** Ian Stokes (Intel) through his [reply at mailing list](https://mail.openvswitch.org/pipermail/ovs-discuss/2019-May/048671.html) provided apt pointers to patches, cover letters and documentation to enable TSO feature for OvS-DPDK. Aim of this repository and its [wiki](https://github.com/harshgondaliya/ovs-dpdk-with-tso/wiki) is to give more low-level guidelines to enable TSO feature in OvS-DPDK. It will be helpful for users who are just getting started with OvS-DPDK.
