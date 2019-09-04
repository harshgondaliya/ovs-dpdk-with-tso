..
      Copyright 2018, Red Hat, Inc.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

===
TSO
===

**Note:** This feature is considered experimental.

TCP Segmentation Offload (TSO) is a mechanism which allows a TCP/IP stack to
offload the TCP segmentation into hardware, thus saving the cycles that would
be required to perform this same segmentation in software.

TCP Segmentation Offload (TSO) enables a network stack to delegate segmentation
of an oversized TCP segment to the underlying physical NIC. Offload of frame
segmentation achieves computational savings in the core, freeing up CPU cycles
for more useful work.

A common use case for TSO is when using virtualization, where traffic that's
coming in from a VM can offload the TCP segmentation, thus avoiding the
fragmentation in software. Additionally, if the traffic is headed to a VM
within the same host further optimization can be expected. As the traffic never
leaves the machine, no MTU needs to be accounted for, and thus no segmentation
and checksum calculations are required, which saves yet more cycles. Only when
the traffic actually leaves the host the segmentation needs to happen, in which
case it will be performed by the egress NIC.

When using TSO with DPDK, the implementation relies on the multi-segment mbufs
feature, described in :doc:`/topics/dpdk/jumbo-frames`, where each mbuf
contains ~2KiB of the entire packet's data and is linked to the next mbuf that
contains the next portion of data.

Enabling TSO
~~~~~~~~~~~~
.. Important::

    Once multi-segment mbufs is enabled, TSO will be enabled by default, if
    there's support for it in the underlying physical NICs attached to
    OvS-DPDK.

When using :doc:`vHost User ports <vhost-user>`, TSO may be enabled in one of
two ways, as follows.

`TSO` is enabled in OvS by the DPDK vHost User backend; when a new guest
connection is established, `TSO` is thus advertised to the guest as an
available feature:

1. QEMU Command Line Parameter::

    $ sudo $QEMU_DIR/x86_64-softmmu/qemu-system-x86_64 \
    ...
    -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,\
    csum=on,guest_csum=on,guest_tso4=on,guest_tso6=on\
    ...

2. Ethtool. Assuming that the guest's OS also supports `TSO`, ethtool can be used to enable same::

    $ ethtool -K eth0 sg on     # scatter-gather is a prerequisite for TSO
    $ ethtool -K eth0 tso on
    $ ethtool -k eth0

To enable TSO in a guest, the underlying NIC must first support `TSO` - consult
your controller's datasheet for compatibility. Secondly, the NIC must have an
associated DPDK Poll Mode Driver (PMD) which supports `TSO`.

~~~~~~~~~~~
Limitations
~~~~~~~~~~~
The current OvS `TSO` implementation supports flat and VLAN networks only (i.e.
no support for `TSO` over tunneled connection [VxLAN, GRE, IPinIP, etc.]).

Also, as TSO is built on top of multi-segments mbufs, the constraints pointed
out in :doc:`/topics/dpdk/jumbo-frames` also apply for TSO. Thus, some
performance hits might be noticed when running specific functionality, like
the Userspace Connection tracker. And as mentioned in the same section, it is
paramount that a packet's headers is contained within the first mbuf (~2KiB in
size).
