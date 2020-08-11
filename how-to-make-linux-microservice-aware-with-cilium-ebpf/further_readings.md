## Table of Contents

From: https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst



- [Further Reading](https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst#toc0)
- [Related Material](https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst#toc1)
- [Presentations](https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst#toc2)
- [Podcasts](https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst#toc3)
- [Community blog posts](https://github.com/cilium/cilium/blob/89b622cf4e0a960e27e5b1bf9f139abee25dfea0/FURTHER_READINGS.rst#toc4)



# Further Reading



## Related Material

- [BPF for security—and chaos—in Kubernetes](https://lwn.net/Articles/790684/)
- [k8s-snowflake: Configs and scripts for bootstrapping an opinionated Kubernetes cluster anywhere using Cilium plugin](https://github.com/jessfraz/k8s-snowflake)
- [Using Cilium for NetworkPolicy: Kubernetes documentation on how to use Cilium to implement NetworkPolicy](https://kubernetes.io/docs/tasks/administer-cluster/cilium-network-policy/)



## Presentations

- Fosdem, Brussels, 2020 - BPF as a revolutionary technology for the container landscape: [Slides](https://docs.google.com/presentation/d/1VOUcoIxgM_c6M_zAV1dLlRCjyYCMdR3tJv6CEdfLMh8/edit#slide=id.g7055f48ba8_0_0), [Video](https://fosdem.org/2020/schedule/event/containers_bpf/)
- KubeCon, North America 2019 - Liberating Kubernetes from kube-proxy and iptables: [Slides](https://docs.google.com/presentation/d/1cZJ-pcwB9WG88wzhDm2jxQY4Sh8adYg0-N3qWQ8593I/edit#slide=id.g7055f48ba8_0_0), [Video](https://www.youtube.com/watch?v=bIRwSIwNHC0)
- KubeCon, Europe 2019 - Using eBPF to Bring Kubernetes-Aware Security to the Linux Kernel: [Video](https://www.youtube.com/watch?v=7PXQB-1U380)
- KubeCon, Europe 2019 - Transparent Chaos Testing with Envoy , Cilium and BPF: [Slides](https://static.sched.com/hosted_files/kccnceu19/54/Chaos Testing with Envoy%2C Cilium and eBPF.pdf), [Video](https://www.youtube.com/watch?v=gPvl2NDIWzY)
- All Systems Go!, Berlin, Sept 2018 - Cilium - Bringing the BPF Revolution to Kubernetes Networking and Security [Slides](https://www.slideshare.net/ThomasGraf5/cilium-bringing-the-bpf-revolution-to-kubernetes-networking-and-security), [Video](https://www.youtube.com/watch?v=QmmId1QEE5k)
- QCon, San Francisco 2018 - How to Make Linux Microservice-Aware with Cilium and eBPF: [Slides](https://www.slideshare.net/InfoQ/how-to-make-linux-microserviceaware-with-cilium-and-ebpf), [Video](https://www.youtube.com/watch?v=_Iq1xxNZOAo)
- KubeCon, North America 2018 - Connecting Kubernetes Clusters Across Cloud Providers: [Slides](https://static.sched.com/hosted_files/kccna18/68/Connecting Multiple Kubernetes Clusters Across Cloud Providers.pdf), [Video](https://www.youtube.com/watch?v=U34lQ8KbQow)
- KubeCon, North America 2018 - Implementing Least Privilege Security and Networking with BPF on Kubernetes: [Slides](https://www.slideshare.net/ThomasGraf5/accelerating-envoy-and-istio-with-cilium-and-the-linux-kernel), [Video](https://www.youtube.com/watch?v=3F_XNbhjgxY)
- KubeCon, Europe 2018 - Accelerating Envoy with the Linux Kernel: [Video](https://www.youtube.com/watch?v=ER9eIXL2_14)
- Open Source Summit, North America - Cilium: Networking and security for containers with BPF and XDP: [Video](https://www.youtube.com/watch?v=CcGtDMm1SJA)
- DockerCon, Austin TX, Apr 2017 - Cilium - Network and Application Security with BPF and XDP: [Slides](https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp), [Video](https://www.youtube.com/watch?v=ilKlmTDdFgk)
- CNCF/KubeCon Meetup, Berlin, Mar 2017 - Linux Native, HTTP Aware Network Security: [Slides](https://www.slideshare.net/ThomasGraf5/linux-native-http-aware-network-security), [Video](https://www.youtube.com/watch?v=Yf_INdTWIHI)
- Docker Distributed Systems Summit, Berlin, Oct 2016: [Slides](http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823), [Video](https://www.youtube.com/watch?v=TnJF7ht3ZYc&list=PLkA60AVN3hh8oPas3cq2VA9xB7WazcIgs&index=7)
- NetDev1.2, Tokyo, Sep 2016 - cls_bpf/eBPF updates since netdev 1.1: [Slides](http://borkmann.ch/talks/2016_tcws.pdf), [Video](https://youtu.be/gwzaKXWIelc?t=12m55s)
- NetDev1.2, Tokyo, Sep 2016 - Advanced programmability and recent updates with tc’s cls_bpf: [Slides](http://borkmann.ch/talks/2016_netdev2.pdf), [Video](https://www.youtube.com/watch?v=GwT9hRiqdUo)
- ContainerCon NA, Toronto, Aug 2016 - Fast IPv6 container networking with BPF & XDP: [Slides](http://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp)



## Podcasts

- Software Gone Wild by Ivan Pepelnjak, Oct 2016: [Blog](http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html), [MP3](http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3)
- OVS Orbit by Ben Pfaff, May 2016: [Blog](https://ovsorbit.benpfaff.org/#e4), [MP3](https://ovsorbit.benpfaff.org/episode-4.mp3)



## Community blog posts

- [Cilium for Network and Application Security with BPF and XDP, Apr 2017](https://blog.scottlowe.org/2017/04/18/black-belt-cilium/)
- [Cilium, BPF and XDP, Google Open Source Blog, Nov 2016](https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html)