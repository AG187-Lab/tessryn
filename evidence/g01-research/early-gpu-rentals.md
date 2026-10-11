# Inexpensive early GPU bare-metal laboratories

Research date: 2026-10-11. Public catalogs and anonymous price previews only;
no account login, provider message, order, payment or hardware action. These
original summaries do not establish stock, a contract or Tessryn compatibility.
Rental, physical inventory, native boot, GPU execution and performance sample
counts remain zero. AWS qualification is deferred while cheaper laboratories
are investigated. No advertised supported profile or device target is frozen.

## Shortlist and analytical costs

| Candidate | Observed whole-server rate | First 24-hour arithmetic | Limits |
| --- | --- | --- | --- |
| GPU Mart Professional RTX 2060 dedicated | USD 0.2200/hour after discount; USD 0 setup | USD 5.28 | Account minimum, stock, exact boot access and conflicting billing FAQ unresolved |
| Hetzner auction 3084066, RTX 4000 SFF Ada | EUR 0.3761/hour; EUR 234.70 monthly cap; no setup | EUR 9.0264 server | VAT and scheduled console extra; ephemeral offer |
| Cherry EPYC 7443P plus A2, Lithuania | USD 0.577/hour; USD 35.10 setup | USD 48.948 including setup | Live preview conflicts with generic setup documentation; tax/initial balance unknown |
| GTHost Toronto T4 | USD 15/day in live daily inventory | USD 15 | Exact ISO/UEFI/RAM-only access and final order terms unverified |

These are conditional observations, not guaranteed all-in prices. Currencies
are not converted. The servers have different single GPUs; this is not a
performance comparison with AWS's eight-T4 node. Re-check exact offers before
booking. Keeping the same Cherry allocation costs USD 13.848 per further 24
hours; destroying and reordering may incur setup again.

## Cheapest credible priced candidate: GPU Mart

The fully loaded [anonymous preview](https://console.databasemart.com/check/gpu_rtx2060_01/de5d23cd630a47c38fc5b3ff6583f914?billingType=1_1)
displayed a dedicated RTX 2060 **6 GB**, two eight-core E5-2660 CPUs, 128 GB
RAM, 120 GB plus 960 GB SSD, 100 Mbps unmetered and one IPv4 in the USA.
On-Demand was selected. The summary showed USD 0.277/hour minus USD 0.057,
actual price USD 0.2200/hour, and zero setup. Delivery was two hours if stocked;
completing an order required login. No personal fields were filled.

The [hourly page](https://www.gpu-mart.com/pricing-hourly) contains a conflicting
12 GB table entry; the preview identifies 6 GB. The parent
[billing FAQ](https://www.databasemart.com/faq/billing-questions) still states a
monthly minimum. Retain that conflict despite the more specific hourly preview.
Minimum deposit/credit, rounding, promotion duration and actual availability
remain unknown. Hourly documentation requires destruction to end billing.

The [dedicated catalog](https://www.gpu-mart.com/gpu-dedicated-server) includes
IPMI. The [technical FAQ](https://www.databasemart.com/faq/technical-questions)
permits a custom ISO and BIOS configuration through dedicated-server IPMI,
with access requiring local-IP allowlisting. Verify those entitlements on the
exact hourly machine, usable console software, 64-bit UEFI, remote media,
independent power/reset recovery and permission for a RAM-only image. A
custom-ISO installer is not authority to write disks in this session.

Decision: GPU Mart is the cheapest credible short-term NVIDIA metal offer
found in this search, conditional on these access and commercial gates. It is
not proven globally cheapest, available to this account or Tessryn-compatible.

## Stronger documented RAM-rescue fallback: Hetzner auction

The live [GPU auction filter](https://www.hetzner.com/sb/?additional=GPU) showed
offer 3084066 in FSN1-DC10: i5-13500, 64 GB DDR4 and two 1.92 TB U.2 NVMe
drives. NVIDIA specifies the [Ada card](https://www.nvidia.com/en-us/products/workstations/rtx-4000-sff/)
with 20 GB ECC GDDR6. This public offer identity is not a booking identifier.
[Auction terms](https://docs.hetzner.com/robot/general/server-auction-faqs/)
provide a whole server, no setup and rescue delivery; new-customer review can
extend delivery beyond one business day. Stock/prices can change immediately.

[Rescue](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system/)
runs in RAM without touching drives. [KVM](https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console/)
supports virtual ISO media subject to scheduling, console availability and
successful mounting. Its older free-first-three-hours statement conflicts with
the [October 7 addon table](https://docs.hetzner.com/de/robot/dedicated-server/dedicated-server-hardware/price-server-addons/),
which lists EUR 10 per three-hour console attachment, including 19% VAT,
charged each time. Confirm the fee; do not promise free console access.
[Cancellation](https://docs.hetzner.com/general/billing-and-account-management/cancellation/cancellations-robot/)
ends the rental; shutdown alone does not. Exact UEFI/IOMMU/GPU recovery remain
unqualified. This is a fallback if GPU Mart's access gates fail.

## Other prices and exclusions

The [Cherry preview](https://portal.cherryservers.com/deployment?plan=732&components=36219,37797&show_hardware=1)
showed EPYC 7443P, 64 GB ECC, two 250 GB NVMe drives and A2 16 GB with IP KVM
self-install selected. Reopening defaults to Monthly: select Hourly. The USD
0.338 base plus USD 0.239 GPU and USD 35.10 setup differ from marketing starting
prices and [generic custom-server fees](https://www.cherryservers.com/knowledge/docs/compute/dedicated-servers/custom-servers).
Its [console documentation](https://www.cherryservers.com/knowledge/docs/compute/configuration-management/out-of-band-management-console)
provides firmware-stage access and ISO mounting. Deployment can take 24–72
hours. Final fee, available GPU and RAM-only access need confirmation.

[GTHost daily inventory](https://gthost.com/gpu-dedicated-servers?currency=usd&billing_term=daily&page=1)
showed T4 16 GB at USD 15/day; cheaper P4 was USD 8/day. Its generic USD 5/day
trial is not a verified GPU offer. [IPMI](https://gthost.com/bare-metal-servers)
is advertised, but exact GPU virtual-media access is unconfirmed.

Hetzner's new [GEX45](https://www.hetzner.com/dedicated-rootserver/gex45/)
displayed EUR 0.3429/hour plus EUR 209 setup: EUR 217.2296 for one day before
tax/console, so its low recurring price is misleading for a fresh short trial.
[Scaleway PAR2](https://www.scaleway.com/en/pricing/elastic-metal/?zone=fr-par-2)
listed two L40S at EUR 4.11/hour, EUR 98.64/day before extras.

Cheap Pascal GTX 1080/P4 and older cards do not match the Turing-or-newer
architecture boundary of the existing [NVIDIA reference](https://github.com/NVIDIA/open-gpu-kernel-modules/blob/2b436058a616676ec888ef3814d1db6b2220f2eb/README.md).
They would add a separate GPU target. That reference still depends on Linux
and matching firmware; newer hardware alone supplies no Tessryn driver.

[TensorDock](https://www.tensordock.com/host.html) supplies VMs;
[RunPod Pods](https://docs.runpod.io/pods/overview) supplies containers;
[Vast](https://docs.vast.ai/guides/instances/virtual-machines) documents VMs.
The cheap [Edgevana RTX 3060](https://nodes.edgevana.com/gpu-servers/rtx-3060)
offer is labelled Cloud GPU, with no exact-SKU physical boot authority found.
These prices cannot qualify an original physical OS boot laboratory.

Keep QEMU as the implementation loop. Rent only for a defined inventory/recovery
experiment or, later, a reproducibly bootable original image with serial output
and bounded tests. Do not install, flash firmware or write physical disks.
