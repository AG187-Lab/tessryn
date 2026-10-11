# G01 rental source notes

Research date: 2026-10-11. These are original research notes based on public
provider documentation and a read-only public catalog fetch. No cloud account
was queried, resource rented, device probed, firmware fetched or physical drive
written. Catalog identities are research candidates, not qualified Tessryn
profiles. No provider page, firmware or third-party implementation is vendored.

## Conditional CPU laboratory candidate

[Scaleway's public Elastic Metal catalog](https://www.scaleway.com/en/pricing/elastic-metal/)
lists EM-A610R-NVMe: AMD Ryzen PRO 3600, six cores/twelve threads, DDR4 ECC,
two NVMe drives and a 500 Mbps public link. The embedded catalog records
34,359,738,368 RAM bytes (32 GiB) and 1,024,209,543,168 bytes per drive. Its
hourly offer ID is `e1680dec-52aa-4cbc-b70c-ef32d863fdb0`; `fr-par-1` lists
normal/rescue boot and a custom-install image through remote access. These
public identifiers contain no account or machine identity.

The catalog does not supply motherboard/BMC identity, UEFI mode/version, NIC
PCI identity, storage-controller identity/firmware, PCI bridge layout,
IOMMU/IVRS exposure, ACS/reset groups or an APIC/MSI-X inventory. No NVIDIA
GPU is listed. These facts must be collected from the exact delivered machine
before selecting a native device target.

## Unresolved rental quote

The same pricing page, fetched on 2026-10-11 at 18:54:43 UTC, advertised
EUR 0.11/hour and EUR 39.99/month before tax. A later same-day fetch still
displayed a no-setup-fee banner and generic hourly-no-commitment language.
Its candidate catalog has hourly/monthly price fields but no setup-fee field;
an absent field does not establish a zero fee.

However, the [October 2026 Elastic Metal changelog](https://www.scaleway.com/en/docs/elastic-metal/)
states that the EM-A610R promotional setup/commitment-fee waiver has ended and
that the standard fee applies to all new subscriptions. The changelog does not
state a fee amount or separate hourly from monthly subscriptions. This conflicts
with the observed pricing page and prevents a reliable purchase budget.

An unauthenticated, read-only request to
`https://api.scaleway.com/baremetal/v1/zones/fr-par-1/offers?per_page=100`
returned HTTP 401. No credential lookup or authenticated request followed.
Public evidence did not resolve the actual offer's setup fee. Confirm the
complete hourly checkout quote or obtain provider clarification before rental.

The fee-free arithmetic is 24 times EUR 0.11 = EUR 2.64, plus an optional
24 times EUR 0.005 flexible IPv4 = EUR 0.12. EUR 2.76 is an analytical
scenario, not a verified payable total. If a EUR 39.99 fee were quoted, that
scenario would become EUR 42.75 before tax. This assumed fee is not a verified
fee or an upper bound. Optional services, rounding, provisioning time, taxes
and actual availability also require confirmation.

[Scaleway's billing FAQ](https://www.scaleway.com/en/docs/billing/faq/)
states that Elastic Metal billing begins at creation and ends at deletion;
powering off keeps the machine allocated and billed. Flexible-IP billing ends
when its reservation is cancelled. Any eventual rental needs an explicit
resource-deletion and billing-confirmation step after evidence is retained.

## Disk-free access and recovery prerequisites

The [ordering guide](https://www.scaleway.com/en/docs/elastic-metal/quickstart/)
offers a No Image selection. The [rescue guide](https://www.scaleway.com/en/docs/elastic-metal/how-to/use-rescue-mode/)
describes Ubuntu rescue running entirely in RAM, while listing an installed
server among its prerequisites. Therefore a No Image to RAM-rescue route is
unverified. An operator must establish that route before a session that forbids
physical-drive writes; installing a provider OS would not satisfy that constraint.

The [remote-access guide](https://www.scaleway.com/en/docs/elastic-metal/how-to/activate-remote-access/)
describes optional KVM-over-IP and remote ISO use on compatible servers. It
requires an IPv4 allowlist and temporary access credentials. This operational
scope is narrower than the pricing page's all-servers/free description. The
exact delivered offer must expose the capability and its charge must be checked.
Arbitrary iPXE control, UEFI boot configuration and a working recovery attempt
are not established by these documents.

An initial session could collect a read-only Linux reference inventory and run
QEMU using RAM files with no physical drives attached. Linux reference results
and emulator results must remain separate evidence. No Tessryn kernel exists
to perform a native boot test in this record. Firmware updates, disk installs,
partitioning, filesystem mounts and swap on physical drives are excluded.

## Alternative provider evidence

[Hetzner Server Auction](https://www.hetzner.com/sb/)
documents delivery in rescue, full root access, web reset and no setup fees.
No exact auction offer or current price was selected; inventory changes.
Its [rescue documentation](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system/)
describes a Debian environment booted by PXE into memory without touching drives.
The [KVM documentation](https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console/)
requests advance scheduling and describes virtual ISO media. Its older free
three-hour statement conflicts with the [October 7 addon table](https://docs.hetzner.com/de/robot/dedicated-server/dedicated-server-hardware/price-server-addons/),
which lists EUR 10 per three-hour attachment including 19% VAT, charged each
time. Confirm the fee. Availability and successful mounting are conditional.
The later [GPU rental research](early-gpu-rentals.md) records an ephemeral Ada
auction offer. Neither record selects supported hardware or guarantees a quote.
