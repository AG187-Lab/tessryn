# AWS bare-metal access for Tessryn

Research date: 2026-10-11. No AWS account was inspected, permission/quota query
executed, image created or resource rented. These are public source facts and
conditional laboratory recommendations, not supported Tessryn profiles.

## Recommended AWS laboratory

An ordinary AWS account can launch genuine EC2 bare-metal instances. Dedicated
Hosts and Dedicated Instances are separate tenancy products and do not by
themselves remove the hypervisor. For this lab, select an actual `.metal`
instance using On-Demand EC2, not a Dedicated Host allocation.
[AWS distinction](https://docs.aws.amazon.com/whitepapers/latest/logical-separation/host-and-instance-features.html).

The first AWS CPU candidate is **`c7i.metal-24xl` in `us-east-1`**: Intel
Sapphire Rapids, 96 vCPUs/48 physical cores, 192 GiB RAM and EBS-only storage.
It is cheaper than the compared `c6i.metal` and `m7i.metal-24xl` options. Start
with a bounded four-hour inventory/recovery trial only after its access gates
are resolved. It remains unqualified for original-kernel boot.
[Compute specifications](https://docs.aws.amazon.com/ec2/latest/instancetypes/co.html).

The later x86 GPU candidate remains **`g4dn.metal`**: 96 vCPUs, 384 GiB RAM
and eight NVIDIA T4 GPUs, each 16 GiB. No native GPU experiment is ready today.
The current accelerated-instance inventory and regional G/P `.metal` price
scan did not identify a newer x86 NVIDIA metal candidate. `g5g.metal` is ARM
Graviton2/T4g, outside the initial x86 target. A large virtual GPU instance
does not establish physical native access.
[Accelerated specifications](https://docs.aws.amazon.com/ec2/latest/instancetypes/ac.html).

| Candidate | USD/hour | Four compute hours | 24 compute hours |
| --- | ---: | ---: | ---: |
| c7i.metal-24xl | 4.284 | 17.136 | 102.816 |
| c6i.metal | 5.440 | 21.760 | 130.560 |
| m7i.metal-24xl | 4.8384 | 19.3536 | 116.1216 |
| g4dn.metal | 7.824 | 31.296 | 187.776 |

These are analytical multiplications of observed public **Linux On-Demand**
reference rates in N. Virginia, not all-in order quotes. They exclude EBS,
snapshots, public IPv4, transfer, tax and other services. Tessryn image billing
classification, regional capacity and exact instance boot support are unknown.
The [price observation](aws-metal-price-observation.json) records source,
publication/fetch time, selected rate codes and response hash. The full feed
was not retained. [AWS public price feed](https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/ec2/USD/current/ec2-ondemand-without-sec-sel/US%20East%20%28N.%20Virginia%29/Linux/index.json).

## What the account entails

1. Use a **Paid Plan** with full AWS features and explicit Region selection.
   The current Free Plan's EC2 list excludes the required metal/GPU types.
   For a new account, the signup choice labelled **advanced** allows explicit
   Region selection and direct account/service administration. A new project
   signup automatically creates managed identity/organization resources, but
   exposes a different feature set. Existing users should inspect their account
   setup rather than blindly activate advanced features: activation is
   irreversible and removes the new experience's spend limits.
   [Plan eligibility](https://aws.amazon.com/free/compute/),
   [signup comparison](https://docs.aws.amazon.com/accounts/latest/reference/sign-up-for-aws.html),
   [advanced activation](https://docs.aws.amazon.com/accounts/latest/reference/activate-advanced-features.html).
2. Protect the owner login with MFA and use a separate role/federated identity
   with temporary credentials for laboratory access. Provide read-only EC2
   metadata and Service Quotas access first; add narrowly scoped launch,
   serial-console and termination permissions when a concrete rental is approved.
   Credentials, account identifiers and private access details stay out of
   public evidence. [AWS identity guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html).
3. Obtain **96 available Standard On-Demand vCPUs** for one `c7i.metal-24xl` in
   the chosen Region. The published default is 5. A later `g4dn.metal` needs
   96 available **G/VT** vCPUs, whose published default is 0. Applied account
   values can differ; other running instances consume the quota. Requests can
   be denied/partially approved and do not reserve capacity.
   [Quota table](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-instance-quotas.html),
   [request behavior](https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html).
4. Inspect exact boot metadata, enable permitted serial-console access, and
   prepare a known-good Linux reference/recovery image. Rehearse recovery via
   the external EC2 control plane, including termination/relaunch if required.
   Configure an external rental deadline before launching; the test OS itself
   must not be the only component responsible for ending billing.
5. Obtain the final cost/access approval, launch a disposable On-Demand trial,
   retain sanitized evidence and terminate it at the deadline. Check residual
   EBS volumes, snapshots and IP allocations separately. Budget notifications
   can arrive after costs exceed the threshold; they are not a reliable rental
   deadline. [Budget timing](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html),
   [running-state billing](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-on-demand-instances.html).

The following commands are **proposed read-only preflight commands**, not
executed results. Run only in the intended authenticated lab profile; do not
publish identity or account-specific responses without review.

```sh
aws ec2 describe-instance-types --profile tessryn --region us-east-1 \
  --instance-types c7i.metal-24xl g4dn.metal \
  --query 'InstanceTypes[].{Type:InstanceType,Metal:BareMetal,Architecture:ProcessorInfo.SupportedArchitectures,Boot:SupportedBootModes,vCPUs:VCpuInfo.DefaultVCpus,ENA:NetworkInfo.EnaSupport}' \
  --output json
aws service-quotas get-service-quota --profile tessryn --region us-east-1 \
  --service-code ec2 --quota-code L-1216C47A
aws service-quotas get-service-quota --profile tessryn --region us-east-1 \
  --service-code ec2 --quota-code L-DB2E81BA
```

The quota commands return applied limits, not remaining capacity. They launch
nothing. [Boot metadata procedure](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-type-boot-mode.html),
[applied quota query](https://docs.aws.amazon.com/cli/latest/reference/service-quotas/get-service-quota.html).

## What AWS does and does not establish

Bare metal supplies direct host CPU execution, but Nitro controls management,
network/storage I/O and firmware protection. Its BMC PCI connection is
firewalled, and the main CPU cannot update firmware. Public EC2 documentation
does not provide customer IPMI/BMC, arbitrary ISO/PXE or firmware-menu access.
This is a limit on documented access, not a claim that every alternative
handoff mechanism is impossible.
[Nitro security design](https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/the-components-of-the-nitro-system.html).

AWS's generic Nitro UEFI/Legacy BIOS guarantee explicitly excludes bare metal.
That exclusion does not prove all metal is BIOS-only. Query the exact SKU's
`SupportedBootModes` before selecting a Tessryn boot target. Bare-metal UEFI
Secure Boot and persistent nonvolatile variables are explicitly unsupported.
[UEFI requirements](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instance-boot-mode.html),
[exact-type boot modes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-type-boot-mode.html).

Serial console support includes the recommended x86 metal types, subject to
account/IAM configuration, a running instance and an OS that implements the
serial interface. This is useful even if networking fails, but is not a
firmware graphical console. Screenshots exclude metal; managed root-volume
replacement excludes non-Mac metal. Recovery must be verified rather than
inferred from a working Linux SSH login.
[Serial prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console-prerequisites.html),
[screenshot limits](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshoot-unreachable-instance.html),
[root replacement](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/replace-root.html).

Booting original Tessryn requires a genuinely bootable image/loader, matching
boot mode and a prepared AMI/root snapshot; account access cannot manufacture
an absent kernel. VM Import's OS allowlist excludes Tessryn. Direct EBS snapshot
creation and AMI registration are separate documented paths, with custom-OS
compatibility still experimental. Native storage/networking would need NVMe
and ENA drivers; a minimal loader-loaded RAM kernel could first print and halt
without those drivers, proving only that measured boot/console behavior.
[AMI registration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-ami-boot-mode.html),
[VM Import prerequisites](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html),
[EBS direct API](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html),
[Nitro interfaces](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html).

The existing RAM-only, no-physical-disk-write session is not automatically
replaced by an EC2 AMI preparation workflow. No raw disk, firmware, AMI or
hardware-changing operation is authorized or performed by this research.
For the first physical cold UEFI boot under those constraints, a provider-
confirmed Hetzner KVM/virtual-media and RAM-rescue target remains a stronger
candidate. Console availability, UEFI media mounting and exact hardware must
still be confirmed. [Hetzner RAM rescue](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system/),
[KVM/UEFI virtual media](https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console/).

Decision: prepare AWS account access and free/read-only preflight first; defer
spending until the test has a useful payload and verified recovery. Keep QEMU
as the reproducible implementation loop. AWS is a separate conditional cloud
qualification target, and cannot replace the physical notebook gate.
