# Security

This project is in early implementation and has no supported release. The [K01 profile](design/first-kernel.md) demonstrates original-kernel CPU boot in QEMU/OVMF; physical platforms remain unqualified.

Report a suspected vulnerability privately through GitHub's **Report a vulnerability** option in this repository's Security tab. Do not include credentials, private prompts, model state or exploitable details in public issues. General design questions without sensitive details can use Discussions.

Every implementation must preserve capability and tenant boundaries, registered-buffer lifetimes, authenticated membership, replay protection and placement-epoch fencing. Candidate software cannot modify its evaluator, promotion/signing or recovery authority. Bare-metal device testing must have a recoverable setup and declared DMA/storage authority.

Hardware tests are authorized for their stated profile. Installing or testing on a contributor's everyday device is a separate operational decision; the project does not require it for participation.
