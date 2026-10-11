# Provenance and artifact policy

New Tessryn code and documentation use Apache-2.0. This repository contains original kernel/assembly and host-tooling source, design documentation and planning data. The [G03](build-and-evaluation.md) and [K01](first-kernel.md) profiles declare checksum-pinned third-party compiler, core-library, emulator and firmware dependencies. Downloaded artifacts stay in ignored build directories, and kernel bundles preserve the linked Rust components' redistribution notices. Native drivers and inference remain unimplemented.

Before introducing a dependency or artifact, record its source URL, revision/hash, license, modified files, notices, build/runtime role and distribution requirements. Keep notices and applicable licenses with that component. Papers and source links are research evidence; a reference does not grant permission to relicense implementation code.

GPU firmware, proprietary libraries, model weights, tokenizers and datasets have independent terms. Do not represent them as covered by this repository's license. Prefer fetching externally supplied artifacts through explicit, reproducible manifests rather than committing binary blobs without their provenance.

Every published support result identifies the deployed kernel, hardware/firmware, compiler, binary target, model/checkpoint, quantization/state formats and measurement setup. External measurements remain attributed and distinct from Tessryn measurements.
