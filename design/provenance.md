# Provenance and artifact policy

New Tessryn code and documentation use Apache-2.0. This repository contains original design documentation, planning data and development tooling, not imported kernel, driver or inference code. G01's candidate/source records are attributed research summaries; its inventory collector is original code. No provider implementation, firmware or proprietary compiler is redistributed by that packet.

Before introducing a dependency or artifact, record its source URL, revision/hash, license, modified files, notices, build/runtime role and distribution requirements. Keep notices and applicable licenses with that component. Papers and source links are research evidence; a reference does not grant permission to relicense implementation code.

GPU firmware, proprietary libraries, model weights, tokenizers and datasets have independent terms. Do not represent them as covered by this repository's license. Prefer fetching externally supplied artifacts through explicit, reproducible manifests rather than committing binary blobs without their provenance.

G01 records the acquisition route, exact version/target requirements and
applicable terms for intended artifacts before selecting an engineering
profile. It does not require acquiring a compiler/firmware binary or proving
native initialization. If an artifact is acquired, its hash, notices and
applicable acquisition/distribution rights become part of the record before
use or publication. Research source links and Linux component compatibility
requirements do not establish a native firmware protocol or grant broader
redistribution rights.

Every published support result identifies the deployed kernel, hardware/firmware, compiler, binary target, model/checkpoint, quantization/state formats and measurement setup. External measurements remain attributed and distinct from Tessryn measurements.
