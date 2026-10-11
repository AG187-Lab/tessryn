"""Reject RAM-size-only claims and exercise synthetic runtime/GOP paging edges."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.build_kernel import HIGH_PROFILES, high_case_flags
from tools import run_kernel_high as runner
from tools import verify_kernel_high as verifier


class HighAddressEvidenceTests(unittest.TestCase):
    def transcript(self, name="handoff-normal"):
        row = HIGH_PROFILES[name]
        image = 0x10000000 if row["low_image"] else 0x140000000
        stack = 0x1A0000000 if row["high_handoff"] else 0x70000000
        allocation = stack + 0x40000
        scratch = 0x1B0000000 if row["high_handoff"] else 0x100000
        lines = ["TESSRYN_K01_ENTRY",
                 f"TESSRYN_K01_LIVE_RANGES image_start={image:#x} image_end={image+0x100000:#x} stack_start={stack:#x} stack_end={stack+0x20000:#x} map_start={allocation:#x} map_end={allocation+0x10000:#x} scratch={scratch:#x} runtime_high=0 gop_start=0x80000000 gop_end=0x81000000",
                 f"TESSRYN_K01_PAGING_READY cr3={image+0x20000:#x} tables=8 leaves=2050 physical_bits=40 guard={runner.GUARD_ADDRESS:#x} free_scope=low-conventional",
                 "TESSRYN_K01_RESET_POINTER address=0x7f600000 method=uefi-runtime",
                 "TESSRYN_K01_MEMORY_MAP_VALID descriptors=104 stride=48 free_pages=510000 attempt=1",
                 "TESSRYN_K01_EXIT_BOOT_SERVICES_OK",
                 f"TESSRYN_K01_CPU_OWNED cr3={image+0x20000:#x} rsp={stack+0x1ff00:#x} rip={image+0x2000:#x} gdt=owned idt=owned tss=owned",
                 f"TESSRYN_K01_MEMORY_OWNERSHIP_OK scratch={scratch:#x} free_pages=510000 loader=reserved runtime=reserved firmware=quarantined"]
        if row["high_handoff"]:
            lines.append(f"TESSRYN_K01_HIGH_OWNERSHIP_OK scratch={scratch:#x} pattern=0x5445535352594e01")
        case = row["case"]
        if case in ("int3", "page_fault"):
            lines.append(f"TESSRYN_K01_EXCEPTION vector={3 if case=='int3' else 14} error=0x0 rip={image+0x3000:#x} cs=0x8 rflags=0x10002 rsp={stack+0x1ff00:#x} cr2={0 if case=='int3' else runner.GUARD_ADDRESS:#x}")
        if case == "int3":
            lines.append("TESSRYN_K01_INT3_RECOVERED fp_state=preserved")
        if case == "page_fault":
            lines.append("TESSRYN_K01_EXPECTED_FAULT")
        elif case == "reboot":
            lines.append("TESSRYN_K01_REBOOT_REQUEST method=uefi-runtime-cold-reset")
        else:
            lines.append("TESSRYN_K01_PASS")
        return ("\n".join(lines)+"\n").encode()

    def checked(self, name, data):
        reboot = HIGH_PROFILES[name]["case"] == "reboot"
        return runner.check_high_transcript(name, data, 0 if reboot else 33, b"CPU Reset (CPU 0)" if reboot else b"")

    def test_all_declared_profiles_require_actual_address_metadata(self):
        for name in HIGH_PROFILES:
            with self.subTest(name=name):
                result = self.checked(name, self.transcript(name))
                self.assertEqual(result["guard"], runner.GUARD_ADDRESS)
                self.assertEqual(result["runtime_high"], 0)  # Fixture makes no high firmware claim.

    def test_ram_size_cannot_substitute_for_high_live_image(self):
        with self.assertRaisesRegex(ValueError, "actual live image"):
            self.checked("image-normal", self.transcript("ram-only"))

    def test_high_handoff_requires_real_high_stack_map_and_scratch(self):
        data = self.transcript()
        for old, new in ((b"stack_start=0x1a0000000", b"stack_start=0x100000"),
                         (b"map_start=0x1a0040000", b"map_start=0x200000"),
                         (b"scratch=0x1b0000000", b"scratch=0x300000")):
            with self.subTest(field=old), self.assertRaises(ValueError):
                self.checked("handoff-normal", data.replace(old,new))

    def test_post_cr3_execution_and_readback_bind_the_admitted_ranges(self):
        data = self.transcript()
        for old, new in ((b"cr3=0x140020000", b"cr3=0x123000"),
                         (b"rip=0x140002000", b"rip=0x100002000"),
                         (b"rsp=0x1a001ff00", b"rsp=0x7001ff00"),
                         (b"pattern=0x5445535352594e01", b"pattern=0"),
                         (b"TESSRYN_K01_HIGH_OWNERSHIP_OK", b"missing")):
            with self.subTest(field=old), self.assertRaises(ValueError):
                self.checked("handoff-normal", data.replace(old,new))

    def test_canonical_guard_and_actual_exception_location_required(self):
        data = self.transcript("image-page_fault")
        for old, new in ((f"cr2={runner.GUARD_ADDRESS:#x}".encode(), b"cr2=0x100000000"),
                         (b"rip=0x140003000", b"rip=0x123000"), (b"vector=14", b"vector=140")):
            with self.subTest(field=old), self.assertRaises(ValueError):
                self.checked("image-page_fault", data.replace(old,new))

    def test_duplicate_malformed_ranges_or_invalid_paging_budget_rejected(self):
        data = self.transcript()
        live = next(line for line in data.splitlines() if line.startswith(b"TESSRYN_K01_LIVE_RANGES"))
        for modified in (data+live+b"\n", data.replace(b"runtime_high=0",b"runtime_high=-1"),
                         data.replace(b"image_end=0x140100000", b"image_end=0x140000000"),
                         data.replace(b"tables=8", b"tables=129"), data.replace(b"leaves=2050",b"leaves=16385")):
            with self.subTest(data=modified), self.assertRaises(ValueError):
                self.checked("handoff-normal", modified)

    def test_reset_must_be_controlled_and_exception_must_recover(self):
        with self.assertRaises(ValueError):
            runner.check_high_transcript("image-reboot",self.transcript("image-reboot"),0,b"CPU Reset\nTriple fault\n")
        with self.assertRaises(ValueError):
            self.checked("image-int3",self.transcript("image-int3").replace(b"fp_state=preserved",b"fp_state=lost"))

    def test_firmware_retry_uses_final_admission_and_requires_retry_witness(self):
        data=self.transcript()
        start=data.index(b'TESSRYN_K01_LIVE_RANGES')
        end=data.index(b'TESSRYN_K01_EXIT_BOOT_SERVICES_OK')
        retry=data[:end]+b'TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY\n'+data[start:].replace(b'attempt=1',b'attempt=2')
        self.assertEqual(self.checked('handoff-normal',retry)['exit_attempts'],2)
        for modified in (retry.replace(b'TESSRYN_K01_EXIT_BOOT_SERVICES_RETRY',b'missing'),
                         retry.replace(b'attempt=2',b'attempt=3')):
            with self.assertRaises(ValueError):
                self.checked('handoff-normal',modified)

    def test_guest_only_high_profile_and_isolated_control_flags(self):
        for name in HIGH_PROFILES:
            command=runner.qemu_command(name)
            self.assertEqual(command[command.index("-m")+1],"8G")
            self.assertIn("if=ide,format=raw,media=disk,file=boot.img",command)
            self.assertIn("-nic",command)
            self.assertNotIn("-fsdev",command)
            self.assertFalse(any("/dev/" in item for item in command))
            flags,extra=high_case_flags(name)
            self.assertEqual("k01_high_handoff" in flags,HIGH_PROFILES[name]["high_handoff"])
            self.assertEqual(bool(extra),HIGH_PROFILES[name]["low_image"])

    def test_retained_result_rechecks_hashes_addresses_command_and_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);mp=directory/'manifest.json';mp.write_text('{}\n')
            data=self.transcript();(directory/'stdout.log').write_bytes(data);(directory/'stderr.log').write_bytes(b'')
            setup={"firmware":{},"verified_tools":{"qemu":{"sha256":"pinned-qemu"}}}
            result={"schema_version":1,"format":"tessryn-k01-high-result","variant":"handoff-normal","case":"normal",
                    "status":"pass","reason":runner.PASS_REASON,"manifest_sha256":hashlib.sha256(mp.read_bytes()).hexdigest(),
                    "scope":runner.RESULT_SCOPE,
                    "evaluator_sha256":runner.evaluator_hash(),"emulator_sha256":"pinned-qemu","firmware":{},
                    "observed_live_addresses":self.checked("handoff-normal",data),
                    "execution":{"command":runner.qemu_command("handoff-normal"),"memory_bytes":runner.MEMORY_BYTES,
                                 "timeout_seconds":30,"elapsed_seconds":2,"max_log_bytes":262144,"returncode":33},
                    "logs":[{"path":name,"sha256":hashlib.sha256(content).hexdigest(),"size_bytes":len(content)}
                            for name,content in (("stdout.log",data),("stderr.log",b''))]}
            rp=directory/'result.json';rp.write_text(json.dumps(result));manifest={"toolchain":{"setup":setup}}
            self.assertEqual(verifier.validate_result(rp,mp,manifest)["status"],"pass")
            mutations=(("evaluator_sha256","wrong"),("observed_live_addresses",{}),("status","fail"),("scope","native AWS qualified"))
            for key,value in mutations:
                modified=copy.deepcopy(result);modified[key]=value;rp.write_text(json.dumps(modified))
                with self.subTest(field=key),self.assertRaises(ValueError):
                    verifier.validate_result(rp,mp,manifest)
            for key,value in (("memory_bytes",256<<20),("elapsed_seconds",float('inf')),("command",["qemu-system-x86_64"]),("returncode",0)):
                modified=copy.deepcopy(result);modified['execution'][key]=value;rp.write_text(json.dumps(modified))
                with self.subTest(field=key),self.assertRaises(ValueError):
                    verifier.validate_result(rp,mp,manifest)
            rp.write_text(json.dumps(result));(directory/'stdout.log').write_bytes(data+b'changed')
            with self.assertRaisesRegex(ValueError,"hash or size"):
                verifier.validate_result(rp,mp,manifest)


class SyntheticPagingFixtures(unittest.TestCase):
    def test_runtime_gop_boundaries_and_sparse_table_budgets(self):
        # These cases execute pure Rust math using synthetic addresses. They do
        # not qualify real high GOP devices or relocated UEFI runtime firmware.
        root=Path(__file__).resolve().parents[1]
        compiler=root/'build/uefi/bin/rustc'
        if not compiler.is_file():
            self.skipTest('checksum-pinned development compiler has not been installed')
        source=r'''
#[path="PAGING_SOURCE"] mod paging;
use paging::*;
#[test] fn actual_required_edges_only() {
    let mut t=Tables::empty(); t.reset(48,0x140100000).unwrap();
    t.map_range(Range::checked(0,LOW_LIMIT).unwrap()).unwrap();
    // Synthetic runtime code/data and unaligned 64-bit GOP window.
    for (start,len) in [(0x400001000,0x3000),(0x400100000,0x2000),(0x100ff1234,0x401000),(0x8000001000,0x3000)] {
        t.map_range(Range::checked(start,len).unwrap()).unwrap();
        assert_eq!(t.translation(start),Some(start));
        assert_eq!(t.translation(start+len-1),Some(start+len-1));
    }
    assert_eq!(t.translation(0x800000000),None); // Unowned high RAM stays unmapped.
    assert_eq!(t.translation(GUARD),None);
}
#[test] fn range_crossing_4g_and_1g_rounding() {
    let mut t=Tables::empty(); t.reset(48,0x800000).unwrap();
    let r=Range::checked(LOW_LIMIT-4096,8192).unwrap();
    t.map_range(r).unwrap();
    assert_eq!(t.translation(r.start),Some(r.start));
    assert_eq!(t.translation(r.end-1),Some(r.end-1));
    assert_eq!(t.leaf_count(),2);
    t.map_range(r).unwrap(); assert_eq!(t.leaf_count(),2);
}
#[test] fn reject_unrepresentable_required_ranges() {
    assert_eq!(Range::checked(u64::MAX,2),Err(Error::Overflow));
    assert_eq!(Range::checked(0,0),Err(Error::Empty));
    assert_eq!(validate_range(Range::checked(LOW_LIMIT,4096).unwrap(),32),Err(Error::PhysicalWidth));
    assert_eq!(validate_range(Range::checked(CANONICAL_LIMIT,4096).unwrap(),48),Err(Error::NonCanonical));
    assert_eq!(mapping_bounds(Range::checked(GUARD-4096,8192).unwrap(),48),Err(Error::Guard));
    let mut t=Tables::empty(); assert_eq!(t.reset(48,0x800001),Err(Error::Alignment));
}
#[test] fn bound_work_and_reset_failed_partial_build() {
    let mut t=Tables::empty(); t.reset(48,0x800000).unwrap();
    assert_eq!(t.map_range(Range::checked(0,(LEAF_CAPACITY as u64+1)*HUGE_PAGE).unwrap()),Err(Error::LeafBudget));
    for i in 0..126 { t.map_range(Range::checked((i as u64)<<30,4096).unwrap()).unwrap(); }
    assert_eq!(t.map_range(Range::checked(126u64<<30,4096).unwrap()),Err(Error::TableBudget));
    t.reset(48,0x800000).unwrap(); assert_eq!(t.leaf_count(),0);
    assert_eq!(t.translation(0),None);
}
#[test] fn aggregated_leaf_budget_is_enforced() {
    let mut t=Tables::empty(); t.reset(48,0x800000).unwrap();
    t.map_range(Range::checked(0,LEAF_CAPACITY as u64*HUGE_PAGE).unwrap()).unwrap();
    assert_eq!(t.leaf_count(),LEAF_CAPACITY);
    assert_eq!(t.map_range(Range::checked(LEAF_CAPACITY as u64*HUGE_PAGE,4096).unwrap()),Err(Error::LeafBudget));
}
'''.replace('PAGING_SOURCE',(root/'kernel/paging.rs').as_posix())
        source = ('#![no_std]\n#![no_main]\n' + source.replace('#[test] ', '')
                  .replace('let mut t=Tables::empty();', 'let t=unsafe { &mut *core::ptr::addr_of_mut!(TABLES) };'))
        source += r'''
static mut TABLES: Tables = Tables::empty();
struct Console;
impl core::fmt::Write for Console {
    fn write_str(&mut self,s:&str)->core::fmt::Result {
        for byte in s.bytes() { unsafe { core::arch::asm!("out dx,al",in("dx")0xe9u16,in("al")byte,options(nomem,nostack)); } }
        Ok(())
    }
}
fn finish(success:bool)->! {
    unsafe { core::arch::asm!("out dx,eax",in("dx")0xf4u16,in("eax")if success {0x10u32}else{0x11u32},options(nomem,nostack)); }
    loop { unsafe { core::arch::asm!("cli","hlt",options(nomem,nostack)); } }
}
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_:usize,_:usize)->usize {
    actual_required_edges_only(); range_crossing_4g_and_1g_rounding();
    reject_unrepresentable_required_ranges(); bound_work_and_reset_failed_partial_build();
    aggregated_leaf_budget_is_enforced();
    use core::fmt::Write;
    let _=Console.write_str("TESSRYN_SYNTHETIC_PAGING_MATH_PASS cases=5 runtime_gop=fixtures_only\n");
    finish(true)
}
#[panic_handler]
fn panic(info:&core::panic::PanicInfo)->! {
    use core::fmt::Write;
    let _=writeln!(Console,"TESSRYN_SYNTHETIC_PAGING_MATH_FAIL {info}");
    finish(false)
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            from tools.build_kernel import compiler_profile, compile_command
            from tools.g03.process import run_bounded
            from tools.k01_media import make_disk
            directory=Path(temporary);path=directory/'fixtures.rs';path.write_text(source);binary=directory/'BOOTX64.EFI'
            profile=compiler_profile()
            compile_result=subprocess.run(compile_command(profile,path,binary,[],[f'--remap-path-prefix={directory}=tessryn-test']),
                                          capture_output=True,text=True,timeout=60)
            self.assertEqual(compile_result.returncode,0,compile_result.stdout+compile_result.stderr)
            (directory/'boot.img').write_bytes(make_disk(binary.read_bytes()))
            for role,filename in (('code','code.fd'),('vars','vars.fd')):
                (directory/filename).write_bytes((root/'build/uefi'/profile['toolchain']['setup']['firmware'][role]['path']).read_bytes())
            command=runner.qemu_command('image-normal');command[command.index('-m')+1]='256M'
            execution=run_bounded([str(root/'build/toolchain/bin/qemu-system-x86_64'),*command[1:]],directory,30,262144)
            self.assertEqual(execution.status,'completed',execution.reason)
            self.assertEqual(execution.returncode,33,execution.stdout+execution.stderr)
            self.assertEqual(execution.stdout,b'TESSRYN_SYNTHETIC_PAGING_MATH_PASS cases=5 runtime_gop=fixtures_only\n')


if __name__ == '__main__':
    unittest.main()
