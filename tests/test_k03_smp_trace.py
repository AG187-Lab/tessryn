"""Self-contained raw parser fixtures from dirty diagnostic6; not release evidence."""
from __future__ import annotations
import copy
import re
import struct
import unittest
from tools.k03_smp_trace import parse_transcript, parse_madt

BINDINGS = {'missing_ap': {'descriptor': {'efi_file_offset': 34560,
                               'efi_rva': 41216,
                               'sha256': 'ec2d5df3ca21c4de9dc9327310483b95e11e03421d38abf60759528a02f10e42',
                               'size_bytes': 96},
                'executable_ranges': [[4096, 37273]],
                'heartbeat': {'efi_file_offset': 1481,
                              'efi_rva': 4553,
                              'sha256': '1f79edab3ac4a629140a8d12af31cf78a00f85db8095718aa76bdf207c345103',
                              'size_bytes': 8},
                'image_size': 819200,
                'trampoline': {'efi_file_offset': 29696,
                               'efi_rva': 32768,
                               'sha256': '006d1eb4450f3b97163a47e74d7ac423bd6fa3d24f6f53c57549f70ae8d11e41',
                               'size_bytes': 4096}},
 'rendezvous': {'descriptor': {'efi_file_offset': 38656,
                               'efi_rva': 45312,
                               'sha256': 'db8067e2b4013db2eab29332850b74bbdab187232252e062400f26f0062be785',
                               'size_bytes': 96},
                'executable_ranges': [[4096, 41369]],
                'heartbeat': {'efi_file_offset': 1481,
                              'efi_rva': 4553,
                              'sha256': '1f79edab3ac4a629140a8d12af31cf78a00f85db8095718aa76bdf207c345103',
                              'size_bytes': 8},
                'image_size': 827392,
                'trampoline': {'efi_file_offset': 33792,
                               'efi_rva': 36864,
                               'sha256': '006d1eb4450f3b97163a47e74d7ac423bd6fa3d24f6f53c57549f70ae8d11e41',
                               'size_bytes': 4096}}}

TRACES = {
'rendezvous': b"""TESSRYN_K01_ENTRY
TESSRYN ORIGINAL KERNEL
TESSRYN_K01_FRAMEBUFFER status=ready width=1280 height=800 stride=1280 base=0x80000000 format=bgrx selection=firmware-console
TESSRYN_K01_LIVE_RANGES image_start=0xe038000 image_end=0xe102000 stack_start=0xe018000 stack_end=0xe038000 map_start=0xe008000 map_end=0xe018000 scratch=0x100000 runtime_high=0 gop_start=0x80000000 gop_end=0x803e8000
TESSRYN_K01_PAGING_READY cr3=0xe05b000 tables=6 leaves=2048 physical_bits=48 guard=0x7fffffe00000 free_scope=low-conventional
TESSRYN_K01_RESET_POINTER address=0xfad3522 method=uefi-runtime
TESSRYN_K01_MEMORY_MAP_VALID descriptors=129 stride=48 free_pages=53331 attempt=1
TESSRYN_K01_EXIT_BOOT_SERVICES_OK
TESSRYN_K01_CPU_OWNED cr3=0xe05b000 rsp=0xe037f20 rip=0xe03949a gdt=owned idt=owned tss=owned
TESSRYN_K03_SMP_BEGIN case=rendezvous cpus=2 bsp=0 ap=1 lapic=0xfee00000 trampoline=0x9f000 cr3=0xe05b000
TESSRYN_K03_SMP_TOPOLOGY madt=41504943800000000375424f4348532042585043202020200100000042585043010000000000e0fe0100000000080000010000000008010101000000010c00000000c0fe00000000020a0000020000000000020a0005050000000d00020a0009090000000d00020a000a0a0000000d00020a000b0b0000000d000406ff000001
TESSRYN_K03_SMP_CLOCK period_fs=10000000 start=102600
TESSRYN_K03_SMP_CPU cpu=0 apic=0 rsp=0xe037d10 rip=0xe03a997 gdt=0xe045040 idt=0xe059170 tss=0xe045068 cr3=0xe05b000 stack_start=0xe018000 stack_end=0xe038000
TESSRYN_K03_SMP_CPU cpu=1 apic=1 rsp=0xe0fef10 rip=0xe03a997 gdt=0xe0450d8 idt=0xe0ed0a8 tss=0xe045100 cr3=0xe05b000 stack_start=0xe0ef000 stack_end=0xe0ff000
TESSRYN_K03_SMP_WORK bsp=4096 ap=4096 total=8192 bsp_heartbeats=39085 ap_heartbeats=23286 ap_before=1 start=1239900 end=3241000
TESSRYN_K03_SMP_IPI generation=1 vector=64 before=1 after=0 ack=1 heartbeat_before=23721 heartbeat_after=25601 rip=0xe0391cf cs=0x8 rflags=0x10213 rsp=0xe0fef78 frame=0xe0feec8 cr3=0xe05b000
TESSRYN_K03_SMP_IPI generation=2 vector=64 before=1 after=0 ack=2 heartbeat_before=26198 heartbeat_after=27730 rip=0xe0391cf cs=0x8 rflags=0x10207 rsp=0xe0fef78 frame=0xe0feec8 cr3=0xe05b000
TESSRYN_K03_SMP_IPI generation=3 vector=64 before=1 after=0 ack=3 heartbeat_before=27854 heartbeat_after=29388 rip=0xe0391cf cs=0x8 rflags=0x10203 rsp=0xe0fef78 frame=0xe0feec8 cr3=0xe05b000
TESSRYN_K03_SMP_STOP generation=4 vector=65 before=2 after=0 ack=4 heartbeat=29746 stable=29746 start=3708100 end=5710200 rip=0xe0391cf cs=0x8 rflags=0x10203 rsp=0xe0fef78 frame=0xe0feec8 cr3=0xe05b000
TESSRYN_K03_SMP_PASS cpus=2 ipis=3 retained=all
""",
'missing_ap': b"""TESSRYN_K01_ENTRY
TESSRYN ORIGINAL KERNEL
TESSRYN_K01_FRAMEBUFFER status=ready width=1280 height=800 stride=1280 base=0x80000000 format=bgrx selection=firmware-console
TESSRYN_K01_LIVE_RANGES image_start=0xe03b000 image_end=0xe103000 stack_start=0xe01b000 stack_end=0xe03b000 map_start=0xe00b000 map_end=0xe01b000 scratch=0x100000 runtime_high=0 gop_start=0x80000000 gop_end=0x803e8000
TESSRYN_K01_PAGING_READY cr3=0xe05d000 tables=6 leaves=2048 physical_bits=48 guard=0x7fffffe00000 free_scope=low-conventional
TESSRYN_K01_RESET_POINTER address=0xfad3522 method=uefi-runtime
TESSRYN_K01_MEMORY_MAP_VALID descriptors=129 stride=48 free_pages=53333 attempt=1
TESSRYN_K01_EXIT_BOOT_SERVICES_OK
TESSRYN_K01_CPU_OWNED cr3=0xe05d000 rsp=0xe03af20 rip=0xe03c49a gdt=owned idt=owned tss=owned
TESSRYN_K03_SMP_BEGIN case=missing_ap cpus=2 bsp=0 ap=1 lapic=0xfee00000 trampoline=0x9f000 cr3=0xe05d000
TESSRYN_K03_SMP_TOPOLOGY madt=41504943800000000375424f4348532042585043202020200100000042585043010000000000e0fe0100000000080000010000000008010101000000010c00000000c0fe00000000020a0000020000000000020a0005050000000d00020a0009090000000d00020a000a0a0000000d00020a000b0b0000000d000406ff000001
TESSRYN_K03_SMP_CLOCK period_fs=10000000 start=142100
TESSRYN_K03_SMP_CPU cpu=0 apic=0 rsp=0xe03adc0 rip=0xe03cef7 gdt=0xe047040 idt=0xe05b170 tss=0xe047068 cr3=0xe05d000 stack_start=0xe01b000 stack_end=0xe03b000
TESSRYN_K03_SMP_EXPECTED_REJECTION reason=ap-start-timeout start=208100 end=201221900 timeout_ns=2000000000
""",
}


def changed(data, marker, key, value, occurrence=0):
    rows = data.decode().splitlines(); matches = [i for i, row in enumerate(rows) if row.startswith(marker + ' ')]
    index = matches[occurrence]; pattern = r'(?<= )' + re.escape(key) + r'=[^ ]+'
    rows[index], count = re.subn(pattern, key + '=' + str(value), rows[index]); assert count == 1
    return ('\n'.join(rows) + '\n').encode()


class SmpTraceTests(unittest.TestCase):
    def parse(self, data=None, case='rendezvous', binding=None):
        return parse_transcript(case, TRACES[case] if data is None else data, 33, b'', BINDINGS[case] if binding is None else binding)

    def reject(self, data, case='rendezvous'):
        with self.assertRaises(ValueError): self.parse(data, case)

    def test_original_positive_and_controlled_negative_are_distinct(self):
        positive, negative = (self.parse(case=case) for case in TRACES)
        self.assertEqual((positive['cpus_online'], positive['total'], positive['ipi_acknowledgments']), (2,8192,3))
        self.assertEqual((negative['cpus_online'], negative['expected_rejection']), (1,'ap-start-timeout'))
        self.assertNotIn('total', negative)

    def test_original_process_exit_stderr_and_completion_are_required(self):
        for code, stderr in ((None,b''),(True,b''),(0,b''),(33,b'host diagnostic')):
            with self.subTest(code=code,stderr=stderr), self.assertRaises(ValueError):
                parse_transcript('rendezvous',TRACES['rendezvous'],code,stderr,BINDINGS['rendezvous'])
        self.reject(TRACES['rendezvous'][:-1])
        self.reject(TRACES['rendezvous']+b'TESSRYN_K01_EXCEPTION vector=6\n')
        self.reject(b'TESSRYN_K01_EXCEPTION vector=6\n'+TRACES['rendezvous'])
        self.reject(TRACES['rendezvous'].replace(b'TESSRYN_K03_SMP_BEGIN',b'TESSRYN_K02_SERVICE_BEGIN'))

    def test_records_are_exact_ordered_complete_and_canonical(self):
        raw=TRACES['rendezvous'];line=next(x for x in raw.splitlines(keepends=True) if x.startswith(b'TESSRYN_K03_SMP_IPI'))
        for data in (raw.replace(line,b'',1),raw.replace(line,line+line,1),raw.replace(b'cpus=2',b'cpus=2 extra=1',1),
                     raw.replace(b'cpus=2',b'cpus=2 cpus=2',1),raw.replace(b'cpus=2',b' cpus=2',1),raw+b'\xff\n'):
            with self.subTest(data=data[-80:]):self.reject(data)

    def test_cpu_ids_and_raw_madt_are_bound(self):
        for marker,key,value in (('TESSRYN_K03_SMP_BEGIN','ap',0),('TESSRYN_K03_SMP_CPU','apic',0)):
            self.reject(changed(TRACES['rendezvous'],marker,key,value,1 if marker.endswith('CPU') else 0))
        raw=TRACES['rendezvous'];m=re.search(rb'madt=([0-9a-f]+)',raw);data=bytearray.fromhex(m.group(1).decode());data[10]^=1
        self.reject(raw.replace(m.group(1),data.hex().encode()))
        data[9]=0;data[9]=(-sum(data))&255
        data[48]=3;data[9]=0;data[9]=(-sum(data))&255
        self.reject(raw.replace(m.group(1),data.hex().encode()))

    def test_madt_disabled_duplicates_x2apic_override_and_bad_structure_reject(self):
        original=bytearray.fromhex(re.search(rb'madt=([0-9a-f]+)',TRACES['rendezvous']).group(1).decode())
        for kind in ('duplicate','override','length','three'):
            d=bytearray(original)
            if kind=='duplicate':d[55]=d[47]
            elif kind=='override':d.extend(bytes([5,12,0,0])+struct.pack('<Q',0xfee00000))
            elif kind=='length':d[45]=0
            else:d.extend(bytes([0,8,2,2])+struct.pack('<I',1))
            struct.pack_into('<I',d,4,len(d));d[9]=0;d[9]=(-sum(d))&255
            with self.subTest(kind=kind),self.assertRaises(ValueError):parse_madt(bytes(d))

    def test_cpu_descriptors_stacks_and_common_root_are_owned(self):
        mutations=(('cr3','0xe05c000'),('rsp','0x1'),('rip','0xe045040'),('stack_start','0xe018000'),
                   ('gdt','0xe045040'),('idt','0xe05b000'),('tss','0xe0450d8'))
        for key,value in mutations:
            with self.subTest(key=key):self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_CPU',key,value,1))
        self.reject(changed(TRACES['missing_ap'],'TESSRYN_K03_SMP_CPU','idt','0xe047040'), 'missing_ap')

    def test_low_trampoline_and_startup_ranges_are_not_forged(self):
        for marker,key,value in (('TESSRYN_K03_SMP_BEGIN','trampoline','0x100000'),('TESSRYN_K03_SMP_BEGIN','trampoline','0x9f001'),
            ('TESSRYN_K03_SMP_BEGIN','trampoline','0x0'),('TESSRYN_K01_LIVE_RANGES','scratch','0x0'),
            ('TESSRYN_K01_LIVE_RANGES','scratch','0xe038000'),('TESSRYN_K01_LIVE_RANGES','image_end','0xe103000')):
            with self.subTest(key=key,value=value):self.reject(changed(TRACES['rendezvous'],marker,key,value))

    def test_two_cpu_work_and_observation_window_are_required(self):
        for key,value in (('bsp',4095),('ap',4095),('total',8191),('bsp_heartbeats',0),('ap_heartbeats',0),('end',1253701)):
            with self.subTest(key=key):self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_WORK',key,value))

    def test_each_actual_ipi_requires_identity_isr_eoi_ack_and_progress(self):
        for key,value in (('generation',2),('vector',65),('before',0),('after',1),('ack',2),('heartbeat_before',0),('heartbeat_after',16090)):
            with self.subTest(key=key):self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_IPI',key,value))
        self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_STOP','before',1))

    def test_raw_interrupt_frame_requires_ap_stack_privilege_if_root_and_code(self):
        for marker in ('TESSRYN_K03_SMP_IPI','TESSRYN_K03_SMP_STOP'):
            for key,value in (('cs','0x33'),('rflags','0x2'),('rflags','0x302'),('rip','0xe045040'),('rsp','0xe037d10'),('frame','0xe0fefff'),('cr3','0xe05c000')):
                with self.subTest(marker=marker,key=key):self.reject(changed(TRACES['rendezvous'],marker,key,value))

    def test_raw_frame_rsp_and_aligned_fp_storage_are_the_same_capture(self):
        for marker in ('TESSRYN_K03_SMP_IPI','TESSRYN_K03_SMP_STOP'):
            self.reject(changed(TRACES['rendezvous'],marker,'frame','0xe0ef000'))
            self.reject(changed(TRACES['rendezvous'],marker,'rsp','0xe0feed8'))
            data=changed(TRACES['rendezvous'],marker,'frame','0xe0ef058')
            self.reject(changed(data,marker,'rsp','0xe0ef100'))

    def test_exact_heartbeat_code_and_mandatory_delays_are_bound(self):
        self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_IPI','rip',hex(0xe038000+0x1000)))
        base=0xe038000+BINDINGS['rendezvous']['heartbeat']['efi_rva']
        for marker in ('TESSRYN_K03_SMP_IPI','TESSRYN_K03_SMP_STOP'):
            for offset in range(8):
                data=changed(TRACES['rendezvous'],marker,'rip',hex(base+offset))
                with self.subTest(marker=marker,offset=offset):
                    if offset in (0,4,6):self.parse(data)
                    else:self.reject(data)
        work=next(row for row in TRACES['rendezvous'].decode().splitlines() if row.startswith('TESSRYN_K03_SMP_WORK '))
        end=int(re.search(r' end=(\d+)',work)[1]);data=changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_STOP','start',end)
        self.reject(changed(data,'TESSRYN_K03_SMP_STOP','end',end+2_000_000))
        negative=TRACES['missing_ap'];start=int(re.search(rb'EXPECTED_REJECTION .* start=(\d+)',negative)[1])
        self.reject(changed(negative,'TESSRYN_K03_SMP_EXPECTED_REJECTION','end',start+200_000_000),'missing_ap')

    def test_terminal_stop_is_stable_and_no_later_progress_is_accepted(self):
        for key,value in (('ack',3),('heartbeat',1),('stable',22300),('end',3730401)):
            with self.subTest(key=key):self.reject(changed(TRACES['rendezvous'],'TESSRYN_K03_SMP_STOP',key,value))
        self.reject(TRACES['rendezvous']+b'TESSRYN_K03_SMP_WORK bsp=4096 ap=4096 total=8192\n')

    def test_missing_ap_timeout_is_bounded_expected_rejection_only(self):
        self.reject(changed(TRACES['missing_ap'],'TESSRYN_K03_SMP_EXPECTED_REJECTION','end',207301),'missing_ap')
        self.reject(changed(TRACES['missing_ap'],'TESSRYN_K03_SMP_EXPECTED_REJECTION','reason','success'),'missing_ap')
        self.reject(TRACES['missing_ap']+b'TESSRYN_K03_SMP_PASS cpus=2 ipis=3 retained=all\n','missing_ap')

    def test_compiled_case_descriptor_and_image_binding_are_required(self):
        for mutate in (lambda b:b['descriptor'].update(sha256='0'*64),lambda b:b['descriptor'].update(size_bytes=True),
                       lambda b:b['trampoline'].update(size_bytes=4095),lambda b:b.update(image_size=4096),
                       lambda b:b.update(executable_ranges=[[0,0xffffffff]])):
            b=copy.deepcopy(BINDINGS['rendezvous']);mutate(b)
            with self.assertRaises(ValueError):self.parse(binding=b)
        with self.assertRaises(ValueError):self.parse(binding=BINDINGS['missing_ap'])

if __name__=='__main__':unittest.main()
