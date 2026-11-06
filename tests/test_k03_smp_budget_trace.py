"""Replay original diagnostic boots only as fixtures, never as release evidence."""
from __future__ import annotations

import copy
import re
import unittest

from tools.k03_smp_budget_protocol import CASES, PROFILE, SCENARIOS
from tools.k03_smp_budget_trace import parse_transcript

BINDINGS = {'late': {'budget': {'efi_file_offset': 76032,
                     'efi_rva': 82176,
                     'sha256': 'c796a0bdf7617e2a843a6069c75e98e6c1535e4aee0bd7bd1592eb2fbe803d77',
                     'size_bytes': 136},
          'context': {'bootstrap': {'descriptor': {'efi_file_offset': 76168,
                                                   'efi_rva': 82312,
                                                   'sha256': 'db8067e2b4013db2eab29332850b74bbdab187232252e062400f26f0062be785',
                                                   'size_bytes': 96},
                                    'executable_ranges': [[4096, 78489]],
                                    'image_size': 1310720,
                                    'trampoline': {'efi_file_offset': 66560,
                                                   'efi_rva': 69632,
                                                   'sha256': '006d1eb4450f3b97163a47e74d7ac423bd6fa3d24f6f53c57549f70ae8d11e41',
                                                   'size_bytes': 4096}},
                      'descriptor': {'efi_file_offset': 76264,
                                     'efi_rva': 82408,
                                     'sha256': '3968769fca6f10b7db217115c179192bb30e0d227aef4e9f9868cc142fdf98d9',
                                     'size_bytes': 112},
                      'program': {'efi_file_offset': 70656,
                                  'efi_rva': 73728,
                                  'instruction_bytes': {'after_yield': 'eb09488b060f0bcd420f0bf048ff07f3',
                                                        'bsp_start': '66b82b00668ee84c396f08752feb2566',
                                                        'forged_fault': 'cd420f0bf048ff07f390ebf80f0b0000',
                                                        'loop_end': '0f0b0000000000000000000000000000',
                                                        'loop_start': 'f048ff07f390ebf80f0b000000000000',
                                                        'peer_fault': '488b060f0bcd420f0bf048ff07f390eb',
                                                        'warmup_end': 'cd80eb09488b060f0bcd420f0bf048ff',
                                                        'warmup_start': '66b82b00668ee84c396f087520f048ff',
                                                        'yield': 'cd80eb09488b060f0bcd420f0bf048ff'},
                                  'offsets': {'after_yield': 41,
                                              'bsp_start': 0,
                                              'forged_fault': 48,
                                              'loop_end': 60,
                                              'loop_start': 52,
                                              'peer_fault': 43,
                                              'warmup_end': 39,
                                              'warmup_start': 15,
                                              'yield': 39},
                                  'sha256': 'c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc',
                                  'size_bytes': 4096}}},
 'preempt': {'budget': {'efi_file_offset': 76032,
                        'efi_rva': 82176,
                        'sha256': '58e9ddff499e98647f593bdd49ec7284af2fc4e6b1806d31d0bb892e5cf872eb',
                        'size_bytes': 136},
             'context': {'bootstrap': {'descriptor': {'efi_file_offset': 76168,
                                                      'efi_rva': 82312,
                                                      'sha256': 'db8067e2b4013db2eab29332850b74bbdab187232252e062400f26f0062be785',
                                                      'size_bytes': 96},
                                       'executable_ranges': [[4096, 78489]],
                                       'image_size': 1310720,
                                       'trampoline': {'efi_file_offset': 66560,
                                                      'efi_rva': 69632,
                                                      'sha256': '006d1eb4450f3b97163a47e74d7ac423bd6fa3d24f6f53c57549f70ae8d11e41',
                                                      'size_bytes': 4096}},
                         'descriptor': {'efi_file_offset': 76264,
                                        'efi_rva': 82408,
                                        'sha256': '3968769fca6f10b7db217115c179192bb30e0d227aef4e9f9868cc142fdf98d9',
                                        'size_bytes': 112},
                         'program': {'efi_file_offset': 70656,
                                     'efi_rva': 73728,
                                     'instruction_bytes': {'after_yield': 'eb09488b060f0bcd420f0bf048ff07f3',
                                                           'bsp_start': '66b82b00668ee84c396f08752feb2566',
                                                           'forged_fault': 'cd420f0bf048ff07f390ebf80f0b0000',
                                                           'loop_end': '0f0b0000000000000000000000000000',
                                                           'loop_start': 'f048ff07f390ebf80f0b000000000000',
                                                           'peer_fault': '488b060f0bcd420f0bf048ff07f390eb',
                                                           'warmup_end': 'cd80eb09488b060f0bcd420f0bf048ff',
                                                           'warmup_start': '66b82b00668ee84c396f087520f048ff',
                                                           'yield': 'cd80eb09488b060f0bcd420f0bf048ff'},
                                     'offsets': {'after_yield': 41,
                                                 'bsp_start': 0,
                                                 'forged_fault': 48,
                                                 'loop_end': 60,
                                                 'loop_start': 52,
                                                 'peer_fault': 43,
                                                 'warmup_end': 39,
                                                 'warmup_start': 15,
                                                 'yield': 39},
                                     'sha256': 'c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc',
                                     'size_bytes': 4096}}}}

TRACES = {
'preempt': b"""TESSRYN_K01_ENTRY
TESSRYN ORIGINAL KERNEL
TESSRYN_K01_FRAMEBUFFER status=ready width=1280 height=800 stride=1280 base=0x80000000 format=bgrx selection=firmware-console
TESSRYN_K01_LIVE_RANGES image_start=0xdf94000 image_end=0xe0d4000 stack_start=0xe0ee000 stack_end=0xe10e000 map_start=0xe0de000 map_end=0xe0ee000 scratch=0x100000 runtime_high=0 gop_start=0x80000000 gop_end=0x803e8000
TESSRYN_K01_PAGING_READY cr3=0xdfe4000 tables=6 leaves=2048 physical_bits=48 guard=0x7fffffe00000 free_scope=low-conventional
TESSRYN_K01_RESET_POINTER address=0xfad3522 method=uefi-runtime
TESSRYN_K01_MEMORY_MAP_VALID descriptors=129 stride=48 free_pages=53213 attempt=1
TESSRYN_K01_EXIT_BOOT_SERVICES_OK
TESSRYN_K01_CPU_OWNED cr3=0xdfe4000 rsp=0xe10df20 rip=0xdf9733a gdt=owned idt=owned tss=owned
TESSRYN_K03_SMP_BEGIN case=rendezvous cpus=2 bsp=0 ap=1 lapic=0xfee00000 trampoline=0x9f000 cr3=0xdfe4000
TESSRYN_K03_SMP_TOPOLOGY madt=41504943800000000375424f4348532042585043202020200100000042585043010000000000e0fe0100000000080000010000000008010101000000010c00000000c0fe00000000020a0000020000000000020a0005050000000d00020a0009090000000d00020a000a0a0000000d00020a000b0b0000000d000406ff000001
TESSRYN_K03_SMP_CLOCK period_fs=10000000 start=1703300
TESSRYN_K03_SMP_CPU cpu=0 apic=0 rsp=0xe10dc70 rip=0xdf98dd7 gdt=0xdfab040 idt=0xdfe2ef0 tss=0xdfab068 cr3=0xdfe4000 stack_start=0xe0ee000 stack_end=0xe10e000
TESSRYN_K03_SMP_CPU cpu=1 apic=1 rsp=0xe086f10 rip=0xdf98dd7 gdt=0xdfab0d8 idt=0xe075060 tss=0xdfab100 cr3=0xdfe4000 stack_start=0xe077000 stack_end=0xe087000
TESSRYN_K03_SMP_BUDGET_BEGIN case=preempt cpus=2 domain=1 vector=67 epoch=3433400
TESSRYN_K03_SMP_BUDGET_IRQS version=0x170020 redirections=24 rtes=000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000
TESSRYN_K03_SMP_USER_SPACE cpu=0 apic=0 root=0xdfac000 root_end=0xdfbd000 code_phys=0xe088000 stack_phys=0xe08c000 data_phys=0xe08a000 peer_phys=0xe0d1000 code=0x100000000 stack=0x100002000 data=0x100004000 peer=0x100200000 leaves=4 gdt=0xe0ce000 idt=0xe0ce080 tss=0xdfab168 trap_start=0xe08e000 trap_end=0xe09e000 fault_start=0xe0ae000 fault_end=0xe0be000 context=0xdfce930 marker=0x5355455200000000
TESSRYN_K03_SMP_USER_STATE cpu=0 cr0=0x80010033 cr4=0x668 efer=0xd00 gsbase=0xdfce930 user_gsbase=0x0 gdt=0xe0ce000 idt=0xe0ce080 tss=0xdfab168 tr=24 ldtr=0 dr7=0x400
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=code va=0x100000000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0xe088005
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=stack va=0x100002000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0x800000000e08c007
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=data va=0x100004000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0x800000000e08a007
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=peer va=0x100200000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb4000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb4007 e3=0x800000000e0d1005
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=code_alias va=0xe088000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=stack_alias va=0xe08c000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=data_alias va=0xe08a000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=hpet va=0xfed00000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb1000 t3=0x0 e0=0xdfad007 e1=0xdfb1003 e2=0x80000000fec0009b e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=lapic va=0xfee00000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb1000 t3=0x0 e0=0xdfad007 e1=0xdfb1003 e2=0x80000000fee0009b e3=0x0
TESSRYN_K03_SMP_USER_PAYLOAD cpu=0 phase=before sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_USER_SPACE cpu=1 apic=1 root=0xdfbd000 root_end=0xdfce000 code_phys=0xe089000 stack_phys=0xe08d000 data_phys=0xe08b000 peer_phys=0x0 code=0x100000000 stack=0x100002000 data=0x100004000 peer=0x100200000 leaves=3 gdt=0xe0ce038 idt=0xe0cf080 tss=0xdfab1d0 trap_start=0xe09e000 trap_end=0xe0ae000 fault_start=0xe0be000 fault_end=0xe0ce000 context=0xdfcec10 marker=0x5355455200000001
TESSRYN_K03_SMP_USER_STATE cpu=1 cr0=0x80010033 cr4=0x620 efer=0xd00 gsbase=0xdfcec10 user_gsbase=0x0 gdt=0xe0ce038 idt=0xe0cf080 tss=0xdfab1d0 tr=24 ldtr=0 dr7=0x400
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=code va=0x100000000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0xe089005
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=stack va=0x100002000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0x800000000e08d007
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=data va=0x100004000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0x800000000e08b007
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=peer va=0x100200000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0x0 e0=0xdfbe007 e1=0xdfc3007 e2=0x0 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=code_alias va=0xe089000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=stack_alias va=0xe08d000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=data_alias va=0xe08b000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=hpet va=0xfed00000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc2000 t3=0x0 e0=0xdfbe007 e1=0xdfc2003 e2=0x80000000fec0009b e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=lapic va=0xfee00000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc2000 t3=0x0 e0=0xdfbe007 e1=0xdfc2003 e2=0x80000000fee0009b e3=0x0
TESSRYN_K03_SMP_USER_PAYLOAD cpu=1 phase=before sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_BUDGET_CAL cpu=0 divider=16 divide_cfg=3 initial=4294967295 first_before=2880900 first_after=2883600 first_count=4294965420 last_before=3388500 last_after=3391000 last_count=4294648233 stopped_count=0 irr=0 isr=0
TESSRYN_K03_SMP_BUDGET_CAL cpu=1 divider=16 divide_cfg=3 initial=4294967295 first_before=2880800 first_after=2883400 first_count=4294965358 last_before=3388100 last_after=3390800 last_count=4294648170 stopped_count=0 irr=0 isr=0
TESSRYN_K03_SMP_BUDGET_BATCH round=1 start=5430600 reserved=1200000000 consumed=0 available=0 ap_ready_heartbeat=1
TESSRYN_K03_SMP_BUDGET_GRANT round=1 cpu=0 task=0 task_generation=1 lease=1 grant_ns=800000000 hard_ns=819972000
TESSRYN_K03_SMP_BUDGET_GRANT round=1 cpu=1 task=1 task_generation=1 lease=1 grant_ns=400000000 hard_ns=419972000
TESSRYN_K03_SMP_BUDGET_TIMER round=1 cpu=0 lease=1 arm_before=5542600 arm_after=5542800 entry=5546300 capture=7782300 retired=7858500 initial=1250000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=115258 resume_rip=0x100000000 heartbeat_before=0 heartbeat_after=107184
TESSRYN_K03_SMP_USER_TRAP cpu=0 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10212 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe09df50 fp=0xe09dd50 root=0xdfac000 apic=0 r12=0x534d505500000000 r13=0x5355455200000000 xmm0lo=0x534d505500000000 xmm0hi=0x5355455200000000 isr_before=8 isr_after=0 generation=1 marker=0x5355455200000000 heartbeat=107184 kernel_rsp=0xe10cc70 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000000000000524555530000000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055504d530000000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_TIMER round=1 cpu=1 lease=1 arm_before=5491100 arm_after=5492600 entry=5523600 capture=13714300 retired=13726000 initial=5000000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=107184 resume_rip=0x100000000 heartbeat_before=0 heartbeat_after=182773
TESSRYN_K03_SMP_USER_TRAP cpu=1 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10206 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe0adf50 fp=0xe0add50 root=0xdfbd000 apic=1 r12=0x534d505500000001 r13=0x5355455200000001 xmm0lo=0x534d505500000001 xmm0hi=0x5355455200000001 isr_before=8 isr_after=0 generation=1 marker=0x5355455200000001 heartbeat=182773 kernel_rsp=0xe086c10 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000001000000524555530100000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000055504d530100000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=1 cpu=0 lease=1 retired=7858500 elapsed_ns=24279000 consumed=24279000 reserved=400000000 available=775721000 halted=0 state=runnable peer_lease=1 peer_reserved=400000000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=1 cpu=1 lease=1 retired=13726000 elapsed_ns=82954000 consumed=107233000 reserved=0 available=1092767000 halted=0 state=runnable peer_lease=0 peer_reserved=0
TESSRYN_K03_SMP_BUDGET_BATCH round=2 start=15294200 reserved=1092767000 consumed=107233000 available=0 ap_ready_heartbeat=182798
TESSRYN_K03_SMP_BUDGET_GRANT round=2 cpu=0 task=0 task_generation=1 lease=2 grant_ns=800000000 hard_ns=918608000
TESSRYN_K03_SMP_BUDGET_GRANT round=2 cpu=1 task=1 task_generation=1 lease=2 grant_ns=292767000 hard_ns=411375000
TESSRYN_K03_SMP_BUDGET_TIMER round=2 cpu=0 lease=2 arm_before=15311000 arm_after=15311700 entry=15314000 capture=17384300 retired=17392700 initial=1250000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=288960 resume_rip=0x10000003a heartbeat_before=107184 heartbeat_after=210650
TESSRYN_K03_SMP_USER_TRAP cpu=0 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10202 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe09df50 fp=0xe09dd50 root=0xdfac000 apic=0 r12=0x534d505500000000 r13=0x5355455200000000 xmm0lo=0x534d505500000000 xmm0hi=0x5355455200000000 isr_before=8 isr_after=0 generation=2 marker=0x5355455200000000 heartbeat=210650 kernel_rsp=0xe10cc70 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000000000000524555530000000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055504d530000000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_TIMER round=2 cpu=1 lease=2 arm_before=15303600 arm_after=15303800 entry=15305900 capture=24169300 retired=24184500 initial=5000000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=210650 resume_rip=0x10000003a heartbeat_before=182773 heartbeat_after=366445
TESSRYN_K03_SMP_USER_TRAP cpu=1 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10202 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe0adf50 fp=0xe0add50 root=0xdfbd000 apic=1 r12=0x534d505500000001 r13=0x5355455200000001 xmm0lo=0x534d505500000001 xmm0hi=0x5355455200000001 isr_before=8 isr_after=0 generation=2 marker=0x5355455200000001 heartbeat=366445 kernel_rsp=0xe086c10 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000001000000524555530100000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000055504d530100000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=2 cpu=0 lease=2 retired=17392700 elapsed_ns=20985000 consumed=128218000 reserved=292767000 available=779015000 halted=0 state=completed peer_lease=2 peer_reserved=292767000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=2 cpu=1 lease=2 retired=24184500 elapsed_ns=88903000 consumed=217121000 reserved=0 available=982879000 halted=0 state=completed peer_lease=0 peer_reserved=0
TESSRYN_K03_SMP_BUDGET_STOP ap_ack=1 start=25994900 end=27999500 cpu0=210650 stable0=210650 cpu1=366445 stable1=366445
TESSRYN_K03_SMP_USER_PAYLOAD cpu=0 phase=after sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_USER_PAYLOAD cpu=1 phase=after sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_BUDGET_PASS cpus=2 rounds=2 irqs=4 consumed=217121000 reserved=0 halted=0 retained=all
""",
'late': b"""TESSRYN_K01_ENTRY
TESSRYN ORIGINAL KERNEL
TESSRYN_K01_FRAMEBUFFER status=ready width=1280 height=800 stride=1280 base=0x80000000 format=bgrx selection=firmware-console
TESSRYN_K01_LIVE_RANGES image_start=0xdf94000 image_end=0xe0d4000 stack_start=0xe0ee000 stack_end=0xe10e000 map_start=0xe0de000 map_end=0xe0ee000 scratch=0x100000 runtime_high=0 gop_start=0x80000000 gop_end=0x803e8000
TESSRYN_K01_PAGING_READY cr3=0xdfe4000 tables=6 leaves=2048 physical_bits=48 guard=0x7fffffe00000 free_scope=low-conventional
TESSRYN_K01_RESET_POINTER address=0xfad3522 method=uefi-runtime
TESSRYN_K01_MEMORY_MAP_VALID descriptors=129 stride=48 free_pages=53213 attempt=1
TESSRYN_K01_EXIT_BOOT_SERVICES_OK
TESSRYN_K01_CPU_OWNED cr3=0xdfe4000 rsp=0xe10df20 rip=0xdf9733a gdt=owned idt=owned tss=owned
TESSRYN_K03_SMP_BEGIN case=rendezvous cpus=2 bsp=0 ap=1 lapic=0xfee00000 trampoline=0x9f000 cr3=0xdfe4000
TESSRYN_K03_SMP_TOPOLOGY madt=41504943800000000375424f4348532042585043202020200100000042585043010000000000e0fe0100000000080000010000000008010101000000010c00000000c0fe00000000020a0000020000000000020a0005050000000d00020a0009090000000d00020a000a0a0000000d00020a000b0b0000000d000406ff000001
TESSRYN_K03_SMP_CLOCK period_fs=10000000 start=665300
TESSRYN_K03_SMP_CPU cpu=0 apic=0 rsp=0xe10dc70 rip=0xdf98dd7 gdt=0xdfab040 idt=0xdfe2ef0 tss=0xdfab068 cr3=0xdfe4000 stack_start=0xe0ee000 stack_end=0xe10e000
TESSRYN_K03_SMP_CPU cpu=1 apic=1 rsp=0xe086f10 rip=0xdf98dd7 gdt=0xdfab0d8 idt=0xe075060 tss=0xdfab100 cr3=0xdfe4000 stack_start=0xe077000 stack_end=0xe087000
TESSRYN_K03_SMP_BUDGET_BEGIN case=late cpus=2 domain=1 vector=67 epoch=2432000
TESSRYN_K03_SMP_BUDGET_IRQS version=0x170020 redirections=24 rtes=000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000
TESSRYN_K03_SMP_USER_SPACE cpu=0 apic=0 root=0xdfac000 root_end=0xdfbd000 code_phys=0xe088000 stack_phys=0xe08c000 data_phys=0xe08a000 peer_phys=0xe0d1000 code=0x100000000 stack=0x100002000 data=0x100004000 peer=0x100200000 leaves=4 gdt=0xe0ce000 idt=0xe0ce080 tss=0xdfab168 trap_start=0xe08e000 trap_end=0xe09e000 fault_start=0xe0ae000 fault_end=0xe0be000 context=0xdfce930 marker=0x5355455200000000
TESSRYN_K03_SMP_USER_STATE cpu=0 cr0=0x80010033 cr4=0x668 efer=0xd00 gsbase=0xdfce930 user_gsbase=0x0 gdt=0xe0ce000 idt=0xe0ce080 tss=0xdfab168 tr=24 ldtr=0 dr7=0x400
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=code va=0x100000000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0xe088005
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=stack va=0x100002000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0x800000000e08c007
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=data va=0x100004000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb3000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb3007 e3=0x800000000e08a007
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=peer va=0x100200000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb2000 t3=0xdfb4000 e0=0xdfad007 e1=0xdfb2007 e2=0xdfb4007 e3=0x800000000e0d1005
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=code_alias va=0xe088000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=stack_alias va=0xe08c000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=data_alias va=0xe08a000 t0=0xdfac000 t1=0xdfad000 t2=0xdfae000 t3=0x0 e0=0xdfad007 e1=0xdfae003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=hpet va=0xfed00000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb1000 t3=0x0 e0=0xdfad007 e1=0xdfb1003 e2=0x80000000fec0009b e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=0 kind=lapic va=0xfee00000 t0=0xdfac000 t1=0xdfad000 t2=0xdfb1000 t3=0x0 e0=0xdfad007 e1=0xdfb1003 e2=0x80000000fee0009b e3=0x0
TESSRYN_K03_SMP_USER_PAYLOAD cpu=0 phase=before sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_USER_SPACE cpu=1 apic=1 root=0xdfbd000 root_end=0xdfce000 code_phys=0xe089000 stack_phys=0xe08d000 data_phys=0xe08b000 peer_phys=0x0 code=0x100000000 stack=0x100002000 data=0x100004000 peer=0x100200000 leaves=3 gdt=0xe0ce038 idt=0xe0cf080 tss=0xdfab1d0 trap_start=0xe09e000 trap_end=0xe0ae000 fault_start=0xe0be000 fault_end=0xe0ce000 context=0xdfcec10 marker=0x5355455200000001
TESSRYN_K03_SMP_USER_STATE cpu=1 cr0=0x80010033 cr4=0x620 efer=0xd00 gsbase=0xdfcec10 user_gsbase=0x0 gdt=0xe0ce038 idt=0xe0cf080 tss=0xdfab1d0 tr=24 ldtr=0 dr7=0x400
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=code va=0x100000000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0xe089005
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=stack va=0x100002000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0x800000000e08d007
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=data va=0x100004000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0xdfc4000 e0=0xdfbe007 e1=0xdfc3007 e2=0xdfc4007 e3=0x800000000e08b007
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=peer va=0x100200000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc3000 t3=0x0 e0=0xdfbe007 e1=0xdfc3007 e2=0x0 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=code_alias va=0xe089000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=stack_alias va=0xe08d000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=data_alias va=0xe08b000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfbf000 t3=0x0 e0=0xdfbe007 e1=0xdfbf003 e2=0xe000083 e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=hpet va=0xfed00000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc2000 t3=0x0 e0=0xdfbe007 e1=0xdfc2003 e2=0x80000000fec0009b e3=0x0
TESSRYN_K03_SMP_USER_WALK cpu=1 kind=lapic va=0xfee00000 t0=0xdfbd000 t1=0xdfbe000 t2=0xdfc2000 t3=0x0 e0=0xdfbe007 e1=0xdfc2003 e2=0x80000000fee0009b e3=0x0
TESSRYN_K03_SMP_USER_PAYLOAD cpu=1 phase=before sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_BUDGET_CAL cpu=0 divider=16 divide_cfg=3 initial=4294967295 first_before=1884200 first_after=1886800 first_count=4294965545 last_before=2390400 last_after=2392900 last_count=4294649170 stopped_count=0 irr=0 isr=0
TESSRYN_K03_SMP_BUDGET_CAL cpu=1 divider=16 divide_cfg=3 initial=4294967295 first_before=1884000 first_after=1886600 first_count=4294965483 last_before=2390200 last_after=2392700 last_count=4294649108 stopped_count=0 irr=0 isr=0
TESSRYN_K03_SMP_BUDGET_BATCH round=1 start=4354900 reserved=60000000 consumed=0 available=0 ap_ready_heartbeat=1
TESSRYN_K03_SMP_BUDGET_GRANT round=1 cpu=0 task=0 task_generation=1 lease=1 grant_ns=40000000 hard_ns=59229000
TESSRYN_K03_SMP_BUDGET_GRANT round=1 cpu=1 task=1 task_generation=1 lease=1 grant_ns=20000000 hard_ns=39229000
TESSRYN_K03_SMP_BUDGET_TIMER round=1 cpu=0 lease=1 arm_before=4476100 arm_after=4476200 entry=4478300 capture=11513800 retired=11579300 initial=3750000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=357050 resume_rip=0x100000000 heartbeat_before=0 heartbeat_after=343534
TESSRYN_K03_SMP_USER_TRAP cpu=0 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10206 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe09df50 fp=0xe09dd50 root=0xdfac000 apic=0 r12=0x534d505500000000 r13=0x5355455200000000 xmm0lo=0x534d505500000000 xmm0hi=0x5355455200000000 isr_before=8 isr_after=0 generation=1 marker=0x5355455200000000 heartbeat=343534 kernel_rsp=0xe10cc40 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000000000000524555530000000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000055504d530000000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_TIMER round=1 cpu=1 lease=1 arm_before=4423400 arm_after=4427000 entry=4454300 capture=28646000 retired=28658500 initial=15000000 current=0 irr_before=0 isr_before=8 irr_after=0 isr_after=0 lvt_before=0x43 lvt_after=0x10043 retire_count=0 peer_heartbeat=343534 resume_rip=0x100000000 heartbeat_before=0 heartbeat_after=541888
TESSRYN_K03_SMP_USER_TRAP cpu=1 stage=timer vector=67 error=0x0 rip=0x10000003a cs=0x33 rflags=0x10216 rsp=0x100002ff0 ss=0x2b cr2=0x0 frame=0xe0adf50 fp=0xe0add50 root=0xdfbd000 apic=1 r12=0x534d505500000001 r13=0x5355455200000001 xmm0lo=0x534d505500000001 xmm0hi=0x5355455200000001 isr_before=8 isr_after=0 generation=1 marker=0x5355455200000001 heartbeat=541888 kernel_rsp=0xe086c10 kernel_cr3=0xdfe4000 gpr=0000000000000000000000000000000001000000524555530100000055504d5300000000000000000000000000000000000000000000000000000000000000000040000001000000000020000100000000000000000000000000000000000000000000000000000000000100000000002b00000000000000 fp_image=7f0300000000000000000000000000000000000000000000801f0000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000055504d530100000052455553000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=1 cpu=0 lease=1 retired=11579300 elapsed_ns=72244000 consumed=72244000 reserved=20000000 available=0 halted=1 state=failed peer_lease=1 peer_reserved=20000000
TESSRYN_K03_SMP_BUDGET_DENY round=1 cpu=0 reason=no-runnable-task consumed=72244000 reserved=20000000 available=0 halted=1 peer_lease=1 peer_reserved=20000000
TESSRYN_K03_SMP_BUDGET_ACCOUNT round=1 cpu=1 lease=1 retired=28658500 elapsed_ns=243036000 consumed=315280000 reserved=0 available=0 halted=1 state=failed peer_lease=0 peer_reserved=0
TESSRYN_K03_SMP_BUDGET_STOP ap_ack=1 start=30117900 end=32122800 cpu0=343534 stable0=343534 cpu1=541888 stable1=541888
TESSRYN_K03_SMP_USER_PAYLOAD cpu=0 phase=after sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_USER_PAYLOAD cpu=1 phase=after sha256=c595d373170e20485aff7face3781e2dfcc64515619fd917710da7f6a451e8cc
TESSRYN_K03_SMP_BUDGET_PASS cpus=2 rounds=1 irqs=2 consumed=315280000 reserved=0 halted=1 retained=all
""",
}


def rows(raw, kind, user=False):
    prefix = b"TESSRYN_K03_SMP_" + (b"USER_" if user else b"BUDGET_") + kind.encode() + b" "
    return [line for line in raw.splitlines(keepends=True) if line.startswith(prefix)]


def field(raw, kind, key, index=0, user=False):
    line = rows(raw, kind, user)[index]
    return re.search(rb"(?<= )" + key.encode() + rb"=([^ \n]+)", line)[1].decode()


def number(raw, kind, key, index=0, user=False):
    return int(field(raw, kind, key, index, user), 0)


def mutate(raw, kind, key, value, index=0, user=False):
    line = rows(raw, kind, user)[index]
    replaced, count = re.subn(rb"(?<= )" + key.encode() + rb"=[^ \n]+", key.encode() + b"=" + str(value).encode(), line)
    assert count == 1 and raw.count(line) == 1
    return raw.replace(line, replaced, 1)


class BudgetTraceTests(unittest.TestCase):
    def parse(self, case="preempt", raw=None, binding=None):
        return parse_transcript(case, TRACES[case] if raw is None else raw, 33, b"", BINDINGS[case] if binding is None else binding)

    def reject(self, raw, case="preempt"):
        with self.assertRaises(ValueError): self.parse(case, raw)

    def test_real_cases_have_distinct_shared_budget_outcomes(self):
        normal, late = (self.parse(case) for case in CASES)
        self.assertEqual([normal["irq_count"], late["irq_count"]], [4, 2])
        self.assertEqual([normal["shared_grant_clips"], late["shared_grant_clips"]], [2, 1])
        self.assertFalse(normal["halted"]); self.assertTrue(late["halted"])
        self.assertFalse(normal["denied_redispatch"]); self.assertTrue(late["denied_redispatch"])
        self.assertLess(normal["consumed_ns"], SCENARIOS["preempt"].cap_ns)
        self.assertGreater(late["consumed_ns"], SCENARIOS["late"].cap_ns)
        self.assertGreater(late["reconciliation"][0]["peer_reserved"], 0)
        self.assertEqual(late["reconciliation"][1]["peer_reserved"], 0)
        self.assertEqual(normal["capture_authentication"], "unverified_offline")

    def test_process_case_and_compiled_binding_are_required(self):
        for code, stderr in ((None, b""), (True, b""), (0, b""), (33, b"host error")):
            with self.subTest(code=code), self.assertRaises(ValueError):
                parse_transcript("preempt", TRACES["preempt"], code, stderr, BINDINGS["preempt"])
        with self.assertRaises(ValueError): self.parse(binding=BINDINGS["late"])
        changed = copy.deepcopy(BINDINGS["preempt"]); changed["budget"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError): self.parse(binding=changed)
        self.reject(TRACES["preempt"][:-1]); self.reject(TRACES["preempt"] + b"EXTRA x=1\n")

    def test_ioapic_all_24_external_routes_are_masked(self):
        raw = TRACES["preempt"]; encoded = field(raw, "IRQS", "rtes")
        self.reject(mutate(raw, "IRQS", "rtes", "00000000" + encoded[8:]))
        self.reject(mutate(raw, "IRQS", "rtes", encoded[:-8]))
        self.reject(mutate(raw, "IRQS", "version", "0x160020"))

    def test_each_local_calibration_binds_hpet_and_idle_state(self):
        raw = TRACES["preempt"]
        for cpu in (0, 1):
            for key, value in (("divider", 8), ("first_count", 2), ("last_count", 1), ("stopped_count", 1), ("irr", 8), ("isr", 8)):
                with self.subTest(cpu=cpu, key=key): self.reject(mutate(raw, "CAL", key, value, cpu))
        self.reject(mutate(raw, "BEGIN", "epoch", number(raw, "CAL", "last_after") - 1))

    def test_shared_grant_clipping_and_cpu_task_generations(self):
        raw = TRACES["preempt"]
        for key, value in (("grant_ns", SCENARIOS["preempt"].quantum_ns), ("hard_ns", 0), ("task", 0), ("task_generation", 2), ("lease", 0)):
            with self.subTest(key=key): self.reject(mutate(raw, "GRANT", key, value, 1))
        self.reject(mutate(raw, "BATCH", "reserved", SCENARIOS["preempt"].cap_ns + 1))
        self.reject(mutate(raw, "BATCH", "consumed", 0, 1))

    def test_timer_origin_countdown_entry_and_mask_eoi_retirement(self):
        raw = TRACES["preempt"]
        for key, value in (("initial", 1), ("current", 1), ("irr_before", 8), ("isr_before", 4), ("isr_after", 8),
                           ("irr_after", 8), ("lvt_before", 66), ("lvt_after", 67), ("retire_count", 1), ("entry", 0),
                           ("capture", number(raw, "TIMER", "entry")), ("retired", number(raw, "TIMER", "capture") - 1)):
            with self.subTest(key=key): self.reject(mutate(raw, "TIMER", key, value))

    def test_late_timer_still_requires_entry_before_hard_bound(self):
        raw = TRACES["late"]
        hard_entry = number(raw, "BEGIN", "epoch") + number(raw, "GRANT", "hard_ns") // 10
        with self.assertRaisesRegex(ValueError, "timer entry"): self.parse("late", mutate(raw, "TIMER", "entry", hard_entry))

    def test_ap_progress_and_expiry_bound_prove_overlap_each_round(self):
        raw = TRACES["preempt"]
        self.reject(mutate(raw, "BATCH", "ap_ready_heartbeat", number(raw, "TIMER", "heartbeat_after", 1), 1))
        self.reject(mutate(raw, "TIMER", "peer_heartbeat", number(raw, "TIMER", "heartbeat_after", 1) + 1))
        earliest_ap = number(raw, "TIMER", "arm_before", 1) + ((number(raw, "TIMER", "initial", 1) + 1) * 16) // 10
        changed = mutate(raw, "TIMER", "retired", earliest_ap)
        changed = mutate(changed, "TIMER", "capture", earliest_ap - 2)
        with self.assertRaisesRegex(ValueError, "actual overlapping CPL3 execution"): self.parse(raw=changed)

    def test_saved_resume_rip_and_full_actual_cpl3_state(self):
        raw = TRACES["preempt"]
        self.reject(mutate(raw, "TIMER", "resume_rip", hex(PROFILE["user_code"]), 2))
        base = PROFILE["user_code"] + BINDINGS["preempt"]["context"]["program"]["offsets"]["loop_start"]
        self.reject(mutate(raw, "TRAP", "rip", hex(base + 1), user=True))
        for key, value in (("cs", 8), ("ss", 16), ("generation", 2), ("vector", 66), ("kernel_cr3", 1), ("frame", 1), ("fp", 1)):
            with self.subTest(key=key): self.reject(mutate(raw, "TRAP", key, value, user=True))
        for key in ("gpr", "fp_image"):
            image = bytearray.fromhex(field(raw, "TRAP", key, user=True)); image[-1] ^= 1
            self.reject(mutate(raw, "TRAP", key, image.hex(), user=True))

    def test_private_roots_and_page_walk_permissions_remain_bound(self):
        raw = TRACES["late"]
        self.reject(mutate(raw, "SPACE", "root", field(raw, "SPACE", "root", user=True), 1, True), "late")
        writable_code = number(raw, "WALK", "e3", user=True) | 2
        self.reject(mutate(raw, "WALK", "e3", hex(writable_code), user=True), "late")

    def test_late_full_charge_sticky_halt_and_peer_reservation_order(self):
        raw = TRACES["late"]
        for key, value in (("elapsed_ns", 40_000_000), ("consumed", 40_000_000), ("halted", 0), ("state", "exhausted"),
                           ("peer_lease", 0), ("peer_reserved", 0), ("reserved", 0)):
            with self.subTest(key=key): self.reject(mutate(raw, "ACCOUNT", key, value), "late")
        denied, = rows(raw, "DENY")
        self.reject(raw.replace(denied, b"", 1), "late")
        self.reject(mutate(raw, "DENY", "peer_reserved", 0), "late")
        first, second = rows(raw, "ACCOUNT")
        self.reject(raw.replace(first, second, 1).replace(denied + second, denied + first, 1), "late")

    def test_terminal_ap_ack_heartbeats_and_retained_payloads(self):
        for case in CASES:
            raw = TRACES[case]
            for key, value in (("ap_ack", 0), ("stable0", 0), ("stable1", 0), ("end", number(raw, "STOP", "start") + 1)):
                self.reject(mutate(raw, "STOP", key, value), case)
            self.reject(mutate(raw, "PAYLOAD", "sha256", "0" * 64, 3, True), case)
            self.reject(mutate(raw, "PASS", "reserved", 1), case)


if __name__ == "__main__": unittest.main()
