// Pure original page-table policy with synthetic physical addresses. No CPU,
// firmware, encoded pointer dereference or native isolation claim.
#![allow(dead_code)]
#[path = "../kernel/paging.rs"]
mod paging;
#[path = "../kernel/k02_paging.rs"]
mod k02_paging;
