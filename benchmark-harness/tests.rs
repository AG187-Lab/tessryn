use super::*;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn config_rejects_missing_duplicates_signs_overflow_and_bounds() {
    for values in [
        vec!["--samples"],
        vec!["--unknown", "1"],
        vec!["--samples", "1", "--samples", "2"],
        vec!["--samples", "0"],
        vec!["--samples", "10001"],
        vec!["--warmup", "10001"],
        vec!["--iterations", "0"],
        vec!["--iterations", "1000001"],
        vec!["--seed", "+1"],
        vec!["--seed", "-1"],
        vec!["--seed", "18446744073709551616"],
        vec!["--seed", " 1"],
    ] {
        assert!(
            parse_config(&arguments(&values)).is_err(),
            "accepted {values:?}"
        );
    }
    assert_eq!(parse_config(&[]).unwrap(), Config::default());
    assert_eq!(
        parse_config(&arguments(&[
            "--samples",
            "2",
            "--warmup",
            "0",
            "--iterations",
            "7",
            "--seed",
            "0"
        ]))
        .unwrap(),
        Config {
            samples: 2,
            warmup: 0,
            iterations: 7,
            seed: 0
        }
    );
    assert!(
        parse_config(&arguments(&[
            "--samples",
            "100",
            "--warmup",
            "20",
            "--iterations",
            "2000"
        ]))
        .is_err()
    );
    assert!(
        parse_config(&arguments(&[
            "--samples",
            "1",
            "--warmup",
            "0",
            "--iterations",
            "1000000"
        ]))
        .is_err()
    );
}

#[test]
fn ring_exhaustive_small_sequences_match_bounded_reference() {
    for bits in 0..1u32 << 12 {
        let mut queue = Ring::<3>::new();
        let mut reference = VecDeque::new();
        for index in 0..12 {
            if bits & (1 << index) != 0 {
                let expected = if reference.len() == 3 {
                    Err(index)
                } else {
                    reference.push_back(index);
                    Ok(())
                };
                assert_eq!(queue.push(index), expected);
            } else {
                assert_eq!(queue.pop(), reference.pop_front());
            }
            assert_eq!(queue.len(), reference.len());
        }
        while let Some(value) = reference.pop_front() {
            assert_eq!(queue.pop(), Some(value));
        }
        assert_eq!(queue.pop(), None);
    }
}

#[test]
fn ring_rejection_and_wrap_reference_checks_execute() {
    ring_self_check();
}

#[test]
fn actual_memory_policy_rejects_access_and_returns_charge_and_frames() {
    memory_self_check();
}

#[test]
fn byte_operations_check_every_output_byte() {
    byte_self_check();
}

#[test]
fn roundtrip_implementations_have_identical_values_and_operation_counts() {
    let config = Config {
        samples: 1,
        warmup: 0,
        iterations: 257,
        seed: u64::MAX,
    };
    for batch in [1, 8, 64] {
        let ring = queue_roundtrip(config, 0, batch, false);
        let reference = queue_roundtrip(config, 0, batch, true);
        assert_eq!(ring.checksum, reference.checksum);
        assert_eq!(ring.operations, 2 * config.iterations * batch as u64);
        assert_eq!(ring.operations, reference.operations);
    }
    for full in [false, true] {
        assert_eq!(
            queue_rejection(config, 0, full, false).checksum,
            queue_rejection(config, 0, full, true).checksum
        );
    }
}

#[test]
fn warmups_are_discarded_and_every_case_has_exact_indices_and_units() {
    let config = Config {
        samples: 3,
        warmup: 2,
        iterations: 17,
        seed: 42,
    };
    let samples = run_benchmarks(config);
    assert_eq!(samples.len(), config.samples as usize * cases_per_round());
    let mut groups = std::collections::BTreeMap::new();
    for item in samples {
        groups
            .entry((item.case, item.implementation))
            .or_insert_with(Vec::new)
            .push(item.sample_index);
        let multiplier = match item.case {
            "scheduler_reference_dispatch_cycle" | "scheduler_policy_dispatch_stop_cycle" => 2,
            "memory_allocate_revoke_release" => 3,
            "queue_roundtrip_batch_1" | "queue_roundtrip_batch_8" | "queue_roundtrip_batch_64" => {
                2 * item.batch_size
            }
            _ => 1,
        };
        assert_eq!(
            item.operations,
            if item.case == "scheduler_policy_dispatch_latency" {
                1
            } else {
                config.iterations * multiplier
            }
        );
        assert_eq!(
            item.sample_unit,
            if item.case == "scheduler_policy_dispatch_latency" {
                "single_operation"
            } else {
                "timed_batch"
            }
        );
        assert_eq!(
            item.bytes_per_operation,
            if item.case.ends_with("4096") {
                4096
            } else if item.case.ends_with("65536") {
                65_536
            } else {
                0
            }
        );
    }
    assert_eq!(groups.len(), cases_per_round());
    for indices in groups.values() {
        assert_eq!(indices, &[0, 1, 2]);
    }
}

#[test]
fn reference_rotation_and_metadata_samples_handle_long_batches() {
    let config = Config {
        samples: 1,
        warmup: 0,
        iterations: 1001,
        seed: 0,
    };
    let reference = scheduler_reference(config, 0);
    assert_eq!(reference.operations, 2002);
    let mut memory = Vec::new();
    memory_samples(config, 0, &mut memory);
    assert_eq!(memory[0].operations, 3003);
    assert_eq!(memory[0].checksum, 1001 * 1002 / 2);
    assert_eq!(memory[1].operations, 1001);
}

#[test]
fn serialization_uses_fixed_public_fields_only() {
    let config = Config {
        samples: 1,
        warmup: 0,
        iterations: 1,
        seed: 1,
    };
    let rendered = render_json(
        config,
        &[sample("known_case", "fixture", 0, 1, 1, 0, (7, 9))],
        &["check"],
        None,
    );
    assert_eq!(
        rendered,
        "{\"schema_version\":1,\"kind\":\"kernel_benchmark_raw\",\"clock\":\"std::time::Instant\",\"config\":{\"samples\":1,\"warmup\":0,\"iterations\":1,\"seed\":1},\"samples\":[{\"case\":\"known_case\",\"implementation\":\"fixture\",\"sample_index\":0,\"elapsed_ns\":7,\"operations\":1,\"checksum\":9,\"batch_size\":1,\"bytes_per_operation\":0,\"sample_unit\":\"timed_batch\"}],\"checks\":[\"check\"],\"logical_replay\":null}\n"
    );
}

#[cfg(scheduler_core)]
#[test]
fn actual_scheduler_reservations_stops_and_rejections_execute() {
    scheduler_policy_self_check();
}

#[cfg(scheduler_core)]
#[test]
fn actual_scheduler_cycle_checksum_matches_the_reference_without_clock_claims() {
    let config = Config {
        samples: 1,
        warmup: 0,
        iterations: 257,
        seed: u64::MAX,
    };
    let actual = scheduler_policy_cycle(config, 0);
    assert_eq!(actual.checksum, scheduler_reference(config, 0).checksum);
    let latency = scheduler_policy_dispatch(config, 0);
    assert_eq!(latency.checksum, config.seed);
    assert_eq!(
        (latency.operations, latency.sample_unit),
        (1, "single_operation")
    );
}

#[cfg(scheduler_core)]
#[test]
fn scheduled_arrivals_preserve_every_readiness_delay_and_the_undispatched_expiry() {
    let replay = scheduler_logical_replay();
    let expected = [
        ("short", 0, 0, 0),
        ("long", 0, 2, 2),
        ("burst", 3, 4, 1),
        ("long", 4, 6, 2),
        ("short", 2, 8, 6),
        ("long", 8, 9, 1),
        ("long", 11, 11, 0),
    ];
    assert_eq!(replay.episodes.len(), expected.len());
    for (index, (episode, (task, ready, dispatched, delay))) in
        replay.episodes.iter().zip(expected).enumerate()
    {
        assert_eq!(
            episode,
            &ReadyEpisode {
                task,
                ready_ns: ready,
                dispatch_ns: dispatched,
                delay_ns: delay,
                dispatch_index: index as u64
            }
        );
    }
    assert_eq!(
        replay.outcomes,
        vec![
            LogicalOutcome {
                task: "short",
                status: "completed",
                completed_ns: Some(9),
                consumed_ns: 3
            },
            LogicalOutcome {
                task: "long",
                status: "completed",
                completed_ns: Some(13),
                consumed_ns: 8
            },
            LogicalOutcome {
                task: "burst",
                status: "completed",
                completed_ns: Some(6),
                consumed_ns: 2
            },
            LogicalOutcome {
                task: "expires",
                status: "deadline_expired",
                completed_ns: None,
                consumed_ns: 0
            },
        ]
    );
    assert!(
        replay
            .episodes
            .iter()
            .all(|episode| episode.task != "expires")
    );
    assert_eq!(
        scheduler_logical_replay(),
        replay,
        "logical trace must be repeatable independent of host timing"
    );
    let rendered = render_json(Config::default(), &[], &[], Some(&replay));
    assert!(rendered.contains("\"clock\":\"synthetic_logical_ns\""));
    assert!(rendered.contains("\"completed_ns\":null,\"consumed_ns\":0"));
    assert!(!rendered.contains("\"elapsed_ns\""));
}
