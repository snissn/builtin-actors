use fvm_ipld_encoding::RawBytes;
use fvm_shared::bigint::BigInt;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::sector::SectorNumber;
use fvm_shared::{ActorID, clock::ChainEpoch};

use fil_actor_miner::ext::verifreg::{AllocationClaim, SectorAllocationClaims};
use fil_actor_miner::{
    DataActivationNotification, PieceChange, SectorChanges, State, daily_proof_fee,
};
use fil_actor_miner::{ProveReplicaUpdates3Return, SectorOnChainInfo};
use fil_actors_runtime::cbor::serialize;
use fil_actors_runtime::test_utils::{MockRuntime, expect_abort_contains_message};
use fil_actors_runtime::{BatchReturn, EPOCHS_IN_DAY, STORAGE_MARKET_ACTOR_ADDR, runtime::Runtime};
use num_traits::Zero;
use util::*;

mod util;

const CLIENT_ID: ActorID = 1000;
const DEFAULT_SECTOR_EXPIRATION_DAYS: ChainEpoch = 220;
const FIRST_SECTOR_NUMBER: SectorNumber = 100;

#[test]
fn update_batch() {
    let (h, rt, sectors) = setup_empty_sectors(4);

    // Reduce the circulating supply. We expect the fees to stay the same after replica update even
    // if the circulating supply changes.
    rt.set_circulating_supply(TokenAmount::from_whole(200_000));

    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    // Update in batch, each with a single piece.
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, 0, 0, 0)]), // No alloc or deal
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 1000, 0)]), // Just an alloc
        make_update_manifest(&st, store, snos[2], &[(piece_size, 0, 0, 2000)]), // Just a deal
        make_update_manifest(&st, store, snos[3], &[(piece_size, CLIENT_ID, 1001, 2001)]), // Alloc and deal
    ];

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, claims, notifications) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);

    // Explicitly verify claims match what we expect.
    assert_eq!(
        vec![
            SectorAllocationClaims {
                sector: snos[0],
                expiry: sectors[0].expiration,
                claims: vec![],
            },
            SectorAllocationClaims {
                sector: snos[1],
                expiry: sectors[1].expiration,
                claims: vec![AllocationClaim {
                    client: CLIENT_ID,
                    allocation_id: 1000,
                    data: sector_updates[1].pieces[0].cid,
                    size: sector_updates[1].pieces[0].size,
                }],
            },
            SectorAllocationClaims {
                sector: snos[2],
                expiry: sectors[2].expiration,
                claims: vec![],
            },
            SectorAllocationClaims {
                sector: snos[3],
                expiry: sectors[3].expiration,
                claims: vec![AllocationClaim {
                    client: CLIENT_ID,
                    allocation_id: 1001,
                    data: sector_updates[3].pieces[0].cid,
                    size: sector_updates[3].pieces[0].size,
                }],
            },
        ],
        claims
    );

    // Explicitly verify notifications match what we expect.
    assert_eq!(
        vec![
            SectorChanges {
                sector: snos[2],
                minimum_commitment_epoch: sectors[2].expiration,
                added: vec![PieceChange {
                    data: sector_updates[2].pieces[0].cid,
                    size: sector_updates[2].pieces[0].size,
                    payload: serialize(&2000, "").unwrap(),
                },],
            },
            SectorChanges {
                sector: snos[3],
                minimum_commitment_epoch: sectors[3].expiration,
                added: vec![PieceChange {
                    data: sector_updates[3].pieces[0].cid,
                    size: sector_updates[3].pieces[0].size,
                    payload: serialize(&2001, "").unwrap(),
                },],
            },
        ],
        notifications
    );

    let sectors_after = snos.iter().map(|sno| h.get_sector(&rt, *sno)).collect::<Vec<_>>();
    let mut total_fees = TokenAmount::zero();
    for (i, (before, after)) in sectors.iter().zip(&sectors_after).enumerate() {
        // Sectors with odd indices (1 and 3) are full of verified data, even indices (0 and 2) are not
        let has_verified = i % 2 == 1;

        verify_weights(
            &rt,
            &h,
            before.sector_number,
            if has_verified { 0 } else { piece_size },
            if has_verified { piece_size } else { 0 },
        );

        // Check daily fees - if we added verified data, we expect the fees to be x10
        let expected_fee = &before.daily_fee * if has_verified { 10 } else { 1 };
        assert_eq!(
            expected_fee, after.daily_fee,
            "daily fees differ for sector {}",
            before.sector_number
        );

        total_fees += &after.daily_fee;
    }

    let (deadline_index, partition_index) = st.find_sector(rt.store(), snos[0]).unwrap();
    // check the deadline and partition state is correct for the replaced sector's fee
    let (deadline, partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);

    // deadline has the total fees for all sectors
    assert_eq!(total_fees, deadline.daily_fee);

    // partition expiration queue has the total fees for all sectors as a deduction
    let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
    let quantized_expiration = quant.quantize_up(sectors_after[0].expiration);
    let p_queue = h.collect_partition_expirations(&rt, &partition);
    let entry = p_queue.get(&quantized_expiration).unwrap().clone();
    assert_eq!(total_fees, entry.fee_deduction);

    h.check_state(&rt);
}

#[test]
fn update_fee() {
    let (h, rt) = setup_basic();

    // Set the circulating supply to 0 to get no fees.
    rt.set_circulating_supply(TokenAmount::zero());
    let sector_expiry = *rt.epoch.borrow() + DEFAULT_SECTOR_EXPIRATION_DAYS * EPOCHS_IN_DAY;
    let sectors = onboard_empty_sectors(&rt, &h, sector_expiry, FIRST_SECTOR_NUMBER, 4);
    let st: State = h.get_state(&rt);
    let (deadline_index, partition_index) =
        st.find_sector(rt.store(), sectors[0].sector_number).unwrap();
    // check the deadline and partition state is correct for the replaced sector's fee
    let (deadline, partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);

    // sanity check the fee state
    // 1. sectors have no fees
    assert!(sectors.iter().all(|s| s.daily_fee.is_zero()));
    // 2. deadline has no fees
    assert!(deadline.daily_fee.is_zero());
    // 3. expiration queue has no fees
    let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
    let quantized_expiration = quant.quantize_up(sectors[0].expiration);
    let p_queue = h.collect_partition_expirations(&rt, &partition);
    let entry = p_queue.get(&quantized_expiration).unwrap().clone();
    assert!(entry.fee_deduction.is_zero());

    // Now set the circulating supply to a non-zero value. Snapping should change the daily fee.
    let new_circulating_supply = TokenAmount::from_whole(500_000);
    rt.set_circulating_supply(new_circulating_supply.clone());

    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    // Update in batch, each with a single piece.
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, 0, 0, 0)]), // No alloc or deal
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 1000, 0)]), // Just an alloc
        make_update_manifest(&st, store, snos[2], &[(piece_size, 0, 0, 2000)]), // Just a deal
        make_update_manifest(&st, store, snos[3], &[(piece_size, CLIENT_ID, 1001, 2001)]), // Alloc and deal
    ];

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, claims, notifications) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);

    // Explicitly verify claims match what we expect.
    assert_eq!(
        vec![
            SectorAllocationClaims {
                sector: snos[0],
                expiry: sectors[0].expiration,
                claims: vec![],
            },
            SectorAllocationClaims {
                sector: snos[1],
                expiry: sectors[1].expiration,
                claims: vec![AllocationClaim {
                    client: CLIENT_ID,
                    allocation_id: 1000,
                    data: sector_updates[1].pieces[0].cid,
                    size: sector_updates[1].pieces[0].size,
                }],
            },
            SectorAllocationClaims {
                sector: snos[2],
                expiry: sectors[2].expiration,
                claims: vec![],
            },
            SectorAllocationClaims {
                sector: snos[3],
                expiry: sectors[3].expiration,
                claims: vec![AllocationClaim {
                    client: CLIENT_ID,
                    allocation_id: 1001,
                    data: sector_updates[3].pieces[0].cid,
                    size: sector_updates[3].pieces[0].size,
                }],
            },
        ],
        claims
    );

    // Explicitly verify notifications match what we expect.
    assert_eq!(
        vec![
            SectorChanges {
                sector: snos[2],
                minimum_commitment_epoch: sectors[2].expiration,
                added: vec![PieceChange {
                    data: sector_updates[2].pieces[0].cid,
                    size: sector_updates[2].pieces[0].size,
                    payload: serialize(&2000, "").unwrap(),
                },],
            },
            SectorChanges {
                sector: snos[3],
                minimum_commitment_epoch: sectors[3].expiration,
                added: vec![PieceChange {
                    data: sector_updates[3].pieces[0].cid,
                    size: sector_updates[3].pieces[0].size,
                    payload: serialize(&2001, "").unwrap(),
                },],
            },
        ],
        notifications
    );

    // When checking sector daily_fee, for a reference we'll calculate the fee for a fully verified
    // sector and divide as required
    let full_verified_fee = daily_proof_fee(
        &rt.policy,
        &new_circulating_supply,
        &BigInt::from(h.sector_size as u64 * 10),
    );

    let sectors_after = snos.iter().map(|sno| h.get_sector(&rt, *sno)).collect::<Vec<_>>();
    let mut total_fees = TokenAmount::zero();
    for (i, (before, after)) in sectors.iter().zip(&sectors_after).enumerate() {
        // Sectors with odd indices (1 and 3) are full of verified data, even indices (0 and 2) are not
        let has_verified = i % 2 == 1;

        verify_weights(
            &rt,
            &h,
            before.sector_number,
            if has_verified { 0 } else { piece_size },
            if has_verified { piece_size } else { 0 },
        );

        // Check daily fees - for unverified sectors, the full verified fee is divided by 10
        let expected_fee = full_verified_fee.div_floor(if has_verified { 1 } else { 10 });
        assert_eq!(
            expected_fee, after.daily_fee,
            "daily fees differ for sector {}",
            before.sector_number
        );

        total_fees += &after.daily_fee;
    }

    let (deadline_index, partition_index) = st.find_sector(rt.store(), snos[0]).unwrap();
    // check the deadline and partition state is correct for the replaced sector's fee
    let (deadline, partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);

    // deadline has the total fees for all sectors
    assert_eq!(total_fees, deadline.daily_fee);

    // partition expiration queue has the total fees for all sectors as a deduction
    let p_queue = h.collect_partition_expirations(&rt, &partition);
    let entry = p_queue.get(&quantized_expiration).unwrap().clone();
    assert_eq!(total_fees, entry.fee_deduction);

    h.check_state(&rt);
}

#[test]
fn multiple_pieces_in_sector() {
    let (h, rt, sectors) = setup_empty_sectors(2);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64 / 2; // Half-sector pieces
    let sector_updates = vec![
        make_update_manifest(
            &st,
            store,
            snos[0],
            &[(piece_size, CLIENT_ID, 1000, 2000), (piece_size, CLIENT_ID, 1001, 2001)],
        ),
        make_update_manifest(
            &st,
            store,
            snos[1],
            &[(piece_size, CLIENT_ID, 1002, 2002), (piece_size, CLIENT_ID, 0, 0)], // no alloc/deal
        ),
    ];

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, claims, notifications) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&[ExitCode::OK, ExitCode::OK], &result);

    // Explicitly verify claims match what we expect.
    assert_eq!(
        vec![
            SectorAllocationClaims {
                sector: snos[0],
                expiry: sectors[0].expiration,
                claims: vec![
                    AllocationClaim {
                        client: CLIENT_ID,
                        allocation_id: 1000,
                        data: sector_updates[0].pieces[0].cid,
                        size: sector_updates[0].pieces[0].size,
                    },
                    AllocationClaim {
                        client: CLIENT_ID,
                        allocation_id: 1001,
                        data: sector_updates[0].pieces[1].cid,
                        size: sector_updates[0].pieces[1].size,
                    },
                ],
            },
            SectorAllocationClaims {
                sector: snos[1],
                expiry: sectors[1].expiration,
                claims: vec![AllocationClaim {
                    client: CLIENT_ID,
                    allocation_id: 1002,
                    data: sector_updates[1].pieces[0].cid,
                    size: sector_updates[1].pieces[0].size,
                }],
            },
        ],
        claims
    );

    // Explicitly verify notifications match what we expect.
    assert_eq!(
        vec![
            SectorChanges {
                sector: snos[0],
                minimum_commitment_epoch: sectors[0].expiration,
                added: vec![
                    PieceChange {
                        data: sector_updates[0].pieces[0].cid,
                        size: sector_updates[0].pieces[0].size,
                        payload: serialize(&2000, "").unwrap(),
                    },
                    PieceChange {
                        data: sector_updates[0].pieces[1].cid,
                        size: sector_updates[0].pieces[1].size,
                        payload: serialize(&2001, "").unwrap(),
                    },
                ],
            },
            SectorChanges {
                sector: snos[1],
                minimum_commitment_epoch: sectors[1].expiration,
                added: vec![PieceChange {
                    data: sector_updates[1].pieces[0].cid,
                    size: sector_updates[1].pieces[0].size,
                    payload: serialize(&2002, "").unwrap(),
                },],
            },
        ],
        notifications
    );

    verify_weights(&rt, &h, snos[0], 0, piece_size * 2);
    verify_weights(&rt, &h, snos[1], piece_size, piece_size);
    h.check_state(&rt);
}

#[test]
fn multiple_notifs_for_piece() {
    let (h, rt, sectors) = setup_empty_sectors(2);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64 / 2;
    let mut sector_updates = vec![
        make_update_manifest(
            &st,
            store,
            snos[0],
            &[(piece_size, CLIENT_ID, 0, 0), (piece_size, CLIENT_ID, 0, 0)],
        ),
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 0, 0)]),
    ];
    // 2 notifications for sector[0], piece[0]
    sector_updates[0].pieces[0].notify.push(DataActivationNotification {
        address: STORAGE_MARKET_ACTOR_ADDR,
        payload: RawBytes::from(vec![6, 6, 6, 6]),
    });
    sector_updates[0].pieces[0].notify.push(DataActivationNotification {
        address: STORAGE_MARKET_ACTOR_ADDR,
        payload: RawBytes::from(vec![7, 7, 7, 7]),
    });
    // One notification for sector[0], piece[1]
    sector_updates[0].pieces[1].notify.push(DataActivationNotification {
        address: STORAGE_MARKET_ACTOR_ADDR,
        payload: RawBytes::from(vec![8, 8, 8, 8]),
    });
    // One notification for sector[1], piece[0]
    sector_updates[1].pieces[0].notify.push(DataActivationNotification {
        address: STORAGE_MARKET_ACTOR_ADDR,
        payload: RawBytes::from(vec![9, 9, 9, 9]),
    });

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, _, notifications) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&[ExitCode::OK, ExitCode::OK], &result);

    // Explicitly verify notifications match what we expect.
    assert_eq!(
        vec![
            SectorChanges {
                sector: snos[0],
                minimum_commitment_epoch: sectors[0].expiration,
                added: vec![
                    PieceChange {
                        data: sector_updates[0].pieces[0].cid,
                        size: sector_updates[0].pieces[0].size,
                        payload: RawBytes::from(vec![6, 6, 6, 6]),
                    },
                    PieceChange {
                        data: sector_updates[0].pieces[0].cid,
                        size: sector_updates[0].pieces[0].size,
                        payload: RawBytes::from(vec![7, 7, 7, 7]),
                    },
                    PieceChange {
                        data: sector_updates[0].pieces[1].cid,
                        size: sector_updates[0].pieces[1].size,
                        payload: RawBytes::from(vec![8, 8, 8, 8]),
                    },
                ],
            },
            SectorChanges {
                sector: snos[1],
                minimum_commitment_epoch: sectors[1].expiration,
                added: vec![PieceChange {
                    data: sector_updates[1].pieces[0].cid,
                    size: sector_updates[1].pieces[0].size,
                    payload: RawBytes::from(vec![9, 9, 9, 9]),
                },],
            },
        ],
        notifications
    );

    verify_weights(&rt, &h, snos[0], piece_size * 2, 0);
    verify_weights(&rt, &h, snos[1], piece_size, 0);
    h.check_state(&rt);
}

#[test]
fn cant_update_nonempty_sector() {
    let (h, rt) = setup_basic();

    // Onboard a non-empty sector
    let sector_expiry = *rt.epoch.borrow() + DEFAULT_SECTOR_EXPIRATION_DAYS * EPOCHS_IN_DAY;
    let challenge = *rt.epoch.borrow();
    let precommits = make_fake_precommits(
        &h,
        FIRST_SECTOR_NUMBER,
        challenge - 1,
        sector_expiry,
        &[&[h.sector_size as u64]], // A piece fills the sector.
    );
    let sectors = onboard_sectors(&rt, &h, &precommits);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();

    // Attempt to update
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let sector_updates =
        vec![make_update_manifest(&st, store, snos[0], &[(h.sector_size as u64, 0, 0, 0)])];

    let cfg = ProveReplicaUpdatesConfig::default();
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        "cannot update sector with non-zero data",
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg),
    );
    h.check_state(&rt);
}

// See prove_replica_failures_test.rs for tests where requiring success is set to true,
// and a single failure aborts the entire batch.
#[test]
fn invalid_update_dropped() {
    let (h, rt, sectors) = setup_empty_sectors(2);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    let mut sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, CLIENT_ID, 1000, 2000)]),
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 1001, 20001)]),
    ];
    sector_updates[0].deadline += 1; // Invalid update

    let cfg = ProveReplicaUpdatesConfig { validation_failure: vec![0], ..Default::default() };
    let (result, claims, notifications) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, false, false, cfg).unwrap();
    assert_update_result(&[ExitCode::USR_ILLEGAL_ARGUMENT, ExitCode::OK], &result);

    // Sector 0: no change.
    verify_weights(&rt, &h, snos[0], 0, 0);
    // Sector 1: verified weight.
    verify_weights(&rt, &h, snos[1], 0, piece_size);
    assert_eq!(1, claims.len());
    assert_eq!(snos[1], claims[0].sector);
    assert_eq!(1, notifications.len());
    assert_eq!(snos[1], notifications[0].sector);
    h.check_state(&rt);
}

#[test]
fn invalid_proof_dropped() {
    let (h, rt, sectors) = setup_empty_sectors(2);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, CLIENT_ID, 1000, 2000)]),
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 1001, 20001)]),
    ];

    let cfg = ProveReplicaUpdatesConfig { proof_failure: vec![0], ..Default::default() };
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, false, false, cfg).unwrap();
    assert_update_result(&[ExitCode::USR_ILLEGAL_ARGUMENT, ExitCode::OK], &result);

    verify_weights(&rt, &h, snos[0], 0, 0);
    verify_weights(&rt, &h, snos[1], 0, piece_size);
    h.check_state(&rt);
}

#[test]
fn invalid_claim_dropped() {
    let (h, rt, sectors) = setup_empty_sectors(2);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, CLIENT_ID, 1000, 2000)]),
        make_update_manifest(&st, store, snos[1], &[(piece_size, CLIENT_ID, 1001, 20001)]),
    ];

    let cfg = ProveReplicaUpdatesConfig { claim_failure: vec![0], ..Default::default() };
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, false, false, cfg).unwrap();
    assert_update_result(&[ExitCode::USR_ILLEGAL_ARGUMENT, ExitCode::OK], &result);

    verify_weights(&rt, &h, snos[0], 0, 0);
    verify_weights(&rt, &h, snos[1], 0, piece_size);
    h.check_state(&rt);
}

#[test]
fn aborted_notification_dropped() {
    let (h, rt, sectors) = setup_empty_sectors(3);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, 0, 0, 0)]),
        make_update_manifest(&st, store, snos[1], &[(piece_size, 0, 0, 2001)]),
        make_update_manifest(&st, store, snos[2], &[(piece_size, CLIENT_ID, 1000, 2002)]),
    ];

    let cfg = ProveReplicaUpdatesConfig {
        notification_result: Some(ExitCode::USR_UNSPECIFIED),
        ..Default::default()
    };
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, false, false, cfg).unwrap();
    // All sectors succeed anyway.
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);

    // All power is activated anyway.
    verify_weights(&rt, &h, snos[0], piece_size, 0);
    verify_weights(&rt, &h, snos[1], piece_size, 0);
    verify_weights(&rt, &h, snos[2], 0, piece_size);
    h.check_state(&rt);
}

#[test]
fn rejected_notification_dropped() {
    let (h, rt, sectors) = setup_empty_sectors(3);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();
    let piece_size = h.sector_size as u64;
    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[(piece_size, 0, 0, 0)]),
        make_update_manifest(&st, store, snos[1], &[(piece_size, 0, 0, 2001)]),
        make_update_manifest(&st, store, snos[2], &[(piece_size, CLIENT_ID, 1000, 2002)]),
    ];

    let cfg = ProveReplicaUpdatesConfig { notification_rejected: true, ..Default::default() };
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, false, false, cfg).unwrap();
    // All sectors succeed anyway.
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);

    // All power is activated anyway.
    verify_weights(&rt, &h, snos[0], piece_size, 0);
    verify_weights(&rt, &h, snos[1], piece_size, 0);
    verify_weights(&rt, &h, snos[2], 0, piece_size);
    h.check_state(&rt);
}

#[test]
fn update_to_empty() {
    let (h, rt, sectors) = setup_empty_sectors(1);
    let snos = sectors.iter().map(|s| s.sector_number).collect::<Vec<_>>();
    let st: State = h.get_state(&rt);
    let store = rt.store();

    let sector_updates = vec![
        make_update_manifest(&st, store, snos[0], &[]), // No pieces
    ];

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);
    verify_weights(&rt, &h, snos[0], 0, 0);

    // Because data is still empty, it's eligible for update again, this time with data.
    let piece_size = h.sector_size as u64;
    let sector_updates = vec![make_update_manifest(&st, store, snos[0], &[(piece_size, 0, 0, 0)])];

    let cfg = ProveReplicaUpdatesConfig::default();
    let (result, _, _) =
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg).unwrap();
    assert_update_result(&vec![ExitCode::OK; sectors.len()], &result);

    // But not again now it's non-empty.
    let cfg = ProveReplicaUpdatesConfig::default();
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        "cannot update sector with non-zero data",
        h.prove_replica_updates3_batch(&rt, &sector_updates, true, true, cfg),
    );

    h.check_state(&rt);
}

fn setup_basic() -> (ActorHarness, MockRuntime) {
    let h = ActorHarness::new_with_options(HarnessOptions::default());
    let rt = h.new_runtime();
    rt.set_balance(BIG_BALANCE.clone());
    h.construct_and_verify(&rt);
    (h, rt)
}

fn setup_empty_sectors(count: usize) -> (ActorHarness, MockRuntime, Vec<SectorOnChainInfo>) {
    let (h, rt) = setup_basic();
    let sector_expiry = *rt.epoch.borrow() + DEFAULT_SECTOR_EXPIRATION_DAYS * EPOCHS_IN_DAY;
    let sectors = onboard_empty_sectors(&rt, &h, sector_expiry, FIRST_SECTOR_NUMBER, count);
    (h, rt, sectors)
}

fn assert_update_result(expected: &[ExitCode], result: &ProveReplicaUpdates3Return) {
    assert_eq!(BatchReturn::of(expected), result.activation_results);
}
