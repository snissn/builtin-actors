use cid::Cid;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::bigint::BigInt;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::deal::DealID;
use fvm_shared::econ::TokenAmount;
use fvm_shared::piece::{PaddedPieceSize, PieceInfo};
use fvm_shared::sector::{RegisteredSealProof, SectorNumber, StoragePower};
use num_traits::Zero;

use export_macro::vm_test;
use fil_actor_market::Method as MarketMethod;
use fil_actor_miner::{
    CompactCommD, DataActivationNotification, PieceActivationManifest, PieceChange, PowerPair,
    ProveCommitSectors3Params, ProveReplicaUpdates3Params, SectorActivationManifest, SectorChanges,
    SectorContentChangedParams, SectorOnChainInfoFlags, SectorUpdateManifest,
    max_prove_commit_duration,
};
use fil_actor_miner::{Method as MinerMethod, VerifiedAllocationKey};
use fil_actor_verifreg::{
    AllocationClaim, AllocationRequest, ClaimAllocationsParams, Method as VerifregMethod,
    SectorAllocationClaims,
};
use fil_actors_runtime::cbor::serialize;
use fil_actors_runtime::runtime::Policy;
use fil_actors_runtime::test_utils::{make_piece_cid, make_sealed_cid};
use fil_actors_runtime::{
    EPOCHS_IN_DAY, EPOCHS_IN_YEAR, STORAGE_MARKET_ACTOR_ADDR, VERIFIED_REGISTRY_ACTOR_ADDR,
};
use vm_api::VM;
use vm_api::trace::{EmittedEvent, ExpectInvocation};
use vm_api::util::apply_ok;

use crate::deals::{DealBatcher, DealOptions};
use crate::expects::Expect;
use crate::util::{
    PrecommitMetadata, advance_by_deadline_to_epoch, advance_by_deadline_to_index,
    advance_to_proving_deadline, create_accounts, create_miner, datacap_create_allocations,
    market_add_balance, market_list_deals, market_list_sectors_deals,
    override_compute_unsealed_sector_cid, precommit_sectors_v2, sector_info, submit_windowed_post,
    verifreg_add_client, verifreg_add_verifier, verifreg_list_claims,
};

#[vm_test]
pub fn prove_replica_update2_test(v: &dyn VM) {
    override_compute_unsealed_sector_cid(v);

    let policy = Policy::default();
    let addrs = create_accounts(v, 3, &TokenAmount::from_whole(10_000));
    let seal_proof = RegisteredSealProof::StackedDRG32GiBV1P1;
    let sector_size = seal_proof.sector_size().unwrap();
    let (owner, worker, verifier, client) = (addrs[0], addrs[0], addrs[1], addrs[2]);
    let worker_id = worker.id().unwrap();
    let client_id = client.id().unwrap();
    let (maddr, _) = create_miner(
        v,
        &owner,
        &worker,
        seal_proof.registered_window_post_proof().unwrap(),
        &TokenAmount::from_whole(8_000),
    );
    let miner_id = maddr.id().unwrap();
    let claim_term_min = 2 * EPOCHS_IN_YEAR;
    let claim_term_max = claim_term_min + 90 * EPOCHS_IN_DAY;

    // Commit capacity sectors
    // Onboard a batch of sectors with a mix of data pieces, claims, and deals.
    let first_sector_number: SectorNumber = 100;
    let activations: Vec<SectorActivationManifest> = (0..5)
        .map(|i| SectorActivationManifest {
            sector_number: first_sector_number + i,
            pieces: vec![],
        })
        .collect();
    let meta: Vec<PrecommitMetadata> = (0..activations.len())
        .map(|_| PrecommitMetadata { deals: vec![], commd: CompactCommD::empty() })
        .collect();
    let sector_expiry = v.epoch() + claim_term_min + 60 * EPOCHS_IN_DAY;
    precommit_sectors_v2(
        v,
        meta.len(),
        meta,
        &worker,
        &maddr,
        seal_proof,
        first_sector_number,
        true,
        Some(sector_expiry),
    );

    let activation_epoch = v.epoch() + policy.pre_commit_challenge_delay + 1;
    advance_by_deadline_to_epoch(v, &maddr, activation_epoch);
    let proofs = vec![RawBytes::new(vec![1, 2, 3, 4]); activations.len()];
    let params = ProveCommitSectors3Params {
        sector_activations: activations,
        sector_proofs: proofs,
        aggregate_proof: RawBytes::default(),
        aggregate_proof_type: None,
        require_activation_success: true,
        require_notification_success: true,
    };
    apply_ok(
        v,
        &worker,
        &maddr,
        &TokenAmount::zero(),
        MinerMethod::ProveCommitSectors3 as u64,
        Some(params),
    );
    // Advance to proving period and submit post for the partition
    let (dlinfo, partition) = advance_to_proving_deadline(v, &maddr, first_sector_number);
    let deadline = dlinfo.index;
    submit_windowed_post(v, &worker, &maddr, dlinfo, partition, None);
    advance_by_deadline_to_index(v, &maddr, dlinfo.index + 1);
    let update_epoch = v.epoch();

    // Note: the allocation and claim configuration here are duplicated from the prove_commit2 test.
    // Register verifier and verified clients
    let datacap = StoragePower::from(32_u128 << 40);
    verifreg_add_verifier(v, &verifier, &datacap * 2);
    verifreg_add_client(v, &verifier, &client, datacap);

    // Publish two verified allocations for half a sector each.
    let full_piece_size = PaddedPieceSize(sector_size as u64);
    let half_piece_size = PaddedPieceSize(sector_size as u64 / 2);
    let allocs = vec![
        AllocationRequest {
            provider: miner_id,
            data: make_piece_cid(b"s2p1"),
            size: half_piece_size,
            term_min: claim_term_min,
            term_max: claim_term_max,
            expiration: 30 * EPOCHS_IN_DAY,
        },
        AllocationRequest {
            provider: miner_id,
            data: make_piece_cid(b"s2p2"),
            size: half_piece_size,
            term_min: claim_term_min,
            term_max: claim_term_max,
            expiration: 30 * EPOCHS_IN_DAY,
        },
    ];
    let alloc_ids_s2 = datacap_create_allocations(v, &client, &allocs);

    // Publish a full-size deal
    let market_collateral = TokenAmount::from_whole(100);
    market_add_balance(v, &worker, &maddr, &market_collateral);
    market_add_balance(v, &client, &client, &market_collateral);
    let deal_start = v.epoch() + max_prove_commit_duration(&Policy::default(), seal_proof).unwrap();
    let opts = DealOptions { deal_start, piece_size: full_piece_size, ..DealOptions::default() };
    let mut batcher = DealBatcher::new(v, opts);
    batcher.stage_with_label(client, maddr, "s3p1".to_string());
    let deal_ids_s3 = batcher.publish_ok(worker).ids;

    // Publish a half-size verified deal.
    // This creates a verified allocation automatically.
    let opts = DealOptions {
        deal_start,
        piece_size: half_piece_size,
        verified: true,
        deal_lifetime: claim_term_min, // The implicit claim term must fit sector life
        ..DealOptions::default()
    };
    let mut batcher = DealBatcher::new(v, opts);
    batcher.stage_with_label(client, maddr, "s4p1".to_string());
    let deal_ids_s4 = batcher.publish_ok(worker).ids;
    let alloc_ids_s4 = [alloc_ids_s2[alloc_ids_s2.len() - 1] + 1];

    // Update all sectors with a mix of data pieces, claims, and deals.
    let first_sector_number: SectorNumber = 100;
    let manifests = vec![
        // Sector 0: no pieces (CC sector)
        SectorUpdateManifest {
            sector: first_sector_number,
            deadline,
            partition,
            pieces: vec![],
            new_sealed_cid: make_sealed_cid(b"s0"),
        },
        // Sector 1: one piece, no claim or deal.
        SectorUpdateManifest {
            sector: first_sector_number + 1,
            deadline,
            partition,
            pieces: vec![PieceActivationManifest {
                cid: make_piece_cid(b"s1p1"),
                size: full_piece_size,
                verified_allocation_key: None,
                notify: vec![],
            }],
            new_sealed_cid: make_sealed_cid(b"s1"),
        },
        // Sector 2: two pieces for verified claims.
        SectorUpdateManifest {
            sector: first_sector_number + 2,
            deadline,
            partition,
            pieces: allocs
                .iter()
                .enumerate()
                .map(|(i, alloc)| PieceActivationManifest {
                    cid: alloc.data,
                    size: alloc.size,
                    verified_allocation_key: Some(VerifiedAllocationKey {
                        client: client_id,
                        id: alloc_ids_s2[i],
                    }),
                    notify: vec![],
                })
                .collect(),
            new_sealed_cid: make_sealed_cid(b"s2"),
        },
        // Sector 3: a full-size, unverified deal
        SectorUpdateManifest {
            sector: first_sector_number + 3,
            deadline,
            partition,
            pieces: vec![PieceActivationManifest {
                cid: make_piece_cid(b"s3p1"),
                size: full_piece_size,
                verified_allocation_key: None,
                notify: vec![DataActivationNotification {
                    address: STORAGE_MARKET_ACTOR_ADDR,
                    payload: serialize(&deal_ids_s3[0], "dealid").unwrap(),
                }],
            }],
            new_sealed_cid: make_sealed_cid(b"s3"),
        },
        // Sector 4: a half-sized, verified deal, and implicit empty space
        SectorUpdateManifest {
            sector: first_sector_number + 4,
            deadline,
            partition,
            pieces: vec![PieceActivationManifest {
                cid: make_piece_cid(b"s4p1"),
                size: half_piece_size,
                verified_allocation_key: Some(VerifiedAllocationKey {
                    client: client_id,
                    id: alloc_ids_s4[0],
                }),
                notify: vec![DataActivationNotification {
                    address: STORAGE_MARKET_ACTOR_ADDR,
                    payload: serialize(&deal_ids_s4[0], "deal id").unwrap(),
                }],
            }],
            new_sealed_cid: make_sealed_cid(b"s4"),
        },
    ];

    let claim_event_1 = Expect::build_verifreg_claim_event(
        "claim",
        alloc_ids_s2[0],
        client_id,
        miner_id,
        &allocs[0].data,
        allocs[0].size.0,
        claim_term_min,
        claim_term_max,
        v.epoch(),
        first_sector_number + 2,
    );
    let claim_event_2 = Expect::build_verifreg_claim_event(
        "claim",
        alloc_ids_s2[1],
        client_id,
        miner_id,
        &allocs[1].data,
        allocs[1].size.0,
        claim_term_min,
        claim_term_max,
        v.epoch(),
        first_sector_number + 2,
    );
    let claim_event_3 = Expect::build_verifreg_claim_event(
        "claim",
        alloc_ids_s4[0],
        client_id,
        miner_id,
        &manifests[4].pieces[0].cid,
        manifests[4].pieces[0].size.0,
        claim_term_min,
        claim_term_max,
        v.epoch(),
        first_sector_number + 4,
    );

    // Replica update
    let update_proof = seal_proof.registered_update_proof().unwrap();
    let proofs = vec![RawBytes::new(vec![1, 2, 3, 4]); manifests.len()];
    let params = ProveReplicaUpdates3Params {
        sector_updates: manifests.clone(),
        sector_proofs: proofs,
        aggregate_proof: RawBytes::default(),
        update_proofs_type: update_proof,
        aggregate_proof_type: None,
        require_activation_success: true,
        require_notification_success: true,
    };
    apply_ok(
        v,
        &worker,
        &maddr,
        &TokenAmount::zero(),
        MinerMethod::ProveReplicaUpdates3 as u64,
        Some(params.clone()),
    );
    let expected_power = StoragePower::from(
        manifests
            .iter()
            .flat_map(|m| m.pieces.iter().filter(|p| p.verified_allocation_key.is_some()))
            .map(|p| p.size.0 * 9)
            .sum::<u64>(),
    );

    let events: Vec<EmittedEvent> = manifests
        .iter()
        .map(|m| {
            let pieces: Vec<(Cid, u64)> = m.pieces.iter().map(|p| (p.cid, p.size.0)).collect();

            let pis: Vec<PieceInfo> =
                m.pieces.iter().map(|p| PieceInfo { cid: p.cid, size: p.size }).collect();

            let unsealed_cid: Option<Cid> = if pis.is_empty() {
                None
            } else {
                Some(v.primitives().compute_unsealed_sector_cid(seal_proof, &pis).unwrap())
            };

            Expect::build_sector_activation_event(
                "sector-updated",
                miner_id,
                m.sector,
                unsealed_cid,
                &pieces,
            )
        })
        .collect();

    ExpectInvocation {
        from: worker_id,
        to: maddr,
        method: MinerMethod::ProveReplicaUpdates3 as u64,
        params: Some(IpldBlock::serialize_cbor(&params).unwrap()),
        subinvocs: Some(vec![
            // Verified claims
            ExpectInvocation {
                from: miner_id,
                to: VERIFIED_REGISTRY_ACTOR_ADDR,
                method: VerifregMethod::ClaimAllocations as u64,
                params: Some(
                    IpldBlock::serialize_cbor(&ClaimAllocationsParams {
                        sectors: vec![
                            no_claims(first_sector_number, sector_expiry),
                            no_claims(first_sector_number + 1, sector_expiry),
                            SectorAllocationClaims {
                                sector: first_sector_number + 2,
                                expiry: sector_expiry,
                                claims: vec![
                                    AllocationClaim {
                                        client: client_id,
                                        allocation_id: alloc_ids_s2[0],
                                        data: allocs[0].data,
                                        size: allocs[0].size,
                                    },
                                    AllocationClaim {
                                        client: client_id,
                                        allocation_id: alloc_ids_s2[1],
                                        data: allocs[1].data,
                                        size: allocs[1].size,
                                    },
                                ],
                            },
                            no_claims(first_sector_number + 3, sector_expiry),
                            SectorAllocationClaims {
                                sector: first_sector_number + 4,
                                expiry: sector_expiry,
                                claims: vec![AllocationClaim {
                                    client: client_id,
                                    allocation_id: alloc_ids_s4[0],
                                    data: make_piece_cid(b"s4p1"),
                                    size: half_piece_size,
                                }],
                            },
                        ],
                        all_or_nothing: true,
                    })
                    .unwrap(),
                ),
                events: Some(vec![claim_event_1, claim_event_2, claim_event_3]),
                ..Default::default()
            },
            Expect::reward_this_epoch(miner_id),
            Expect::power_current_total(miner_id),
            Expect::power_update_pledge(miner_id, None),
            Expect::power_update_claim(miner_id, PowerPair::new(BigInt::zero(), expected_power)),
            // Market notifications.
            ExpectInvocation {
                from: miner_id,
                to: STORAGE_MARKET_ACTOR_ADDR,
                method: MarketMethod::SectorContentChangedExported as u64,
                params: Some(
                    IpldBlock::serialize_cbor(&SectorContentChangedParams {
                        sectors: vec![
                            SectorChanges {
                                sector: first_sector_number + 3,
                                minimum_commitment_epoch: sector_expiry,
                                added: vec![piece_change(b"s3p1", full_piece_size, &deal_ids_s3)],
                            },
                            SectorChanges {
                                sector: first_sector_number + 4,
                                minimum_commitment_epoch: sector_expiry,
                                added: vec![piece_change(b"s4p1", half_piece_size, &deal_ids_s4)],
                            },
                        ],
                    })
                    .unwrap(),
                ),
                value: Some(TokenAmount::zero()),
                subinvocs: Some(vec![]),
                events: Some(
                    deal_ids_s3
                        .iter()
                        .chain(deal_ids_s4.iter())
                        .map(|deal_id| {
                            Expect::build_market_event(
                                "deal-activated",
                                *deal_id,
                                client_id,
                                miner_id,
                            )
                        })
                        .collect::<Vec<_>>(),
                ),

                ..Default::default()
            },
        ]),
        events: Some(events),
        ..Default::default()
    }
    .matches(v.take_invocations().last().unwrap());

    // Checks on sector state.
    let sectors = manifests.iter().map(|m| sector_info(v, &maddr, m.sector)).collect::<Vec<_>>();
    for sector in &sectors {
        assert_eq!(activation_epoch, sector.activation);
        assert_eq!(update_epoch, sector.power_base_epoch);
        assert!(sector.flags.contains(SectorOnChainInfoFlags::SIMPLE_QA_POWER));
        assert!(sector.deprecated_deal_ids.is_empty());
    }
    let full_sector_weight =
        BigInt::from(full_piece_size.0 * (sector_expiry - update_epoch) as u64);
    assert_eq!(BigInt::zero(), sectors[0].deal_weight);
    assert_eq!(BigInt::zero(), sectors[0].verified_deal_weight);
    assert_eq!(full_sector_weight, sectors[1].deal_weight);
    assert_eq!(BigInt::zero(), sectors[1].verified_deal_weight);
    assert_eq!(BigInt::zero(), sectors[2].deal_weight);
    assert_eq!(full_sector_weight, sectors[2].verified_deal_weight);
    assert_eq!(full_sector_weight, sectors[3].deal_weight);
    assert_eq!(BigInt::zero(), sectors[3].verified_deal_weight);
    assert_eq!(BigInt::zero(), sectors[4].deal_weight);
    assert_eq!(full_sector_weight / 2, sectors[4].verified_deal_weight);

    // Brief checks on state consistency between actors.
    let claims = verifreg_list_claims(v, miner_id);
    assert_eq!(claims.len(), 3);
    assert_eq!(first_sector_number + 2, claims[&alloc_ids_s2[0]].sector);
    assert_eq!(first_sector_number + 2, claims[&alloc_ids_s2[1]].sector);
    assert_eq!(first_sector_number + 4, claims[&alloc_ids_s4[0]].sector);

    let deals = market_list_deals(v);
    assert_eq!(deals.len(), 2);
    assert_eq!(maddr, deals[&deal_ids_s3[0]].0.provider);
    assert_eq!(first_sector_number + 3, deals[&deal_ids_s3[0]].1.unwrap().sector_number);
    assert_eq!(maddr, deals[&deal_ids_s4[0]].0.provider);
    assert_eq!(first_sector_number + 4, deals[&deal_ids_s4[0]].1.unwrap().sector_number);

    let sector_deals = market_list_sectors_deals(v, &maddr);
    assert_eq!(sector_deals.len(), 2);
    assert_eq!(deal_ids_s3, sector_deals[&(first_sector_number + 3)]);
    assert_eq!(deal_ids_s4, sector_deals[&(first_sector_number + 4)]);
}

fn no_claims(sector: SectorNumber, expiry: ChainEpoch) -> SectorAllocationClaims {
    SectorAllocationClaims { sector, expiry, claims: vec![] }
}

fn piece_change(cid_seed: &[u8], piece_size: PaddedPieceSize, deal_ids: &[DealID]) -> PieceChange {
    PieceChange {
        data: make_piece_cid(cid_seed),
        size: piece_size,
        payload: serialize(&deal_ids[0], "deal id").unwrap(),
    }
}
