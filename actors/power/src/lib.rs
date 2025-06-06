// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use fil_actors_runtime::reward::ThisEpochRewardReturn;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::bigint::bigint_ser::BigIntSer;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::{METHOD_CONSTRUCTOR, MethodNum};
use log::{debug, error};
use num_derive::FromPrimitive;
use num_traits::Zero;

use ext::init;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::runtime::{ActorCode, Runtime};
use fil_actors_runtime::{
    ActorDowncast, ActorError, CRON_ACTOR_ADDR, INIT_ACTOR_ADDR, Multimap, REWARD_ACTOR_ADDR,
    SYSTEM_ACTOR_ADDR, actor_dispatch, actor_error, deserialize_block, extract_send_result,
};

pub use self::policy::*;
pub use self::state::*;
pub use self::types::*;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

#[doc(hidden)]
pub mod ext;
mod policy;
mod state;
pub mod testing;
mod types;

// * Updated to specs-actors commit: 999e57a151cc7ada020ca2844b651499ab8c0dec (v3.0.1)

/// Storage power actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    /// Constructor for Storage Power Actor
    Constructor = METHOD_CONSTRUCTOR,
    CreateMiner = 2,
    UpdateClaimedPower = 3,
    EnrollCronEvent = 4,
    OnEpochTickEnd = 5,
    UpdatePledgeTotal = 6,
    // OnConsensusFault = 7, // Deprecated v2
    // SubmitPoRepForBulkVerify = 8, // Deprecated
    CurrentTotalPower = 9,
    // Method numbers derived from FRC-0042 standards
    CreateMinerExported = frc42_dispatch::method_hash!("CreateMiner"),
    NetworkRawPowerExported = frc42_dispatch::method_hash!("NetworkRawPower"),
    MinerRawPowerExported = frc42_dispatch::method_hash!("MinerRawPower"),
    MinerCountExported = frc42_dispatch::method_hash!("MinerCount"),
    MinerConsensusCountExported = frc42_dispatch::method_hash!("MinerConsensusCount"),
    MinerPowerExported = frc42_dispatch::method_hash!("MinerPower"),
}

pub const ERR_TOO_MANY_PROVE_COMMITS: ExitCode = ExitCode::new(32);

/// Storage Power Actor
pub struct Actor;

impl Actor {
    /// Constructor for StoragePower actor
    fn constructor(rt: &impl Runtime) -> Result<(), ActorError> {
        rt.validate_immediate_caller_is(std::iter::once(&SYSTEM_ACTOR_ADDR))?;

        let st = State::new(rt.store()).map_err(|e| {
            e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "Failed to create power actor state")
        })?;
        rt.create(&st)?;
        Ok(())
    }

    fn create_miner(
        rt: &impl Runtime,
        params: CreateMinerParams,
    ) -> Result<CreateMinerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let value = rt.message().value_received();

        let constructor_params = RawBytes::serialize(ext::miner::MinerConstructorParams {
            owner: params.owner,
            worker: params.worker,
            window_post_proof_type: params.window_post_proof_type,
            peer_id: params.peer,
            multi_addresses: params.multiaddrs,
            control_addresses: Default::default(),
        })?;

        let miner_actor_code_cid = rt.get_code_cid_for_type(Type::Miner);
        let ext::init::ExecReturn { id_address, robust_address } =
            deserialize_block(extract_send_result(rt.send_simple(
                &INIT_ACTOR_ADDR,
                ext::init::EXEC_METHOD,
                IpldBlock::serialize_cbor(&init::ExecParams {
                    code_cid: miner_actor_code_cid,
                    constructor_params,
                })?,
                value,
            ))?)?;

        let window_post_proof_type = params.window_post_proof_type;
        rt.transaction(|st: &mut State, rt| {
            let mut claims = st.load_claims(rt.store())?;
            set_claim(
                &mut claims,
                &id_address,
                Claim {
                    window_post_proof_type,
                    quality_adj_power: Default::default(),
                    raw_byte_power: Default::default(),
                },
            )?;
            st.miner_count += 1;

            st.update_stats_for_new_miner(rt.policy(), window_post_proof_type).map_err(|e| {
                actor_error!(
                    illegal_state,
                    "failed to update power stats for new miner {}: {}",
                    &id_address,
                    e
                )
            })?;

            st.save_claims(&mut claims)?;
            Ok(())
        })?;
        Ok(CreateMinerReturn { id_address, robust_address })
    }

    /// Adds or removes claimed power for the calling actor.
    /// May only be invoked by a miner actor.
    fn update_claimed_power(
        rt: &impl Runtime,
        params: UpdateClaimedPowerParams,
    ) -> Result<(), ActorError> {
        rt.validate_immediate_caller_type(std::iter::once(&Type::Miner))?;
        let miner_addr = rt.message().caller();

        rt.transaction(|st: &mut State, rt| {
            let mut claims = st.load_claims(rt.store())?;

            st.add_to_claim(
                rt.policy(),
                &mut claims,
                &miner_addr,
                &params.raw_byte_delta,
                &params.quality_adjusted_delta,
            )?;

            st.save_claims(&mut claims)?;
            Ok(())
        })
    }

    fn enroll_cron_event(
        rt: &impl Runtime,
        params: EnrollCronEventParams,
    ) -> Result<(), ActorError> {
        rt.validate_immediate_caller_type(std::iter::once(&Type::Miner))?;
        let miner_event = CronEvent {
            miner_addr: rt.message().caller(),
            callback_payload: params.payload.clone(),
        };

        // Ensure it is not possible to enter a large negative number which would cause
        // problems in cron processing.
        if params.event_epoch < 0 {
            return Err(actor_error!(illegal_argument;
                "cron event epoch {} cannot be less than zero", params.event_epoch));
        }

        rt.transaction(|st: &mut State, rt| {
            let mut events = Multimap::from_root(
                rt.store(),
                &st.cron_event_queue,
                CRON_QUEUE_HAMT_BITWIDTH,
                CRON_QUEUE_AMT_BITWIDTH,
            )
            .map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load cron events")
            })?;

            st.append_cron_event(&mut events, params.event_epoch, miner_event).map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to enroll cron event")
            })?;

            st.cron_event_queue = events.root().map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to flush cron events")
            })?;
            Ok(())
        })?;
        Ok(())
    }

    fn on_epoch_tick_end(rt: &impl Runtime) -> Result<(), ActorError> {
        rt.validate_immediate_caller_is(std::iter::once(&CRON_ACTOR_ADDR))?;

        let rewret: ThisEpochRewardReturn = deserialize_block(
            extract_send_result(rt.send_simple(
                &REWARD_ACTOR_ADDR,
                ext::reward::Method::ThisEpochReward as MethodNum,
                None,
                TokenAmount::zero(),
            ))
            .map_err(|e| e.wrap("failed to check epoch baseline power"))?,
        )?;

        Self::process_deferred_cron_events(rt, rewret)?;

        let this_epoch_raw_byte_power = rt.transaction(|st: &mut State, _| {
            let (raw_byte_power, qa_power) = st.current_total_power();
            st.this_epoch_pledge_collateral = st.total_pledge_collateral.clone();
            st.this_epoch_quality_adj_power = qa_power;
            st.this_epoch_raw_byte_power = raw_byte_power;
            // Can assume delta is one since cron is invoked every epoch.
            st.update_smoothed_estimate(1);

            Ok(IpldBlock::serialize_cbor(&BigIntSer(&st.this_epoch_raw_byte_power))?)
        })?;

        // Update network KPA in reward actor
        extract_send_result(rt.send_simple(
            &REWARD_ACTOR_ADDR,
            ext::reward::UPDATE_NETWORK_KPI,
            this_epoch_raw_byte_power,
            TokenAmount::zero(),
        ))
        .map_err(|e| e.wrap("failed to update network KPI with reward actor"))?;

        Ok(())
    }

    fn update_pledge_total(
        rt: &impl Runtime,
        params: UpdatePledgeTotalParams,
    ) -> Result<(), ActorError> {
        rt.validate_immediate_caller_type(std::iter::once(&Type::Miner))?;
        rt.transaction(|st: &mut State, rt| {
            st.validate_miner_has_claim(rt.store(), &rt.message().caller())?;
            st.add_pledge_total(params.pledge_delta);
            if st.total_pledge_collateral.is_negative() {
                return Err(actor_error!(
                    illegal_state,
                    "negative total pledge collateral {}",
                    st.total_pledge_collateral
                ));
            }
            Ok(())
        })
    }

    /// Returns the total power and pledge recorded by the power actor.
    /// The returned values are frozen during the cron tick before this epoch
    /// so that this method returns consistent values while processing all messages
    /// of an epoch.
    fn current_total_power(rt: &impl Runtime) -> Result<CurrentTotalPowerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        Ok(CurrentTotalPowerReturn {
            raw_byte_power: st.this_epoch_raw_byte_power,
            quality_adj_power: st.this_epoch_quality_adj_power,
            pledge_collateral: st.this_epoch_pledge_collateral,
            quality_adj_power_smoothed: st.this_epoch_qa_power_smoothed,
            ramp_start_epoch: st.ramp_start_epoch,
            ramp_duration_epochs: st.ramp_duration_epochs,
        })
    }

    /// Returns the total raw power of the network.
    /// This is defined as the sum of the active (i.e. non-faulty) byte commitments
    /// of all miners that have more than the consensus minimum amount of storage active.
    /// This value is static over an epoch, and does NOT get updated as messages are executed.
    /// It is recalculated after all messages at an epoch have been executed.
    fn network_raw_power(rt: &impl Runtime) -> Result<NetworkRawPowerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        Ok(NetworkRawPowerReturn { raw_byte_power: st.this_epoch_raw_byte_power })
    }

    /// Returns the raw power claimed by the specified miner,
    /// and whether the miner has more than the consensus minimum amount of storage active.
    /// The raw power is defined as the active (i.e. non-faulty) byte commitments of the miner.
    fn miner_raw_power(
        rt: &impl Runtime,
        params: MinerRawPowerParams,
    ) -> Result<MinerRawPowerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        let (raw_byte_power, meets_consensus_minimum) =
            st.miner_nominal_power_meets_consensus_minimum(rt.policy(), rt.store(), params.miner)?;

        Ok(MinerRawPowerReturn { raw_byte_power, meets_consensus_minimum })
    }

    /// Returns the total number of miners created, regardless of whether or not
    /// they have any pledged storage.
    fn miner_count(rt: &impl Runtime) -> Result<MinerCountReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        Ok(MinerCountReturn { miner_count: st.miner_count })
    }

    /// Returns the total number of miners that have more than the consensus minimum amount of storage active.
    /// Active means that the storage must not be faulty.
    fn miner_consensus_count(rt: &impl Runtime) -> Result<MinerConsensusCountReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        Ok(MinerConsensusCountReturn { miner_consensus_count: st.miner_above_min_power_count })
    }

    /// Returns the miner's quality-adjusted and raw power
    fn miner_power(
        rt: &impl Runtime,
        params: MinerPowerParams,
    ) -> Result<MinerPowerReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let st: State = rt.state()?;

        let miner_address = &fvm_shared::address::Address::new_id(params.miner);
        let claim = st.miner_power(rt.store(), miner_address)?;

        if let Some(claim) = claim {
            Ok(MinerPowerReturn {
                raw_byte_power: claim.raw_byte_power,
                quality_adj_power: claim.quality_adj_power,
            })
        } else {
            Err(actor_error!(not_found, "miner not found"))
        }
    }

    fn process_deferred_cron_events(
        rt: &impl Runtime,
        rewret: ThisEpochRewardReturn,
    ) -> Result<(), ActorError> {
        let rt_epoch = rt.curr_epoch();
        let mut cron_events = Vec::new();
        let st: State = rt.state()?;
        rt.transaction(|st: &mut State, rt| {
            let mut events = Multimap::from_root(
                rt.store(),
                &st.cron_event_queue,
                CRON_QUEUE_HAMT_BITWIDTH,
                CRON_QUEUE_AMT_BITWIDTH,
            )
            .map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to load cron events")
            })?;

            let claims = st.load_claims(rt.store())?;
            for epoch in st.first_cron_epoch..=rt_epoch {
                let epoch_events = load_cron_events(&events, epoch).map_err(|e| {
                    e.downcast_default(
                        ExitCode::USR_ILLEGAL_STATE,
                        format!("failed to load cron events at {}", epoch),
                    )
                })?;

                if epoch_events.is_empty() {
                    continue;
                }

                for evt in epoch_events.into_iter() {
                    let miner_has_claim = claims.contains_key(&evt.miner_addr)?;
                    if !miner_has_claim {
                        debug!("skipping cron event for unknown miner: {}", evt.miner_addr);
                        continue;
                    }
                    cron_events.push(evt);
                }

                events.remove_all(&epoch_key(epoch)).map_err(|e| {
                    e.downcast_default(
                        ExitCode::USR_ILLEGAL_STATE,
                        format!("failed to clear cron events at {}", epoch),
                    )
                })?;
            }

            st.first_cron_epoch = rt_epoch + 1;
            st.cron_event_queue = events.root().map_err(|e| {
                e.downcast_default(ExitCode::USR_ILLEGAL_STATE, "failed to flush events")
            })?;

            Ok(())
        })?;

        let mut failed_miner_crons = Vec::new();
        for event in cron_events {
            let params = IpldBlock::serialize_cbor(&ext::miner::DeferredCronEventParams {
                event_payload: event.callback_payload.bytes().to_owned(),
                reward_smoothed: rewret.this_epoch_reward_smoothed.clone(),
                quality_adj_power_smoothed: st.this_epoch_qa_power_smoothed.clone(),
            })?;
            let res = extract_send_result(rt.send_simple(
                &event.miner_addr,
                ext::miner::ON_DEFERRED_CRON_EVENT_METHOD,
                params,
                Default::default(),
            ));
            // If a callback fails, this actor continues to invoke other callbacks
            // and persists state removing the failed event from the event queue. It won't be tried again.
            // Failures are unexpected here but will result in removal of miner power
            // A log message would really help here.
            if let Err(e) = res {
                error!("OnDeferredCronEvent failed for miner {}: res {}", event.miner_addr, e);
                failed_miner_crons.push(event.miner_addr)
            }
        }

        if !failed_miner_crons.is_empty() {
            rt.transaction(|st: &mut State, rt| {
                let mut claims = st.load_claims(rt.store())?;

                // Remove power and leave miner frozen
                for miner_addr in failed_miner_crons {
                    if let Err(e) = st.delete_claim(rt.policy(), &mut claims, &miner_addr) {
                        error!(
                            "failed to delete claim for miner {} after\
                            failing on deferred cron event: {}",
                            miner_addr, e
                        );
                        continue;
                    }
                    st.miner_count -= 1
                }
                st.save_claims(&mut claims)?;
                Ok(())
            })?;
        }
        Ok(())
    }
}

impl ActorCode for Actor {
    type Methods = Method;

    fn name() -> &'static str {
        "StoragePower"
    }

    actor_dispatch! {
        Constructor => constructor,
        CreateMiner|CreateMinerExported => create_miner,
        UpdateClaimedPower => update_claimed_power            ,
        EnrollCronEvent => enroll_cron_event,
        OnEpochTickEnd => on_epoch_tick_end,
        UpdatePledgeTotal => update_pledge_total,
        CurrentTotalPower => current_total_power,
        NetworkRawPowerExported => network_raw_power,
        MinerRawPowerExported => miner_raw_power,
        MinerCountExported => miner_count,
        MinerConsensusCountExported => miner_consensus_count,
        MinerPowerExported => miner_power,
    }
}
