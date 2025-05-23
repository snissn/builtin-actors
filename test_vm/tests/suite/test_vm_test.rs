use fil_actor_account::State as AccountState;
use fil_actors_integration_tests::util::{assert_invariants, check_invariants};
use fil_actors_runtime::runtime::{EMPTY_ARR_CID, Policy};
use fil_actors_runtime::test_blockstores::MemoryBlockstore;
use fil_actors_runtime::test_utils::{ACCOUNT_ACTOR_CODE_ID, PAYCH_ACTOR_CODE_ID};
use fvm_shared::METHOD_SEND;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use num_traits::Zero;
use test_vm::{FIRST_TEST_USER_ADDR, TEST_FAUCET_ADDR, TestVM};
use vm_api::util::{get_state, pk_addrs_from};
use vm_api::{VM, new_actor};

#[test]
fn state_control() {
    let store = MemoryBlockstore::new();
    let v = TestVM::new(store);
    let addr1 = Address::new_id(1000);
    let addr2 = Address::new_id(2222);

    // set actor
    let a1 =
        new_actor(*ACCOUNT_ACTOR_CODE_ID, EMPTY_ARR_CID, 42, TokenAmount::from_atto(10u8), None);
    v.set_actor(&addr1, a1.clone());
    let out = v.actor(&addr1).unwrap();
    assert_eq!(out, a1);
    let check = v.checkpoint();

    let a2 = new_actor(*PAYCH_ACTOR_CODE_ID, EMPTY_ARR_CID, 88, TokenAmount::from_atto(1u8), None);
    v.set_actor(&addr2, a2.clone());
    assert_eq!(v.actor(&addr2).unwrap(), a2);
    // rollback removes a2 but not a1
    v.rollback(check);

    // a2 is gone
    assert_eq!(None, v.actor(&addr2));
    assert_eq!(v.actor(&addr1).unwrap(), a1);

    let invariants_check = check_invariants(&v, &Policy::default(), Some(TokenAmount::zero()));
    let err = invariants_check.unwrap_err();
    assert!(err.to_string().contains("AccountState is empty"), "unexpected error: {err}");
}

fn assert_account_actor(
    exp_call_seq: u64,
    exp_bal: TokenAmount,
    exp_pk_addr: Address,
    v: &TestVM,
    addr: Address,
) {
    let act = v.actor(&addr).unwrap();
    let st: AccountState = get_state(v, &addr).unwrap();
    assert_eq!(exp_call_seq, act.sequence);
    assert_eq!(*ACCOUNT_ACTOR_CODE_ID, act.code);
    assert_eq!(exp_bal, act.balance);
    assert_eq!(exp_pk_addr, st.address);
}

#[test]
fn test_sent() {
    let store = MemoryBlockstore::new();
    let v = TestVM::new_with_singletons(store);

    // send to uninitialized account actor
    let addr1 = Address::new_bls(&[1; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    v.execute_message(&TEST_FAUCET_ADDR, &addr1, &TokenAmount::from_atto(42u8), METHOD_SEND, None)
        .unwrap();
    let expect_id_addr1 = Address::new_id(FIRST_TEST_USER_ADDR);
    assert_account_actor(0, TokenAmount::from_atto(42u8), addr1, &v, expect_id_addr1);

    // send from this account actor to another uninit account actor
    let addr2 = Address::new_bls(&[2; fvm_shared::address::BLS_PUB_LEN]).unwrap();
    v.execute_message(&addr1, &addr2, &TokenAmount::from_atto(41u8), METHOD_SEND, None).unwrap();
    let expect_id_addr2 = Address::new_id(FIRST_TEST_USER_ADDR + 1);
    assert_account_actor(0, TokenAmount::from_atto(41u8), addr2, &v, expect_id_addr2);

    // send between two initialized account actors
    v.execute_message(&addr2, &addr1, &TokenAmount::from_atto(41u8), METHOD_SEND, None).unwrap();
    assert_account_actor(1, TokenAmount::from_atto(42u8), addr1, &v, expect_id_addr1);
    assert_account_actor(1, TokenAmount::zero(), addr2, &v, expect_id_addr2);

    // self send is noop
    v.execute_message(&addr1, &addr1, &TokenAmount::from_atto(1u8), METHOD_SEND, None).unwrap();
    assert_account_actor(2, TokenAmount::from_atto(42u8), addr1, &v, expect_id_addr1);

    // fail with insufficient funds
    let mres =
        v.execute_message(&addr2, &addr1, &TokenAmount::from_atto(1u8), METHOD_SEND, None).unwrap();
    assert_eq!(ExitCode::SYS_INSUFFICIENT_FUNDS, mres.code);
    assert_account_actor(2, TokenAmount::from_atto(42u8), addr1, &v, expect_id_addr1);
    assert_account_actor(2, TokenAmount::zero(), addr2, &v, expect_id_addr2);

    // fail to send to non existent id actor (vm doesn't create those on send)
    let mres = v
        .execute_message(
            &addr1,
            &Address::new_id(88),
            &TokenAmount::from_atto(1u8),
            METHOD_SEND,
            None,
        )
        .unwrap();
    assert_eq!(ExitCode::SYS_INVALID_RECEIVER, mres.code);
    assert_account_actor(3, TokenAmount::from_atto(42u8), addr1, &v, expect_id_addr1);
    assert_account_actor(2, TokenAmount::zero(), addr2, &v, expect_id_addr2);

    assert_invariants(&v, &Policy::default(), None)
}

#[test]
fn test_pk_gen() {
    let addrs = pk_addrs_from(5, 2);
    let second_addr_seeded_five = addrs[1];
    let addrs = pk_addrs_from(6, 1);
    let first_addr_seeded_six = addrs[0];
    assert_ne!(second_addr_seeded_five, first_addr_seeded_six);
}
