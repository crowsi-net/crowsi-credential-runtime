use std::sync::atomic::Ordering;

use super::super::PreparedUse;
use super::executor::ExecutorMode;
use super::fixture::{fixture, sign};
use crate::RuntimeError;

#[test]
fn prepared_operation_is_one_use_and_expires() {
    let (mut engine, request, ticket, unchanged_clock, _) = fixture(ExecutorMode::Signed, sign());
    let mut prepared = PreparedUse::new(&engine.broker, &ticket, request).expect("prepare");
    engine.execute(&mut prepared).expect("first use");
    assert_eq!(engine.execute(&mut prepared), Err(RuntimeError::Replay));

    let (mut engine, request, ticket, clock, _) = fixture(ExecutorMode::Signed, sign());
    let mut prepared = PreparedUse::new(&engine.broker, &ticket, request).expect("prepare");
    clock.0.store(1_011, Ordering::SeqCst);
    assert_eq!(engine.execute(&mut prepared), Err(RuntimeError::Expired));
    assert_eq!(unchanged_clock.0.load(Ordering::SeqCst), 1_000);
}
