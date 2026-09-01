use tempris_collector::singleton::{LockResult, SingleInstanceGuard};
use uuid::Uuid;

#[test]
fn test_singleton_acquire_and_release() {
    let suffix = format!("_test_{}", Uuid::new_v4().simple());

    // Initially not running
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));

    // Acquire lock
    let lock1 = SingleInstanceGuard::acquire(Some(&suffix));
    match lock1 {
        LockResult::Acquired(guard) => {
            assert!(guard.name().contains(&suffix));
            // Now is_another_instance_running should report true
            assert!(SingleInstanceGuard::is_another_instance_running(Some(
                &suffix
            )));

            // Drop the guard explicitly
            drop(guard);
        }
        other => panic!("Expected LockResult::Acquired, got {:?}", other),
    }

    // After dropping, is_another_instance_running should report false
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix
    )));
}

#[test]
fn test_singleton_second_instance_rejected() {
    let suffix = format!("_test_{}", Uuid::new_v4().simple());

    // Acquire first instance
    let lock1 = SingleInstanceGuard::acquire(Some(&suffix));
    let guard1 = match lock1 {
        LockResult::Acquired(g) => g,
        other => panic!("Expected LockResult::Acquired, got {:?}", other),
    };

    // Attempt second acquire with the same suffix
    let lock2 = SingleInstanceGuard::acquire(Some(&suffix));
    assert_eq!(lock2, LockResult::AlreadyRunning);

    // Drop first guard
    drop(guard1);

    // Now second acquire should succeed
    let lock3 = SingleInstanceGuard::acquire(Some(&suffix));
    match lock3 {
        LockResult::Acquired(_g3) => {
            // Success
        }
        other => panic!("Expected LockResult::Acquired after drop, got {:?}", other),
    }
}

#[test]
fn test_singleton_drop_allows_reacquire() {
    let suffix = format!("_test_{}", Uuid::new_v4().simple());

    for _ in 0..3 {
        let lock = SingleInstanceGuard::acquire(Some(&suffix));
        assert!(matches!(lock, LockResult::Acquired(_)));
        // Lock drops here at end of iteration scope
    }
}

#[test]
fn test_singleton_different_suffixes_coexist() {
    let suffix_a = format!("_test_a_{}", Uuid::new_v4().simple());
    let suffix_b = format!("_test_b_{}", Uuid::new_v4().simple());

    let lock_a = SingleInstanceGuard::acquire(Some(&suffix_a));
    let lock_b = SingleInstanceGuard::acquire(Some(&suffix_b));

    assert!(matches!(lock_a, LockResult::Acquired(_)));
    assert!(matches!(lock_b, LockResult::Acquired(_)));

    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix_a
    )));
    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix_b
    )));

    drop(lock_a);
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix_a
    )));
    assert!(SingleInstanceGuard::is_another_instance_running(Some(
        &suffix_b
    )));

    drop(lock_b);
    assert!(!SingleInstanceGuard::is_another_instance_running(Some(
        &suffix_b
    )));
}
