//! PVOS D261b — a temporary probe for the retest proof (removed before merge).
//! In pvfs-core, so test binaries of later packages still have to run.

#[test]
fn d261_probe() {
    assert_eq!(1 + 1, 2, "fixed: a test-only change the retest checks");
}
