//! PVOS D261b — a temporary probe for the retest proof (removed before merge).
//! In pvfs-core, so test binaries of later packages still have to run.

#[test]
fn d261_probe() {
    assert_eq!(1 + 1, 3, "the probe fails on purpose: every binary after it must still run");
}
