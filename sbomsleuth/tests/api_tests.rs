use sbomsleuth::report::Report;
use sbomsleuth::validate::parse_sbom;

#[test]
fn test_validate_spdx() {
    let contents = parse_sbom("../etc/test-data/spdx/simple.json");
    assert!(contents.is_ok());
}

#[test]
fn test_report() {
    let sbom = parse_sbom("../etc/test-data/spdx/simple.json");
    assert!(sbom.is_ok());
    let report_instance = Report::default();
    let report = report_instance.run(sbom.unwrap()).unwrap();
    assert_eq!(report.core.comp_count, 8);
}
