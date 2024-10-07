use sbomsleuth::license::Licenses;
use sbomsleuth::validate::parse_sbom;

#[test]
fn test_validate_spdx() {
    let contents = parse_sbom("../etc/test-data/spdx/simple.json");
    assert!(contents.is_ok());
}

#[tokio::test]
async fn test_report() {
    let sbom = parse_sbom("../etc/test-data/spdx/simple.json");
    assert!(sbom.is_ok());
    let parsed_sbom = sbom.unwrap();

    let license_instance = Licenses::default();
    let report_instance = sbomsleuth::report::Report {
        licenses: license_instance.run(&parsed_sbom).await.unwrap(),
        ..Default::default()
    };
    let report = report_instance.run(parsed_sbom).unwrap();

    assert_eq!(report.core.comp_count, 8);
}
