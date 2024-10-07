use crate::check::{Components, Core};
use crate::license::Licenses;
use sbom_walker::Sbom;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Report {
    pub core: Core,
    pub components: Components,
    pub licenses: Licenses,
}

impl Report {
    pub fn run(mut self, sbom: Sbom) -> Result<Report, String> {
        log::trace!("Running report for SBOM: {:?}", &sbom);
        let core_instance = Core::default();
        self.core = core_instance.run(&sbom).unwrap();
        let components_instance = Components::default();
        self.components = components_instance.run(&sbom).unwrap();
        Ok(self)
    }
}

#[cfg(test)]
mod test {
    use crate::report::Report;
    use crate::validate::parse_sbom;

    #[test]
    fn test_check() {
        let sbom = parse_sbom("../etc/test-data/spdx/simple.json").unwrap();

        let report_instance = Report::default();

        let report = report_instance.run(sbom).unwrap();
        println!("{:?}", report);
    }
}
