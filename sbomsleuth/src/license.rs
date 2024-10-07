use anyhow::__private::not;
use reqwest::Error;
use sbom_walker::Sbom;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::string::ToString;

const SPDX_LICENSE_URL: &str =
    "https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/json/licenses.json";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SpdxLicenseList {
    pub licenses: Vec<License>,
}
#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct License {
    pub reference: String,
    pub isDeprecatedLicenseId: Option<bool>,
    pub detailsUrl: Option<String>,
    pub referenceNumber: Option<i64>,
    pub name: String,
    pub licenseId: Option<String>,
    pub seeAlso: Option<Vec<String>>,
    pub isOsiApproved: Option<bool>,
    pub isFsfLibre: Option<bool>,
}

impl SpdxLicenseList {
    pub async fn new() -> Result<SpdxLicenseList, Error> {
        // Retrieve the environment variable
        let license_url =
            env::var("SBOMSLEUTH_SPDX_LICENSE").unwrap_or(SPDX_LICENSE_URL.to_string());

        // Perform the HTTP GET request
        let response = reqwest::get(&license_url).await?;

        // Check if the response status is successful
        if response.status().is_success() {
            // Deserialize the response body into LicenseList
            let license_list: SpdxLicenseList = response.json().await?;
            // println!("{:?}", license_list);
            Ok(license_list)
        } else {
            Err(response.error_for_status().unwrap_err())
        }
    }

    pub fn is_valid_license(&self, license_id: String) -> bool {
        if license_id == "NOASSERTION" {
            true
        } else {
            self.licenses
                .iter()
                .any(|license| license.licenseId == Some(license_id.clone()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Licenses {
    pub processed: bool,
    pub comp_count: i64,
    pub concluded_license_types: Vec<String>,
    pub concluded_invalid_license_types: Vec<String>,
    pub comp_with_invalid_concluded_license: i64,
    pub comp_without_concluded_license: i64,
    pub comp_with_concluded_noassertion: i64,
    pub declared_license_types: Vec<String>,
    pub declared_invalid_license_types: Vec<String>,
    pub comp_with_invalid_declared_license: i64,
    pub comp_without_declared_license: i64,
    pub comp_with_declared_noassertion: i64,
}

impl crate::license::Licenses {
    pub async fn run(mut self, sbom: &Sbom) -> Result<crate::license::Licenses, String> {
        let spdx_license_list = SpdxLicenseList::new().await.unwrap();
        match sbom {
            Sbom::Spdx(spdx) => {
                log::trace!("Running checks for SPDX component licences.");
                // add checks for noassertion
                let mut unique_license_set: BTreeSet<String> = BTreeSet::new();
                let mut unique_invalid_license_set: BTreeSet<String> = BTreeSet::new();
                let mut unique_license_declared_set: BTreeSet<String> = BTreeSet::new();
                let mut unique_invalid_license_declared_set: BTreeSet<String> = BTreeSet::new();
                for comp in spdx.package_information.clone() {
                    let comp_id = comp.package_spdx_identifier.to_string();
                    let comp_name = comp.package_name.to_string();
                    self.comp_count += 1;
                    if comp.concluded_license.is_none() {
                        log::info!("HAS NO CONCLUDED LICENSE | {} | {}", comp_id, comp_name,);
                        self.comp_without_concluded_license += 1;
                    }
                    for license in comp.concluded_license.unwrap().licenses() {
                        let concluded_license = license.to_string();
                        if concluded_license == "NOASSERTION" {
                            log::info!(
                                "HAS NOASSERTION CONCLUDED LICENSE | {} | {}",
                                comp_id,
                                comp_name,
                            );
                            self.comp_with_concluded_noassertion += 1;
                        }
                        if not(spdx_license_list.is_valid_license(concluded_license.clone())) {
                            log::info!(
                                "HAS INVALID CONCLUDED LICENSE | {} | {} | {}",
                                comp_id,
                                comp_name,
                                concluded_license.clone()
                            );
                            unique_invalid_license_set.insert(concluded_license.clone());
                            self.comp_with_invalid_concluded_license += 1;
                        }
                        unique_license_set.insert(license.to_string());
                    }
                    if comp.declared_license.is_none() {
                        log::info!("HAS NO DECLARED LICENSE | {} | {}", comp_id, comp_name,);
                        self.comp_without_declared_license += 1;
                    }

                    for license in comp.declared_license.unwrap().licenses() {
                        let declared_license = license.to_string();
                        if declared_license == "NOASSERTION" {
                            log::info!(
                                "HAS NOASSERTION DECLARED LICENSE | {} | {}",
                                comp_id,
                                comp_name,
                            );
                            self.comp_with_declared_noassertion += 1;
                        }
                        if not(spdx_license_list.is_valid_license(declared_license.clone())) {
                            log::info!(
                                "HAS INVALID CONCLUDED LICENSE | {} | {} | {}",
                                comp_id,
                                comp_name,
                                declared_license.clone()
                            );
                            unique_invalid_license_declared_set.insert(declared_license.clone());
                            self.comp_with_invalid_declared_license += 1;
                        }

                        unique_license_declared_set.insert(license.to_string());
                    }
                }
                self.concluded_license_types = unique_license_set.into_iter().collect();
                self.concluded_invalid_license_types =
                    unique_invalid_license_set.into_iter().collect();
                self.declared_license_types = unique_license_declared_set.into_iter().collect();
                self.declared_invalid_license_types =
                    unique_invalid_license_declared_set.into_iter().collect();
                self.processed = true;
                Ok(self)
            }
            Sbom::CycloneDx(cyclonedx_bom) => {
                log::trace!("Running checks for CycloneDX component licenses.");
                log::trace!("{:?}", cyclonedx_bom.components);
                Ok(self)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::license::SpdxLicenseList;
    use std::env;

    #[allow(clippy::bool_assert_comparison)]
    #[tokio::test]
    async fn test_fetch_spdx_license_data_not_found() {
        env::set_var("SBOMSLEUTH_SPDX_LICENSE","https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/json/licenses.json" );

        // let license_list = SpdxLicenseList::default();
        let result = SpdxLicenseList::new().await;
        assert!(result.is_ok());

        let spdx_licenses = result.unwrap();
        // assert_eq!(spdx_licenses.licenses.len(),671);
        assert!(spdx_licenses.is_valid_license("0BSD".to_string()));
        assert_eq!(
            spdx_licenses.is_valid_license("NONEXISTANTLICENSE".to_string()),
            false
        );
    }
}
