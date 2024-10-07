use anyhow::__private::not;
use sbom_walker::Sbom;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Core {
    pub processed: bool,
    pub spec_type: String,
    pub spec_version: String,
    pub sbom_filename: String,
    pub sbom_author: Vec<String>,
    pub sbom_creation_dt: String,
    pub sbom_doc_license: String,
    pub sbom_dependency: String,
    pub sbom_primary_component: String,
    pub comp_count: i64,
}

impl Core {
    pub fn run(mut self, sbom: &Sbom) -> Result<Core, String> {
        match sbom {
            Sbom::Spdx(spdx) => {
                log::trace!("Running checks for SPDX SBOM: {}", self.sbom_filename);
                self.sbom_filename = "none".to_string();
                self.sbom_doc_license = spdx.document_creation_information.data_license.to_string();
                self.sbom_author = spdx
                    .document_creation_information
                    .creation_info
                    .creators
                    .clone();
                self.spec_type = "spdx".to_string();
                self.spec_version = spdx.document_creation_information.spdx_version.to_string();
                self.sbom_creation_dt = spdx
                    .document_creation_information
                    .creation_info
                    .created
                    .to_string();
                self.comp_count = spdx.package_information.len() as i64;
                self.processed = true;
                Ok(self)
            }
            Sbom::CycloneDx(cyclonedx_bom) => {
                log::trace!(
                    "Running checks for CycloneDX SBOM: {}",
                    cyclonedx_bom.version
                );
                self.sbom_filename = "none".to_string();
                // self.sbom_doc_license = licenses.
                self.spec_type = "cycleondx".to_string();
                self.spec_version = cyclonedx_bom.version.to_string();
                if let Some(metadata) = cyclonedx_bom.clone().metadata {
                    if let Some(authors) = &metadata.authors {
                        self.sbom_author = authors
                            .iter()
                            .filter_map(|author| author.name.as_ref().map(|name| name.to_string()))
                            .collect();
                    } else {
                        self.sbom_author = Vec::new();
                    }

                    self.sbom_creation_dt = metadata.timestamp.expect("NONE").to_string();
                }
                if let Some(components) = cyclonedx_bom.components.clone() {
                    for _ in components.0 {
                        self.comp_count += 1;
                    }
                }
                self.processed = true;

                Ok(self)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Components {
    pub processed: bool,
    pub comp_count: i64,
    pub comp_with_name: i64,
    pub comp_without_name: i64,
    pub comp_with_duplicate_id: i64,
    pub duplicate_ids: Vec<String>,
    pub comp_without_id: i64,
    pub comp_with_purl: i64,
    pub comp_with_cpe: i64,
    pub comp_without_cpe_or_purl: i64,
    pub comp_without_supplier: i64,
    pub comp_without_version: i64,
}

fn find_duplicates(spdx_identifier_list: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();

    for identifier in spdx_identifier_list {
        if !seen.insert(identifier.clone()) {
            duplicates.insert(identifier);
        }
    }

    duplicates.into_iter().collect()
}

impl crate::check::Components {
    pub fn run(mut self, sbom: &Sbom) -> Result<crate::check::Components, String> {
        match sbom {
            Sbom::Spdx(spdx) => {
                log::trace!("Running checks for SPDX components.");
                let mut spdx_identifier_list: Vec<String> = Vec::new();
                // add checks for noassertion
                for comp in &spdx.package_information {
                    self.comp_count += 1;
                    let comp_id = comp.package_spdx_identifier.to_string();
                    spdx_identifier_list.push(comp_id.clone());
                    let comp_name = comp.package_name.to_string();

                    // check if component has an id
                    if comp_id.is_empty() {
                        self.comp_without_id += 1;
                        log::warn!("HAS NO ID | {}", comp_name,);
                    }

                    // check if component has a supplier
                    if let Some(supplier) = comp.package_supplier.clone() {
                        if not(supplier.is_empty()) {
                            log::trace!(
                                "{}: {} has suppler {}",
                                comp_id,
                                comp_name,
                                comp.package_supplier.clone().unwrap()
                            );
                        } else {
                            log::info!("HAS NO SUPPLIER | {} | {}", comp_id, comp_name,);
                            self.comp_without_supplier += 1;
                        }
                    } else {
                        log::info!("HAS NO SUPPLIER | {} | {}", comp_id, comp_name,);
                        self.comp_without_supplier += 1;
                    }

                    //check if component has a name
                    if not(comp.package_name.is_empty()) {
                        self.comp_with_name += 1;
                    } else {
                        log::warn!("HAS NO NAME | {} | {:?}", comp_id, comp);
                        self.comp_without_name += 1;
                    }

                    // check if component has a version
                    if let Some(version) = comp.package_version.clone() {
                        if version.is_empty() {
                            self.comp_without_version += 1;
                            log::info!("HAS NO VERSION | {} | {}", comp_id, comp_name);
                        }
                    } else {
                        self.comp_without_version += 1;
                        log::info!("HAS NO VERSION | {} | {}", comp_id, comp_name);
                    }

                    // check if component has a purl or version
                    let external_package_references = &comp.external_reference;
                    let mut has_purl: bool = false;
                    let mut has_cpe: bool = false;
                    for external_package_ref in external_package_references {
                        if external_package_ref.reference_type == "purl" {
                            has_purl = true;
                            log::trace!(
                                "{}: {} has purl {}",
                                comp_id,
                                comp_name,
                                external_package_ref.reference_locator
                            );
                            self.comp_with_purl += 1;
                        } else if external_package_ref.reference_type == "cpe" {
                            has_cpe = true;
                            log::trace!(
                                "{}: {} has cpe {}",
                                comp_id,
                                comp_name,
                                external_package_ref.reference_locator
                            );
                            self.comp_with_cpe += 1;
                        }
                    }
                    if not(has_purl) && not(has_cpe) {
                        log::debug!("{}: {} has no purl or cpe", comp_id, comp_name);
                        self.comp_without_cpe_or_purl += 1;
                    } else {
                        log::trace!("{}: {} has purl or cpe", comp_id, comp_name);
                    }
                }

                //check if there are components with duplicate ids
                let duplicates = find_duplicates(spdx_identifier_list);
                self.comp_with_duplicate_id = duplicates.len() as i64;
                self.duplicate_ids = duplicates;

                self.processed = true;
                Ok(self)
            }
            Sbom::CycloneDx(cyclonedx_bom) => {
                log::trace!("Running checks for CycloneDX SBOM components.");
                log::trace!("{:?}", cyclonedx_bom.components);

                let mut cyclonedx_identifier_list: Vec<String> = Vec::new();
                for comp in cyclonedx_bom.components.clone().unwrap().0 {
                    self.comp_count += 1;
                    let comp_id = comp.bom_ref.unwrap();
                    cyclonedx_identifier_list.push(comp_id.clone());
                    let comp_name = comp.name.to_string();

                    // check if component has an id
                    if comp_id.is_empty() {
                        self.comp_without_id += 1;
                        log::warn!("HAS NO ID | {}", comp_name,);
                    }

                    // check if component has a supplier
                    if let Some(supplier_option) = comp.supplier.clone() {
                        if let Some(supplier_name) = supplier_option.name {
                            if !supplier_name.is_empty() {
                                log::trace!(
                                    "{}: {} has supplier {}",
                                    comp_id,
                                    comp_name,
                                    supplier_name
                                );
                            } else {
                                log::info!("HAS NO SUPPLIER | {} | {}", comp_id, comp_name);
                                self.comp_without_supplier += 1;
                            }
                        } else {
                            log::info!("HAS NO SUPPLIER | {} | {}", comp_id, comp_name);
                            self.comp_without_supplier += 1;
                        }
                    } else {
                        log::info!("HAS NO SUPPLIER | {} | {}", comp_id, comp_name);
                        self.comp_without_supplier += 1;
                    }

                    //check if component has a name
                    if not(comp_name.is_empty()) {
                        self.comp_with_name += 1;
                    } else {
                        log::warn!("HAS NO NAME | {}", comp_id);
                        self.comp_without_name += 1;
                    }

                    // check if component has a version
                    if let Some(version) = comp.version.clone() {
                        if version.is_empty() {
                            self.comp_without_version += 1;
                            log::info!("HAS NO VERSION | {} | {}", comp_id, comp_name);
                        }
                    } else {
                        self.comp_without_version += 1;
                        log::info!("HAS NO VERSION | {} | {}", comp_id, comp_name);
                    }

                    // check if component has a purl
                    if let Some(purl) = comp.purl.clone() {
                        if not(purl.to_string().is_empty()) {
                            self.comp_with_purl += 1;
                            log::info!("HAS PURL | {} | {} | {}", comp_id, comp_name, purl);
                        }
                    }
                }
                //check if there are components with duplicate ids
                let duplicates = find_duplicates(cyclonedx_identifier_list);
                self.comp_with_duplicate_id = duplicates.len() as i64;
                self.duplicate_ids = duplicates;

                self.processed = true;
                Ok(self)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::check::Core;
    use crate::validate::parse_sbom;

    #[test]
    fn test_check() {
        let sbom = parse_sbom("../etc/test-data/spdx/simple.json").unwrap();
        let core_instance = Core::default();
        let populated_core = core_instance.run(&sbom).unwrap();
        println!("{:?}", populated_core);
    }
}
