use sbom_walker::Sbom;
use std::fs::File;
use std::io::Read;

pub fn parse_sbom(file_name: &str) -> Result<Sbom, String> {
    log::trace!("Parsing sbom file: {}", file_name);

    let mut file = match File::open(file_name) {
        Ok(file) => file,
        Err(err) => return Err(format!("Failed to open file: {}", err)),
    };

    let mut contents = Vec::new();
    match file.read_to_end(&mut contents) {
        Ok(_) => (),
        Err(err) => return Err(format!("Failed to read file: {}", err)),
    }
    // log::debug!("read json {:?}", &contents);

    match Sbom::try_parse_any(&contents) {
        Ok(sbom) => {
            log::trace!("parsed sbom {:?}", sbom);
            Ok(sbom)
        }
        Err(err) => Err(format!("Failed to parse SBOM: {}", err)),
    }
}
#[cfg(test)]
mod test {
    use crate::validate::parse_sbom;

    #[test]
    fn test_load_spdx() {
        let contents = parse_sbom("../etc/test-data/spdx/simple.json");
        assert!(contents.is_ok());
    }

    #[test]
    fn test_load_invalid_spdx() {
        let contents = parse_sbom("../etc/test-data/spdx/invalid.json");
        assert!(contents.is_err());
    }

    #[test]
    fn test_load_cyclonedx() {
        let contents = parse_sbom("../etc/test-data/cyclonedx/simple.json");
        assert!(contents.is_ok());
    }
}
