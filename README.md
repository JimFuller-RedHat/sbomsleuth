# sbomsleuth

**WARNING - this is a work in progress - once we get a 0.1.0 release ...** 

CLI for investigating sboms.

Inspired by: 
* https://github.com/ctron/csaf-walker
* https://github.com/anthonyharrison/sbomaudit
* https://github.com/interlynk-io/sbomqs / https://sbombenchmark.dev/

### Installation

To install library from crates.io:
```shell
> cargo install sbomsleuth
```

To install cli from crates.io
```shell
> cargo install sbomsleuth-cli
```

### Usage

#### CLI
```shell
> sbomsleuth --help

CLI for investigating sboms.

Usage: sbomsleuth [OPTIONS] [FILE] [COMMAND]

Commands:
  report    Generate quality report on SBOM.
  license   Generate license report on SBOM.
  validate  Validate SBOM.
  help      Print this message or the help of the given subcommand(s)

Arguments:
  [FILE]  

Options:
  -v, --verbosity...  Increase verbosity level. Use multiple times for more verbosity.
  -q, --quiet         
  -h, --help          Print help

```

When invoked with no command and just a file argument will generate a full report on SBOM quality.
```shell
> sbomsleuth openshift-4.11.z.json | jq
```

```json
{
  "core": {
    "processed": true,
    "spec_type": "spdx",
    "spec_version": "SPDX-2.3",
    "sbom_filename": "none",
    "sbom_author": [
      "Organization: Red Hat Product Security (secalert@redhat.com)"
    ],
    "sbom_creation_dt": "2024-08-06 11:34:13 UTC",
    "sbom_doc_license": "CC0-1.0",
    "sbom_dependency": "",
    "sbom_primary_component": "",
    "comp_count": 24726
  },
  "components": {
    "processed": true,
    "comp_count": 24726,
    "comp_with_name": 24726,
    "comp_with_duplicate_id": 0,
    "comp_with_missing_id": 0,
    "comp_with_purl": 24725,
    "comp_with_cpe": 0,
    "comp_without_cpe_or_purl": 1,
    "comp_without_supplier": 0,
    "comp_without_version": 4438
  },
  "licenses": {
    "processed": true,
    "comp_count": 24726,
    "concluded_license_types": [
      "0BSD",
      "AFL-2.1",
      "AFL-3.0",
      "AGPL-3.0-only",
      "AGPL-3.0-or-later",
      "Apache-2.0",
      "Artistic-2.0",
      "BSD-2-Clause",
      "BSD-2-Clause-Views",
      "BSD-3-Clause",
      "BSD-3-Clause-Clear",
      "CC-BY-3.0",
      "CC-BY-SA-4.0",
      "CC0-1.0",
      "CDDL-1.0",
      "GPL-1.0-or-later",
      "GPL-2.0-only",
      "GPL-2.0-or-later",
      "GPL-3.0-only",
      "GPL-3.0-or-later",
      "ISC",
      "JSON",
      "LGPL-2.0-only",
      "LGPL-2.0-or-later",
      "LGPL-2.1-only",
      "LGPL-2.1-or-later",
      "LGPL-3.0-only",
      "LGPL-3.0-or-later",
      "MIT",
      "MIT-0",
      "MPL-1.0",
      "MPL-1.1",
      "MPL-2.0",
      "NOASSERTION",
      "ODC-By-1.0",
      "OFL-1.1",
      "Python-2.0",
      "TMate",
      "Unlicense",
      "W3C",
      "W3C-20150513",
      "X11"
    ],
    "concluded_comp_without_license": 0,
    "concluded_comp_with_noassertion": 22710,
    "declared_license_types": [
      "Apache-2.0",
      "BSD-2-Clause-Patent",
      "BSD-3-Clause",
      "BSL-1.0",
      "CC-BY-SA-1.0",
      "CC0-1.0",
      "FSFAP",
      "GPL-2.0-only",
      "GPL-2.0-or-later",
      "IJG",
      "ISC",
      "LGPL-2.0-or-later",
      "LGPL-2.1-only",
      "LGPL-2.1-or-later",
      "LicenseRef-0",
      "LicenseRef-1",
      "LicenseRef-10",
      "LicenseRef-11",
      "LicenseRef-12",
      "LicenseRef-13",
      "LicenseRef-14",
      "LicenseRef-15",
      "LicenseRef-16",
      "LicenseRef-17",
      "LicenseRef-18",
      "LicenseRef-19",
      "LicenseRef-2",
      "LicenseRef-20",
      "LicenseRef-21",
      "LicenseRef-22",
      "LicenseRef-23",
      "LicenseRef-24",
      "LicenseRef-25",
      "LicenseRef-26",
      "LicenseRef-27",
      "LicenseRef-3",
      "LicenseRef-4",
      "LicenseRef-5",
      "LicenseRef-6",
      "LicenseRef-7",
      "LicenseRef-8",
      "LicenseRef-9",
      "LicenseRef-AFL",
      "LicenseRef-Artistic",
      "LicenseRef-BSD",
      "LicenseRef-Boost",
      "LicenseRef-CC-BY",
      "LicenseRef-CC-BY-SA",
      "LicenseRef-GFDL",
      "LicenseRef-GPLv2",
      "LicenseRef-GPLv3",
      "LicenseRef-HSRL",
      "LicenseRef-LGPLv2",
      "LicenseRef-LGPLv3",
      "LicenseRef-MPL",
      "LicenseRef-MPLv1.1",
      "LicenseRef-MPLv2.0",
      "LicenseRef-Netscape",
      "LicenseRef-Nmap",
      "LicenseRef-OpenLDAP",
      "LicenseRef-Python",
      "LicenseRef-UCD",
      "LicenseRef-Unicode",
      "LicenseRef-ZPLv2.0",
      "LicenseRef-ZPLv2.1",
      "MIT",
      "NCSA",
      "NOASSERTION",
      "OpenSSL",
      "PostgreSQL",
      "SISSL",
      "Sendmail",
      "Sleepycat",
      "TTWL",
      "Vim",
      "Zlib",
      "libtiff"
    ],
    "declared_comp_without_license": 0,
    "declared_comp_with_noassertion": 21478
  }
}

```

#### Library

Using the crate `sbomsleuth`, the library can be used to generate a report:

```rust
    use sbomsleuth::report::Report;
    use sbomsleuth::license::Licenses;
    use sbomsleuth::validate::parse_sbom;
    
    // validate and parse spdx/cyclonedx
    let file = "/som/spdx_file.json".to_string();
    let sbom = parse_sbom(file).unwrap(); 
    
    // generate quality report on spdx/cyclonedx
    let license_instance = Licenses::default();
    let report_instance = sbomsleuth::report::Report {
        licenses: license_instance.run(&parsed_sbom).unwrap(),
        ..Default::default()
    };
    let report = report_instance.run(parsed_sbom).unwrap();

    println!("{}", (serde_json::to_string(&report).unwrap()));
```
