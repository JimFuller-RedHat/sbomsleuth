# sbomsleuth

[![crates.io](https://img.shields.io/crates/v/sbomsleuth-cli.svg)](https://crates.io/crates/sbomsleuth-cli)
[![docs.rs](https://docs.rs/sbomsleuth/badge.svg)](https://docs.rs/sbomsleuth)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/tag/JimFuller-RedHat/sbomsleuth?sort=semver)](https://github.com/JimFuller-RedHat/sbomsleuth/releases)
[![CI](https://github.com/JimFuller-RedHat/sbomsleuth/workflows/CI/badge.svg)](https://github.com/JimFuller-RedHat/sbomsleuth/actions?query=workflow%3A%22CI%22)

**WARNING - this is a work in progress - expect breaking changes until we get a 1.0.0 release ... mostly spdx supported, working on cyclonedx ...**

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
    "sbom_creation_dt": "2024-08-15 11:53:55 UTC",
    "sbom_doc_license": "CC0-1.0",
    "sbom_dependency": "",
    "sbom_primary_component": "",
    "comp_count": 64869
  },
  "components": {
    "processed": true,
    "comp_count": 64869,
    "comp_with_name": 64869,
    "comp_without_name": 0,
    "comp_with_duplicate_id": 0,
    "duplicate_ids": [],
    "comp_without_id": 0,
    "comp_with_purl": 64868,
    "comp_with_cpe": 0,
    "comp_without_cpe_or_purl": 1,
    "comp_without_supplier": 0,
    "comp_without_version": 1790
  },
  "licenses": {
    "processed": true,
    "comp_count": 64869,
    "concluded_license_types": [
      "0BSD",
      "AFL-2.1",
      "AGPL-3.0-only",
      "AGPL-3.0-or-later",
      "Apache-1.1",
      "Apache-2.0",
      "Artistic-2.0",
      "BSD-2-Clause",
      "BSD-2-Clause-Views",
      "BSD-3-Clause",
      "BSD-3-Clause-Clear",
      "CC-BY-3.0",
      "CC-BY-4.0",
      "CC-BY-SA-2.5",
      "CC-BY-SA-3.0",
      "CC-BY-SA-4.0",
      "CC0-1.0",
      "CPL-1.0",
      "DOC",
      "EPL-1.0",
      "EPL-2.0",
      "EUPL-1.1",
      "GPL-1.0-or-later",
      "GPL-2.0-only",
      "GPL-3.0-only",
      "ISC",
      "JSON",
      "LGPL-2.0-only",
      "LGPL-2.0-or-later",
      "LGPL-2.1-only",
      "LGPL-3.0-only",
      "LPPL-1.1",
      "LPPL-1.3c",
      "MIT",
      "MIT-0",
      "MPL-2.0",
      "NOASSERTION",
      "ODC-By-1.0",
      "OFL-1.1",
      "PHP-3.01",
      "Python-2.0",
      "Unlicense",
      "WTFPL",
      "X11",
      "Zlib"
    ],
    "concluded_invalid_license_types": [],
    "comp_with_invalid_concluded_license": 0,
    "comp_without_concluded_license": 0,
    "comp_with_concluded_noassertion": 62495,
    "declared_license_types": [
      "ANTLR-PD",
      "Afmparse",
      "Apache-2.0",
      "BSD-2-Clause",
      "BSD-2-Clause-Patent",
      "BSD-3-Clause",
      "CC-BY-SA-3.0",
      "CC-BY-SA-4.0",
      "CC0-1.0",
      "EPL-1.0",
      "EPL-2.0",
      "Eurosym",
      "FDK-AAC",
      "FSFAP",
      "GPL-2.0-or-later",
      "IJG",
      "ISC",
      "LGPL-2.1-or-later",
      "Leptonica",
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
      "LicenseRef-28",
      "LicenseRef-29",
      "LicenseRef-3",
      "LicenseRef-30",
      "LicenseRef-31",
      "LicenseRef-32",
      "LicenseRef-33",
      "LicenseRef-34",
      "LicenseRef-35",
      "LicenseRef-36",
      "LicenseRef-37",
      "LicenseRef-38",
      "LicenseRef-39",
      "LicenseRef-4",
      "LicenseRef-40",
      "LicenseRef-41",
      "LicenseRef-42",
      "LicenseRef-43",
      "LicenseRef-44",
      "LicenseRef-45",
      "LicenseRef-46",
      "LicenseRef-47",
      "LicenseRef-48",
      "LicenseRef-49",
      "LicenseRef-5",
      "LicenseRef-50",
      "LicenseRef-51",
      "LicenseRef-52",
      "LicenseRef-53",
      "LicenseRef-54",
      "LicenseRef-55",
      "LicenseRef-56",
      "LicenseRef-57",
      "LicenseRef-58",
      "LicenseRef-59",
      "LicenseRef-6",
      "LicenseRef-60",
      "LicenseRef-61",
      "LicenseRef-62",
      "LicenseRef-7",
      "LicenseRef-8",
      "LicenseRef-9",
      "LicenseRef-AFL",
      "LicenseRef-AGPLv3",
      "LicenseRef-Arphic",
      "LicenseRef-Artistic",
      "LicenseRef-BSD",
      "LicenseRef-Boost",
      "LicenseRef-CC-BY",
      "LicenseRef-CC-BY-SA",
      "LicenseRef-CC0",
      "LicenseRef-CDDL",
      "LicenseRef-CPL",
      "LicenseRef-DMIT",
      "LicenseRef-DMTF",
      "LicenseRef-EPL",
      "LicenseRef-GFDL",
      "LicenseRef-GPLv2",
      "LicenseRef-GPLv3",
      "LicenseRef-HSRL",
      "LicenseRef-IBM",
      "LicenseRef-IEEE",
      "LicenseRef-JasPer",
      "LicenseRef-Knuth",
      "LicenseRef-LGPLv2",
      "LicenseRef-LGPLv3",
      "LicenseRef-LPPL",
      "LicenseRef-Liberation",
      "LicenseRef-Lucida",
      "LicenseRef-MPL",
      "LicenseRef-MPLv1.1",
      "LicenseRef-MPLv2.0",
      "LicenseRef-Netscape",
      "LicenseRef-Nmap",
      "LicenseRef-OFL",
      "LicenseRef-OFSFDL",
      "LicenseRef-OpenLDAP",
      "LicenseRef-PHP",
      "LicenseRef-Python",
      "LicenseRef-RSA",
      "LicenseRef-Romio",
      "LicenseRef-Rsfs",
      "LicenseRef-TCGL",
      "LicenseRef-Threeparttable",
      "LicenseRef-UCD",
      "LicenseRef-UPL",
      "LicenseRef-Unicode",
      "LicenseRef-Utopia",
      "LicenseRef-Verbatim",
      "LicenseRef-Wadalab",
      "LicenseRef-ZPLv2.1",
      "LicenseRef-Zend",
      "LicenseRef-ec",
      "LicenseRef-mecab-ipadic",
      "MIT",
      "MIT-0",
      "MPL-2.0",
      "MS-PL",
      "MakeIndex",
      "Minpack",
      "MirOS",
      "NCSA",
      "NOASSERTION",
      "OML",
      "OpenSSL",
      "Plexus",
      "PostgreSQL",
      "Qhull",
      "Ruby",
      "SISSL",
      "SWL",
      "Sendmail",
      "Sleepycat",
      "TCL",
      "TTWL",
      "Vim",
      "W3C",
      "WTFPL",
      "Zlib",
      "libtiff",
      "psfrag",
      "xpp"
    ],
    "declared_invalid_license_types": [
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
      "LicenseRef-28",
      "LicenseRef-29",
      "LicenseRef-3",
      "LicenseRef-30",
      "LicenseRef-31",
      "LicenseRef-32",
      "LicenseRef-33",
      "LicenseRef-34",
      "LicenseRef-35",
      "LicenseRef-36",
      "LicenseRef-37",
      "LicenseRef-38",
      "LicenseRef-39",
      "LicenseRef-4",
      "LicenseRef-40",
      "LicenseRef-41",
      "LicenseRef-42",
      "LicenseRef-43",
      "LicenseRef-44",
      "LicenseRef-45",
      "LicenseRef-46",
      "LicenseRef-47",
      "LicenseRef-48",
      "LicenseRef-49",
      "LicenseRef-5",
      "LicenseRef-50",
      "LicenseRef-51",
      "LicenseRef-52",
      "LicenseRef-53",
      "LicenseRef-54",
      "LicenseRef-55",
      "LicenseRef-56",
      "LicenseRef-57",
      "LicenseRef-58",
      "LicenseRef-59",
      "LicenseRef-6",
      "LicenseRef-60",
      "LicenseRef-61",
      "LicenseRef-62",
      "LicenseRef-7",
      "LicenseRef-8",
      "LicenseRef-9",
      "LicenseRef-AFL",
      "LicenseRef-AGPLv3",
      "LicenseRef-Arphic",
      "LicenseRef-Artistic",
      "LicenseRef-BSD",
      "LicenseRef-Boost",
      "LicenseRef-CC-BY",
      "LicenseRef-CC-BY-SA",
      "LicenseRef-CC0",
      "LicenseRef-CDDL",
      "LicenseRef-CPL",
      "LicenseRef-DMIT",
      "LicenseRef-DMTF",
      "LicenseRef-EPL",
      "LicenseRef-GFDL",
      "LicenseRef-GPLv2",
      "LicenseRef-GPLv3",
      "LicenseRef-HSRL",
      "LicenseRef-IBM",
      "LicenseRef-IEEE",
      "LicenseRef-JasPer",
      "LicenseRef-Knuth",
      "LicenseRef-LGPLv2",
      "LicenseRef-LGPLv3",
      "LicenseRef-LPPL",
      "LicenseRef-Liberation",
      "LicenseRef-Lucida",
      "LicenseRef-MPL",
      "LicenseRef-MPLv1.1",
      "LicenseRef-MPLv2.0",
      "LicenseRef-Netscape",
      "LicenseRef-Nmap",
      "LicenseRef-OFL",
      "LicenseRef-OFSFDL",
      "LicenseRef-OpenLDAP",
      "LicenseRef-PHP",
      "LicenseRef-Python",
      "LicenseRef-RSA",
      "LicenseRef-Romio",
      "LicenseRef-Rsfs",
      "LicenseRef-TCGL",
      "LicenseRef-Threeparttable",
      "LicenseRef-UCD",
      "LicenseRef-UPL",
      "LicenseRef-Unicode",
      "LicenseRef-Utopia",
      "LicenseRef-Verbatim",
      "LicenseRef-Wadalab",
      "LicenseRef-ZPLv2.1",
      "LicenseRef-Zend",
      "LicenseRef-ec",
      "LicenseRef-mecab-ipadic"
    ],
    "comp_with_invalid_declared_license": 78882,
    "comp_without_declared_license": 0,
    "comp_with_declared_noassertion": 13444
  }
}
```

Use **-v** to get more information (add more 'v' for even more information).
```shell
> sbomsleuth openshift-4.11.z.json -vvv
```

#### Library

Using the crate `sbomsleuth`, the library can generate an SBOM quality report:

```rust
    use sbomsleuth::license::Licenses;
    use sbomsleuth::validate::parse_sbom;
    
    let sbom = parse_sbom("../etc/test-data/spdx/simple.json");
    assert!(sbom.is_ok());
    let parsed_sbom = sbom.unwrap();
    
    let license_instance = Licenses::default();
    let report_instance = sbomsleuth::report::Report {
    licenses: license_instance.run(&parsed_sbom).await.unwrap(),
    ..Default::default()
    };
    let report = report_instance.run(parsed_sbom).unwrap();
    
    println!("{}", (serde_json::to_string(&report).unwrap()));

```

## Release

To create a release

1) Create PR (ex. prepare-v1.0.0 branch) with changes to Cargo.toml version and sbomsleuth dependency
2) Review and Merge PR
3) Create new release with new tag (ex. v1.0.0) on main

Creating a release will start workflow that builds and pushes release to crates.io.