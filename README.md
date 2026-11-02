# 🛡️ Image Metadata Security Analyzer

[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/type-CLI-lightgrey)](#usage)

A high-performance command-line tool written in **Rust** that extracts and audits EXIF/metadata from image files and flags potential **privacy and security risks**: GPS location, device serial numbers, personal data, software fingerprints, and more.

Every finding is assigned a severity from **Info → Low → Medium → High → Critical** together with a concrete remediation recommendation.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Stripping Metadata (Remediation)](#stripping-metadata-remediation)
- [Supported Formats](#supported-formats)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Category         | What It Detects                                                                                      |
|------------------|------------------------------------------------------------------------------------------------------|
| 📍 Location      | GPS coordinates, altitude, speed, sub-meter coordinate precision, precise maps link                  |
| 🎥 Device ID     | Camera make/model, serial numbers, lens info, MakerNote                                              |
| 👤 Personal Data | Artist name, user comments (including phone/email/name PII), host computer hostname, Windows XP tags |
| 🛠 Software      | Editing software fingerprint, version numbers, document names / file paths                           |
| ⏰ Timing        | Capture timestamp, modification timestamp, sub-24h mismatches, >24h inconsistencies                  |
| 🖼 Integrity     | Embedded thumbnail leak, unique image ID tracking                                                    |
| ⚠️ Format        | Anomalous file formats, suspiciously small files                                                     |

Additional capabilities:

- **Risk scoring**: each file gets an overall risk level and numeric score.
- **File fingerprinting**: SHA-256 and MD5 hashes for every analyzed file.
- **Batch analysis**: pass any number of files (or shell globs) in one run.
- **Machine-readable output**: JSON reports with a `findings_summary` (`total`, `by_severity`, `by_category`).
- **Actionable advice**: every finding comes with a fix you can apply right away.

---

## Installation

### Prerequisites

- Rust toolchain (stable, ≥ 1.80 recommended): <https://rustup.rs>

### Build from source

```bash
git clone https://github.com/faridhafizh/image-meta-analyzer.git
cd image-meta-analyzer
cargo build --release
```

The binary will be at `target/release/image_meta_analyzer`.

### Run without installing

```bash
cargo run --release -- photo.jpg
```

### Optional: install to your PATH

```bash
cargo install --path .
```

---

## Usage

```
image_meta_analyzer [OPTIONS] <FILES>...
```

### Analyze a single image

```bash
./image_meta_analyzer photo.jpg
```

### Analyze multiple images

```bash
./image_meta_analyzer *.jpg *.png
```

### Show only security warnings

```bash
./image_meta_analyzer photo.jpg --warnings-only
```

### Output as JSON

```bash
./image_meta_analyzer photo.jpg --json
```

JSON output is a parseable array (the banner is suppressed). Each report includes a `findings_summary` object with `total`, `by_severity`, and `by_category` counts.

### Save JSON report to file

```bash
./image_meta_analyzer photo.jpg --json --output report.json
```

### Verbose mode (dumps all raw EXIF tags)

```bash
./image_meta_analyzer photo.jpg --verbose
```

### Full help

```bash
./image_meta_analyzer --help
```

### Options summary

| Option             | Description                                      |
|--------------------|--------------------------------------------------|
| `--warnings-only`  | Show only security findings, hide informational output |
| `--json`           | Output reports as JSON (banner suppressed)       |
| `--output <FILE>`  | Write the report to a file (use with `--json`)   |
| `--verbose`        | Dump all raw EXIF tags                           |
| `--help`           | Show help                                        |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════╗
║        IMAGE METADATA SECURITY ANALYZER  v1.0.0         ║
║          Detect privacy leaks hidden in images           ║
╚══════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────
 FILE: DSC_0042.jpg
 PATH: ./DSC_0042.jpg  |  2025-04-11T08:23:01Z
──────────────────────────────────────────────────────────────
 RISK LEVEL:  CRITICAL  (score: 57)
 FINDINGS:  9 findings

  File Information
    Format:                   JPEG
    Size:                     4.2 MB
    SHA-256:                  3d9f...
    MD5:                      a1b2...

  Security Findings
  ☢ [CRITICAL] [GPS-001] Precise GPS Location Embedded
     The image contains exact GPS coordinates...
     → Lat: 48.858844 (48°51'31.84"N)  Lon: 2.294351 (2°17'39.66"E)
     → Maps: https://www.google.com/maps?q=48.858844,2.294351
     💡 Strip GPS data with ExifTool before sharing.

  ✖ [HIGH] [DEV-002] Camera Serial Number Present
     A unique camera serial number is embedded...
     → Serial: 083074052489
     💡 Remove CameraSerialNumber tag immediately before sharing.
```

---

## Stripping Metadata (Remediation)

The analyzer only **reads** your files; it never modifies them. To clean an image, use one of these tools:

### Remove ALL metadata

```bash
exiftool -all= photo.jpg
```

### Remove only GPS

```bash
exiftool -gps:all= photo.jpg
```

### Remove specific dangerous tags

```bash
exiftool -CameraSerialNumber= -BodySerialNumber= -Artist= -HostComputer= photo.jpg
```

### Using ImageMagick

```bash
convert photo.jpg -strip clean_photo.jpg
```

> Tip: after cleaning, run the analyzer again to confirm nothing sensitive is left.

---

## Supported Formats

- JPEG / JFIF
- PNG
- TIFF
- WEBP
- GIF
- BMP
- JPEG2000
- HEIC / HEIF (detection and metadata analysis)

---

## Project Structure

```
image-meta-analyzer/
├── src/
│   └── main.rs        # Binary entry point (CLI, analysis, reporting)
├── Cargo.toml         # Package manifest & dependencies
├── Cargo.lock         # Locked dependency versions
├── LICENSE            # MIT license
└── README.md
```

Build artifacts are generated in `target/` by Cargo.

---

## Dependencies

| Crate                  | Purpose                                    |
|------------------------|--------------------------------------------|
| `kamadak-exif`         | EXIF tag parsing                           |
| `image`                | Pixel dimensions & format detection        |
| `clap`                 | CLI argument parsing                       |
| `colored`              | Terminal color output                      |
| `serde` / `serde_json` | JSON report serialization                  |
| `sha2` / `md-5`        | File integrity hashing                     |
| `hex`                  | Hash hex encoding                          |
| `chrono`               | Timestamp formatting                       |
| `regex`                | PII and software-version pattern detection |
| `humansize`            | Human-readable file sizes                  |

The release profile is optimized for speed and size (`opt-level = 3`, `strip = true`).

---

## Contributing

Issues and pull requests are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes and push the branch
4. Open a pull request

Before submitting, please run:

```bash
cargo fmt
cargo clippy
cargo test
```

---

## License

Released under the [MIT License](LICENSE).
