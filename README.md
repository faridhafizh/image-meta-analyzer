# Image Metadata Security Analyzer

A command-line tool written in **Rust** that extracts and audits EXIF/metadata from image files, flagging potential **privacy and security risks**.

---

## Features

| Category | What It Detects |
|---|---|
| 📍 Location | GPS coordinates, altitude, speed, sub-meter coordinate precision, precise maps link |
| 🎥 Device ID | Camera make/model, serial numbers, lens info, MakerNote |
| 👤 Personal Data | Artist name, user comments (including phone/email/name PII), host computer hostname, Windows XP tags |
| 🛠 Software | Editing software fingerprint, version numbers, document names / file paths |
| ⏰ Timing | Capture timestamp, modification timestamp, sub-24h mismatches, >24h inconsistencies |
| 🖼 Integrity | Embedded thumbnail leak, unique image ID tracking |
| ⚠️ Format | Anomalous file formats, suspiciously small files |

Each finding is assigned a severity: **Info → Low → Medium → High → Critical** with a remediation recommendation.

---

## Installation

### Prerequisites

- Rust toolchain (≥ 1.80): https://rustup.rs

### Build

```bash
git clone <repo>
cd image_meta_analyzer
cargo build --release
```

The binary will be at `target/release/image_meta_analyzer`.

---

## Usage

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

JSON output is a parseable array (the banner is suppressed). Each report includes a
`findings_summary` object with `total`, `by_severity`, and `by_category` counts.

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

## Dependencies

| Crate | Purpose |
|---|---|
| `kamadak-exif` | EXIF tag parsing |
| `image` | Pixel dimensions & format detection |
| `clap` | CLI argument parsing |
| `colored` | Terminal color output |
| `serde` / `serde_json` | JSON report serialization |
| `sha2` / `md-5` | File integrity hashing |
| `chrono` | Timestamp formatting |
| `regex` | PII and software-version pattern detection |
| `humansize` | Human-readable file sizes |
| `hex` | Hash hex encoding |

---

## License

MIT
