use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use chrono::Utc;
use exif::{In, Reader, Tag, Value};
use image::GenericImageView;
use serde::{Deserialize, Serialize};

use crate::hash;
use crate::security::{self, SecurityFinding}; // Remove Severity if not needed in this file

// ──────────────────────────────────────────────────────────────────────────────
// Data structures
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageReport {
    pub file_path: String,
    pub file_name: String,
    pub analysis_timestamp: String,

    pub file_info: FileInfo,
    pub image_info: ImageInfo,
    pub camera_info: CameraInfo,
    pub gps_info: Option<GpsInfo>,
    pub timestamps: TimestampInfo,
    pub software_info: SoftwareInfo,
    pub raw_exif: HashMap<String, String>,

    pub security_findings: Vec<SecurityFinding>,
    pub risk_level: String,
    pub risk_score: u32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FileInfo {
    pub size_bytes: u64,
    pub size_human: String,
    pub format: String,
    pub sha256: String,
    pub md5: String,
    pub mime_type: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub color_mode: String,
    pub bit_depth: Option<u32>,
    pub compression: Option<String>,
    pub orientation: Option<String>,
    pub x_resolution: Option<String>,
    pub y_resolution: Option<String>,
    pub resolution_unit: Option<String>,
    pub color_space: Option<String>,
    pub icc_profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CameraInfo {
    pub make: Option<String>,
    pub model: Option<String>,
    pub lens_make: Option<String>,
    pub lens_model: Option<String>,
    pub serial_number: Option<String>,
    pub body_serial: Option<String>,
    pub exposure_time: Option<String>,
    pub f_number: Option<String>,
    pub iso: Option<String>,
    pub focal_length: Option<String>,
    pub focal_length_35mm: Option<String>,
    pub flash: Option<String>,
    pub white_balance: Option<String>,
    pub metering_mode: Option<String>,
    pub exposure_program: Option<String>,
    pub exposure_bias: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GpsInfo {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
    pub latitude_dms: String,
    pub longitude_dms: String,
    pub gps_timestamp: Option<String>,
    pub gps_datestamp: Option<String>,
    pub speed: Option<String>,
    pub direction: Option<String>,
    pub maps_url: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TimestampInfo {
    pub datetime_original: Option<String>,
    pub datetime_digitized: Option<String>,
    pub datetime_modified: Option<String>,
    pub subsec_time: Option<String>,
    pub timezone_offset: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SoftwareInfo {
    pub software: Option<String>,
    pub processing_software: Option<String>,
    pub artist: Option<String>,
    pub copyright: Option<String>,
    pub image_description: Option<String>,
    pub user_comment: Option<String>,
    pub xp_author: Option<String>,
    pub xp_comment: Option<String>,
    pub xp_keywords: Option<String>,
    pub xp_title: Option<String>,
    pub document_name: Option<String>,
    pub host_computer: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Main analysis entry point
// ──────────────────────────────────────────────────────────────────────────────

pub fn analyze_image(path: &Path, verbose: bool) -> Result<ImageReport, Box<dyn std::error::Error>> {
    // ── File-level info ──────────────────────────────────────────────────────
    let metadata = std::fs::metadata(path)?;
    let file_bytes = std::fs::read(path)?;
    let size_bytes = metadata.len();

    let (sha256, md5) = hash::compute_hashes(&file_bytes);
    let format = detect_format(&file_bytes);
    let mime_type = format_to_mime(&format);
    let size_human = humansize::format_size(size_bytes, humansize::DECIMAL);

    let file_info = FileInfo {
        size_bytes,
        size_human,
        format: format.clone(),
        sha256,
        md5,
        mime_type,
    };

    // ── Pixel dimensions via `image` crate ──────────────────────────────────
    let mut image_info = ImageInfo::default();
    if let Ok(img) = image::open(path) {
        let (w, h) = img.dimensions();
        image_info.width = w;
        image_info.height = h;
        image_info.color_mode = format!("{:?}", img.color());
    }

    // ── EXIF parsing ─────────────────────────────────────────────────────────
    let file = File::open(path)?;
    let mut bufreader = BufReader::new(&file);
    let exif_reader = Reader::new();

    let mut camera_info = CameraInfo::default();
    let mut gps_info_opt: Option<GpsInfo> = None;
    let mut timestamps = TimestampInfo::default();
    let mut software_info = SoftwareInfo::default();
    let mut raw_exif: HashMap<String, String> = HashMap::new();

    if let Ok(exif) = exif_reader.read_from_container(&mut bufreader) {
        for field in exif.fields() {
            let tag_name = format!("{}", field.tag);
            let value_str = field.display_value().with_unit(&exif).to_string();

            if verbose {
                raw_exif.insert(
                    format!("{} (IFD:{:?})", tag_name, field.ifd_num),
                    value_str.clone(),
                );
            }

            // populate structured fields
            match field.tag {
                // ── Image info ───────────────────────────────────────────────
                Tag::Orientation => image_info.orientation = Some(decode_orientation(&field.value)),
                Tag::XResolution => image_info.x_resolution = Some(value_str.clone()),
                Tag::YResolution => image_info.y_resolution = Some(value_str.clone()),
                Tag::ResolutionUnit => image_info.resolution_unit = Some(value_str.clone()),
                Tag::ColorSpace => image_info.color_space = Some(value_str.clone()),

                // ── Camera ───────────────────────────────────────────────────
                Tag::Make => camera_info.make = Some(value_str.clone()),
                Tag::Model => camera_info.model = Some(value_str.clone()),
                Tag::LensMake => camera_info.lens_make = Some(value_str.clone()),
                Tag::LensModel => camera_info.lens_model = Some(value_str.clone()),
                // Tag::BodySerialNumber => camera_info.body_serial = Some(value_str.clone()),
                Tag::BodySerialNumber => camera_info.serial_number = Some(value_str.clone()),
                // Tag::CameraSerialNumber => camera_info.serial_number = Some(value_str.clone()),
                Tag::ExposureTime => camera_info.exposure_time = Some(value_str.clone()),
                Tag::FNumber => camera_info.f_number = Some(value_str.clone()),
                Tag::PhotographicSensitivity => camera_info.iso = Some(value_str.clone()),
                Tag::FocalLength => camera_info.focal_length = Some(value_str.clone()),
                Tag::FocalLengthIn35mmFilm => camera_info.focal_length_35mm = Some(value_str.clone()),
                Tag::Flash => camera_info.flash = Some(value_str.clone()),
                Tag::WhiteBalance => camera_info.white_balance = Some(value_str.clone()),
                Tag::MeteringMode => camera_info.metering_mode = Some(value_str.clone()),
                Tag::ExposureProgram => camera_info.exposure_program = Some(value_str.clone()),
                Tag::ExposureBiasValue => camera_info.exposure_bias = Some(value_str.clone()),

                // ── Timestamps ───────────────────────────────────────────────
                Tag::DateTimeOriginal => timestamps.datetime_original = Some(value_str.clone()),
                Tag::DateTimeDigitized => timestamps.datetime_digitized = Some(value_str.clone()),
                Tag::DateTime => timestamps.datetime_modified = Some(value_str.clone()),
                Tag::SubSecTime => timestamps.subsec_time = Some(value_str.clone()),

                // ── Software / Authoring ─────────────────────────────────────
                Tag::Software => software_info.software = Some(value_str.clone()),
                Tag::Artist => software_info.artist = Some(value_str.clone()),
                Tag::Copyright => software_info.copyright = Some(value_str.clone()),
                Tag::ImageDescription => software_info.image_description = Some(value_str.clone()),
                Tag::UserComment => software_info.user_comment = Some(clean_user_comment(&field.value)),
                // Tag::DocumentName => software_info.document_name = Some(value_str.clone()),
                t if t.number() == 0x010d => software_info.document_name = Some(value_str.clone()),
                // Tag::HostComputer => software_info.host_computer = Some(value_str.clone()),
                t if t.number() == 0x013c => software_info.host_computer = Some(value_str.clone()),

                // ── GPS ──────────────────────────────────────────────────────
                Tag::GPSLatitude | Tag::GPSLongitude | Tag::GPSAltitude
                | Tag::GPSLatitudeRef | Tag::GPSLongitudeRef | Tag::GPSAltitudeRef
                | Tag::GPSTimeStamp | Tag::GPSDateStamp
                | Tag::GPSSpeed | Tag::GPSTrack => {
                    // Handled in a second pass below for clarity
                }

                _ => {}
            }
        }

        // ── GPS second pass (needs multiple tags together) ────────────────────
        gps_info_opt = extract_gps(&exif);

        // ── Always collect raw EXIF for non-verbose JSON export ──────────────
        if !verbose {
            for field in exif.fields() {
                let tag_name = format!("{}", field.tag);
                let value_str = field.display_value().with_unit(&exif).to_string();
                raw_exif.insert(tag_name, value_str);
            }
        }
    }

    // ── Security analysis ────────────────────────────────────────────────────
    let security_findings = security::analyze(
        &file_info,
        &camera_info,
        &gps_info_opt,
        &timestamps,
        &software_info,
        &raw_exif,
    );

    let risk_score = security_findings.iter().map(|f| f.severity.score()).sum();
    let risk_level = severity_label(risk_score);

    Ok(ImageReport {
        file_path: path.display().to_string(),
        file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
        analysis_timestamp: Utc::now().to_rfc3339(),
        file_info,
        image_info,
        camera_info,
        gps_info: gps_info_opt,
        timestamps,
        software_info,
        raw_exif,
        security_findings,
        risk_level,
        risk_score,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// GPS helpers
// ──────────────────────────────────────────────────────────────────────────────

fn extract_gps(exif: &exif::Exif) -> Option<GpsInfo> {
    let lat = rational_to_degrees(exif.get_field(Tag::GPSLatitude, In::PRIMARY)?)?;
    let lat_ref = exif
        .get_field(Tag::GPSLatitudeRef, In::PRIMARY)
        .and_then(|f| ascii_value(&f.value));
    let lon = rational_to_degrees(exif.get_field(Tag::GPSLongitude, In::PRIMARY)?)?;
    let lon_ref = exif
        .get_field(Tag::GPSLongitudeRef, In::PRIMARY)
        .and_then(|f| ascii_value(&f.value));

    let lat_signed = if lat_ref.as_deref() == Some("S") { -lat } else { lat };
    let lon_signed = if lon_ref.as_deref() == Some("W") { -lon } else { lon };

    let altitude = exif.get_field(Tag::GPSAltitude, In::PRIMARY).and_then(|f| {
        if let Value::Rational(ref rationals) = f.value {
            rationals.first().map(|r| r.to_f64())
        } else {
            None
        }
    });

    let gps_timestamp = exif.get_field(Tag::GPSTimeStamp, In::PRIMARY)
        .map(|f| f.display_value().to_string());
    let gps_datestamp = exif.get_field(Tag::GPSDateStamp, In::PRIMARY)
        .map(|f| f.display_value().to_string());

    let speed = exif.get_field(Tag::GPSSpeed, In::PRIMARY)
        .map(|f| f.display_value().to_string());
    let direction = exif.get_field(Tag::GPSTrack, In::PRIMARY)
        .map(|f| f.display_value().to_string());

    Some(GpsInfo {
        latitude: lat_signed,
        longitude: lon_signed,
        altitude,
        latitude_dms: decimal_to_dms(lat_signed, true),
        longitude_dms: decimal_to_dms(lon_signed, false),
        gps_timestamp,
        gps_datestamp,
        speed,
        direction,
        maps_url: format!(
            "https://www.google.com/maps?q={:.6},{:.6}",
            lat_signed, lon_signed
        ),
    })
}

fn rational_to_degrees(field: &exif::Field) -> Option<f64> {
    if let Value::Rational(ref v) = field.value {
        if v.len() >= 3 {
            let deg = v[0].to_f64();
            let min = v[1].to_f64();
            let sec = v[2].to_f64();
            return Some(deg + min / 60.0 + sec / 3600.0);
        }
    }
    None
}

fn ascii_value(val: &Value) -> Option<String> {
    if let Value::Ascii(ref v) = val {
        v.first()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.trim_end_matches('\0').to_string())
    } else {
        None
    }
}

fn decimal_to_dms(decimal: f64, is_lat: bool) -> String {
    let abs = decimal.abs();
    let deg = abs as u32;
    let min = ((abs - deg as f64) * 60.0) as u32;
    let sec = (abs - deg as f64 - min as f64 / 60.0) * 3600.0;
    let dir = if is_lat {
        if decimal >= 0.0 { "N" } else { "S" }
    } else {
        if decimal >= 0.0 { "E" } else { "W" }
    };
    format!("{}°{}'{:.2}\"{}", deg, min, sec, dir)
}

// ──────────────────────────────────────────────────────────────────────────────
// Misc helpers
// ──────────────────────────────────────────────────────────────────────────────

fn detect_format(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "JPEG".into()
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "PNG".into()
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        "GIF".into()
    } else if bytes.starts_with(b"II\x2A\x00") || bytes.starts_with(b"MM\x00\x2A") {
        "TIFF".into()
    } else if bytes.starts_with(b"RIFF") && bytes.len() > 12 && &bytes[8..12] == b"WEBP" {
        "WEBP".into()
    } else if bytes.starts_with(b"BM") {
        "BMP".into()
    } else if bytes.starts_with(b"\x00\x00\x00\x0C\x6A\x50") {
        "JPEG2000".into()
    } else {
        "Unknown".into()
    }
}

fn format_to_mime(fmt: &str) -> String {
    match fmt {
        "JPEG" => "image/jpeg",
        "PNG" => "image/png",
        "GIF" => "image/gif",
        "TIFF" => "image/tiff",
        "WEBP" => "image/webp",
        "BMP" => "image/bmp",
        "JPEG2000" => "image/jp2",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn decode_orientation(val: &Value) -> String {
    if let Value::Short(ref v) = val {
        return match v.first() {
            Some(1) => "Normal (0°)".into(),
            Some(2) => "Flipped Horizontally".into(),
            Some(3) => "Rotated 180°".into(),
            Some(4) => "Flipped Vertically".into(),
            Some(5) => "Transposed".into(),
            Some(6) => "Rotated 90° CW".into(),
            Some(7) => "Transverse".into(),
            Some(8) => "Rotated 270° CW".into(),
            _ => "Unknown".into(),
        };
    }
    "Unknown".into()
}

fn clean_user_comment(val: &Value) -> String {
    if let Value::Undefined(ref bytes, _) = val {
        // First 8 bytes are charset identifier
        if bytes.len() > 8 {
            let payload = &bytes[8..];
            return String::from_utf8_lossy(payload)
                .trim_matches('\0')
                .to_string();
        }
    }
    String::new()
}

fn severity_label(score: u32) -> String {
    match score {
        0 => "CLEAN".into(),
        1..=5 => "LOW".into(),
        6..=15 => "MEDIUM".into(),
        16..=30 => "HIGH".into(),
        _ => "CRITICAL".into(),
    }
}
