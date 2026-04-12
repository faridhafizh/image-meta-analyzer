use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::analyzer::{CameraInfo, FileInfo, GpsInfo, SoftwareInfo, TimestampInfo};

// ──────────────────────────────────────────────────────────────────────────────
// Security finding types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    pub description: String,
    pub detail: Option<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 10,
            Severity::Critical => 20,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Category {
    Location,
    DeviceIdentification,
    PersonalData,
    SoftwareFingerprint,
    TimingIntelligence,
    ContentIntegrity,
    FormatAnomaly,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Category::Location => "Location",
            Category::DeviceIdentification => "Device Identification",
            Category::PersonalData => "Personal Data",
            Category::SoftwareFingerprint => "Software Fingerprint",
            Category::TimingIntelligence => "Timing Intelligence",
            Category::ContentIntegrity => "Content Integrity",
            Category::FormatAnomaly => "Format Anomaly",
        };
        write!(f, "{}", s)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Main security analysis function
// ──────────────────────────────────────────────────────────────────────────────

pub fn analyze(
    file_info: &FileInfo,
    camera: &CameraInfo,
    gps: &Option<GpsInfo>,
    timestamps: &TimestampInfo,
    software: &SoftwareInfo,
    raw_exif: &HashMap<String, String>,
) -> Vec<SecurityFinding> {
    let mut findings: Vec<SecurityFinding> = Vec::new();

    check_gps(&mut findings, gps);
    check_device_identity(&mut findings, camera);
    check_personal_data(&mut findings, software);
    check_software_fingerprint(&mut findings, software);
    check_timing(&mut findings, timestamps);
    check_format_anomaly(&mut findings, file_info);
    check_suspicious_fields(&mut findings, raw_exif);

    // Sort by severity (highest first)
    findings.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));
    findings
}

// ──────────────────────────────────────────────────────────────────────────────
// Individual checks
// ──────────────────────────────────────────────────────────────────────────────

fn check_gps(findings: &mut Vec<SecurityFinding>, gps: &Option<GpsInfo>) {
    if let Some(g) = gps {
        findings.push(SecurityFinding {
            id: "GPS-001".into(),
            severity: Severity::Critical,
            category: Category::Location,
            title: "Precise GPS Location Embedded".into(),
            description: "The image contains exact GPS coordinates that reveal where it was taken.".into(),
            detail: Some(format!(
                "Lat: {:.6} ({})  Lon: {:.6} ({})\nMaps: {}",
                g.latitude, g.latitude_dms,
                g.longitude, g.longitude_dms,
                g.maps_url
            )),
            recommendation: "Strip GPS data with ExifTool (`exiftool -gps:all= image.jpg`) or any privacy-aware image editor before sharing.".into(),
        });

        if let Some(alt) = g.altitude {
            findings.push(SecurityFinding {
                id: "GPS-002".into(),
                severity: Severity::Medium,
                category: Category::Location,
                title: "GPS Altitude Recorded".into(),
                description: "Altitude metadata reveals the elevation at capture time, which can narrow down indoor/floor location.".into(),
                detail: Some(format!("{:.1} m above sea level", alt)),
                recommendation: "Remove altitude tags together with latitude/longitude.".into(),
            });
        }

        if g.speed.is_some() {
            findings.push(SecurityFinding {
                id: "GPS-003".into(),
                severity: Severity::Low,
                category: Category::Location,
                title: "GPS Speed Recorded".into(),
                description: "Movement speed at capture time may reveal transport mode or activity.".into(),
                detail: g.speed.clone(),
                recommendation: "Remove GPSSpeed tag when stripping location data.".into(),
            });
        }

        if g.gps_timestamp.is_some() || g.gps_datestamp.is_some() {
            findings.push(SecurityFinding {
                id: "GPS-004".into(),
                severity: Severity::Low,
                category: Category::TimingIntelligence,
                title: "GPS Timestamp Embedded".into(),
                description: "Precise UTC time-of-capture is stored in GPS tags, independent of system clock.".into(),
                detail: Some(format!(
                    "Date: {}  Time: {}",
                    g.gps_datestamp.as_deref().unwrap_or("N/A"),
                    g.gps_timestamp.as_deref().unwrap_or("N/A")
                )),
                recommendation: "Remove GPSDateStamp and GPSTimeStamp fields.".into(),
            });
        }
    }
}

fn check_device_identity(findings: &mut Vec<SecurityFinding>, camera: &CameraInfo) {
    if camera.make.is_some() || camera.model.is_some() {
        findings.push(SecurityFinding {
            id: "DEV-001".into(),
            severity: Severity::Medium,
            category: Category::DeviceIdentification,
            title: "Camera Make & Model Exposed".into(),
            description: "Device manufacturer and model are embedded, enabling device fingerprinting across images.".into(),
            detail: Some(format!(
                "Make: {}  Model: {}",
                camera.make.as_deref().unwrap_or("N/A"),
                camera.model.as_deref().unwrap_or("N/A")
            )),
            recommendation: "Remove Make and Model tags before publishing.".into(),
        });
    }

    if let Some(ref serial) = camera.serial_number {
        findings.push(SecurityFinding {
            id: "DEV-002".into(),
            severity: Severity::High,
            category: Category::DeviceIdentification,
            title: "Camera Serial Number Present".into(),
            description: "A unique camera serial number is embedded. This can definitively link multiple images to the same physical device.".into(),
            detail: Some(format!("Serial: {}", serial)),
            recommendation: "Remove CameraSerialNumber tag immediately before sharing.".into(),
        });
    }

    if let Some(ref serial) = camera.body_serial {
        findings.push(SecurityFinding {
            id: "DEV-003".into(),
            severity: Severity::High,
            category: Category::DeviceIdentification,
            title: "Camera Body Serial Number Present".into(),
            description: "Body serial number uniquely identifies the camera body used to capture this image.".into(),
            detail: Some(format!("Body Serial: {}", serial)),
            recommendation: "Remove BodySerialNumber tag before sharing.".into(),
        });
    }

    if camera.lens_model.is_some() || camera.lens_make.is_some() {
        findings.push(SecurityFinding {
            id: "DEV-004".into(),
            severity: Severity::Low,
            category: Category::DeviceIdentification,
            title: "Lens Information Exposed".into(),
            description: "Lens make/model narrows down equipment profile of the photographer.".into(),
            detail: Some(format!(
                "Lens Make: {}  Lens Model: {}",
                camera.lens_make.as_deref().unwrap_or("N/A"),
                camera.lens_model.as_deref().unwrap_or("N/A")
            )),
            recommendation: "Remove LensMake and LensModel tags.".into(),
        });
    }
}

fn check_personal_data(findings: &mut Vec<SecurityFinding>, software: &SoftwareInfo) {
    if let Some(ref artist) = software.artist {
        if !artist.trim().is_empty() {
            findings.push(SecurityFinding {
                id: "PII-001".into(),
                severity: Severity::High,
                category: Category::PersonalData,
                title: "Artist / Author Name Embedded".into(),
                description: "A personal name is stored in the Artist EXIF field.".into(),
                detail: Some(format!("Artist: {}", artist)),
                recommendation: "Remove the Artist tag before sharing externally.".into(),
            });
        }
    }

    if let Some(ref comment) = software.user_comment {
        if !comment.trim().is_empty() {
            findings.push(SecurityFinding {
                id: "PII-002".into(),
                severity: Severity::Medium,
                category: Category::PersonalData,
                title: "User Comment Field Contains Data".into(),
                description: "Free-text user comment may contain sensitive or identifying information.".into(),
                detail: Some(format!("Comment: {}", truncate(comment, 200))),
                recommendation: "Review and clear the UserComment field.".into(),
            });
        }
    }

    if let Some(ref desc) = software.image_description {
        if !desc.trim().is_empty() {
            findings.push(SecurityFinding {
                id: "PII-003".into(),
                severity: Severity::Low,
                category: Category::PersonalData,
                title: "Image Description Contains Text".into(),
                description: "A freeform image description is embedded; may reveal context or authorship.".into(),
                detail: Some(format!("Description: {}", truncate(desc, 200))),
                recommendation: "Clear ImageDescription before sharing.".into(),
            });
        }
    }

    if let Some(ref host) = software.host_computer {
        findings.push(SecurityFinding {
            id: "PII-004".into(),
            severity: Severity::Medium,
            category: Category::PersonalData,
            title: "Host Computer Name Recorded".into(),
            description: "The hostname of the computer that processed this image is stored in the metadata.".into(),
            detail: Some(format!("Hostname: {}", host)),
            recommendation: "Remove the HostComputer tag. Hostnames can uniquely identify internal systems.".into(),
        });
    }

    // XP Windows-specific tags
    for (field_name, id, val) in [
        ("XP Author", "PII-005", &software.xp_author),
        ("XP Comment", "PII-006", &software.xp_comment),
        ("XP Keywords", "PII-007", &software.xp_keywords),
        ("XP Title", "PII-008", &software.xp_title),
    ] {
        if let Some(ref v) = val {
            if !v.trim().is_empty() {
                findings.push(SecurityFinding {
                    id: id.into(),
                    severity: Severity::Low,
                    category: Category::PersonalData,
                    title: format!("Windows {} Tag Present", field_name),
                    description: format!(
                        "Windows-specific metadata '{}' is embedded and may contain personal information.",
                        field_name
                    ),
                    detail: Some(format!("{}: {}", field_name, truncate(v, 200))),
                    recommendation: format!("Remove the {} tag before sharing.", field_name),
                });
            }
        }
    }
}

fn check_software_fingerprint(findings: &mut Vec<SecurityFinding>, software: &SoftwareInfo) {
    if let Some(ref sw) = software.software {
        // Detect common editing software signatures
        let sw_lower = sw.to_lowercase();
        let editing_tools = ["photoshop", "lightroom", "gimp", "darktable", "capture one", "affinity", "luminar"];
        let is_editor = editing_tools.iter().any(|t| sw_lower.contains(t));

        let severity = if is_editor { Severity::Medium } else { Severity::Low };
        let extra = if is_editor {
            " This reveals post-processing and may indicate image manipulation."
        } else {
            ""
        };

        findings.push(SecurityFinding {
            id: "SW-001".into(),
            severity,
            category: Category::SoftwareFingerprint,
            title: "Software Tag Reveals Processing Tool".into(),
            description: format!(
                "The Software field identifies the application used to capture or edit the image.{}",
                extra
            ),
            detail: Some(format!("Software: {}", sw)),
            recommendation: "Remove or anonymize the Software tag to prevent revealing your toolchain.".into(),
        });
    }

    if let Some(ref doc) = software.document_name {
        findings.push(SecurityFinding {
            id: "SW-002".into(),
            severity: Severity::Medium,
            category: Category::SoftwareFingerprint,
            title: "Document Name / File Path Embedded".into(),
            description: "A document name or file system path is stored, potentially revealing internal directory structure.".into(),
            detail: Some(format!("DocumentName: {}", doc)),
            recommendation: "Remove the DocumentName tag; it can expose internal file paths.".into(),
        });
    }
}

fn check_timing(findings: &mut Vec<SecurityFinding>, timestamps: &TimestampInfo) {
    let has_original = timestamps.datetime_original.is_some();
    let has_modified = timestamps.datetime_modified.is_some();

    if has_original {
        findings.push(SecurityFinding {
            id: "TIME-001".into(),
            severity: Severity::Medium,
            category: Category::TimingIntelligence,
            title: "Original Capture Timestamp Present".into(),
            description: "The exact date and time of capture is stored. This can establish physical presence at a location and time.".into(),
            detail: timestamps.datetime_original.clone(),
            recommendation: "Remove DateTimeOriginal if temporal privacy is needed.".into(),
        });
    }

    if has_modified {
        findings.push(SecurityFinding {
            id: "TIME-002".into(),
            severity: Severity::Low,
            category: Category::TimingIntelligence,
            title: "Modification Timestamp Present".into(),
            description: "The DateTime field records when the file was last processed/modified. If it differs from DateTimeOriginal, editing may be inferred.".into(),
            detail: timestamps.datetime_modified.clone(),
            recommendation: "Clear the DateTime field before publishing.".into(),
        });
    }

    // Detect timestamp inconsistency (possible manipulation indicator)
    if let (Some(ref orig), Some(ref modified)) = (&timestamps.datetime_original, &timestamps.datetime_modified) {
        if orig != modified {
            findings.push(SecurityFinding {
                id: "TIME-003".into(),
                severity: Severity::Medium,
                category: Category::ContentIntegrity,
                title: "Timestamp Mismatch — Possible Post-Processing".into(),
                description: "DateTimeOriginal and DateTime differ, indicating the image was modified after capture.".into(),
                detail: Some(format!("Original: {}  |  Modified: {}", orig, modified)),
                recommendation: "Verify the image chain of custody if authenticity matters.".into(),
            });
        }
    }
}

fn check_format_anomaly(findings: &mut Vec<SecurityFinding>, file_info: &FileInfo) {
    // Very small files with EXIF are suspicious
    if file_info.size_bytes < 2048 && file_info.format == "JPEG" {
        findings.push(SecurityFinding {
            id: "FMT-001".into(),
            severity: Severity::Low,
            category: Category::FormatAnomaly,
            title: "Unusually Small JPEG File".into(),
            description: "This JPEG is very small but contains EXIF metadata. Could be a thumbnail or steganographic payload.".into(),
            detail: Some(format!("File size: {} bytes", file_info.size_bytes)),
            recommendation: "Verify the image content and origin. Check for hidden payloads.".into(),
        });
    }

    if file_info.format == "Unknown" {
        findings.push(SecurityFinding {
            id: "FMT-002".into(),
            severity: Severity::Medium,
            category: Category::FormatAnomaly,
            title: "Unrecognized File Format".into(),
            description: "File magic bytes do not match any known image format. The file may have been renamed, tampered with, or contains an unusual container.".into(),
            detail: None,
            recommendation: "Inspect the file with a hex editor. Do not open in production systems without sandboxing.".into(),
        });
    }
}

fn check_suspicious_fields(findings: &mut Vec<SecurityFinding>, raw_exif: &HashMap<String, String>) {
    // Thumbnail presence — thumbnails can leak pre-edit content
    let has_thumbnail = raw_exif.keys().any(|k| k.to_lowercase().contains("thumbnail") || k.to_lowercase().contains("jpeginterchange"));

    if has_thumbnail {
        findings.push(SecurityFinding {
            id: "INT-001".into(),
            severity: Severity::Medium,
            category: Category::ContentIntegrity,
            title: "Embedded Thumbnail May Differ from Main Image".into(),
            description: "EXIF thumbnails are pre-rendered and can contain original, unedited content even after the main image has been cropped or edited — a known privacy leak.".into(),
            detail: None,
            recommendation: "Strip thumbnails (`exiftool -ThumbnailImage= image.jpg`) when distributing edited images.".into(),
        });
    }

    // MakerNote — can contain proprietary device fingerprints
    if raw_exif.keys().any(|k| k.to_lowercase() == "makernote" || k.to_lowercase().contains("maker note")) {
        findings.push(SecurityFinding {
            id: "DEV-005".into(),
            severity: Severity::Low,
            category: Category::DeviceIdentification,
            title: "Proprietary MakerNote Data Present".into(),
            description: "Manufacturer-specific MakerNote block contains undocumented device-specific data that can fingerprint the exact device and firmware.".into(),
            detail: None,
            recommendation: "Remove MakerNote (`exiftool -MakerNote= image.jpg`), though this may break some metadata tools.".into(),
        });
    }

    // Unique image ID
    if raw_exif.contains_key("ImageUniqueID") {
        findings.push(SecurityFinding {
            id: "DEV-006".into(),
            severity: Severity::Medium,
            category: Category::DeviceIdentification,
            title: "Unique Image ID Present".into(),
            description: "A globally unique identifier is embedded in this image. This allows the image to be tracked across platforms.".into(),
            detail: raw_exif.get("ImageUniqueID").cloned(),
            recommendation: "Remove ImageUniqueID before sharing.".into(),
        });
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… (truncated)", &s[..max])
    }
}
