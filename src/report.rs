use colored::*;
use crate::analyzer::ImageReport;
use crate::security::{SecurityFinding, Severity};

pub fn print_report(report: &ImageReport, warnings_only: bool) {
    let divider = "─".repeat(62);

    // ── Header ────────────────────────────────────────────────────────────────
    println!("{}", divider.bright_black());
    println!(
        " {} {}",
        "FILE:".bold(),
        report.file_name.white().bold()
    );
    println!(
        " {} {}  {}  {}",
        "PATH:".dimmed(),
        report.file_path.dimmed(),
        "|".bright_black(),
        report.analysis_timestamp.dimmed()
    );
    println!("{}", divider.bright_black());

    // ── Risk summary ──────────────────────────────────────────────────────────
    let risk_colored = match report.risk_level.as_str() {
        "CLEAN" => report.risk_level.green().bold(),
        "LOW" => report.risk_level.yellow().bold(),
        "MEDIUM" => report.risk_level.truecolor(255, 165, 0).bold(),
        "HIGH" => report.risk_level.red().bold(),
        "CRITICAL" => report.risk_level.bright_red().bold(),
        _ => report.risk_level.white().bold(),
    };
    println!(
        " {}  {}  (score: {})",
        "RISK LEVEL:".bold(),
        risk_colored,
        report.risk_score
    );
    println!(
        " {}  {} findings",
        "FINDINGS:".bold(),
        report.security_findings.len()
    );
    println!();

    if !warnings_only {
        // ── File Info ─────────────────────────────────────────────────────────
        section_header("File Information");
        kv("Format", &report.file_info.format);
        kv("MIME Type", &report.file_info.mime_type);
        kv("Size", &report.file_info.size_human);
        kv("SHA-256", &report.file_info.sha256);
        kv("MD5", &report.file_info.md5);
        println!();

        // ── Image Info ────────────────────────────────────────────────────────
        section_header("Image Properties");
        kv("Dimensions", &format!("{}×{} px", report.image_info.width, report.image_info.height));
        kv("Color Mode", &report.image_info.color_mode);
        kv_opt("Orientation", report.image_info.orientation.as_deref());
        kv_opt("Color Space", report.image_info.color_space.as_deref());
        kv_opt("X Resolution", report.image_info.x_resolution.as_deref());
        kv_opt("Y Resolution", report.image_info.y_resolution.as_deref());
        println!();

        // ── Camera ────────────────────────────────────────────────────────────
        if report.camera_info.make.is_some() || report.camera_info.model.is_some() {
            section_header("Camera Information");
            kv_opt("Make", report.camera_info.make.as_deref());
            kv_opt("Model", report.camera_info.model.as_deref());
            kv_opt("Lens Make", report.camera_info.lens_make.as_deref());
            kv_opt("Lens Model", report.camera_info.lens_model.as_deref());
            kv_opt("Serial Number", report.camera_info.serial_number.as_deref());
            kv_opt("Body Serial", report.camera_info.body_serial.as_deref());
            kv_opt("Exposure Time", report.camera_info.exposure_time.as_deref());
            kv_opt("F-Number", report.camera_info.f_number.as_deref());
            kv_opt("ISO", report.camera_info.iso.as_deref());
            kv_opt("Focal Length", report.camera_info.focal_length.as_deref());
            kv_opt("Focal Length (35mm)", report.camera_info.focal_length_35mm.as_deref());
            kv_opt("Flash", report.camera_info.flash.as_deref());
            kv_opt("White Balance", report.camera_info.white_balance.as_deref());
            println!();
        }

        // ── GPS ───────────────────────────────────────────────────────────────
        if let Some(ref gps) = report.gps_info {
            section_header("GPS Location");
            kv("Latitude", &format!("{:.6}  ({})", gps.latitude, gps.latitude_dms));
            kv("Longitude", &format!("{:.6}  ({})", gps.longitude, gps.longitude_dms));
            if let Some(alt) = gps.altitude {
                kv("Altitude", &format!("{:.1} m", alt));
            }
            kv_opt("GPS Date", gps.gps_datestamp.as_deref());
            kv_opt("GPS Time", gps.gps_timestamp.as_deref());
            kv_opt("Speed", gps.speed.as_deref());
            kv("Maps URL", &gps.maps_url);
            println!();
        }

        // ── Timestamps ────────────────────────────────────────────────────────
        if report.timestamps.datetime_original.is_some() || report.timestamps.datetime_modified.is_some() {
            section_header("Timestamps");
            kv_opt("Original", report.timestamps.datetime_original.as_deref());
            kv_opt("Digitized", report.timestamps.datetime_digitized.as_deref());
            kv_opt("Modified", report.timestamps.datetime_modified.as_deref());
            println!();
        }

        // ── Software / Author ─────────────────────────────────────────────────
        let has_sw = report.software_info.software.is_some()
            || report.software_info.artist.is_some()
            || report.software_info.host_computer.is_some()
            || report.software_info.user_comment.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

        if has_sw {
            section_header("Software & Authorship");
            kv_opt("Software", report.software_info.software.as_deref());
            kv_opt("Artist", report.software_info.artist.as_deref());
            kv_opt("Copyright", report.software_info.copyright.as_deref());
            kv_opt("Host Computer", report.software_info.host_computer.as_deref());
            kv_opt("User Comment", report.software_info.user_comment.as_deref());
            kv_opt("Description", report.software_info.image_description.as_deref());
            println!();
        }
    }

    // ── Security Findings ─────────────────────────────────────────────────────
    section_header("Security Findings");

    if report.security_findings.is_empty() {
        println!("  {} No security issues found.", "✓".green().bold());
    } else {
        for finding in &report.security_findings {
            print_finding(finding);
        }
    }

    println!("{}", divider.bright_black());
    println!();
}

fn print_finding(f: &SecurityFinding) {
    let (icon, label_colored) = match f.severity {
        Severity::Info => ("ℹ", f.severity.label().white()),
        Severity::Low => ("▲", f.severity.label().yellow()),
        Severity::Medium => ("⚠", f.severity.label().truecolor(255, 165, 0)),
        Severity::High => ("✖", f.severity.label().red().bold()),
        Severity::Critical => ("☢", f.severity.label().bright_red().bold()),
    };

    println!(
        "  {} [{}] [{}] {}",
        icon,
        label_colored,
        f.id.bright_black(),
        f.title.bold()
    );
    println!("     {}", f.description.dimmed());

    if let Some(ref detail) = f.detail {
        for line in detail.lines() {
            println!("     → {}", line.cyan());
        }
    }

    println!("     💡 {}", f.recommendation.bright_black().italic());
    println!();
}

fn section_header(title: &str) {
    println!("  {}", title.underline().bold());
}

fn kv(key: &str, value: &str) {
    println!("    {:25} {}", format!("{}:", key).bright_black(), value.white());
}

fn kv_opt(key: &str, value: Option<&str>) {
    if let Some(v) = value {
        if !v.trim().is_empty() {
            kv(key, v);
        }
    }
}
