# Plan: Add AI metadata detection

## Goal
Add security checks to detect AI-generated image metadata (both tool names and generation parameters/C2PA-related indicators).

## Scope
- Modify `src/security.rs` to add `check_ai_metadata` function
- Call it from `analyze()` 
- Cover common AI tools: Midjourney, DALL-E/Bing/Civitai/Bing, Stable Diffusion/Automatic1111/ComfyUI/SDXL/Stable, Flux, Ideogram, Replika, Leonardo, DreamStudio, Bing Image Creator, Ideogram, Glyph, etc.
- Cover generation params in Software/UserComment/Description/XP fields and common tag names like "Prompt", "AI", "Generation", "StableDiffusion", "Parameters", "C2PA", "ai", "generator", "dream", etc.
- Add new finding IDs (e.g., AI-001 for tool detection, AI-002 for params/C2PA)
- Keep consistent severity/category (likely SoftwareFingerprint or ContentIntegrity)

## Implementation
1. Add `check_ai_metadata(findings: &mut Vec<SecurityFinding>, software: &SoftwareInfo, raw_exif: &HashMap<String, String>)`
2. Check `software.software`, `software.processing_software`, `user_comment`, `image_description`, `xp_*` for AI tool names/patterns
3. Scan all raw_exif keys/values case-insensitively for AI indicators (prompt, parameters, c2pa, "AI generated", etc.)
4. Emit findings with appropriate severity/recommendations
5. Add tests if easy

## Validation
- Run `cargo test` to ensure existing tests pass
- Try on test images if available

## Notes
- Be careful not to produce excessive false positives; prefer patterns common in AI metadata
- Keep recommendations actionable (strip/anonymize)
