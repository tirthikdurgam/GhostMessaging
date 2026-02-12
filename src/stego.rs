use anyhow::Result;

/// Wraps the ticket in our format: [Ghost:<DATA>]
/// We no longer use Hex encoding to keep the size small.
pub fn hide(_cover: &str, secret: &str) -> String {
    format!("[Ghost:{}]", secret)
}

/// Extracts the ticket from the [Ghost:...] format
pub fn reveal(text: &str) -> Result<String> {
    // Check if it matches our format
    if let Some(start) = text.find("[Ghost:") {
        if let Some(end) = text[start..].find(']') {
            // Extract the string between [Ghost: and ]
            // Since we removed Hex, this is the raw Base64 string we need.
            let secret = &text[start + 7..start + end];
            return Ok(secret.to_string());
        }
    }
    
    // Fallback: If user pasted raw text without the [Ghost:] wrapper
    Ok(text.trim().to_string())
}