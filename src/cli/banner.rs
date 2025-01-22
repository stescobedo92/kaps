use colored::Colorize;

pub fn show_banner() {
    println!(
        r#"
    {}{}{}{}
    / __/ /  / / | / / | / /
   / _/ / /__/ /|   /|   /
  /_/  /____/_/ |_/ |_/
    "#,
        "▄".cyan(),
        "▀".purple(),
        "▄".cyan(),
        "▀".purple()
    );
    println!("{}", " Secure File Vault v1.0.0 ".bold().on_cyan());
    println!("{}", "🔐 AES-256-CBC | PBKDF2-HMAC-SHA256 🔐\n".blue());
}