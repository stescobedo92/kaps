use colored::Colorize;

pub fn show_banner() {
    println!(
        r#"
    {}{}{}{}
     /$$
| $$
| $$   /$$  /$$$$$$   /$$$$$$   /$$$$$$$
| $$  /$$/ |____  $$ /$$__  $$ /$$_____/
| $$$$$$/   /$$$$$$$| $$  \ $$|  $$$$$$
| $$_  $$  /$$__  $$| $$  | $$ \____  $$
| $$ \  $$|  $$$$$$$| $$$$$$$/ /$$$$$$$/
|__/  \__/ \_______/| $$____/ |_______/
                    | $$
                    | $$
                    |__/
    "#,
        "▄".cyan(),
        "▀".purple(),
        "▄".cyan(),
        "▀".purple()
    );
    println!("{}", " Keep Assets Protected Securely v0.1.0 ".bold().on_cyan());
    println!("{}", "🔐 AES-256-CBC | PBKDF2-HMAC-SHA256 🔐\n".blue());
}

pub fn show_runtime_banner() {
    println!("{}", "🔐 AES-256-CBC | PBKDF2-HMAC-SHA256 🔐".blue());
}