//! Standalone sandbox helper (the device binary embeds the same logic).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = match args.first().map(String::as_str) {
        Some(cjs_sandbox::HELPER_ARG) => &args[1..],
        _ => &args[..],
    };
    cjs_sandbox::helper_main(rest)
}
