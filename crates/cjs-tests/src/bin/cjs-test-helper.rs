//! Sandbox helper used by the test suite (same role as `cjs-device __cjs_sandbox`).
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = match args.first().map(String::as_str) {
        Some(cjs_sandbox::HELPER_ARG) => &args[1..],
        _ => &args[..],
    };
    cjs_sandbox::helper_main(rest)
}
