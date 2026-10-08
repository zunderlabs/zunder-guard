// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
use std::{env, process, thread, time::Duration};
fn main() {
    let executable = env::current_exe().expect("synthetic executable");
    let mode = executable.file_stem().expect("synthetic mode").to_string_lossy();
    let expected = "Error: service refused: managed WER or LocalDumps policy prevents service secret admission";
    match mode.as_ref() {
        "policy-good" => { eprintln!("{expected}"); process::exit(1); }
        "policy-wrong-status" => { eprintln!("{expected}"); process::exit(2); }
        "policy-wrong-message" => { eprintln!("unexpected refusal"); process::exit(1); }
        "policy-stdout" => { println!("unexpected output"); eprintln!("{expected}"); process::exit(1); }
        "policy-oversize" => { eprintln!("{}", "x".repeat(600)); process::exit(1); }
        "policy-timeout" => { thread::sleep(Duration::from_secs(20)); }
        _ => { process::exit(3); }
    }
}
