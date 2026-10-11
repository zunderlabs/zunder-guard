// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
use std::{env, fs, process, thread, time::Duration};
fn main() {
    let mut args = env::args().skip(1);
    let output = args.next().expect("test output path");
    if output == "--fail" { process::exit(7); }
    if output == "--sleep" {
        fs::write(args.next().expect("test pid path"), process::id().to_string()).expect("write test pid");
        thread::sleep(Duration::from_secs(40));
        return;
    }
    let mut encoded = String::new();
    for arg in args {
        encoded.push_str("arg:");
        for byte in arg.as_bytes() { encoded.push_str(&format!("{byte:02x}")); }
        encoded.push('\n');
    }
    fs::write(output, encoded).expect("write synthetic argv receipt");
}
