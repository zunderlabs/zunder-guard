// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The rules code (`zr1_…`, rules schema v1) of Guard's policy, through the shared rules
//! crate (`zunder-guard-rules` in `deploy/guard/rules`), whose bounds are the core policy's.

use zunder_guard_core::policy::Policy;
use zunder_guard_rules::Rules;

/// The rules code of `policy`'s nine rules. A policy that validated is always valid rules;
/// should one not be, the text says why instead of a code.
pub fn encode(policy: &Policy) -> String {
    Rules::encode_policy(policy)
        .unwrap_or_else(|error| format!("(not expressible as a rules code: {error})"))
}

/// The policy a rules code describes: its nine rules, the rest from `base`, validated.
pub fn decode(code: &str, base: &Policy) -> Result<Policy, String> {
    let rules =
        Rules::decode(code.trim()).map_err(|error| format!("{error} ({})", error.code()))?;
    rules.to_policy(base).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rust_decimal::dec;
    use zunder_guard_core::policy::{Markets, StopPolicy};

    use super::*;

    #[test]
    fn the_default_policy_is_the_default_rules_code_and_back() {
        // The shared vector "defaults written out" (deploy/guard/rules/vectors.json).
        let code = encode(&Policy::default());
        assert_eq!(
            code,
            "zr1_eyJ2IjoxLCJtYXhMZXZlcmFnZSI6NSwibWF4TG9zc0F0U3RvcFBjdCI6Miwic3RvcFBvbGljeSI6ImF0dGFjaCIsImRlZmF1bHRTdG9wRGlzdGFuY2VQY3QiOjIsIm1pbkxpcURpc3RhbmNlUGN0IjoxMCwibWF4UG9zaXRpb25QY3QiOjIwMCwibWF4T3BlblJpc2tQY3QiOjYsImRhaWx5TG9zc1N0b3BQY3QiOjYsImRyYXdkb3duSGFsdFBjdCI6MjUsIm1hcmtldHMiOlsiKiJdfQ"
        );
        assert_eq!(
            decode(&code, &Policy::default()).unwrap(),
            Policy::default()
        );
        // A stricter policy round-trips.
        let strict = Policy {
            max_leverage: dec!(3),
            max_loss_at_stop: dec!(0.0085),
            stop: StopPolicy::Refuse,
            default_stop_distance: dec!(0.015),
            markets: Markets::Only(["BTC".to_owned(), "ETH".to_owned()].into()),
            ..Policy::default()
        };
        assert_eq!(
            decode(&encode(&strict), &Policy::default()).unwrap(),
            strict
        );
        // Refused: bad codes, out of bounds, the stop beyond the liquidation distance, the
        // removed requireStop field. Nothing is clamped.
        for json in [
            r#"{"v":1,"maxLeverage":11}"#,
            r#"{"v":1,"defaultStopDistancePct":10}"#,
            r#"{"v":1,"requireStop":true}"#,
        ] {
            use base64::Engine as _;
            let code = format!(
                "zr1_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
            );
            assert!(decode(&code, &Policy::default()).is_err(), "{json}");
        }
        assert!(decode("zr2_x", &Policy::default()).is_err());
    }
}
