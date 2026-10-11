// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Time as integer milliseconds. There are no time zones: everything is UTC.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Milliseconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const MS_PER_HOUR: i64 = 3_600_000;
    pub const MS_PER_DAY: i64 = 24 * Self::MS_PER_HOUR;
    /// 365 days. Used to turn annual rates into per-bar rates.
    pub const MS_PER_YEAR: i64 = 365 * Self::MS_PER_DAY;

    pub const fn from_millis(ms: i64) -> Self {
        Self(ms)
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Whole days since the epoch. Daily risk windows roll when this changes.
    pub const fn utc_day(self) -> i64 {
        self.0.div_euclid(Self::MS_PER_DAY)
    }

    /// Calendar date in UTC as `(year, month, day)`.
    pub const fn utc_ymd(self) -> (i64, u32, u32) {
        civil_from_days(self.utc_day())
    }

    /// Midnight UTC at the start of the given date. `None` for a date that
    /// does not exist, such as 30 February, or one too far out to represent.
    pub fn from_utc_ymd(year: i64, month: u32, day: u32) -> Option<Self> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year.abs() > 1_000_000 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        // Round-tripping rejects 31 April and 29 February outside leap years.
        if civil_from_days(days) != (year, month, day) {
            return None;
        }
        days.checked_mul(Self::MS_PER_DAY).map(Self)
    }
}

impl fmt::Display for Timestamp {
    /// ISO 8601 with second precision, e.g. `2026-10-04T12:00:00Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = self.utc_ymd();
        let ms = self.0.rem_euclid(Self::MS_PER_DAY);
        let (hour, minute, second) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1_000 % 60);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )
    }
}

/// A proleptic Gregorian date to days since 1970-01-01.
///
/// Howard Hinnant's `days_from_civil` algorithm, the inverse of
/// [`civil_from_days`].
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
///
/// Howard Hinnant's `civil_from_days` algorithm.
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = Timestamp::MS_PER_DAY;

    #[test]
    fn epoch_is_first_of_january_1970() {
        assert_eq!(Timestamp::from_millis(0).utc_ymd(), (1970, 1, 1));
        assert_eq!(Timestamp::from_millis(0).utc_day(), 0);
    }

    #[test]
    fn known_dates_convert_correctly() {
        // Leap day in a year divisible by 400.
        assert_eq!(
            Timestamp::from_millis(11_016 * DAY).utc_ymd(),
            (2000, 2, 29)
        );
        assert_eq!(Timestamp::from_millis(11_017 * DAY).utc_ymd(), (2000, 3, 1));
        // The day this file was written.
        assert_eq!(
            Timestamp::from_millis(20_730 * DAY).utc_ymd(),
            (2026, 10, 4)
        );
        // Last and first day of a year.
        assert_eq!(
            Timestamp::from_millis(20_453 * DAY).utc_ymd(),
            (2025, 12, 31)
        );
        assert_eq!(Timestamp::from_millis(20_454 * DAY).utc_ymd(), (2026, 1, 1));
    }

    #[test]
    fn times_before_the_epoch_round_towards_the_past() {
        let just_before = Timestamp::from_millis(-1);
        assert_eq!(just_before.utc_day(), -1);
        assert_eq!(just_before.utc_ymd(), (1969, 12, 31));
    }

    #[test]
    fn day_rolls_exactly_at_midnight() {
        let last_ms = Timestamp::from_millis(20_730 * DAY - 1);
        let first_ms = Timestamp::from_millis(20_730 * DAY);
        assert_eq!(last_ms.utc_day() + 1, first_ms.utc_day());
    }

    #[test]
    fn dates_convert_to_midnight_and_back() {
        assert_eq!(
            Timestamp::from_utc_ymd(1970, 1, 1),
            Some(Timestamp::from_millis(0))
        );
        // Day numbers from `known_dates_convert_correctly`.
        assert_eq!(
            Timestamp::from_utc_ymd(2026, 10, 4),
            Some(Timestamp::from_millis(20_730 * DAY))
        );
        assert_eq!(
            Timestamp::from_utc_ymd(2000, 2, 29),
            Some(Timestamp::from_millis(11_016 * DAY))
        );
        assert_eq!(
            Timestamp::from_utc_ymd(1969, 12, 31),
            Some(Timestamp::from_millis(-DAY))
        );
        // Every day of four years, leap year included, round-trips.
        for day in 20_000..20_000 + 4 * 366 {
            let (year, month, date) = Timestamp::from_millis(day * DAY).utc_ymd();
            assert_eq!(
                Timestamp::from_utc_ymd(year, month, date),
                Some(Timestamp::from_millis(day * DAY))
            );
        }
    }

    #[test]
    fn impossible_dates_are_refused() {
        assert_eq!(Timestamp::from_utc_ymd(2026, 2, 29), None);
        assert_eq!(Timestamp::from_utc_ymd(2026, 4, 31), None);
        assert_eq!(Timestamp::from_utc_ymd(2026, 13, 1), None);
        assert_eq!(Timestamp::from_utc_ymd(2026, 0, 1), None);
        assert_eq!(Timestamp::from_utc_ymd(2026, 1, 0), None);
        assert!(Timestamp::from_utc_ymd(2024, 2, 29).is_some());
        assert_eq!(Timestamp::from_utc_ymd(i64::MAX, 1, 1), None);
    }

    #[test]
    fn displays_as_iso_8601() {
        let ts = Timestamp::from_millis(20_730 * DAY + 13 * 3_600_000 + 5 * 60_000 + 9_000 + 250);
        assert_eq!(ts.to_string(), "2026-10-04T13:05:09Z");
    }
}
