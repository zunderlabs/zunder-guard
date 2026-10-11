// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Instruments and market data.

use std::{fmt, ops::Range, sync::Arc};

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// Instrument name as the venue spells it, e.g. `BTC` for the Hyperliquid BTC perp.
///
/// Cheap to clone: the name is shared, not copied.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Symbol(Arc<str>);

impl Symbol {
    pub fn new(name: &str) -> Self {
        Self(Arc::from(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Symbol {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One OHLCV bar. `ts` is the bar's opening time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candle {
    pub ts: Timestamp,
    pub open: Decimal,
    pub high: Decimal,
    pub low: Decimal,
    pub close: Decimal,
    pub volume: Decimal,
}

impl Candle {
    /// Prices are positive, `high` is the highest, `low` the lowest, volume is not negative.
    pub fn is_well_formed(&self) -> bool {
        self.low > Decimal::ZERO
            && self.low <= self.open
            && self.low <= self.close
            && self.high >= self.open
            && self.high >= self.close
            && self.volume >= Decimal::ZERO
    }
}

/// How many leading candles of `candles` the instrument traded on: up to
/// and including the last one with volume.
///
/// Some archives (Binance's) go on after a delisting with flat candles
/// without trades at the settlement price. Nobody could trade those, and a
/// strategy that did would see a range of zero, put its stop a hair away and
/// be sized up to the leverage cap. Only such a run at the very end of the
/// data is cut: a candle without volume in the middle is a quiet bar. With
/// no candle with volume at all, nothing was traded: zero.
pub fn traded_until(candles: &[Candle]) -> usize {
    candles
        .iter()
        .rposition(|candle| candle.volume > Decimal::ZERO)
        .map_or(0, |last| last + 1)
}

/// A run of candles without volume that lasts longer than this is a
/// delisting where candles without volume mean one ([`QuietRuns::Delisting`]):
/// 24 hours.
///
/// Binance's archive fills the time after a delisting, and between a
/// delisting and a relisting (or a ticker reused for another coin), with
/// flat candles without volume: 19 to 898 days in the files of 5 Oct 2026
/// (AERGO, AIA, CTK, CVC, CVX, MAVIA, SLP, TLM), while a listed Binance
/// perpetual trades every hour (the one exception in the files is a quiet
/// hour on 28 Oct 2024, kept). A day or less without volume stays a quiet
/// stretch. Measured in time, the rule is the same for hourly, four-hourly
/// and daily candles: 24 hours of quiet bars are kept, 25 hourly, seven
/// four-hourly or two daily ones are a delisting.
pub const NOT_TRADING_AFTER_MS: i64 = Timestamp::MS_PER_DAY;

/// What candles without volume mean in a venue's archive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuietRuns {
    /// A run longer than [`NOT_TRADING_AFTER_MS`], or one at the end of the
    /// data, is a delisting: Binance's archive. Binance announces a delisting
    /// days ahead and settles open positions when it happens, so closing at
    /// the last traded close is what a bot could have done; listed Binance
    /// perpetuals do not go a day without a trade. The default, also for
    /// data whose venue is not known: trading flat candles without volume
    /// sizes positions up to the leverage cap behind stops a hair away.
    #[default]
    Delisting,
    /// Candles without volume are a quiet market that is still listed, and a
    /// delisted instrument's data simply ends: Hyperliquid's archive, whose
    /// thin perpetuals had quiet stretches of two to five days in 2024
    /// (BANANA, HPOS, NFTI, OX). Nobody knew then how long a lull would last,
    /// so a position is held through it, pays its funding and takes the gap
    /// when trading resumes. The candles are taken as they are.
    Market,
}

/// The stretches of `candles` in which the instrument traded, oldest first,
/// as index ranges.
///
/// With [`QuietRuns::Delisting`] each stretch starts and ends with a candle
/// with volume. Two stretches are separated by a run of candles without
/// volume that lasts longer than [`NOT_TRADING_AFTER_MS`], measured from the
/// opening of its first candle to the opening of the next candle with
/// volume (so candles missing from the file inside or right after the run
/// count as part of it). Shorter quiet runs stay inside their stretch.
/// Candles without volume before the first candle with volume and after the
/// last belong to no stretch: the last stretch ends at [`traded_until`]. No
/// volume at all: no stretch.
///
/// With [`QuietRuns::Market`] all candles are one stretch.
pub fn trading_stretches(candles: &[Candle], quiet: QuietRuns) -> Vec<Range<usize>> {
    let mut stretches = Vec::new();
    if quiet == QuietRuns::Market {
        if !candles.is_empty() {
            stretches.push(0..candles.len());
        }
        return stretches;
    }
    let mut traded = candles
        .iter()
        .enumerate()
        .filter(|(_, candle)| candle.volume > Decimal::ZERO)
        .map(|(index, _)| index);
    let Some(first) = traded.next() else {
        return stretches;
    };
    let (mut start, mut last) = (first, first);
    for index in traded {
        if let (Some(quiet), Some(next)) = (candles.get(last + 1), candles.get(index))
            && index > last + 1
        {
            let quiet_ms = next.ts.as_millis().saturating_sub(quiet.ts.as_millis());
            if quiet_ms > NOT_TRADING_AFTER_MS {
                stretches.push(start..last + 1);
                start = index;
            }
        }
        last = index;
    }
    stretches.push(start..last + 1);
    stretches
}

/// Funding exchanged at one moment, as a fraction of position value.
///
/// Positive means longs pay shorts. Venues settle at different intervals:
/// Hyperliquid every hour, Binance every eight hours for most perps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRate {
    pub ts: Timestamp,
    pub rate: Decimal,
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    fn candle(open: Decimal, high: Decimal, low: Decimal, close: Decimal) -> Candle {
        Candle {
            ts: Timestamp::from_millis(0),
            open,
            high,
            low,
            close,
            volume: dec!(1),
        }
    }

    #[test]
    fn well_formed_candle_passes() {
        assert!(candle(dec!(100), dec!(101), dec!(99), dec!(100.5)).is_well_formed());
        // A bar that never moved is still a valid bar.
        assert!(candle(dec!(100), dec!(100), dec!(100), dec!(100)).is_well_formed());
    }

    #[test]
    fn malformed_candles_are_rejected() {
        // High below the close.
        assert!(!candle(dec!(100), dec!(100), dec!(99), dec!(101)).is_well_formed());
        // Low above the open.
        assert!(!candle(dec!(100), dec!(102), dec!(101), dec!(102)).is_well_formed());
        // Non-positive prices.
        assert!(!candle(dec!(0), dec!(1), dec!(0), dec!(1)).is_well_formed());
    }

    #[test]
    fn trading_ends_at_the_last_candle_with_volume() {
        let at = |volume: Decimal| Candle {
            volume,
            ..candle(dec!(100), dec!(101), dec!(99), dec!(100))
        };
        // Volume 5, 0 (a quiet bar), 3, then two flat bars without trades:
        // three candles were traded on.
        let candles = [
            at(dec!(5)),
            at(dec!(0)),
            at(dec!(3)),
            at(dec!(0)),
            at(dec!(0)),
        ];
        assert_eq!(traded_until(&candles), 3);
        // Volume up to the end: all of them.
        assert_eq!(traded_until(&candles[..3]), 3);
        // No volume anywhere, or no candles: none.
        assert_eq!(traded_until(&candles[3..]), 0);
        assert_eq!(traded_until(&[]), 0);
    }

    #[test]
    fn a_quiet_run_longer_than_a_day_splits_the_trading() {
        const HOUR: i64 = Timestamp::MS_PER_HOUR;
        // Volume 1 or 0 at each hour, `holes` left out of the file.
        let hourly = |volumes: &[u8], holes: &[usize]| -> Vec<Candle> {
            volumes
                .iter()
                .enumerate()
                .filter(|(hour, _)| !holes.contains(hour))
                .map(|(hour, volume)| Candle {
                    ts: Timestamp::from_millis(hour as i64 * HOUR),
                    volume: Decimal::from(*volume),
                    ..candle(dec!(100), dec!(101), dec!(99), dec!(100))
                })
                .collect()
        };
        // Hours 0-1 traded, 2-25 quiet (24 bars: from 02:00 to the 26:00
        // open is exactly 24 hours, not longer), 26 traded, 27-51 quiet (25
        // bars: 25 hours), 52 traded, then a quiet hour at the end.
        let mut volumes = vec![1, 1];
        volumes.extend([0; 24]);
        volumes.push(1);
        volumes.extend([0; 25]);
        volumes.extend([1, 0]);
        let candles = hourly(&volumes, &[]);
        assert_eq!(candles.len(), 54);
        assert_eq!(
            trading_stretches(&candles, QuietRuns::Delisting),
            vec![0..27, 52..53]
        );
        assert_eq!(traded_until(&candles), 53);

        // Daily candles: one quiet day stays (24 hours), two do not (48).
        let daily = |volumes: &[u8]| -> Vec<Candle> {
            (0..)
                .zip(volumes)
                .map(|(day, volume)| Candle {
                    ts: Timestamp::from_millis(day * Timestamp::MS_PER_DAY),
                    volume: Decimal::from(*volume),
                    ..candle(dec!(100), dec!(101), dec!(99), dec!(100))
                })
                .collect()
        };
        assert_eq!(
            trading_stretches(&daily(&[1, 0, 1, 0, 0, 1]), QuietRuns::Delisting),
            vec![0..3, 5..6]
        );

        // A quiet hour followed by a hole of 24 missing hours: from the quiet
        // 02:00 bar to the 27:00 open is 25 hours, one run.
        let candles = hourly(
            &[&[1, 1, 0][..], &[0; 24][..], &[1][..]].concat(),
            &(3..27).collect::<Vec<_>>(),
        );
        assert_eq!(candles.len(), 4);
        assert_eq!(
            trading_stretches(&candles, QuietRuns::Delisting),
            vec![0..2, 3..4]
        );
        // A hole without a quiet bar is not a quiet run: holes are the
        // simulator's business.
        let candles = hourly(
            &[&[1, 1][..], &[0; 30][..], &[1][..]].concat(),
            &(2..32).collect::<Vec<_>>(),
        );
        assert_eq!(
            trading_stretches(&candles, QuietRuns::Delisting),
            vec![0..3]
        );

        // Quiet candles before the first trade and after the last belong to
        // no stretch; no volume at all, no stretch.
        assert_eq!(
            trading_stretches(&daily(&[0, 0, 0, 1, 1, 0]), QuietRuns::Delisting),
            vec![3..5]
        );
        assert_eq!(
            trading_stretches(&daily(&[0, 0]), QuietRuns::Delisting),
            Vec::<Range<usize>>::new()
        );
        assert_eq!(
            trading_stretches(&[], QuietRuns::Delisting),
            Vec::<Range<usize>>::new()
        );

        // Where candles without volume are a quiet market, they are all
        // traded: one stretch, quiet days at either end included.
        let quiet_market = daily(&[0, 1, 0, 0, 0, 1, 0]);
        assert_eq!(
            trading_stretches(&quiet_market, QuietRuns::Market),
            vec![0..7]
        );
        assert_eq!(
            trading_stretches(&[], QuietRuns::Market),
            Vec::<Range<usize>>::new()
        );
    }

    #[test]
    fn symbols_compare_by_name() {
        assert_eq!(Symbol::new("BTC"), Symbol::from("BTC"));
        assert_ne!(Symbol::new("BTC"), Symbol::new("ETH"));
        assert_eq!(Symbol::new("BTC").to_string(), "BTC");
    }
}
