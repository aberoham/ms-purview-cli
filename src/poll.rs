//! Waiting for an operation to finish (`docs/SPEC.md` section 4.6).
//!
//! - One deadline covers the whole wait: the reads, the sleeps between
//!   them and the retries inside each read. A read still in flight when it
//!   passes is abandoned.
//! - Reads are spaced 10 s apart for the first 2 minutes, then 30 s up to
//!   10 minutes, then 60 s, unless a fixed interval is given.
//! - A read that fails in a way a later read may not (no response, or HTTP
//!   429 or 5xx after the client's own retries, including a `Retry-After`
//!   longer than the client waits for) does not end the wait: the next read
//!   comes after the usual interval or Graph's `Retry-After`, whichever is
//!   longer, still within the deadline. Any other failure ends it.
//! - Ctrl-C ends the wait. The service carries on running the operation.

use std::io::Write;
use std::time::Duration;

use crate::env::{Clock, Interrupt};
use crate::error::{PurviewError, Result};
use crate::graph::GraphClient;
use crate::model::valid::PollTarget;
use crate::model::wire::OperationRecord;
use crate::output::sanitize;
use crate::routes::{Query, ReadRoute};

/// The default deadline of `operation get --wait` (`docs/SPEC.md` section
/// 3.5).
pub const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
/// The shortest `--poll-interval`.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The longest `--wait-timeout`: a day.
pub const MAX_WAIT_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// How long to wait and how often to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub timeout: Duration,
    /// A fixed interval; `None` follows `scheduled_interval`.
    pub interval: Option<Duration>,
}

/// The interval after `elapsed` of waiting: 10 s for the first 2 minutes,
/// then 30 s up to 10 minutes, then 60 s.
pub fn scheduled_interval(elapsed: Duration) -> Duration {
    if elapsed < Duration::from_secs(2 * 60) {
        Duration::from_secs(10)
    } else if elapsed < Duration::from_secs(10 * 60) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(60)
    }
}

/// How a wait ended. `last` is the newest record read, if any.
#[derive(Debug, Clone, PartialEq)]
pub enum PollEnd {
    /// The operation reached a status that stops polling.
    Finished(OperationRecord),
    /// The deadline passed first.
    TimedOut { last: Option<OperationRecord> },
    /// Ctrl-C.
    Interrupted { last: Option<OperationRecord> },
}

/// What the wait needs besides the route.
pub struct Poller<'a> {
    pub graph: &'a GraphClient,
    pub clock: &'a dyn Clock,
    pub interrupt: &'a dyn Interrupt,
    pub timing: Timing,
    /// For an operation the same command has just submitted: a 404 within
    /// this long of the start is read as "not visible yet" and retried
    /// (Assumption). `None` for an operation named on the command line,
    /// whose 404 fails at once.
    pub not_found_grace: Option<Duration>,
}

impl Poller<'_> {
    /// Reads `route` until the operation stops, the deadline passes or
    /// Ctrl-C. `progress` is called after each read of a running
    /// operation, with the time waited so far.
    pub async fn wait(
        &self,
        route: &ReadRoute,
        log: &mut (dyn Write + Send),
        progress: &mut (dyn FnMut(&OperationRecord, Duration, &mut (dyn Write + Send)) + Send),
    ) -> Result<PollEnd> {
        let started = self.clock.elapsed();
        let deadline = started + self.timing.timeout;
        let mut last: Option<OperationRecord> = None;
        let query = Query::new();
        // One listener for the whole wait, so that a Ctrl-C between a read
        // and the sleep after it is not missed.
        let interrupted = self.interrupt.wait();
        tokio::pin!(interrupted);
        loop {
            let Some(remaining) = deadline
                .checked_sub(self.clock.elapsed())
                .filter(|left| !left.is_zero())
            else {
                return Ok(PollEnd::TimedOut { last });
            };
            let read = tokio::select! {
                biased;
                () = &mut interrupted => return Ok(PollEnd::Interrupted { last }),
                read = tokio::time::timeout(remaining, self.graph.get(route, &query, log)) => read,
            };
            let waited = self.clock.elapsed().saturating_sub(started);
            let mut asked: Option<Duration> = None;
            let read = match read {
                Err(_elapsed) => return Ok(PollEnd::TimedOut { last }),
                Ok(read) => read.and_then(|body| checked(body, route)),
            };
            // A read that ended after the deadline does not count, whatever
            // it says: the deadline covers the whole wait. A valid record
            // still gives the last status.
            if self.clock.elapsed() >= deadline {
                if let Ok(record) = read {
                    last = Some(record);
                }
                return Ok(PollEnd::TimedOut { last });
            }
            match read {
                Ok(record) => {
                    if record.status.is_terminal() {
                        return Ok(PollEnd::Finished(record));
                    }
                    progress(&record, waited, log);
                    last = Some(record);
                }
                Err(error)
                    if error.graph_status() == Some(404)
                        && self.not_found_grace.is_some_and(|grace| waited < grace) =>
                {
                    let _ = writeln!(
                        log,
                        "notice: the operation is not visible yet; reading it again"
                    );
                }
                Err(error) if error.is_transient_graph_failure() => {
                    asked = error.retry_after();
                    let _ = writeln!(
                        log,
                        "warning: reading the operation failed ({}); still waiting",
                        sanitize(&error.to_string())
                    );
                }
                Err(error) => return Err(error),
            }
            let waited = self.clock.elapsed().saturating_sub(started);
            let interval = self
                .timing
                .interval
                .unwrap_or_else(|| scheduled_interval(waited));
            let pause = asked.map_or(interval, |asked| asked.max(interval));
            let Some(remaining) = deadline
                .checked_sub(self.clock.elapsed())
                .filter(|left| !left.is_zero())
            else {
                return Ok(PollEnd::TimedOut { last });
            };
            tokio::select! {
                biased;
                () = &mut interrupted => return Ok(PollEnd::Interrupted { last }),
                () = self.clock.sleep(pause.min(remaining)) => {}
            }
        }
    }
}

/// The record in a poll's answer, checked: every record read, not only
/// the last, must have a valid id and status and be the operation asked
/// for.
pub fn checked(body: serde_json::Value, route: &ReadRoute) -> Result<OperationRecord> {
    let record = OperationRecord::from_value(body).ok_or_else(|| {
        PurviewError::message("Graph returned an operation that is not an object")
    })?;
    let target = PollTarget::new(&record)?;
    if let ReadRoute::Operation(_, wanted) = route {
        if target.id != *wanted {
            return Err(PurviewError::message(format!(
                "Graph answered the read of operation {wanted} with operation {}",
                target.id
            )));
        }
    }
    Ok(record)
}

/// A duration for a person: `35s`, `4m10s`, `1h02m`.
pub fn elapsed_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h{:02}m", seconds / 3600, seconds % 3600 / 60),
    }
}

/// A `--wait-timeout` or `--poll-interval` value: whole seconds, or a
/// number followed by `s`, `m` or `h`, or several of those run together
/// (`1h30m`).
pub fn parse_duration(flag: &str, text: &str) -> Result<Duration> {
    let refuse = || {
        PurviewError::message(format!(
            "{flag} must be a duration such as 90s, 15m, 2h or 1h30m, or whole seconds"
        ))
    };
    let text = text.trim();
    if text.is_empty() {
        return Err(refuse());
    }
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    for character in text.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let unit = match character {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(refuse()),
        };
        let value: u64 = digits.parse().map_err(|_| refuse())?;
        total = value
            .checked_mul(unit)
            .and_then(|part| total.checked_add(part))
            .ok_or_else(refuse)?;
        digits.clear();
    }
    if !digits.is_empty() {
        return Err(refuse());
    }
    Ok(Duration::from_secs(total))
}

/// The timing flags, checked: `--poll-interval` of at least 5 s, and a
/// `--wait-timeout` from 1 s to a day.
pub fn timing(
    wait_timeout: Option<&str>,
    poll_interval: Option<&str>,
    default_timeout: Duration,
) -> Result<Timing> {
    let timeout = match wait_timeout {
        Some(text) => parse_duration("--wait-timeout", text)?,
        None => default_timeout,
    };
    if timeout.is_zero() || timeout > MAX_WAIT_TIMEOUT {
        return Err(PurviewError::message(
            "--wait-timeout must be at least 1 second and at most 24 hours",
        ));
    }
    let interval = poll_interval
        .map(|text| parse_duration("--poll-interval", text))
        .transpose()?;
    if interval.is_some_and(|interval| interval < MIN_POLL_INTERVAL) {
        return Err(PurviewError::message(
            "--poll-interval must be at least 5 seconds",
        ));
    }
    Ok(Timing { timeout, interval })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schedule_steps_from_10_to_30_to_60_seconds() {
        let at = |seconds| scheduled_interval(Duration::from_secs(seconds)).as_secs();
        assert_eq!(
            [at(0), at(119), at(120), at(599), at(600), at(7200)],
            [10, 10, 30, 30, 60, 60]
        );
    }

    #[test]
    fn durations_take_units_or_whole_seconds() {
        let parse = |text| parse_duration("--wait-timeout", text).map(|value| value.as_secs());
        assert_eq!(parse("90").unwrap(), 90);
        assert_eq!(parse("90s").unwrap(), 90);
        assert_eq!(parse("15m").unwrap(), 900);
        assert_eq!(parse("2h").unwrap(), 7200);
        assert_eq!(parse("1h30m").unwrap(), 5400);
        for bad in [
            "",
            "m",
            "5d",
            "1.5h",
            "10m5",
            "-5s",
            "99999999999999999999h",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timing_flags_are_bounded() {
        assert_eq!(
            timing(None, None, DEFAULT_WAIT_TIMEOUT).unwrap(),
            Timing {
                timeout: DEFAULT_WAIT_TIMEOUT,
                interval: None
            }
        );
        assert!(timing(Some("0"), None, DEFAULT_WAIT_TIMEOUT).is_err());
        assert!(timing(Some("25h"), None, DEFAULT_WAIT_TIMEOUT).is_err());
        assert!(timing(None, Some("4s"), DEFAULT_WAIT_TIMEOUT).is_err());
        assert_eq!(
            timing(Some("10m"), Some("5s"), DEFAULT_WAIT_TIMEOUT).unwrap(),
            Timing {
                timeout: Duration::from_secs(600),
                interval: Some(Duration::from_secs(5))
            }
        );
    }

    #[test]
    fn elapsed_time_reads_as_seconds_minutes_or_hours() {
        let text = |seconds| elapsed_text(Duration::from_secs(seconds));
        assert_eq!(text(35), "35s");
        assert_eq!(text(250), "4m10s");
        assert_eq!(text(3720), "1h02m");
    }
}
