//! Bounded UTC five-field cron parsing and evaluation.
//!
//! The accepted grammar is closed: five whitespace-separated fields over
//! digits, `*`, `,`, `-`, and `/`. Names, macros, seconds, and the usual
//! extensions are rejected before the parser crate sees the expression.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

const MAX_CRON_EXPR_BYTES: usize = 256;
const MAX_CRON_HORIZON: Duration = Duration::from_secs(3_660 * 24 * 60 * 60);

/// One bounded cron grammar/evaluation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CronError(&'static str);

impl fmt::Display for CronError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Validates the closed five-field UTC grammar and range bounds.
pub(crate) fn validate_cron_expr(expression: &str) -> Result<(), CronError> {
    if expression.is_empty() || expression.len() > MAX_CRON_EXPR_BYTES {
        return Err(CronError(
            "cron expression must be non-empty and at most 256 bytes",
        ));
    }
    let fields: Vec<&str> = expression.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(CronError("cron expression must have exactly five fields"));
    }
    for (field, (minimum, maximum)) in fields.iter().zip(FIELD_BOUNDS) {
        validate_field(field, minimum, maximum)?;
    }
    expression
        .parse::<croner::Cron>()
        .map(|_| ())
        .map_err(|_| CronError("cron expression is not valid"))
}

const FIELD_BOUNDS: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];

fn validate_field(field: &str, minimum: u32, maximum: u32) -> Result<(), CronError> {
    if field.is_empty() {
        return Err(CronError("cron expression has an empty field"));
    }
    for character in field.chars() {
        if !character.is_ascii_digit() && !matches!(character, '*' | ',' | '-' | '/') {
            return Err(CronError(
                "cron expression contains an unsupported character",
            ));
        }
    }
    if field == "*" {
        return Ok(());
    }
    if let Some(step) = field.strip_prefix("*/") {
        validate_step(step)?;
        return Ok(());
    }
    for item in field.split(',') {
        validate_item(item, minimum, maximum)?;
    }
    Ok(())
}

fn validate_item(item: &str, minimum: u32, maximum: u32) -> Result<(), CronError> {
    if item.is_empty() {
        return Err(CronError("cron expression has an empty list item"));
    }
    if item.contains('*') {
        return Err(CronError("cron wildcard must be the whole field"));
    }
    let (range, stepped) = match item.split_once('/') {
        Some((range, step)) => {
            validate_step(step)?;
            (range, true)
        }
        None => (item, false),
    };
    if range.contains('/') {
        return Err(CronError("cron step must be a single suffix"));
    }
    match range.split_once('-') {
        Some((start, end)) => {
            if end.contains('-') {
                return Err(CronError("cron range has too many separators"));
            }
            let start = parse_value(start, minimum, maximum)?;
            let end = parse_value(end, minimum, maximum)?;
            if start > end {
                return Err(CronError("cron range must not descend"));
            }
        }
        None => {
            if stepped {
                return Err(CronError("cron step requires a range or wildcard"));
            }
            parse_value(range, minimum, maximum)?;
        }
    }
    Ok(())
}

fn parse_value(value: &str, minimum: u32, maximum: u32) -> Result<u32, CronError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| CronError("cron field value is not a number"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(CronError("cron field value is out of range"));
    }
    Ok(parsed)
}

fn validate_step(step: &str) -> Result<(), CronError> {
    let step = step
        .parse::<u32>()
        .map_err(|_| CronError("cron step is not a number"))?;
    if step == 0 {
        return Err(CronError("cron step must be positive"));
    }
    Ok(())
}

/// Cheap calendar feasibility check, run before asking croner to search.
///
/// Under POSIX DOM/DOW OR semantics, any restricted day-of-week is satisfiable
/// because every month contains every weekday. When day-of-week is `*`, the
/// day-of-month and month fields must overlap in at least one real date.
fn calendar_satisfiable(fields: &[&str; 5]) -> bool {
    if fields[4] != "*" {
        return true;
    }
    let (Some(days), Some(months)) = (
        allowed_values(fields[2], 1, 31),
        allowed_values(fields[3], 1, 12),
    ) else {
        return true;
    };
    months
        .iter()
        .any(|month| days.iter().any(|day| *day <= days_in_month(*month)))
}

fn days_in_month(month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 => 29,
        _ => 31,
    }
}

/// Expands one validated field into its allowed values. Returns `None` for a
/// shape this cheap parser does not understand so the caller stays permissive.
fn allowed_values(field: &str, minimum: u32, maximum: u32) -> Option<Vec<u32>> {
    if field == "*" {
        return Some((minimum..=maximum).collect());
    }
    let mut values = Vec::new();
    for item in field.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((range, step)) => (range, step.parse::<u32>().ok()?),
            None => (item, 1),
        };
        if step == 0 {
            return None;
        }
        let (start, end) = if range == "*" {
            (minimum, maximum)
        } else if let Some((start, end)) = range.split_once('-') {
            (start.parse::<u32>().ok()?, end.parse::<u32>().ok()?)
        } else {
            let value = range.parse::<u32>().ok()?;
            (value, value)
        };
        if start < minimum || end > maximum || start > end {
            return None;
        }
        values.extend((start..=end).step_by(usize::try_from(step).ok()?));
    }
    Some(values)
}

/// First matching occurrence strictly after `after` in UTC.
pub(crate) fn next_cron_at(expression: &str, after: SystemTime) -> Option<SystemTime> {
    validate_cron_expr(expression).ok()?;
    let fields: [&str; 5] = expression
        .split_whitespace()
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    if !calendar_satisfiable(&fields) {
        return None;
    }
    let cron = expression.parse::<croner::Cron>().ok()?;
    let after_secs = after.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let after_secs = i64::try_from(after_secs).ok()?;
    let start = DateTime::<Utc>::from_timestamp(after_secs, 0)?;
    let next = cron.find_next_occurrence(&start, false).ok()?;
    let next_secs = u64::try_from(next.timestamp()).ok()?;
    let next = UNIX_EPOCH.checked_add(Duration::new(next_secs, next.timestamp_subsec_nanos()))?;
    checked_next(next, after)
}

fn checked_next(next: SystemTime, after: SystemTime) -> Option<SystemTime> {
    if next <= after {
        return None;
    }
    if next.duration_since(after).ok()? > MAX_CRON_HORIZON {
        return None;
    }
    Some(next)
}

/// Boundary for the next cron tick. A still-future boundary is returned
/// unchanged; a due one advances to the first occurrence strictly after `now`.
pub(crate) fn advance_cron_due(
    scheduled_for: SystemTime,
    expression: &str,
    now: SystemTime,
) -> Option<SystemTime> {
    if scheduled_for > now {
        return Some(scheduled_for);
    }
    next_cron_at(expression, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn utc(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> SystemTime {
        let timestamp = Utc
            .with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .expect("valid UTC datetime")
            .timestamp();
        UNIX_EPOCH + Duration::from_secs(u64::try_from(timestamp).expect("positive timestamp"))
    }

    #[test]
    fn validate_accepts_the_closed_grammar() {
        for expression in [
            "* * * * *",
            "*/5 * * * *",
            "0 0 * * *",
            "10,20 * * * *",
            "8-17 * * * *",
            "5-59/15 * * * *",
            "0 0 1 * 1",
            "0 0 29 2 *",
            "0 0 31 2 *",
            "  */15 1 1,15 1 1-5  ",
        ] {
            assert!(
                validate_cron_expr(expression).is_ok(),
                "must accept {expression:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_unsupported_shapes_and_values() {
        for expression in [
            "",
            " ",
            "* * * *",
            "* * * * * *",
            "* * * * * * *",
            "@daily",
            "0 0 * * MON",
            "? * * * *",
            "0 0 * * L",
            "0 0 15W * *",
            "0 0 * * 5#2",
            "*/0 * * * *",
            "0/5 * * * *",
            "60 * * * *",
            "0 24 * * *",
            "0 0 0 * *",
            "0 0 32 * *",
            "0 0 * 0 *",
            "0 0 * 13 *",
            "0 0 * * 8",
            "5-1 * * * *",
            "1,,2 * * * *",
            "*,2 * * * *",
            "1- * * * *",
            "-1 * * * *",
            "1/2 * * * *",
        ] {
            assert!(
                validate_cron_expr(expression).is_err(),
                "must reject {expression:?}"
            );
        }
    }

    #[test]
    fn next_cron_at_follows_minute_steps_and_wildcards() {
        let start = utc(2024, 1, 1, 0, 0);
        assert_eq!(
            next_cron_at("* * * * *", start),
            Some(utc(2024, 1, 1, 0, 1))
        );
        assert_eq!(
            next_cron_at("*/5 * * * *", start),
            Some(utc(2024, 1, 1, 0, 5))
        );
        assert_eq!(
            next_cron_at("0 0 * * *", utc(2024, 1, 1, 12, 34)),
            Some(utc(2024, 1, 2, 0, 0))
        );
    }

    #[test]
    fn next_cron_at_handles_lists_ranges_and_steps() {
        assert_eq!(
            next_cron_at("10,20 8-9 * * *", utc(2024, 1, 1, 8, 10)),
            Some(utc(2024, 1, 1, 8, 20))
        );
        assert_eq!(
            next_cron_at("5-59/15 * * * *", utc(2024, 1, 1, 0, 5)),
            Some(utc(2024, 1, 1, 0, 20))
        );
        assert_eq!(
            next_cron_at("0 8-9 * * *", utc(2024, 1, 1, 8, 30)),
            Some(utc(2024, 1, 1, 9, 0))
        );
    }

    #[test]
    fn next_cron_at_uses_posix_dom_dow_or_semantics() {
        // 2024-01-01 is a Monday. OR moves this to the next Monday; an AND
        // interpretation would wait for a month that starts on a Monday.
        assert_eq!(
            next_cron_at("0 0 1 * 1", utc(2024, 1, 1, 0, 0)),
            Some(utc(2024, 1, 8, 0, 0))
        );
    }

    #[test]
    fn next_cron_at_handles_leap_day_and_impossible_dates() {
        assert_eq!(
            next_cron_at("0 0 29 2 *", utc(2023, 3, 1, 0, 0)),
            Some(utc(2024, 2, 29, 0, 0))
        );
        assert_eq!(
            next_cron_at("0 0 29 2 *", utc(2024, 3, 1, 0, 0)),
            Some(utc(2028, 2, 29, 0, 0))
        );
        assert_eq!(next_cron_at("0 0 31 2 *", utc(2024, 1, 1, 0, 0)), None);
    }

    #[test]
    fn validate_reports_stable_messages_without_echoing_the_expression() {
        for (expression, message) in [
            ("60 * * * *", "cron field value is out of range"),
            ("5-1 * * * *", "cron range must not descend"),
            ("*/0 * * * *", "cron step must be positive"),
            ("1/2 * * * *", "cron step requires a range or wildcard"),
            ("1- * * * *", "cron field value is not a number"),
        ] {
            let error = validate_cron_expr(expression).expect_err("must reject");
            assert_eq!(error.to_string(), message, "for {expression:?}");
            assert!(
                !error.to_string().contains(expression),
                "the raw expression must not be echoed"
            );
        }
    }

    #[test]
    fn validate_enforces_the_byte_bound_inclusively() {
        let accepted = format!("{} * * * *", "0".repeat(248));
        assert_eq!(accepted.len(), 256);
        assert!(validate_cron_expr(&accepted).is_ok());

        let rejected = format!("{} * * * *", "0".repeat(249));
        assert_eq!(rejected.len(), 257);
        assert_eq!(
            validate_cron_expr(&rejected).unwrap_err().to_string(),
            "cron expression must be non-empty and at most 256 bytes"
        );
    }

    #[test]
    fn next_cron_at_rejects_impossible_calendar_dates_without_searching() {
        let start = utc(2024, 1, 1, 0, 0);
        for expression in [
            "0 0 31 2 *",
            "0 0 30 2 *",
            "0 0 31 4,6,9,11 *",
            "0 0 31 2,4,6,9,11 *",
        ] {
            assert_eq!(
                next_cron_at(expression, start),
                None,
                "must reject {expression:?}"
            );
        }
        assert!(
            next_cron_at("0 0 29 2 *", start).is_some(),
            "leap-day February stays representable"
        );
    }

    #[test]
    fn next_cron_at_keeps_a_dow_restricted_impossible_dom() {
        // February never has a 31st, but OR semantics means every Monday in
        // February matches. 2024-02-05 is the first Monday after 2024-01-01.
        assert_eq!(
            next_cron_at("0 0 31 2 1", utc(2024, 1, 1, 0, 0)),
            Some(utc(2024, 2, 5, 0, 0))
        );
    }

    #[test]
    fn checked_next_enforces_order_and_the_horizon() {
        let after = utc(2024, 1, 1, 0, 0);
        assert_eq!(
            checked_next(after + Duration::from_secs(60), after),
            Some(after + Duration::from_secs(60))
        );
        assert_eq!(
            checked_next(after + MAX_CRON_HORIZON + Duration::from_secs(1), after),
            None,
            "a result beyond the horizon must be rejected"
        );
        assert_eq!(checked_next(after, after), None);
        assert_eq!(checked_next(after - Duration::from_secs(1), after), None);
    }

    #[test]
    fn next_cron_at_is_strictly_after_even_on_and_between_boundaries() {
        let boundary = utc(2024, 1, 1, 12, 0);
        assert_eq!(
            next_cron_at("* * * * *", boundary),
            Some(utc(2024, 1, 1, 12, 1))
        );
        assert_eq!(
            next_cron_at("* * * * *", boundary + Duration::from_millis(500)),
            Some(utc(2024, 1, 1, 12, 1))
        );
        assert_eq!(
            next_cron_at(
                "* * * * *",
                utc(2024, 1, 1, 11, 59) + Duration::from_millis(59_500)
            ),
            Some(boundary)
        );
    }

    #[test]
    fn advance_cron_due_keeps_a_future_boundary_and_moves_a_due_one() {
        let scheduled = utc(2024, 1, 1, 12, 0);
        assert_eq!(
            advance_cron_due(scheduled, "* * * * *", utc(2024, 1, 1, 11, 59)),
            Some(scheduled)
        );
        assert_eq!(
            advance_cron_due(scheduled, "* * * * *", scheduled),
            Some(utc(2024, 1, 1, 12, 1))
        );
    }
}
