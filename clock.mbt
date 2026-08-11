// clock.mbt — Clock abstraction for time-based signature validation.
//
// All time checks (created-in-future, expires, max age) run through a Clock
// so that tests can use a `FixedClock` and production can use `SystemClock`.

///|
/// Provides the current UNIX timestamp in whole seconds.
pub(open) trait Clock {
  /// The current time as a UNIX timestamp in seconds.
  fn now_unix_seconds(Self) -> Int64
}

///|
/// A clock backed by the host's wall clock (`@env.now`, milliseconds since
/// the Unix epoch, converted to whole seconds).
pub enum SystemClock {
  SystemClock
}

///|
/// Constructs the system clock.
pub fn SystemClock::new() -> SystemClock {
  SystemClock
}

///|
/// A clock pinned to a fixed timestamp (for tests and reproducible examples).
pub struct FixedClock {
  fixed : Int64
}

///|
/// Constructs a clock fixed at `timestamp`.
pub fn FixedClock::new(timestamp : Int64) -> FixedClock {
  { fixed: timestamp }
}

///|
/// Returns the fixed timestamp.
pub fn FixedClock::timestamp(self : FixedClock) -> Int64 {
  self.fixed
}

///|
/// Implements `Clock` for `SystemClock` using the host clock.
pub impl Clock for SystemClock with fn now_unix_seconds(_self) {
  (@env.now() / 1000).reinterpret_as_int64()
}

///|
/// Implements `Clock` for `FixedClock`.
pub impl Clock for FixedClock with fn now_unix_seconds(self) {
  self.fixed
}
