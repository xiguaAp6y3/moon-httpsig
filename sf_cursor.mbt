// sf_cursor.mbt — Cursor for structured field parsing.
//
// The cursor scans a UTF-16 string by code-unit offset. Structured field
// values are ASCII by grammar, so for valid input a code-unit offset equals a
// UTF-8 byte offset; all reported `HsError.offset` values are therefore byte
// offsets. Non-ASCII input is rejected by the grammar checks.
//
// Every cursor operation that can fail raises `HsError`; boundary functions
// convert to `Result`.

///|
/// A forward-only cursor over a string being parsed as a structured field.
priv struct SfCursor {
  input : String
  mut offset : Int
}

///|
/// Creates a cursor positioned at the start of `input`.
fn SfCursor::new(input : String) -> SfCursor {
  { input, offset: 0 }
}

///|
/// Returns the current offset in code units.
fn SfCursor::pos(self : SfCursor) -> Int {
  self.offset
}

///|
/// Returns `true` when the input is exhausted.
fn SfCursor::at_end(self : SfCursor) -> Bool {
  self.offset >= self.input.length()
}

///|
/// Returns the code unit at the current offset, or raises `UnexpectedEnd`.
fn SfCursor::peek(self : SfCursor) -> Char raise HsError {
  if self.at_end() {
    raise hs_error_at(
      StructuredFieldParsing,
      UnexpectedEnd,
      self.offset,
      "unexpected end of structured field",
    )
  }
  self.input
  .get_char(self.offset)
  .unwrap_or_else(() => {
    raise hs_error_at(
      StructuredFieldParsing,
      UnexpectedEnd,
      self.offset,
      "unexpected end of structured field",
    )
  })
}

///|
/// Advances the cursor by one code unit. The caller must have verified that
/// the cursor is not at the end.
fn SfCursor::advance(self : SfCursor) -> Unit {
  self.offset = self.offset + 1
}

///|
/// Skips zero or more ASCII SP characters.
fn SfCursor::skip_sp(self : SfCursor) -> Unit raise HsError {
  while !self.at_end() {
    match self.peek() {
      ' ' => self.advance()
      _ => return
    }
  }
}

///|
/// Returns the substring consumed since `start` as an owned string.
fn SfCursor::slice_from(self : SfCursor, start : Int) -> String {
  self.input.sub(start~, end=self.offset).to_owned()
}

///|
/// Consumes exactly one character and returns it.
fn SfCursor::take(self : SfCursor) -> Char raise HsError {
  let c = self.peek()
  self.advance()
  c
}
