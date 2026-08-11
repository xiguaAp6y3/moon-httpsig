// error.mbt — Structured error model for moon-httpsig.
//
// RFC 9421 HTTP Message Signatures has many failure modes across distinct
// processing stages. Public APIs never return `Result[T, String]`; they
// return `Result[T, HsError]` so that callers can dispatch on a stable
// (stage, kind) pair, an optional UTF-8 byte offset, and a short context
// string without leaking secrets.
//
// Note: `HsError` is declared as a `suberror` (MoonBit's raise-based error
// type) so that internal processing functions can use `raise HsError` and
// let errors propagate through the call stack with zero plumbing. Public
// boundary functions wrap those internals in `try`/`catch` and convert to
// `Result[T, HsError]`. Field access is provided by accessor methods because
// MoonBit suberror payloads are positional.

///|
/// The processing stage in which an error was detected. Used to answer the
/// question "where did this fail?" at a glance.
pub(all) enum HsErrorStage {
  MessageConstruction
  StructuredFieldParsing
  SignatureInputParsing
  SignatureFieldParsing
  ComponentResolution
  SignatureBaseConstruction
  Signing
  KeyResolution
  PolicyValidation
  CryptographicVerification
  ReplayProtection
  DigestBinding
}

///|
/// The concrete error category. Stable across versions so callers can switch
/// on it without string matching.
pub(all) enum HsErrorKind {
  UnexpectedEnd
  UnexpectedByte(Byte)
  InvalidHeaderName
  InvalidHeaderValue
  InvalidMethod
  InvalidScheme
  InvalidAuthority
  InvalidPath
  InvalidStatus
  DuplicateLabel
  MissingSignatureInput
  MissingSignature
  LabelMismatch
  InvalidSignatureInput
  InvalidSignatureField
  InvalidAcceptSignature
  InvalidCoveredComponent
  UnsupportedDerivedComponent
  UnsupportedComponentParameter
  MissingComponent
  InvalidComponentCombination
  InvalidStructuredField
  InvalidBase64
  InvalidInteger
  InvalidTimestamp
  CreatedInFuture
  SignatureExpired
  SignatureTooOld
  MissingKeyId
  KeyIdTooLong
  KeyNotFound
  AlgorithmMissing
  AlgorithmNotAllowed
  AlgorithmMismatch
  InvalidKeyMaterial
  SignatureMismatch
  MissingRequiredComponent
  DuplicateNonce
  NonceRequired
  NonceTooLong
  InvalidTag
  ContentDigestRequired
  ContentDigestNotCovered
  ContentDigestInvalid
  InputTooLarge
  TooManyHeaders
  TooManySignatures
  TooManyComponents
  TooManyParameters
  SerializationFailure
}

///|
/// A structured error returned by every public API.
///
/// - `offset()` is a UTF-8 byte offset into the input being processed when
///   the offset is meaningful, otherwise `0`.
/// - `context()` is a short, caller-visible description. It never contains
///   keys, full signatures, full bodies, or huge header values.
pub(all) suberror HsError {
  HsError(HsErrorStage, HsErrorKind, Int, String)
}

///|
/// Constructs an `HsError` with the given stage, kind, and context and a zero
/// offset.
pub fn hs_error(
  stage : HsErrorStage,
  kind : HsErrorKind,
  context : String,
) -> HsError {
  HsError(stage, kind, 0, context)
}

///|
/// Constructs an `HsError` carrying an explicit UTF-8 byte offset.
pub fn hs_error_at(
  stage : HsErrorStage,
  kind : HsErrorKind,
  offset : Int,
  context : String,
) -> HsError {
  HsError(stage, kind, offset, context)
}

///|
/// The processing stage of the error.
pub fn HsError::stage(self : HsError) -> HsErrorStage {
  let HsError(stage, _, _, _) = self
  stage
}

///|
/// The error kind.
pub fn HsError::kind(self : HsError) -> HsErrorKind {
  let HsError(_, kind, _, _) = self
  kind
}

///|
/// The UTF-8 byte offset, or `0` when not meaningful.
pub fn HsError::offset(self : HsError) -> Int {
  let HsError(_, _, offset, _) = self
  offset
}

///|
/// The short diagnostic context string.
pub fn HsError::context(self : HsError) -> String {
  let HsError(_, _, _, context) = self
  context
}

///|
/// Returns the stage name as a stable string (used by CLI JSON output).
pub fn HsError::stage_name(self : HsError) -> String {
  match self.stage() {
    MessageConstruction => "MessageConstruction"
    StructuredFieldParsing => "StructuredFieldParsing"
    SignatureInputParsing => "SignatureInputParsing"
    SignatureFieldParsing => "SignatureFieldParsing"
    ComponentResolution => "ComponentResolution"
    SignatureBaseConstruction => "SignatureBaseConstruction"
    Signing => "Signing"
    KeyResolution => "KeyResolution"
    PolicyValidation => "PolicyValidation"
    CryptographicVerification => "CryptographicVerification"
    ReplayProtection => "ReplayProtection"
    DigestBinding => "DigestBinding"
  }
}

///|
/// Returns the error kind name as a stable string.
pub fn HsError::kind_name(self : HsError) -> String {
  match self.kind() {
    UnexpectedEnd => "UnexpectedEnd"
    UnexpectedByte(_) => "UnexpectedByte"
    InvalidHeaderName => "InvalidHeaderName"
    InvalidHeaderValue => "InvalidHeaderValue"
    InvalidMethod => "InvalidMethod"
    InvalidScheme => "InvalidScheme"
    InvalidAuthority => "InvalidAuthority"
    InvalidPath => "InvalidPath"
    InvalidStatus => "InvalidStatus"
    DuplicateLabel => "DuplicateLabel"
    MissingSignatureInput => "MissingSignatureInput"
    MissingSignature => "MissingSignature"
    LabelMismatch => "LabelMismatch"
    InvalidSignatureInput => "InvalidSignatureInput"
    InvalidSignatureField => "InvalidSignatureField"
    InvalidAcceptSignature => "InvalidAcceptSignature"
    InvalidCoveredComponent => "InvalidCoveredComponent"
    UnsupportedDerivedComponent => "UnsupportedDerivedComponent"
    UnsupportedComponentParameter => "UnsupportedComponentParameter"
    MissingComponent => "MissingComponent"
    InvalidComponentCombination => "InvalidComponentCombination"
    InvalidStructuredField => "InvalidStructuredField"
    InvalidBase64 => "InvalidBase64"
    InvalidInteger => "InvalidInteger"
    InvalidTimestamp => "InvalidTimestamp"
    CreatedInFuture => "CreatedInFuture"
    SignatureExpired => "SignatureExpired"
    SignatureTooOld => "SignatureTooOld"
    MissingKeyId => "MissingKeyId"
    KeyIdTooLong => "KeyIdTooLong"
    KeyNotFound => "KeyNotFound"
    AlgorithmMissing => "AlgorithmMissing"
    AlgorithmNotAllowed => "AlgorithmNotAllowed"
    AlgorithmMismatch => "AlgorithmMismatch"
    InvalidKeyMaterial => "InvalidKeyMaterial"
    SignatureMismatch => "SignatureMismatch"
    MissingRequiredComponent => "MissingRequiredComponent"
    DuplicateNonce => "DuplicateNonce"
    NonceRequired => "NonceRequired"
    NonceTooLong => "NonceTooLong"
    InvalidTag => "InvalidTag"
    ContentDigestRequired => "ContentDigestRequired"
    ContentDigestNotCovered => "ContentDigestNotCovered"
    ContentDigestInvalid => "ContentDigestInvalid"
    InputTooLarge => "InputTooLarge"
    TooManyHeaders => "TooManyHeaders"
    TooManySignatures => "TooManySignatures"
    TooManyComponents => "TooManyComponents"
    TooManyParameters => "TooManyParameters"
    SerializationFailure => "SerializationFailure"
  }
}

///|
/// Renders the error as a short human-readable line.
pub fn HsError::to_debug_string(self : HsError) -> String {
  let mut s = self.stage_name() + "/" + self.kind_name()
  if self.offset() > 0 {
    s = s + " @" + self.offset().to_string()
  }
  if !self.context().is_empty() {
    s = s + " (" + self.context() + ")"
  }
  s
}
