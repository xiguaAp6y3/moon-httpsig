// sf_model.mbt — Structured Field data model (RFC 9651 subset).
//
// moon-httpsig does not implement a full RFC 9651 library. It implements the
// subset needed by RFC 9421: Dictionary, Inner List, String, Token, Integer,
// Byte Sequence, Boolean, and Parameters. Order is preserved everywhere
// (dictionary order, inner-list order, parameter order) because RFC 9421
// signatures depend on canonical serialization.

///|
/// The "bare item" of a structured field item: the value without parameters.
pub(all) enum SfBareItem {
  /// An RFC 9651 string, `"..."`.
  SfString(String)
  /// An RFC 9651 token, `token`.
  SfToken(String)
  /// An RFC 9651 integer, `-?digits` (fits in 64-bit signed).
  SfInteger(Int64)
  /// An RFC 9651 byte sequence, `:base64:`.
  SfByteSequence(Bytes)
  /// An RFC 9651 boolean, `?0` / `?1`.
  SfBoolean(Bool)
}

///|
/// A single structured field parameter: `name=value`.
pub(all) struct SfParameter {
  name : String
  value : SfBareItem
}

///|
/// A structured field item: bare item plus its parameters.
pub(all) struct SfItem {
  value : SfBareItem
  parameters : Array[SfParameter]
}

///|
/// A structured field inner list: `(items) params`.
pub(all) struct SfInnerList {
  items : Array[SfItem]
  parameters : Array[SfParameter]
}

///|
/// A dictionary member: either an item or an inner list.
pub(all) enum SfMember {
  ItemMember(SfItem)
  InnerListMember(SfInnerList)
}

///|
/// A single dictionary entry: a key plus its member value.
pub(all) struct SfDictionaryEntry {
  key : String
  value : SfMember
}

///|
/// Constructs a parameter with the given name and value.
pub fn sf_param(name : String, value : SfBareItem) -> SfParameter {
  { name, value }
}

///|
/// Constructs a bare string item.
pub fn sf_string(v : String) -> SfItem {
  { value: SfString(v), parameters: Array::new() }
}

///|
/// Constructs a bare token item.
pub fn sf_token(v : String) -> SfItem {
  { value: SfToken(v), parameters: Array::new() }
}

///|
/// Constructs a bare integer item.
pub fn sf_integer(v : Int64) -> SfItem {
  { value: SfInteger(v), parameters: Array::new() }
}

///|
/// Constructs a bare boolean item.
pub fn sf_boolean(v : Bool) -> SfItem {
  { value: SfBoolean(v), parameters: Array::new() }
}

///|
/// Constructs a bare byte-sequence item.
pub fn sf_bytes(v : Bytes) -> SfItem {
  { value: SfByteSequence(v), parameters: Array::new() }
}

///|
/// Returns the parameter with the given name (exact case-sensitive match),
/// or `None`.
pub fn SfItem::parameter(self : SfItem, name : String) -> SfParameter? {
  for p in self.parameters {
    if p.name == name {
      return Some(p)
    }
  }
  None
}
