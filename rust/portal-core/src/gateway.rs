//! What a Gateway is willing to be told — the operator's side of the policy.
//!
//! **Phase 0 of `docs/portal_gateway_plan.md`**, and the security-relevant half
//! of Gateway mode. `agent_access_spec_draft.md` §3.1 splits policy in two: the
//! centre holds classes and attribute *values*, the enforcement point holds the
//! *rules*. This file is the enforcement point's half, and **nothing in it
//! crosses the wire.**
//!
//! ```toml
//! [protocols."pg-sales-ro-v1"]
//! windows = ["business_hours"]
//!
//! [protocols."pg-sales-ro-v1".attributes]
//! region = { type = "enum", allowed = ["kanto", "kansai", "kyushu"] }
//!
//! [[protocols."pg-sales-ro-v1".operations]]
//! name     = "query_sales"
//! sql      = "SELECT id, region, amount FROM sales WHERE region = $1 AND month = $2"
//! bind     = ["{{region}}", "$month"]
//! max_rows = 1000
//!
//! [protocols."pg-sales-ro-v1".operations.params]
//! month = { type = "string", pattern = '^\d{4}-\d{2}$' }
//! ```
//!
//! # Why this file is what makes stage 2 worth shipping
//!
//! The PEP — running an operation, binding a row filter — is deferred. What is
//! *not* deferred is deciding **whether a policy row may be applied at all**,
//! and that decision is made here, before any grant is created.
//!
//! Draft §3.1.0 claims that a compromised centre cannot exceed the envelope the
//! operator defined. **That claim rests entirely on this file being consulted**,
//! because the centre chooses attribute values and window labels, and those are
//! the two things it could otherwise widen on its own.
//!
//! # There is no way to send SQL in
//!
//! Draft §3.5: a resource must not accept a free query language. That is
//! enforced by the shape of [`Operation`] rather than by a check — a policy row
//! carries a protocol name and attribute values, and **there is no field
//! anywhere on this path that a statement could arrive in.** Adding one would
//! be the change to refuse, not a value to validate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Context as _;
use serde::Deserialize;

/// A policy file to start from, which `portal-server --example-gateway-config`
/// prints.
pub const EXAMPLE: &str = r#"# What this Gateway is willing to be told.
#
# The control plane sends a protocol class, attribute values and a window
# label. This file says which of those are acceptable -- it is the envelope a
# compromised control plane cannot talk its way out of, so it is worth reading
# as carefully as the service catalogue.

[protocols."pg-sales-ro-v1"]
# Window labels this Gateway understands. A policy row naming a window that is
# not here is NOT applied.
#
# **Leaving this out does not mean "any window".** It means no label is
# recognised, so every row carrying one is refused -- which is the safe way
# round, because the alternative is a row meant for business hours being served
# around the clock.
windows = ["business_hours"]

# The values the control plane may choose from. A row whose attribute falls
# outside its schema is not applied.
[protocols."pg-sales-ro-v1".attributes]
region = { type = "enum", allowed = ["kanto", "kansai", "kyushu"] }

# What may be done. Statements live here and only here; nothing the agent sends
# becomes SQL.
[[protocols."pg-sales-ro-v1".operations]]
name     = "query_sales"
sql      = "SELECT id, region, amount FROM sales WHERE region = $1 AND month = $2"
# One entry per placeholder, in order. `{{name}}` takes the attribute the
# control plane chose; `$name` takes a parameter the caller supplies.
bind     = ["{{region}}", "$month"]
max_rows = 1000

[protocols."pg-sales-ro-v1".operations.params]
month = { type = "string", pattern = '^\d{4}-\d{2}$' }
"#;

/// The whole file: what each protocol class permits.
#[derive(Debug, Clone, Default)]
pub struct GatewayPolicy {
    protocols: BTreeMap<String, ProtocolPolicy>,
}

impl GatewayPolicy {
    /// What this Gateway permits for `protocol`, or `None` if it serves no such
    /// class.
    ///
    /// **`None` means refuse the row.** A class this file does not describe has
    /// no envelope, and a policy row for it cannot be checked against anything.
    pub fn protocol(&self, protocol: &str) -> Option<&ProtocolPolicy> {
        self.protocols.get(protocol)
    }

    /// The classes this Gateway serves.
    pub fn protocols(&self) -> impl Iterator<Item = &str> {
        self.protocols.keys().map(String::as_str)
    }
}

/// One protocol class.
#[derive(Debug, Clone)]
pub struct ProtocolPolicy {
    windows: BTreeSet<String>,
    attributes: BTreeMap<String, ValueSchema>,
    operations: BTreeMap<String, Operation>,
}

impl ProtocolPolicy {
    /// Whether a policy row's `constraints.window` may be applied.
    ///
    /// **`None` — no window at all — is accepted**; a row without a window is
    /// not restricted to one. An unrecognised label is refused.
    ///
    /// Identity's spec warns about this by name: *the most natural
    /// implementation ignores unknown labels, and that is twenty-four hour
    /// access.* Enforcing the window is the PEP's job and is deferred; refusing
    /// a label this Gateway cannot enforce is not, because the row would
    /// otherwise be applied with nothing standing behind its one restriction.
    pub fn accepts_window(&self, window: Option<&str>) -> bool {
        match window {
            None => true,
            Some(label) => self.windows.contains(label),
        }
    }

    /// Whether the control plane's attribute values fall inside this envelope.
    ///
    /// Every declared attribute must be present and in range, and **an
    /// attribute this file does not declare is refused** rather than passed
    /// through — an unknown key is a value nobody bounded.
    pub fn accepts_attributes(
        &self,
        attributes: &BTreeMap<String, serde_json::Value>,
    ) -> Result<(), AttributeRefusal> {
        for (name, value) in attributes {
            let Some(schema) = self.attributes.get(name) else {
                return Err(AttributeRefusal::Unknown { name: name.clone() });
            };
            if !schema.accepts(value) {
                return Err(AttributeRefusal::OutOfRange {
                    name: name.clone(),
                    value: value.clone(),
                });
            }
        }
        for name in self.attributes.keys() {
            if !attributes.contains_key(name) {
                return Err(AttributeRefusal::Missing { name: name.clone() });
            }
        }
        Ok(())
    }

    /// The operations this class permits, by name.
    pub fn operation(&self, name: &str) -> Option<&Operation> {
        self.operations.get(name)
    }

    /// Every operation, for the catalogue a Gateway shows an agent once the PEP
    /// exists (draft §6.4.1).
    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.operations.values()
    }

    /// The window labels this Gateway understands.
    pub fn windows(&self) -> impl Iterator<Item = &str> {
        self.windows.iter().map(String::as_str)
    }
}

/// Why a policy row's attributes were refused.
///
/// **Named cases rather than a bare bool**, because the three mean different
/// things to whoever is reading the log: an unknown key says the centre and
/// this file disagree about the class, a missing one says the same in the other
/// direction, and out-of-range says the centre tried to choose a value this
/// operator did not offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeRefusal {
    /// The row carries an attribute this file does not declare.
    Unknown { name: String },
    /// This file declares an attribute the row does not carry.
    Missing { name: String },
    /// The value is outside the declared range.
    OutOfRange {
        name: String,
        value: serde_json::Value,
    },
}

impl std::fmt::Display for AttributeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { name } => {
                write!(f, "attribute `{name}` is not declared for this protocol")
            }
            Self::Missing { name } => write!(f, "attribute `{name}` is missing"),
            Self::OutOfRange { name, value } => {
                write!(f, "attribute `{name}` is out of range: {value}")
            }
        }
    }
}

/// The range a value may take.
#[derive(Debug, Clone)]
pub enum ValueSchema {
    /// One of a fixed set.
    Enum { allowed: BTreeSet<String> },
    /// A string matching a pattern.
    Pattern { regex: regex::Regex, source: String },
}

impl ValueSchema {
    /// Whether `value` is inside this range.
    ///
    /// **A non-string is always refused.** Both forms describe strings, and
    /// accepting `42` for an enum of names by stringifying it would be this
    /// file quietly widening itself.
    pub fn accepts(&self, value: &serde_json::Value) -> bool {
        let Some(text) = value.as_str() else {
            return false;
        };
        match self {
            Self::Enum { allowed } => allowed.contains(text),
            // **Anchored by the operator, not by us.** Adding `^...$` here
            // would make a pattern mean something other than what it says, and
            // an operator who reads their own file would be wrong about it.
            Self::Pattern { regex, .. } => regex.is_match(text),
        }
    }
}

/// One thing that may be done, with its statement and its bindings.
#[derive(Debug, Clone)]
pub struct Operation {
    name: String,
    sql: String,
    bind: Vec<Bind>,
    params: BTreeMap<String, ValueSchema>,
    max_rows: u32,
}

impl Operation {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn sql(&self) -> &str {
        &self.sql
    }
    pub fn bind(&self) -> &[Bind] {
        &self.bind
    }
    pub fn params(&self) -> &BTreeMap<String, ValueSchema> {
        &self.params
    }
    pub fn max_rows(&self) -> u32 {
        self.max_rows
    }
}

/// Where one placeholder's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    /// `{{name}}` — the attribute the control plane chose.
    ///
    /// **The agent cannot reach this.** Draft §3.5's whole point is that a row
    /// filter is bound on this side; an agent that could supply `region` could
    /// read every region.
    Attribute(String),
    /// `$name` — a parameter the caller supplies, checked against its schema.
    Param(String),
}

/// Read the policy from `path`.
pub fn load(path: &Path) -> anyhow::Result<GatewayPolicy> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the gateway policy at {}", path.display()))?;
    parse(&text).with_context(|| format!("in {}", path.display()))
}

/// [`load`] from a string, which is what the tests use.
///
/// **Everything that can be checked is checked here**, at startup, because the
/// alternative is finding out when a policy row arrives — or, for the parts the
/// PEP will use, not until enforcement lands months later.
pub fn parse(text: &str) -> anyhow::Result<GatewayPolicy> {
    let file: File = toml::from_str(text).context("the gateway policy is not valid TOML")?;
    anyhow::ensure!(
        !file.protocols.is_empty(),
        "the gateway policy describes no protocol; add a [protocols.\"<name>\"] section",
    );

    let mut protocols = BTreeMap::new();
    for (name, entry) in file.protocols {
        let policy = protocol(&entry).with_context(|| format!("protocol `{name}`"))?;
        protocols.insert(name, policy);
    }
    Ok(GatewayPolicy { protocols })
}

fn protocol(entry: &ProtocolEntry) -> anyhow::Result<ProtocolPolicy> {
    let mut windows = BTreeSet::new();
    for label in &entry.windows {
        anyhow::ensure!(
            is_window_label(label),
            "window `{label}` is not a label: lowercase letters, digits, `_` and `-`, \
             starting with a letter or digit, at most 64 characters",
        );
        anyhow::ensure!(
            windows.insert(label.clone()),
            "window `{label}` is listed twice",
        );
    }

    let mut attributes = BTreeMap::new();
    for (name, schema) in &entry.attributes {
        let schema = value_schema(schema).with_context(|| format!("attribute `{name}`"))?;
        attributes.insert(name.clone(), schema);
    }

    let mut operations: BTreeMap<String, Operation> = BTreeMap::new();
    for entry in &entry.operations {
        let op =
            operation(entry, &attributes).with_context(|| format!("operation `{}`", entry.name))?;
        anyhow::ensure!(
            !operations.contains_key(&op.name),
            "operation `{}` is defined twice",
            op.name,
        );
        operations.insert(op.name.clone(), op);
    }

    Ok(ProtocolPolicy {
        windows,
        attributes,
        operations,
    })
}

fn operation(
    entry: &OperationEntry,
    attributes: &BTreeMap<String, ValueSchema>,
) -> anyhow::Result<Operation> {
    anyhow::ensure!(!entry.name.is_empty(), "an operation needs a name");
    anyhow::ensure!(!entry.sql.trim().is_empty(), "an operation needs a `sql`");
    anyhow::ensure!(entry.max_rows > 0, "`max_rows` must be at least 1");

    let mut params = BTreeMap::new();
    for (name, schema) in &entry.params {
        let schema = value_schema(schema).with_context(|| format!("param `{name}`"))?;
        params.insert(name.clone(), schema);
    }

    let mut bind = Vec::with_capacity(entry.bind.len());
    for text in &entry.bind {
        bind.push(binding(text, attributes, &params)?);
    }

    check_placeholders(&entry.sql, bind.len())?;

    Ok(Operation {
        name: entry.name.clone(),
        sql: entry.sql.clone(),
        bind,
        params,
        max_rows: entry.max_rows,
    })
}

/// `{{name}}` or `$name`, and the name has to exist.
///
/// **A typo here is silent otherwise.** `{{reigon}}` would bind nothing, and
/// depending on how the PEP is written that is either an error much later or a
/// filter that matches everything.
fn binding(
    text: &str,
    attributes: &BTreeMap<String, ValueSchema>,
    params: &BTreeMap<String, ValueSchema>,
) -> anyhow::Result<Bind> {
    if let Some(name) = text.strip_prefix("{{").and_then(|t| t.strip_suffix("}}")) {
        let name = name.trim();
        anyhow::ensure!(
            attributes.contains_key(name),
            "binding `{text}` names attribute `{name}`, which this protocol does not declare",
        );
        return Ok(Bind::Attribute(name.to_owned()));
    }
    if let Some(name) = text.strip_prefix('$') {
        anyhow::ensure!(
            params.contains_key(name),
            "binding `{text}` names param `{name}`, which this operation does not declare",
        );
        return Ok(Bind::Param(name.to_owned()));
    }
    anyhow::bail!(
        "binding `{text}` is neither `{{{{attribute}}}}` nor `$param`. \
         A literal would be a value this file could have put in the statement itself",
    )
}

/// Every `$n` in the statement must have a binding, and every binding must be
/// used.
///
/// **This is the check that pays for the whole file being parsed at startup.**
/// A statement with three placeholders and two bindings is a bug that would
/// otherwise surface the first time the operation ran — which, with the PEP
/// deferred, is not in this release at all.
fn check_placeholders(sql: &str, binds: usize) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > start {
            // `$0` is not a placeholder in any dialect that numbers from one,
            // and treating it as one would invent an index nothing can bind.
            if let Ok(n) = sql[start..end].parse::<usize>() {
                if n >= 1 {
                    seen.insert(n);
                }
            }
        }
        i = end.max(start);
    }

    for n in &seen {
        anyhow::ensure!(
            *n <= binds,
            "the statement uses ${n} but only {binds} binding(s) are given",
        );
    }
    for n in 1..=binds {
        anyhow::ensure!(
            seen.contains(&n),
            "binding {n} is given but the statement never uses ${n}",
        );
    }
    Ok(())
}

fn value_schema(entry: &SchemaEntry) -> anyhow::Result<ValueSchema> {
    match entry {
        SchemaEntry::Enum { allowed } => {
            anyhow::ensure!(
                !allowed.is_empty(),
                "an enum with nothing in it accepts nothing; remove it or list its values",
            );
            Ok(ValueSchema::Enum {
                allowed: allowed.iter().cloned().collect(),
            })
        }
        SchemaEntry::String { pattern } => {
            let regex = regex::Regex::new(pattern).with_context(|| {
                format!("pattern `{pattern}` is not a valid regular expression")
            })?;
            Ok(ValueSchema::Pattern {
                regex,
                source: pattern.clone(),
            })
        }
    }
}

/// Identity's rule for a window label: `[a-z0-9_-]`, starting `[a-z0-9]`, ≤64.
fn is_window_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 64 {
        return false;
    }
    let mut chars = label.chars();
    let first = chars.next().expect("non-empty");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    label
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

// -- The file's shape -------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// `#[serde(default)]` so an empty file reaches the message in [`parse`]
    /// rather than a missing-field error about a table nobody wrote.
    #[serde(default)]
    protocols: BTreeMap<String, ProtocolEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolEntry {
    /// **Absent means no label is recognised**, not "any label". See
    /// [`ProtocolPolicy::accepts_window`].
    #[serde(default)]
    windows: Vec<String>,
    #[serde(default)]
    attributes: BTreeMap<String, SchemaEntry>,
    #[serde(default)]
    operations: Vec<OperationEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationEntry {
    name: String,
    sql: String,
    #[serde(default)]
    bind: Vec<String>,
    #[serde(default)]
    params: BTreeMap<String, SchemaEntry>,
    max_rows: u32,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum SchemaEntry {
    Enum { allowed: Vec<String> },
    String { pattern: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> GatewayPolicy {
        parse(text).expect("the policy parses")
    }

    #[test]
    fn the_example_parses() {
        // It is printed for operators to start from, so it had better.
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").expect("the class is there");
        assert_eq!(sales.windows().collect::<Vec<_>>(), ["business_hours"]);
        let op = sales.operation("query_sales").expect("the operation");
        assert_eq!(
            op.bind(),
            [
                Bind::Attribute("region".into()),
                Bind::Param("month".into())
            ]
        );
        assert_eq!(op.max_rows(), 1000);
    }

    #[test]
    fn an_unknown_window_label_is_refused() {
        // **The one the spec warns about by name.** Ignoring a label nobody can
        // enforce turns a business-hours grant into a round-the-clock one.
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").unwrap();
        assert!(sales.accepts_window(Some("business_hours")));
        assert!(!sales.accepts_window(Some("after_hours")));
        // No window at all is not a restriction that went missing.
        assert!(sales.accepts_window(None));
    }

    #[test]
    fn a_protocol_with_no_windows_recognises_none() {
        // Absent must not read as "anything goes" -- that is the same failure
        // by omission rather than by typo.
        let p = policy(
            r#"
            [protocols."x"]
            [[protocols."x".operations]]
            name = "ping"
            sql = "SELECT 1"
            max_rows = 1
            "#,
        );
        let x = p.protocol("x").unwrap();
        assert!(x.accepts_window(None));
        assert!(!x.accepts_window(Some("business_hours")));
    }

    #[test]
    fn an_attribute_outside_its_enum_is_refused() {
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").unwrap();
        let ok = BTreeMap::from([("region".to_owned(), serde_json::json!("kanto"))]);
        assert_eq!(sales.accepts_attributes(&ok), Ok(()));

        // This is the centre trying to widen its own envelope, which §3.1.0
        // says must not work.
        let wide = BTreeMap::from([("region".to_owned(), serde_json::json!("*"))]);
        assert!(matches!(
            sales.accepts_attributes(&wide),
            Err(AttributeRefusal::OutOfRange { .. })
        ));
    }

    #[test]
    fn an_undeclared_attribute_is_refused_rather_than_passed_through() {
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").unwrap();
        let extra = BTreeMap::from([
            ("region".to_owned(), serde_json::json!("kanto")),
            ("tenant".to_owned(), serde_json::json!("acme")),
        ]);
        assert!(matches!(
            sales.accepts_attributes(&extra),
            Err(AttributeRefusal::Unknown { .. })
        ));
    }

    #[test]
    fn a_declared_attribute_that_is_missing_is_refused() {
        // A template binding `{{region}}` with no region would filter on
        // nothing, so the row cannot be applied.
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").unwrap();
        assert!(matches!(
            sales.accepts_attributes(&BTreeMap::new()),
            Err(AttributeRefusal::Missing { .. })
        ));
    }

    #[test]
    fn a_non_string_is_refused() {
        // Stringifying to make it fit would be the file widening itself.
        let p = policy(EXAMPLE);
        let sales = p.protocol("pg-sales-ro-v1").unwrap();
        for value in [
            serde_json::json!(42),
            serde_json::json!(null),
            serde_json::json!(["kanto"]),
        ] {
            let attrs = BTreeMap::from([("region".to_owned(), value)]);
            assert!(matches!(
                sales.accepts_attributes(&attrs),
                Err(AttributeRefusal::OutOfRange { .. })
            ));
        }
    }

    #[test]
    fn a_statement_with_more_placeholders_than_bindings_is_refused() {
        // **The check that pays for parsing at startup.** With the PEP
        // deferred, the first execution is not in this release, so this would
        // otherwise go unnoticed for months.
        let err = parse(
            r#"
            [protocols."x"]
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1 WHERE a = $1 AND b = $2"
            bind = ["$a"]
            max_rows = 1
            [protocols."x".operations.params]
            a = { type = "string", pattern = "." }
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("$2"), "{err:#}");
    }

    #[test]
    fn a_binding_the_statement_never_uses_is_refused() {
        let err = parse(
            r#"
            [protocols."x"]
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1 WHERE a = $1"
            bind = ["$a", "$b"]
            max_rows = 1
            [protocols."x".operations.params]
            a = { type = "string", pattern = "." }
            b = { type = "string", pattern = "." }
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("never uses"), "{err:#}");
    }

    #[test]
    fn a_binding_that_names_nothing_is_refused() {
        // `{{reigon}}` binds nothing, and what that means at execution time
        // depends on a PEP nobody has written yet.
        let err = parse(
            r#"
            [protocols."x"]
            [protocols."x".attributes]
            region = { type = "enum", allowed = ["kanto"] }
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1 WHERE r = $1"
            bind = ["{{reigon}}"]
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("reigon"), "{err:#}");
    }

    #[test]
    fn a_literal_binding_is_refused() {
        let err = parse(
            r#"
            [protocols."x"]
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1 WHERE r = $1"
            bind = ["kanto"]
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("neither"), "{err:#}");
    }

    #[test]
    fn a_pattern_that_does_not_compile_is_refused_at_startup() {
        let err = parse(
            r#"
            [protocols."x"]
            [protocols."x".attributes]
            month = { type = "string", pattern = "[0-9" }
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1"
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("regular expression"), "{err:#}");
    }

    #[test]
    fn an_empty_enum_is_refused() {
        // It accepts nothing, so every row for the class would be refused --
        // a policy that silently does nothing is worse than one that will not
        // load.
        let err = parse(
            r#"
            [protocols."x"]
            [protocols."x".attributes]
            region = { type = "enum", allowed = [] }
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1"
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("accepts nothing"), "{err:#}");
    }

    #[test]
    fn a_duplicate_operation_is_refused_rather_than_overwritten() {
        // TOML's array of tables happily holds two with the same name, and the
        // last one silently winning is how an operator ends up enforcing a
        // statement they thought they had replaced.
        let err = parse(
            r#"
            [protocols."x"]
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1"
            max_rows = 1
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 2"
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("twice"), "{err:#}");
    }

    #[test]
    fn a_bad_window_label_is_refused() {
        let err = parse(
            r#"
            [protocols."x"]
            windows = ["Business Hours"]
            [[protocols."x".operations]]
            name = "q"
            sql  = "SELECT 1"
            max_rows = 1
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a label"), "{err:#}");
    }

    #[test]
    fn an_unknown_protocol_has_no_envelope() {
        // The class this file does not describe cannot be checked against
        // anything, so there is nothing to apply.
        let p = policy(EXAMPLE);
        assert!(p.protocol("pg-payroll-rw-v1").is_none());
    }

    #[test]
    fn an_empty_file_says_so() {
        let err = parse("").unwrap_err();
        assert!(format!("{err:#}").contains("no protocol"), "{err:#}");
    }

    #[test]
    fn a_misspelt_table_is_refused() {
        // `deny_unknown_fields`, for the same reason the service catalogue has
        // it: `[protocol."x"]` would otherwise parse as an empty file.
        let err = parse(r#"[protocol."x"]"#).unwrap_err();
        assert!(format!("{err:#}").contains("TOML"), "{err:#}");
    }
}
