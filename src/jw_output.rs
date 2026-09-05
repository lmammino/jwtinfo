use crate::jws::JwsToken;
use serde_json::{json, to_string_pretty, Value};

/// How a token should be rendered, mirroring the CLI display flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayOptions {
    /// Show both the header and the payload (`--full`).
    pub full: bool,
    /// Pretty-print the JSON output (`--pretty`).
    pub pretty: bool,
    /// Show only the header(s) (`--header`).
    pub header: bool,
}

/// A serializable piece of output. `Raw` is emitted verbatim (not quoted),
/// `Json` is serialized as JSON.
pub enum Output {
    Json(Value),
    Raw(String),
}

impl Output {
    fn render(&self, opts: DisplayOptions) -> String {
        match self {
            Output::Json(value) => render(value, opts.pretty),
            Output::Raw(s) => s.clone(),
        }
    }
}

fn render(value: &Value, pretty: bool) -> String {
    if pretty {
        // Serializing an in-memory `Value` cannot fail: it holds no custom
        // types, non-string map keys or unbounded nesting from user input.
        to_string_pretty(value).expect("serializing a serde_json::Value cannot fail")
    } else {
        value.to_string()
    }
}

/// Implemented by anything that can be rendered as a token body:
/// a `JwsToken` (has header + claims) or a raw `String` (plaintext payload).
pub trait TokenContent {
    /// The primary content shown when neither `header` nor `full` is set.
    fn primary(&self) -> Output;
    /// The full dump, including every available section.
    fn full(&self, jwe_header: Option<&Value>) -> Value;
    /// Only the available headers.
    fn header(&self, jwe_header: Option<&Value>) -> Value;
}

impl TokenContent for JwsToken {
    fn primary(&self) -> Output {
        Output::Json(self.body.clone())
    }

    fn full(&self, jwe_header: Option<&Value>) -> Value {
        match jwe_header {
            Some(h) => json!({"jwe_header": h, "jws_header": self.header, "claims": self.body}),
            None => json!({"header": self.header, "claims": self.body}),
        }
    }

    fn header(&self, jwe_header: Option<&Value>) -> Value {
        match jwe_header {
            Some(h) => json!({"jwe_header": h, "jws_header": self.header}),
            None => self.header.clone(),
        }
    }
}

impl TokenContent for String {
    fn primary(&self) -> Output {
        Output::Raw(self.clone())
    }

    fn full(&self, jwe_header: Option<&Value>) -> Value {
        json!({"header": jwe_header, "payload": self})
    }

    fn header(&self, jwe_header: Option<&Value>) -> Value {
        jwe_header.cloned().unwrap_or(Value::Null)
    }
}

/// Renders a token according to the display options.
/// `jwe_header` is `Some` when the token has an outer JWE level.
pub fn stringify<T: TokenContent>(
    jwe_header: Option<Value>,
    content: T,
    opts: DisplayOptions,
) -> String {
    let output = if opts.header {
        Output::Json(content.header(jwe_header.as_ref()))
    } else if opts.full {
        Output::Json(content.full(jwe_header.as_ref()))
    } else {
        content.primary()
    };
    output.render(opts)
}
