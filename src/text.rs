//! Messages for people, kept as an English template and its arguments, so that the
//! application shows them in its own language and time zone.
//!
//! [`crate::i18n::Words`] puts what kzcrypto reports (errors, statuses) into these: `tr("...")`
//! and `trf("... {} ...", &[..])` mirror [`crate::i18n`]'s translation calls, and
//! [`crate::i18n::text`] translates [`Text::template`] and fills in the arguments. `Display`
//! gives the English, with times in ISO-8601 UTC.

use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text {
    /// The English text, with `{}` for each argument in order.
    pub template: &'static str,
    pub args: Vec<Arg>,
}

/// An argument of a [`Text`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    /// Shown as it is (names, numbers, algorithm OIDs, ...).
    Str(String),
    /// A time, milliseconds since 1970 (UTC); None: unknown. Shown in the reader's time zone.
    Time(Option<i64>),
    /// Another message, translated in turn.
    Text(Box<Text>),
}

/// A text without arguments.
pub fn tr(en: &'static str) -> Text {
    Text {
        template: en,
        args: Vec::new(),
    }
}

/// A text with each `{}` of `template` filled by the next argument.
pub fn trf(template: &'static str, args: &[&dyn ToArg]) -> Text {
    Text {
        template,
        args: args.iter().map(|a| a.to_arg()).collect(),
    }
}

/// A time argument for [`trf`].
#[derive(Clone, Copy, Debug)]
pub struct Time(pub Option<i64>);

pub trait ToArg {
    fn to_arg(&self) -> Arg;
}

impl ToArg for str {
    fn to_arg(&self) -> Arg {
        Arg::Str(self.into())
    }
}

impl ToArg for &str {
    fn to_arg(&self) -> Arg {
        Arg::Str((*self).into())
    }
}

impl ToArg for String {
    fn to_arg(&self) -> Arg {
        Arg::Str(self.clone())
    }
}

impl ToArg for Text {
    fn to_arg(&self) -> Arg {
        Arg::Text(Box::new(self.clone()))
    }
}

impl ToArg for Time {
    fn to_arg(&self) -> Arg {
        Arg::Time(self.0)
    }
}

macro_rules! numbers {
    ($($t:ty)*) => {$(
        impl ToArg for $t {
            fn to_arg(&self) -> Arg {
                Arg::Str(self.to_string())
            }
        }
    )*};
}
numbers!(u8 u16 u32 u64 usize i8 i16 i32 i64 isize);

impl From<&'static str> for Text {
    fn from(s: &'static str) -> Text {
        tr(s)
    }
}

impl From<String> for Text {
    /// A text that is not translated (details such as library error messages).
    fn from(s: String) -> Text {
        trf("{}", &[&s])
    }
}

impl Text {
    /// The text with `render` applied to each argument; the application passes its own
    /// translation and time formatting.
    pub fn fill(&self, template: &str, render: &mut dyn FnMut(&Arg) -> String) -> String {
        let mut out = String::new();
        let mut args = self.args.iter();
        let mut parts = template.split("{}");
        if let Some(first) = parts.next() {
            out.push_str(first);
        }
        for p in parts {
            if let Some(a) = args.next() {
                out.push_str(&render(a));
            }
            out.push_str(p);
        }
        out
    }

    /// The English text.
    pub fn english(&self) -> String {
        self.fill(self.template, &mut |a| match a {
            Arg::Str(s) => s.clone(),
            Arg::Time(Some(ms)) => kzcrypto::time::iso(*ms),
            Arg::Time(None) => "-".into(),
            Arg::Text(t) => t.english(),
        })
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.english())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english() {
        let inner = trf("bad {}", &[&"thing"]);
        let t = trf(
            "A {} at {} ({}) {}",
            &[&7u8, &Time(Some(0)), &inner, &Time(None)],
        );
        assert_eq!(t.to_string(), "A 7 at 1970-01-01T00:00:00Z (bad thing) -");
        assert_eq!(tr("plain").to_string(), "plain");
        assert_eq!(Text::from(String::from("x {}")).to_string(), "x {}");
        // extra arguments are dropped, missing ones left empty
        assert_eq!(trf("{}", &[&"a", &"b"]).to_string(), "a");
        assert_eq!(trf("{} and {}", &[&"a"]).to_string(), "a and ");
    }
}
