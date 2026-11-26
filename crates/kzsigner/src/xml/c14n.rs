//! XML canonicalization (C14N 1.0 inclusive and exclusive) of a parsed document, or a part of
//! it, as XML signatures sign it.

use roxmltree::{Node, NodeId, NodeType};
use std::collections::BTreeMap;

pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A canonicalization method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    pub exclusive: bool,
    pub comments: bool,
    /// Exclusive: the prefixes treated as in inclusive canonicalization (InclusiveNamespaces).
    pub inclusive_prefixes: Vec<String>,
}

impl Method {
    /// The method named by `uri`, if supported.
    pub fn by_uri(uri: &str) -> Option<Method> {
        let (exclusive, comments) = match uri {
            C14N => (false, false),
            C14N_COMMENTS => (false, true),
            EXC_C14N => (true, false),
            EXC_C14N_COMMENTS => (true, true),
            _ => return None,
        };
        Some(Method {
            exclusive,
            comments,
            inclusive_prefixes: Vec::new(),
        })
    }

    pub fn inclusive() -> Method {
        Method {
            exclusive: false,
            comments: false,
            inclusive_prefixes: Vec::new(),
        }
    }
}

/// Namespace declarations in effect for output: prefix ("" for the default) to URI ("" for none).
type Rendered = BTreeMap<String, String>;

/// The canonical form of `apex` (an element, or the document's root node for all of it),
/// leaving out the subtrees at `skip` (signatures). `text` is the source the
/// document was parsed from.
pub fn canonicalize(text: &str, apex: Node, m: &Method, skip: &[NodeId]) -> Vec<u8> {
    let mut out = String::new();
    let c = Canon { text, m, skip };
    if apex.node_type() == NodeType::Root {
        let mut after = false;
        for n in apex.children() {
            match n.node_type() {
                NodeType::Element => {
                    c.element(&mut out, n, &Rendered::new(), true);
                    after = true;
                }
                NodeType::Comment | NodeType::PI => {
                    if n.node_type() == NodeType::Comment && !m.comments {
                        continue;
                    }
                    if after {
                        out.push('\n');
                    }
                    c.other(&mut out, n);
                    if !after {
                        out.push('\n');
                    }
                }
                _ => {}
            }
        }
    } else {
        c.element(&mut out, apex, &Rendered::new(), true);
    }
    out.into_bytes()
}

struct Canon<'t, 'm, 's> {
    text: &'t str,
    m: &'m Method,
    skip: &'s [NodeId],
}

impl Canon<'_, '_, '_> {
    /// The element's name as written (prefix:local).
    fn qname<'a>(&'a self, n: Node) -> &'a str {
        let s = &self.text[n.range().start + 1..];
        let end = s
            .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .unwrap_or(s.len());
        &s[..end]
    }

    fn other(&self, out: &mut String, n: Node) {
        match n.node_type() {
            NodeType::Comment => {
                out.push_str("<!--");
                out.push_str(n.text().unwrap_or_default());
                out.push_str("-->");
            }
            NodeType::PI => {
                if let Some(pi) = n.pi() {
                    out.push_str("<?");
                    out.push_str(pi.target);
                    if let Some(v) = pi.value {
                        out.push(' ');
                        out.push_str(v);
                    }
                    out.push_str("?>");
                }
            }
            _ => {}
        }
    }

    fn element(&self, out: &mut String, n: Node, parent: &Rendered, apex: bool) {
        if self.skip.contains(&n.id()) {
            return;
        }
        let qname = self.qname(n);
        let prefix = qname.split_once(':').map_or("", |(p, _)| p);
        // every namespace in scope here ("" URI for an undeclared default)
        let mut scope = Rendered::new();
        scope.insert(String::new(), String::new());
        for ns in n.namespaces() {
            let p = ns.name().unwrap_or_default();
            if p == "xml" {
                continue;
            }
            scope.insert(p.to_string(), ns.uri().to_string());
        }
        // the attributes, with their names as written
        let attrs: Vec<(String, &str, &str, &str)> = n
            .attributes()
            .map(|a| {
                let q = &self.text[a.range_qname()];
                (
                    q.to_string(),
                    a.namespace().unwrap_or_default(),
                    a.name(),
                    a.value(),
                )
            })
            .collect();
        let mut decls = Rendered::new();
        let mut rendered = parent.clone();
        let consider = |p: &str, decls: &mut Rendered, rendered: &mut Rendered| {
            let uri = scope.get(p).cloned().unwrap_or_default();
            let before = rendered.get(p).cloned().unwrap_or_default();
            if uri != before {
                decls.insert(p.to_string(), uri.clone());
                rendered.insert(p.to_string(), uri);
            }
        };
        if self.m.exclusive {
            let mut used: Vec<String> = vec![prefix.to_string()];
            for (q, ..) in &attrs {
                if let Some((p, _)) = q.split_once(':')
                    && p != "xml"
                {
                    used.push(p.to_string());
                }
            }
            for p in &self.m.inclusive_prefixes {
                let p = if p == "#default" { "" } else { p.as_str() };
                if scope.contains_key(p) {
                    used.push(p.to_string());
                }
            }
            used.sort();
            used.dedup();
            for p in &used {
                consider(p, &mut decls, &mut rendered);
            }
        } else {
            for p in scope.keys() {
                consider(p, &mut decls, &mut rendered);
            }
        }

        out.push('<');
        out.push_str(qname);
        for (p, uri) in &decls {
            if p.is_empty() {
                out.push_str(" xmlns=\"");
            } else {
                out.push_str(" xmlns:");
                out.push_str(p);
                out.push_str("=\"");
            }
            escape_attr(out, uri);
            out.push('"');
        }
        let mut sorted: Vec<(String, String, String, String)> = attrs
            .iter()
            .map(|(q, ns, l, v)| (ns.to_string(), l.to_string(), q.clone(), v.to_string()))
            .collect();
        // inclusive canonicalization of a part brings in the xml: attributes of its ancestors
        if apex && !self.m.exclusive {
            for anc in n.ancestors().skip(1) {
                for a in anc.attributes() {
                    if a.namespace() == Some(XML_NS)
                        && !sorted.iter().any(|s| s.0 == XML_NS && s.1 == a.name())
                    {
                        sorted.push((
                            XML_NS.into(),
                            a.name().into(),
                            format!("xml:{}", a.name()),
                            a.value().into(),
                        ));
                    }
                }
            }
        }
        sorted.sort_by(|a, b| (!a.0.is_empty(), &a.0, &a.1).cmp(&(!b.0.is_empty(), &b.0, &b.1)));
        for (_, _, q, v) in &sorted {
            out.push(' ');
            out.push_str(q);
            out.push_str("=\"");
            escape_attr(out, v);
            out.push('"');
        }
        out.push('>');
        for ch in n.children() {
            match ch.node_type() {
                NodeType::Element => self.element(out, ch, &rendered, false),
                NodeType::Text => escape_text(out, ch.text().unwrap_or_default()),
                NodeType::Comment if self.m.comments => self.other(out, ch),
                NodeType::PI => self.other(out, ch),
                _ => {}
            }
        }
        out.push_str("</");
        out.push_str(qname);
        out.push('>');
    }
}

fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(s: &str, m: &Method) -> String {
        let doc = roxmltree::Document::parse(s).unwrap();
        String::from_utf8(canonicalize(s, doc.root(), m, &[])).unwrap()
    }

    // examples from the C14N 1.0 recommendation, section 3
    #[test]
    fn w3c_examples() {
        let inc = Method::inclusive();
        // 3.1 PIs, comments, outside the document element
        let s = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->";
        assert_eq!(
            c14n(s, &inc),
            "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
        );
        let mut com = inc.clone();
        com.comments = true;
        assert_eq!(
            c14n(s, &com),
            "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
        );
        // 3.3 start and end tags
        let s = "<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
        let doc = roxmltree::Document::parse_with_options(
            s,
            roxmltree::ParsingOptions {
                allow_dtd: true,
                ..Default::default()
            },
        )
        .unwrap();
        let out = String::from_utf8(canonicalize(s, doc.root(), &inc, &[])).unwrap();
        // (roxmltree does not add DTD default attributes, so e9 has no attr="default")
        assert_eq!(
            out,
            "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>"
        );
        // 3.4 character modifications
        let s = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";
        assert_eq!(
            c14n(s, &inc),
            "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>"
        );
    }

    #[test]
    fn parts_and_exclusive() {
        let s = "<a:r xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xml:lang=\"kk\"><a:x b:y=\"1\"><c/></a:x></a:r>";
        let doc = roxmltree::Document::parse(s).unwrap();
        let x = doc.root_element().first_child().unwrap();
        let inc = String::from_utf8(canonicalize(s, x, &Method::inclusive(), &[])).unwrap();
        assert_eq!(
            inc,
            "<a:x xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" xml:lang=\"kk\" b:y=\"1\"><c></c></a:x>"
        );
        let exc =
            String::from_utf8(canonicalize(s, x, &Method::by_uri(EXC_C14N).unwrap(), &[])).unwrap();
        assert_eq!(
            exc,
            "<a:x xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" b:y=\"1\"><c></c></a:x>"
        );
        // a default namespace above, then an unprefixed child: exclusive declares it where used
        let s = "<r xmlns=\"urn:d\"><p:s xmlns:p=\"urn:p\"><t/></p:s></r>";
        let doc = roxmltree::Document::parse(s).unwrap();
        let ps = doc.root_element().first_child().unwrap();
        let exc = String::from_utf8(canonicalize(s, ps, &Method::by_uri(EXC_C14N).unwrap(), &[]))
            .unwrap();
        assert_eq!(exc, "<p:s xmlns:p=\"urn:p\"><t xmlns=\"urn:d\"></t></p:s>");
        // leaving out a subtree
        let s = "<r><s>1</s><t/></r>";
        let doc = roxmltree::Document::parse(s).unwrap();
        let sid = doc.root_element().first_child().unwrap().id();
        let out =
            String::from_utf8(canonicalize(s, doc.root(), &Method::inclusive(), &[sid])).unwrap();
        assert_eq!(out, "<r><t></t></r>");
    }

    #[test]
    fn methods_by_name() {
        let m = |u| Method::by_uri(u).map(|m| (m.exclusive, m.comments));
        assert_eq!(m(C14N), Some((false, false)));
        assert_eq!(m(C14N_COMMENTS), Some((false, true)));
        assert_eq!(m(EXC_C14N), Some((true, false)));
        assert_eq!(m(EXC_C14N_COMMENTS), Some((true, true)));
        assert_eq!(m("http://www.w3.org/2006/12/xml-c14n11"), None);
    }
}
