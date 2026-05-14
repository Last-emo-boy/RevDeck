use crate::ObjectRef;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    Note,
    Tag,
    Rename,
    Status,
    Todo,
    Hypothesis,
}

impl AnnotationKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Tag => "tag",
            Self::Rename => "rename",
            Self::Status => "status",
            Self::Todo => "todo",
            Self::Hypothesis => "hypothesis",
        }
    }

    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::Note => 0,
            Self::Tag => 1,
            Self::Rename => 2,
            Self::Status => 3,
            Self::Todo => 4,
            Self::Hypothesis => 5,
        }
    }
}

impl std::fmt::Display for AnnotationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AnnotationKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "note" => Ok(Self::Note),
            "tag" => Ok(Self::Tag),
            "rename" => Ok(Self::Rename),
            "status" => Ok(Self::Status),
            "todo" => Ok(Self::Todo),
            "hypothesis" => Ok(Self::Hypothesis),
            other => Err(format!("unknown annotation kind `{other}`")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub object_ref: ObjectRef,
    pub subject: ObjectRef,
    pub kind: AnnotationKind,
    pub body: String,
    pub evidence: Vec<AnnotationEvidence>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Annotation {
    pub fn new(
        object_ref: ObjectRef,
        subject: ObjectRef,
        kind: AnnotationKind,
        body: impl Into<String>,
        evidence: Vec<AnnotationEvidence>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            object_ref,
            subject,
            kind,
            body: body.into(),
            evidence,
            created_at,
            updated_at,
        }
    }

    pub fn normalized(mut self) -> Self {
        self.body = self.body.trim().to_string();
        self.evidence.sort_by(|left, right| {
            left.order
                .cmp(&right.order)
                .then_with(|| left.object_ref.cmp(&right.object_ref))
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotationEvidence {
    pub object_ref: ObjectRef,
    pub order: u64,
    pub note: String,
}

impl AnnotationEvidence {
    pub fn new(object_ref: ObjectRef, order: u64, note: impl Into<String>) -> Self {
        Self {
            object_ref,
            order,
            note: note.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectKind, ObjectRef, StableObjectKey};
    use time::macros::datetime;

    fn artifact() -> ObjectRef {
        ObjectRef::artifact("abc123", "fixtures/memory").unwrap()
    }

    fn function() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::Function,
            StableObjectKey::function(&artifact.key, 0x401000, Some(32), Some("main")).unwrap(),
        )
    }

    fn string() -> ObjectRef {
        let artifact = artifact();
        ObjectRef::new(
            ObjectKind::String,
            StableObjectKey::string(&artifact.key, 0x20, Some(0x402020), "password").unwrap(),
        )
    }

    #[test]
    fn memory_annotations() {
        let subject = function();
        let evidence = string();
        let kinds = [
            AnnotationKind::Note,
            AnnotationKind::Tag,
            AnnotationKind::Rename,
            AnnotationKind::Status,
            AnnotationKind::Todo,
            AnnotationKind::Hypothesis,
        ];
        let annotations = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                let created_at = format!("2026-05-13T00:00:0{index}Z");
                Annotation::new(
                    ObjectRef::new(
                        ObjectKind::Annotation,
                        StableObjectKey::annotation(&subject, kind.as_str(), &created_at).unwrap(),
                    ),
                    subject.clone(),
                    kind.clone(),
                    format!("body {index}"),
                    vec![AnnotationEvidence::new(evidence.clone(), 0, "linked")],
                    datetime!(2026-05-13 00:00 UTC),
                    datetime!(2026-05-13 00:00 UTC),
                )
                .normalized()
            })
            .collect::<Vec<_>>();

        assert_eq!(annotations.len(), 6);
        assert!(annotations
            .iter()
            .any(|annotation| annotation.kind == AnnotationKind::Hypothesis));
        assert!(annotations
            .iter()
            .all(|annotation| !annotation.evidence.is_empty()));
    }
}
