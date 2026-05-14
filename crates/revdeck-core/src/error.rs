use thiserror::Error;

pub type RevDeckResult<T> = Result<T, RevDeckError>;

#[derive(Debug, Error)]
pub enum RevDeckError {
    #[error("invalid object key component `{component}`: {reason}")]
    InvalidObjectKeyComponent { component: String, reason: String },

    #[error("invalid analysis run status `{0}`")]
    InvalidAnalysisRunStatus(String),
}
