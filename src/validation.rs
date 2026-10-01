use crate::{RuntimeError, RuntimeResult};

pub(crate) fn component(value: &str, max: usize) -> RuntimeResult<()> {
    let valid = !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    valid.then_some(()).ok_or(RuntimeError::Contract)
}

pub(crate) fn digest(value: &str) -> RuntimeResult<()> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    valid.then_some(()).ok_or(RuntimeError::Contract)
}

pub(crate) fn schema(value: &str) -> RuntimeResult<()> {
    let Some((scheme, path)) = value.split_once("://") else {
        return Err(RuntimeError::Contract);
    };
    let valid = value.len() <= 160
        && !scheme.is_empty()
        && !path.is_empty()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
        });
    valid.then_some(()).ok_or(RuntimeError::Contract)
}

pub(crate) fn content_type(value: &str) -> RuntimeResult<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_graphic());
    valid.then_some(()).ok_or(RuntimeError::Contract)
}
