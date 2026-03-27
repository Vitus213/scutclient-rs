//! EAP (Extensible Authentication Protocol) definitions

/// EAP Code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
    H3cData = 10,
}

impl From<u8> for EapCode {
    fn from(value: u8) -> Self {
        match value {
            1 => EapCode::Request,
            2 => EapCode::Response,
            3 => EapCode::Success,
            4 => EapCode::Failure,
            10 => EapCode::H3cData,
            _ => EapCode::Request,
        }
    }
}

/// EAP Type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    Identity = 1,
    Notification = 2,
    MD5 = 4,
    Available = 20,
    Allocated0x07 = 7,
    Allocated0x08 = 8,
    Unknown(u8),
}

impl From<u8> for EapType {
    fn from(value: u8) -> Self {
        match value {
            1 => EapType::Identity,
            2 => EapType::Notification,
            4 => EapType::MD5,
            20 => EapType::Available,
            7 => EapType::Allocated0x07,
            8 => EapType::Allocated0x08,
            _ => EapType::Unknown(value),
        }
    }
}
