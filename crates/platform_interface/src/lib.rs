mod t2_api;
mod rfc_api;

pub const PLATFORM_LIB_VER: &str = "v1.0";
pub use t2_api::{t2_count_notify, t2_val_notify};
pub use rfc_api::{set_rfc_param, get_rfc_param};
