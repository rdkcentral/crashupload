mod rfc_api;
mod t2_api;

pub const PLATFORM_LIB_VER: &str = "v1.0";
pub use rfc_api::{get_rfc_param, set_rfc_param};
pub use t2_api::{t2_count_notify, t2_val_notify};
