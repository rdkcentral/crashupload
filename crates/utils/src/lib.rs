mod command;
mod device_info;

pub const UTILS_LIB_VER: &str = "v1.0";
pub use command::{rm, rm_rf, sleep, touch};
pub use device_info::*;
