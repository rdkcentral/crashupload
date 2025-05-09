mod device_info;
mod command;

pub const UTILS_LIB_VER: &str = "v1.0";
pub use device_info::{get_property_value_from_file};
pub use command::*;
