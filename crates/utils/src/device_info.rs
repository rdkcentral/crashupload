// utils/src/device_info.rs
use std::fs::File;
use std::io::{BufRead, BufReader};

// Module-level constants
const DEVICE_PROP_FILE: &str = "/etc/device.properties";
const INCLUDE_PROP_FILE: &str = "/etc/include.properties";
const COMMON_PROP_FILE: &str = "/etc/common.properties";


pub fn get_property_value<M>(key: M, val: &mut String) -> bool
where
    M: AsRef<str>,
{
    let key = key.as_ref().trim();
    *val = String::new();

    for path in [DEVICE_PROP_FILE, INCLUDE_PROP_FILE, COMMON_PROP_FILE] {
        let file = match File::open(path){
            Ok(f) => f,
            Err(_) => continue,
        };

        let reader = BufReader::new(file);
        for line in reader.lines().flatten(){
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    let value = v.trim();
                    if !value.is_empty() {
                        val.push_str(value);
                        return true;
                    }
                    else{
                        return false;
                    }
                }
            }
        }
    }
    false
}