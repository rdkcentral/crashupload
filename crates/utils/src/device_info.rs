// utils/src/device_info.rs
use std::fs::File;
use std::path::Path;
use std::io::{BufRead, BufReader};

// Module-level constants
const DEVICE_PROP_FILE: &str = "/etc/device.properties";
const INCLUDE_PROP_FILE: &str = "/etc/include.properties";
const COMMON_PROP_FILE: &str = "/etc/common.properties";


pub fn get_property_value_from_file<P: AsRef<Path>, K: AsRef<str>>(path: P, key: K, val: &mut String) -> bool
{
    let key = key.as_ref().trim();
    *val = String::new();
    let prop_file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let reader = BufReader::new(prop_file);
    for line in reader.lines().flatten()
    {
        if let Some((k, v)) = line.split_once('=') 
        {
            if k.trim() == key 
            {
                let value = v.trim();
                if !value.is_empty() 
                {
                    val.push_str(value);
                    return true;
                }
                else{
                    return false;
                }
            }
        }
    }
    false
}