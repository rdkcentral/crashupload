// utils/src/device_info.rs
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::Command;

// Module-level constants
pub const DEVICE_PROP_FILE: &str = "/etc/device.properties";
pub const INCLUDE_PROP_FILE: &str = "/etc/include.properties";
pub const COMMON_PROP_FILE: &str = "/etc/common.properties";
pub const DEVICE_MAC_FILE: &str = "/tmp/.macAddress";
pub const VERSION_FILE: &str = "/version.txt";

// use this fn to getModel() using "MODEL_NUM" key
pub fn get_property_value_from_file<P: AsRef<Path>, K: AsRef<str>>(path: P, key: K, val: &mut String) -> bool {
    let key = key.as_ref().trim();
    *val = String::new();
    let prop_file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let reader = BufReader::new(prop_file);
    for line in reader.lines().flatten() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let value = v.trim();
                if !value.is_empty() {
                    val.push_str(value);
                    return true;
                } else {
                    return false;
                }
            }
        }
    }
    false
}

// TODO
pub fn get_sha1_value(sha1_val: &mut String) -> bool {
    let output = match Command::new("sha1sum")
        .arg(VERSION_FILE)
        .output() {
        Ok(output) => output,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha1_hash = stdout.split_whitespace().next().unwrap_or("").to_string();
    *sha1_val = sha1_hash;
    true
}

pub fn get_device_mac(mac: &mut String) -> io::Result<()> {
    let mut mac_val = String::new();
    let mut file = File::open(DEVICE_MAC_FILE)?;

    file.read_to_string(&mut mac_val)?;

    *mac = mac_val.trim().replace(":", "");
    Ok(())
}

