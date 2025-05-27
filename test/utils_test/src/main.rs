use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn create_file_with_content(file_path: &str, content: &str) {
    let mut file = File::create(file_path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
}

fn remove_file(file_path: &str) {
    if PathBuf::from(file_path).exists() {
        fs::remove_file(file_path).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;
    use utils::*;

    // Test for get_property_value_from_file() function
    #[test]
    fn test_get_property_value_from_file() {
        thread::sleep(Duration::from_secs(2));
        create_file_with_content("device.properties", "MODEL_NUM=TestModel");
        let mut value = String::new();
        let res = get_property_value_from_file("device.properties", "MODEL_NUM", &mut value);
        assert_eq!(res, true);
        assert_eq!(value, "TestModel");

        remove_file("device.properties");
    }

    #[test]
    fn test_get_property_value_from_file_no_key() {
        thread::sleep(Duration::from_secs(2));
        create_file_with_content("device.properties", "MODEL_NUM=TestModel");
        let mut value = String::new();
        let res = get_property_value_from_file("device.properties", "DEVICE_TYPE", &mut value);
        assert_eq!(res, false);
        assert!(value.is_empty());

        remove_file("device.properties");
    }

    // Test for get_device_mac() function
    #[test]
    fn test_get_device_mac_success_with_colon() {
        thread::sleep(Duration::from_secs(2));
        create_file_with_content("/tmp/.macAddress", "00:11:22:33:44:55");
        let mut mac = String::new();
        let res = get_device_mac(&mut mac);
        assert_eq!(res.is_ok(), true);
        assert_eq!(mac, "001122334455");

        remove_file("/tmp/.macAddress");
    }

    fn test_get_device_mac_success_no_colon() {
        thread::sleep(Duration::from_secs(2));
        create_file_with_content("/tmp/.macAddress", "001122334455");
        let mut mac = String::new();
        let res = get_device_mac(&mut mac);
        assert_eq!(res.is_ok(), true);
        assert_eq!(mac, "001122334455");

        remove_file("/tmp/.macAddress");
    }

    #[test]
    fn test_get_device_mac_failure() {
        thread::sleep(Duration::from_secs(2));
        create_file_with_content("/tmp/.macAddress", "");
        let mut mac = String::new();
        let res = get_device_mac(&mut mac);
        assert_eq!(res.is_err(), false);
        assert_eq!(mac.is_empty(), true);

        remove_file("/tmp/.macAddress");
    }

    // Test for touch function
    #[test]
    fn test_touch() {
        thread::sleep(Duration::from_secs(2));
        touch("test_file.txt");
        assert!(PathBuf::from("test_file.txt").exists());
        rm("test_file.txt");
    }

    // Test for rm function
    #[test]
    fn test_rm() {
        thread::sleep(Duration::from_secs(2));
        touch("test_file.txt");
        rm("test_file.txt");
        assert!(!PathBuf::from("test_file.txt").exists());
    }

    // Test for rm_rf function
    #[test]
    fn test_rm_rf() {
        thread::sleep(Duration::from_secs(2));
        touch("test_file.txt");
        rm_rf("test_file.txt");
        assert!(!PathBuf::from("test_file.txt").exists());

        let dir_path = "test_dir";
        fs::create_dir(dir_path).unwrap();
        touch(&format!("{}/test_file.txt", dir_path));
        rm_rf(dir_path);
        assert!(!PathBuf::from(dir_path).exists());
    }

    // Test for sleep function
    #[test]
    fn test_sleep() {
        thread::sleep(Duration::from_secs(2));
        let start = std::time::Instant::now();
        sleep(5);
        let duration = start.elapsed();
        assert!(duration.as_secs() >= 5);
        assert!(duration.as_secs() < 6);
    }
}

fn main() {}
