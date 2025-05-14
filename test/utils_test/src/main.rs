use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn create_mock_property_file() {
    let mut mock_props_file = File::create("device.properties").unwrap();
    let content = "MODEL_NUM=TestModel\nOTHER_KEY=OtherValue";
    mock_props_file.write_all(content.as_bytes()).unwrap();
}

fn remove_mock_property_file() {
    if PathBuf::from("device.properties").exists() {
        fs::remove_file("device.properties").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::*;

    // Test for get_property_value_from_file function
    #[test]
    fn test_get_property_value_from_file() {
        create_mock_property_file();
        let mut value = String::new();
        let res = get_property_value_from_file("device.properties", "MODEL_NUM", &mut value);
        assert_eq!(res, true);
        assert_eq!(value, "TestModel");

        remove_mock_property_file();
    }

    #[test]
    fn test_get_property_value_from_file_no_key() {
        create_mock_property_file();
        let mut value = String::new();
        let res = get_property_value_from_file("device.properties", "DEVICE_TYPE", &mut value);
        assert_eq!(res, false);
        assert!(value.is_empty());

        remove_mock_property_file();
    }

    // Test for touch function
    #[test]
    fn test_touch() {
        touch("test_file.txt");
        assert!(PathBuf::from("test_file.txt").exists());
        rm("test_file.txt");
    }

    // Test for rm function
    #[test]
    fn test_rm() {
        touch("test_file.txt");
        rm("test_file.txt");
        assert!(!PathBuf::from("test_file.txt").exists());
    }

    // Test for rm_rf function
    #[test]
    fn test_rm_rf() {
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
        let start = std::time::Instant::now();
        sleep(5);
        let duration = start.elapsed();
        assert!(duration.as_secs() >= 5);
        assert!(duration.as_secs() < 6);
    }
}

fn main() {}
