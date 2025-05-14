// platform_interface/src/rfc_api.rs
use std::path::Path;
use std::process::Command;

// Module-level constants
const TR181_BIN: &str = "tr181";
//const TR181_SET_BIN: &str = "tr181Set"; TODO

fn rfc_bin_path() -> &'static Path {
    Path::new(TR181_BIN)
}

/// Set a TR-181 RFC parameter to a value
pub fn set_rfc_param<R: AsRef<str>, V: AsRef<str>>(rfc: R, value: V) -> bool {
    let rfc_bin = rfc_bin_path();
    if rfc_bin.exists() {
        match Command::new(rfc_bin)
            .arg("-s")
            .arg("-v")
            .arg(value.as_ref())
            .arg(rfc.as_ref())
            .spawn()
        {
            Ok(_) => true,
            Err(err) => {
                eprintln!("{} get failed with {}", rfc_bin.display(), err);
                false
            }
        }
    } else {
        false
    }
}

/// Get a TR-181 RFC parameter into a mutable string
pub fn get_rfc_param<R: AsRef<str>>(rfc: R, res: &mut String) -> bool {
    let rfc_bin = rfc_bin_path();
    if rfc_bin.exists() {
        match Command::new(rfc_bin).arg("-g").arg(rfc.as_ref()).output() {
            Ok(output) => {
                if output.status.success() {
                    // Convert command output to string and update res
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    *res = output_str.trim().to_string(); // Update the mutable reference
                    true
                } else {
                    false
                }
            }
            Err(err) => {
                println!("{} get failed with {}", TR181_BIN, err);
                false
            }
        }
    } else {
        false
    }
}
