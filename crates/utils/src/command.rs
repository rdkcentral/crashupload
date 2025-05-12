use std::fs::{self, OpenOptions};
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn touch<P: AsRef<Path>>(path: P){
    let _ = OpenOptions::new().create(true).write(true).open(path);
}

pub fn rm<P: AsRef<Path>>(path: P) {
    let _ = fs::remove_file(path);
}

pub fn rm_rf<P: AsRef<Path>>(path: P) {
    let path_ref = path.as_ref();
    let _ = if path_ref.is_dir() {
        fs::remove_dir_all(path_ref)
    } else {
        rm(path_ref);
        Ok(())
    };
}

pub fn sleep(seconds: u64) -> bool {
    thread::sleep(Duration::from_secs(seconds));
    true
}