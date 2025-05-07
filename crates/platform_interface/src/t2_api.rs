// platform_interface/src/t2.rs
use std::path::Path;
use std::process::Command;

// Module-level constants
const T2_MSG_CLIENT_PATH: &str = "/usr/bin/telemetry2_0_client";

fn t2_msg_client_path() -> &'static Path {
    Path::new(T2_MSG_CLIENT_PATH)
}

/// Notify a telemetry marker with a count (default 1 if None)
pub fn t2_count_notify<M, C>(marker: M, count: Option<C>) -> bool 
where
    M: AsRef<str>,
    C: AsRef<str>,
{
    let t2_client = t2_msg_client_path();
    if t2_client.exists() {
        let count_val = count.as_ref().map(|c| c.as_ref()).unwrap_or("1");
        match Command::new(t2_client).arg(marker.as_ref()).arg(count_val).spawn()
        {
            Ok(_) => true,
            Err(err) => {
                eprintln!("{} execution failed with {}", t2_client.display(), err);
                false
            }
        }
    } 
    else 
    {
        false
    }
}

/// Notify a telemetry marker with a value
pub fn t2_val_notify<M, V>(marker: M, value: V) -> bool 
where
    M: AsRef<str>,
    V: AsRef<str>,
    
{
    let t2_client = t2_msg_client_path();
    if t2_client.exists() {
        match Command::new(t2_client).arg(marker.as_ref()).arg(value.as_ref()).spawn()
        {
            Ok(_) => true,
            Err(err) => {
                eprintln!("{} execution failed with {}", t2_client.display(), err);
                false
            }
        }
    } 
    else 
    {
        false
    }
}
