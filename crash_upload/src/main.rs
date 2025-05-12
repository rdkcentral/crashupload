use std::env;

mod utils;



fn main() {
    println!("Starting Crash Upload Binary...");
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: <program> <string> <number>");
        std::process::exit(1);
    }
    let arg1 = &args[1]; // the string
    let dump_flag = args[2].parse::<u32>().expect("Second argument must be a number");
    let dump_name = if dump_flag == 1 {"coredump"} else {"minidump"};
    let timestamp_filename = utils::get_timestamp_filename(dump_name);
}


