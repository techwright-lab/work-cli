//! Run inside the intended adapter/UID, without reconstructing its environment:
//! cargo run -p work-cli --example qualify_linux -- RUN_ID ADAPTER [--real-user-scope]
//! Default is read-only; opt-in creates ONLY a bounded disposable user scope.
//! stdout is sanitized JSON. Exit 2 means unknown/hold, not qualification success.
use work_cli::linux_scope::{qualify, Disposition, QualificationOptions};
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(args.len() == 2 || (args.len() == 3 && args[2] == "--real-user-scope")) {
        eprintln!("usage: qualify_linux RUN_ID ADAPTER [--real-user-scope]");
        std::process::exit(64);
    }
    match qualify(QualificationOptions {
        run_id: &args[0],
        adapter: &args[1],
        opt_in_fixture: args.len() == 3,
    }) {
        Ok(report) => {
            println!("{}", serde_json::to_string(&report).expect("report JSON"));
            if report.disposition == Disposition::UnknownHold {
                std::process::exit(2);
            }
        }
        Err(_) => {
            eprintln!("qualification failed; hold (check bounded non-secret identifiers)");
            std::process::exit(2);
        }
    }
}
