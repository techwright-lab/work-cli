// Shared assertions for strict historical lifecycle reads.
pub fn files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut result = Vec::new();
    for sub in [".work-authorities", "private"] {
        for entry in std::fs::read_dir(dir.join(sub)).unwrap() {
            let path = entry.unwrap().path();
            // SHM contains SQLite's normal reader lock bookkeeping.
            let bytes = if path.to_string_lossy().ends_with("-shm") {
                Vec::new()
            } else {
                std::fs::read(&path).unwrap()
            };
            result.push((path, bytes));
        }
    }
    result.sort();
    result
}
