use super::collector_target::{runtime_scope::ChildIdentity, scope_child::LibraryCollector};
use std::{cell::Cell, fs, path::PathBuf};
pub struct Collector {
    pub root: PathBuf,
    pub context: serde_json::Value,
    pub initialized: Cell<bool>,
}
impl LibraryCollector for Collector {
    fn identities(&self) -> Result<(ChildIdentity, ChildIdentity), &'static str> {
        let pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let start_ticks = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let unit = self.context["unit"].as_str().unwrap();
        let group = format!("/user.slice/{unit}");
        if !self.initialized.replace(true) {
            let cg = self.root.join("cg").join(group.trim_start_matches('/'));
            fs::create_dir_all(&cg).unwrap();
            fs::write(cg.join("cgroup.type"), "domain\n").unwrap();
            fs::write(cg.join("cgroup.procs"), format!("{pid}\n")).unwrap();
            let proc = self.root.join(format!("proc/{pid}"));
            fs::create_dir_all(&proc).unwrap();
            fs::write(proc.join("stat"), stat).unwrap();
            fs::write(proc.join("cgroup"), format!("0::{group}\n")).unwrap();
            fs::write(self.root.join("properties"),format!("Id={unit}\nInvocationID=1234567890abcdef1234567890abcdef\nControlGroup={group}\nLoadState=loaded\nActiveState=active\n")).unwrap();
        }
        let p = &self.context["parent"];
        let parent = ChildIdentity {
            pid: p["pid"].as_u64().unwrap() as u32,
            start_ticks: p["start_ticks"].as_u64().unwrap(),
            boot: p["boot"].as_str().unwrap().into(),
            cgroup: p["cgroup"].as_str().unwrap().into(),
        };
        Ok((
            ChildIdentity {
                pid,
                start_ticks,
                boot: parent.boot.clone(),
                cgroup: group,
            },
            parent,
        ))
    }
}
