// Included by git_binding.rs on Darwin only. Metadata-only access proof under
// the existing cooperative route contract, not atomic exec-by-FD containment.
use std::os::fd::AsFd;

#[derive(Clone, Debug, PartialEq, Eq)]
enum DarwinAclWitness {
    SupportedNone,
    Present {
        flags: u32,
        entries: Vec<(work_darwin::Ace, work_darwin::Principal)>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DarwinGitAccessWitness {
    stat_fsid: [i32; 2],
    physical_device: i32,
    mount_fsid: [i32; 2],
    mount_flags: u32,
    effective_access: u32,
    acl: DarwinAclWitness,
}

fn darwin_acl_witness(
    acl: work_darwin::GitAcl<'_>,
    actor: u32,
    mut resolve: impl FnMut(&[u8; 16]) -> std::io::Result<work_darwin::Principal>,
) -> Result<DarwinAclWitness, GitBindingReason> {
    use work_darwin::{GitAcl, GrantExposure, Principal};
    let GitAcl::Present(acl) = acl else {
        return Ok(DarwinAclWitness::SupportedNone);
    };
    // SDK kauth.h: only DEFER_INHERIT and NO_INHERIT are public ACL flags.
    // Private or unknown flags cannot be assumed harmless.
    if acl.absent || acl.flags & !0x0003_0000 != 0 {
        return Err(GitBindingReason::AccessUnproven);
    }
    let mut entries = Vec::with_capacity(acl.len());
    for ace in acl.entries() {
        // Resolve every principal, including harmless/deny/inherit-only ACEs.
        // Known groups may have harmless rights; unknown identities never pass.
        let principal = resolve(&ace.principal).map_err(|_| GitBindingReason::AccessUnproven)?;
        if principal == Principal::Unknown {
            return Err(GitBindingReason::AccessUnproven);
        }
        let trusted = if principal == Principal::User(0) {
            0
        } else {
            actor
        };
        let exposure = ace
            .exposure(principal, trusted)
            .map_err(|_| GitBindingReason::AccessUnproven)?;
        if exposure != GrantExposure::default() {
            return Err(GitBindingReason::UnsafeAccess);
        }
        entries.push((ace, principal));
    }
    Ok(DarwinAclWitness::Present {
        flags: acl.flags,
        entries,
    })
}

fn darwin_metadata_matches(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn darwin_git_access(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<DarwinGitAccessWitness, GitBindingError> {
    use std::{ffi::CString, os::unix::fs::OpenOptionsExt};
    use work_darwin::{
        git_access_at, git_access_fd, mounted_volume_fd, open_directory_at, GitAccessDomain,
    };
    let unproven = || error(path, GitBindingReason::AccessUnproven);
    let actor = rustix::process::geteuid().as_raw();
    let symlink = metadata.file_type().is_symlink();
    let object_type = if metadata.is_dir() {
        2
    } else if symlink {
        5
    } else if metadata.is_file() {
        1
    } else {
        return Err(unproven());
    };
    if (metadata.uid() != 0 && metadata.uid() != actor)
        || (!symlink
            && metadata.mode() & 0o022 != 0
            && !(metadata.is_dir() && metadata.mode() & 0o1000 != 0))
    {
        return Err(error(path, GitBindingReason::UnsafeAccess));
    }
    // Acquire directories only, rooted at a held root, with NOFOLLOW on every
    // component. Never open a Git executable/helper/symlink as regular payload.
    let mut parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC)
                .bits() as i32,
        )
        .open("/")
        .map_err(|_| unproven())?;
    if path != Path::new("/") {
        for component in path.parent().ok_or_else(unproven)?.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| unproven())?;
                    parent = fs::File::from(
                        open_directory_at(parent.as_fd(), &name).map_err(|_| unproven())?,
                    );
                }
                _ => return Err(unproven()),
            }
        }
    }
    let mut buffer = [0; work_darwin::GIT_ACCESS_BUFFER_SIZE];
    let mut held_child = None;
    let observed = if path == Path::new("/") {
        git_access_fd(parent.as_fd(), GitAccessDomain::Stat, &mut buffer).map_err(|_| unproven())?
    } else {
        let name = CString::new(path.file_name().ok_or_else(unproven)?.as_bytes())
            .map_err(|_| unproven())?;
        let observed = git_access_at(parent.as_fd(), &name, GitAccessDomain::Stat, &mut buffer)
            .map_err(|_| unproven())?;
        if metadata.is_dir() {
            held_child = Some(fs::File::from(
                open_directory_at(parent.as_fd(), &name).map_err(|_| unproven())?,
            ));
        }
        observed
    };
    // A volume group's default FSID is not necessarily its actual mounted ID.
    // Query the explicit physical domain separately; never relabel or discard
    // the default observation that correlated to ordinary stat.
    let mut physical_buffer = [0; work_darwin::GIT_ACCESS_BUFFER_SIZE];
    let physical = if path == Path::new("/") {
        git_access_fd(
            parent.as_fd(),
            GitAccessDomain::Physical,
            &mut physical_buffer,
        )
    } else {
        let name = CString::new(path.file_name().ok_or_else(unproven)?.as_bytes())
            .map_err(|_| unproven())?;
        git_access_at(
            parent.as_fd(),
            &name,
            GitAccessDomain::Physical,
            &mut physical_buffer,
        )
    }
    .map_err(|_| unproven())?;
    if observed.file_id != physical.file_id
        || observed.object_type != physical.object_type
        || observed.change_time != physical.change_time
        || observed.owner != physical.owner
        || observed.group != physical.group
        || observed.mode != physical.mode
        || observed.effective_access != physical.effective_access
        || observed.acl != physical.acl
        || observed.fsid == [0, 0]
    {
        return Err(unproven());
    }
    let held = held_child.as_ref().unwrap_or(&parent);
    let held_metadata = held.metadata().map_err(|_| unproven())?;
    if metadata.is_dir() {
        if !darwin_metadata_matches(metadata, &held_metadata) {
            return Err(unproven());
        }
    } else if metadata.dev() != held_metadata.dev() {
        // No regular-file FD: actual-mount correlation is to the held parent.
        // Do not accept a cross-device leaf using its parent's mount evidence.
        return Err(unproven());
    }
    let mount = mounted_volume_fd(held.as_fd()).map_err(|_| unproven())?;
    if mount.flags & 0x0020_0000 != 0 // SDK MNT_IGNORE_OWNERSHIP
        || physical.fsid != mount.fsid
        || observed.device != metadata.dev() as i32
        || observed.file_id != metadata.ino()
        || observed.object_type != object_type
        || observed.owner != metadata.uid()
        || observed.group != metadata.gid()
        || observed.mode & 0o7777 != metadata.mode() & 0o7777
        || observed.change_time != (metadata.ctime(), metadata.ctime_nsec())
        || (!symlink && observed.effective_access & 1 == 0)
    {
        return Err(unproven());
    }
    let acl = darwin_acl_witness(observed.acl, actor, work_darwin::principal)
        .map_err(|reason| error(path, reason))?;
    // USERACCESS is not an atomic snapshot. Correlate the path again after ACL
    // resolution; ctime is an observation guard, NOT a persistent directory
    // stability field (unrelated directory content changes remain permissible).
    let after = fs::symlink_metadata(path).map_err(|_| unproven())?;
    if !darwin_metadata_matches(metadata, &after) {
        return Err(unproven());
    }
    Ok(DarwinGitAccessWitness {
        stat_fsid: observed.fsid,
        physical_device: physical.device,
        mount_fsid: mount.fsid,
        mount_flags: mount.flags,
        effective_access: observed.effective_access,
        acl,
    })
}

#[cfg(test)]
mod darwin_policy_tests {
    use super::*;
    use work_darwin::{decode_filesec, GitAcl, Principal};

    fn filesec(rights: u32, flags: u32) -> Vec<u8> {
        let mut bytes = vec![0; 68];
        bytes[..4].copy_from_slice(&0x012c_c16du32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&1u32.to_ne_bytes());
        bytes[44..60].fill(7);
        bytes[60..64].copy_from_slice(&flags.to_ne_bytes());
        bytes[64..68].copy_from_slice(&rights.to_ne_bytes());
        bytes
    }

    #[test]
    fn harmless_unknown_principals_refuse_including_deny_and_inherit_only() {
        for flags in [1, 2, 1 | 256] {
            let bytes = filesec(128, flags); // READ_ATTRIBUTES only
            let acl = GitAcl::Present(decode_filesec(&bytes).unwrap());
            assert_eq!(
                darwin_acl_witness(acl, 501, |_| Ok(Principal::Unknown)),
                Err(GitBindingReason::AccessUnproven)
            );
        }
    }

    #[test]
    fn harmless_known_groups_pass_but_dangerous_groups_do_not() {
        let harmless = filesec(128, 1);
        let dangerous = filesec(4, 1); // WRITE_DATA / ADD_FILE
        assert!(darwin_acl_witness(
            GitAcl::Present(decode_filesec(&harmless).unwrap()),
            501,
            |_| Ok(Principal::Group(12))
        )
        .is_ok());
        assert_eq!(
            darwin_acl_witness(
                GitAcl::Present(decode_filesec(&dangerous).unwrap()),
                501,
                |_| Ok(Principal::Group(12))
            ),
            Err(GitBindingReason::AccessUnproven)
        );
    }

    #[test]
    fn grants_cover_mutation_delete_child_security_and_owner_and_keep_witness() {
        for rights in [4, 16, 32, 64, 256, 1024, 4096, 8192] {
            let bytes = filesec(rights, 1);
            let acl = GitAcl::Present(decode_filesec(&bytes).unwrap());
            assert_eq!(
                darwin_acl_witness(acl, 501, |_| Ok(Principal::User(502))),
                Err(GitBindingReason::UnsafeAccess)
            );
            for trusted in [0, 501] {
                assert!(darwin_acl_witness(acl, 501, |_| Ok(Principal::User(trusted))).is_ok());
            }
        }
        let bytes = filesec(128, 1);
        let acl = GitAcl::Present(decode_filesec(&bytes).unwrap());
        assert_ne!(
            darwin_acl_witness(acl, 501, |_| Ok(Principal::Group(12))).unwrap(),
            darwin_acl_witness(GitAcl::SupportedNone, 501, |_| unreachable!()).unwrap()
        );
    }
}
