use super::{bounded_read, private_directory, LoadedMember, MemberError, MemberResult};
use loki_relay_client::{open_descriptor, seal_descriptor, AuthenticatedDescriptor};
use loki_relay_protocol::{envelope::MAX_WIRE_LEN, types::MemberPublic};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub struct CourierFile {
    name: String,
    wire: Vec<u8>,
    peer: u16,
    digest: [u8; 32],
}
impl CourierFile {
    pub fn prepare(
        member: &LoadedMember,
        descriptor: &AuthenticatedDescriptor,
        peer: &MemberPublic,
    ) -> MemberResult<Self> {
        if peer.id == member.identity.public().id {
            return Err(MemberError::Identity);
        }
        let object = seal_descriptor(&member.identity, &member.roster, descriptor.body(), peer)
            .map_err(|_| MemberError::Identity)?;
        Ok(Self {
            name: name(
                &member.roster.vault,
                descriptor.body().owner,
                peer.id,
                descriptor.body().revision,
            ),
            wire: object.wire,
            peer: peer.id,
            digest: *descriptor.digest(),
        })
    }
    pub(super) fn restore(
        member: &LoadedMember,
        descriptor: &AuthenticatedDescriptor,
        peer: u16,
        wire: &[u8],
    ) -> MemberResult<Self> {
        loki_relay_protocol::envelope::validate_wire(wire).map_err(|_| MemberError::Sealed)?;
        if &wire[..8] != b"LOKICFG1"
            || descriptor.body().owner != member.identity.public().id
            || peer == descriptor.body().owner
            || !member.roster.members.iter().any(|m| m.id == peer)
        {
            return Err(MemberError::Identity);
        }
        Ok(Self {
            name: name(
                &descriptor.body().vault,
                descriptor.body().owner,
                peer,
                descriptor.body().revision,
            ),
            wire: wire.to_vec(),
            peer,
            digest: *descriptor.digest(),
        })
    }
    pub(crate) fn peer(&self) -> u16 {
        self.peer
    }
    pub(super) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }
    pub fn file_name(&self) -> &str {
        &self.name
    }
    pub fn publish(&self, directory: &Path) -> MemberResult<PathBuf> {
        private_directory(directory)?;
        atomic_publish(directory, &self.name, &self.wire)?;
        Ok(directory.join(&self.name))
    }
}
fn name(vault: &[u8; 32], owner: u16, peer: u16, revision: u64) -> String {
    format!(
        "{}-relay-config-{owner}-{peer}-{revision}.bin",
        hex::encode(vault)
    )
}
pub struct CourierImport {
    wire: Vec<u8>,
    descriptor: AuthenticatedDescriptor,
}
impl CourierImport {
    pub fn read(member: &LoadedMember, path: &Path) -> MemberResult<Self> {
        private_directory(path.parent().ok_or(MemberError::Io)?)?;
        let wire = bounded_read(path, MAX_WIRE_LEN, true)?;
        let descriptor = open_descriptor(&member.identity, &member.roster, &wire)
            .map_err(|_| MemberError::Identity)?;
        super::config::check_peer_destinations(member, &descriptor)?;
        let body = descriptor.body();
        if body.owner == member.identity.public().id
            || path.file_name().and_then(|s| s.to_str())
                != Some(
                    name(
                        &body.vault,
                        body.owner,
                        member.identity.public().id,
                        body.revision,
                    )
                    .as_str(),
                )
        {
            return Err(MemberError::Identity);
        }
        Ok(Self {
            wire: wire.to_vec(),
            descriptor,
        })
    }
    pub fn descriptor(&self) -> &AuthenticatedDescriptor {
        &self.descriptor
    }
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }
}
pub(crate) fn atomic_publish(directory: &Path, name: &str, bytes: &[u8]) -> MemberResult<()> {
    let path = directory.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if bounded_read(&path, MAX_WIRE_LEN, true)?.as_slice() != bytes {
                return Err(MemberError::Sealed);
            }
            sync(&File::open(&path).map_err(|_| MemberError::Io)?, 1)?;
            sync(&File::open(directory).map_err(|_| MemberError::Io)?, 2)?;
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(MemberError::Io),
    }
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    let temp = directory.join(format!(".{name}.{}.tmp", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|_| MemberError::Io)?;
    file.write_all(bytes).map_err(|_| MemberError::Io)?;
    sync(&file, 1)?;
    // A failed publication retains its private temporary file for inspection.
    match fs::hard_link(&temp, &path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if bounded_read(&path, MAX_WIRE_LEN, true)?.as_slice() != bytes {
                return Err(MemberError::Sealed);
            }
        }
        Err(_) => return Err(MemberError::Io),
    }
    sync(&File::open(&path).map_err(|_| MemberError::Io)?, 1)?;
    sync(&File::open(directory).map_err(|_| MemberError::Io)?, 2)?;
    fs::remove_file(&temp).map_err(|_| MemberError::Io)?;
    sync(&File::open(directory).map_err(|_| MemberError::Io)?, 2)?;
    Ok(())
}

fn sync(file: &File, _point: u8) -> MemberResult<()> {
    #[cfg(test)]
    SYNC_ERROR.with(|p| {
        if p.get() == _point {
            return Err(MemberError::Io);
        }
        Ok(())
    })?;
    file.sync_all().map_err(|_| MemberError::Io)
}
#[cfg(test)]
thread_local! {static SYNC_ERROR:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        crate::state::MemberDir::create(
            &std::env::temp_dir(),
            &format!(
                "relay54-courier-{}-{}",
                std::process::id(),
                hex::encode(crate::setup_transport::Identity::new(1).public().signing)
            ),
        )
        .unwrap()
        .path()
        .to_owned()
    }
    #[test]
    fn successful_courier_publish_leaves_only_the_named_file() {
        let directory = directory();
        atomic_publish(&directory, "courier.bin", b"synthetic").unwrap();
        let names: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["courier.bin"]);
    }
    #[test]
    fn sealed_revision_courier_file_sync_failure_prevents_link() {
        let directory = directory();
        SYNC_ERROR.with(|p| p.set(1));
        assert!(atomic_publish(&directory, "courier.bin", b"synthetic").is_err());
        assert!(!directory.join("courier.bin").exists());
        SYNC_ERROR.with(|p| p.set(0));
        atomic_publish(&directory, "courier.bin", b"synthetic").unwrap();
    }
    #[test]
    fn sealed_revision_courier_directory_sync_failure_prevents_exposure_and_retry_resyncs() {
        let directory = directory();
        SYNC_ERROR.with(|p| p.set(2));
        assert!(atomic_publish(&directory, "courier.bin", b"synthetic").is_err());
        assert_eq!(
            fs::read(directory.join("courier.bin")).unwrap(),
            b"synthetic"
        );
        assert!(atomic_publish(&directory, "courier.bin", b"synthetic").is_err());
        SYNC_ERROR.with(|p| p.set(0));
        atomic_publish(&directory, "courier.bin", b"synthetic").unwrap();
    }
}
