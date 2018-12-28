#[macro_use]
extern crate nom;

use std::io::Result;
use libc::pid_t;

pub enum Permissions {
    Read,
    Write,
    Execute,
    Shared,
    Private,
}

pub struct Map {
    pub base: *const u8,
    pub size: usize,
    pub perms: Permissions,
    pub offset: usize,
    pub dev_major: usize,
    pub dev_minor: usize,
    pub inode: usize,
    pub pathname: String,
}

pub fn maps(pid: pid_t) -> Result<Map> {
    Ok( Map {
        base: 0x00000 as *const u8,
        size: 0,
        perms: Permissions::Read,
        offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        pathname: String::from("hello"),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let input = b"55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash";
        assert_eq!(2 + 2, 4);
    }
}
