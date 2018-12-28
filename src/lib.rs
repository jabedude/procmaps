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
/*
pub struct Map {
    pub base: usize,
    pub ceiling: usize,
    pub perms: String,
    pub offset: usize,
    pub dev_major: usize,
    pub dev_minor: usize,
    pub inode: usize,
    pub pathname: String,
}
*/
#[derive(Debug)]
pub struct Map {
    pub base: String,
    pub ceiling: String,
    pub perms: String,
    pub offset: String,
    pub dev_major: String,
    pub dev_minor: String,
    pub inode: String,
    pub pathname: String,
}

named!(parse_map<&str, Map>,
    do_parse!(
        base: map!(take_until!("-"), String::from)      >>
        take!(1)                                        >>
        ceiling: map!(take_until!(" "), String::from)   >>
        take!(1)                                        >>
        perms: map!(take_until!(" "), String::from)     >>
        take!(1)                                        >>
        offset: map!(take_until!(" "), String::from)    >>
        dev_major: map!(take_until!(":"), String::from) >>
        dev_minor: map!(take_until!(" "), String::from) >>
        inode: map!(take_until!(" "), String::from)     >>
        pathname: map!(take_until!("\n"), String::from) >>
        (Map {base: base.into(), ceiling: ceiling.into(), perms: perms.into(), offset: offset.into(), dev_major: dev_major.into(), dev_minor: dev_minor.into(), inode: inode.into(), pathname: pathname.into()})
    )
);

/*
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
*/

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = parse_map(input);
        println!("{:?}", res);
    }
}
