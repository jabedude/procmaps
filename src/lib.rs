#[macro_use]
extern crate nom;

use std::io::{Read, Result, Error, ErrorKind};
use libc::pid_t;
use nom::{IResult, is_alphabetic};
use std::fs::File;

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
    pub base: usize,
    pub ceiling: usize,
    pub perms: String,
    pub offset: usize,
    pub dev_major: usize,
    pub dev_minor: usize,
    pub inode: usize,
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
        take!(1)                                        >>
        dev_major: map!(take_until!(":"), String::from) >>
        take!(1)                                        >>
        dev_minor: map!(take_until!(" "), String::from) >>
        take!(1)                                        >>
        inode: map!(take_until!(" "), String::from)     >>
        take_while!(|ch: char| ch.is_whitespace())      >>
        pathname: map!(take_until!("\n"), String::from) >>
        (Map {
            base: usize::from_str_radix(&base, 16).unwrap(),
            ceiling: usize::from_str_radix(&ceiling, 16).unwrap(), 
            perms: perms.into(), 
            offset: usize::from_str_radix(&ceiling, 16).unwrap(), 
            dev_major: usize::from_str_radix(&dev_major, 16).unwrap(), 
            dev_minor: usize::from_str_radix(&dev_minor, 16).unwrap(),
            inode: usize::from_str_radix(&inode, 16).unwrap(),
            pathname: pathname.into()
        })
    )
);

fn maps_from_file(file: &mut File) -> Result<Map> {
    let mut input = String::new();
    file.read_to_string(&mut input)?;

    let res = parse_map(&input);

    match res {
        Ok(val) => Ok(val.1),
        Err(e) => Err(Error::new(ErrorKind::InvalidInput, "unable to parse")),
    }
}

pub fn maps(pid: pid_t) -> Result<Map> {
    let path = format!("/proc/{}/maps", pid);
    let mut file = File::open(path)?;
    maps_from_file(&mut file)
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = parse_map(input);
        println!("{:?}", res);
    }

    #[test]
    fn test_maps_from_file() {
        let mut infile = File::open("tests/example.txt").unwrap();
        let res = maps_from_file(&mut infile);
        println!("{:?}", res);
    }

}
