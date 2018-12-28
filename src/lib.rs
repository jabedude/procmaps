#[macro_use]
extern crate nom;

use std::io::{Read, Result, Error, ErrorKind};
use libc::pid_t;
use std::fs::File;


//TODO: create error/result type

#[derive(PartialEq, Debug)]
pub enum Privacy {
    Shared,
    Private,
}

#[derive(Debug)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub privacy: Privacy,
}

impl From<String> for Permissions {
    fn from(input: String) -> Self {
        let readable = input.chars().nth(0) == Some('r');
        let writable = input.chars().nth(1) == Some('w');
        let executable = input.chars().nth(2) == Some('x');

        let privacy = match input.chars().nth(3) {
            Some('p') => Privacy::Private,
            Some('s') => Privacy::Shared,
            e => panic!("Unknown {:?}", e),
        };

        Permissions {
            readable: readable,
            writable: writable,
            executable: executable,
            privacy: privacy,
        }
    }
}

/// man 5 proc
/// /proc/[pid]/maps
#[derive(Debug)]
pub struct Map {
    pub base: *const u8,
    pub ceiling: *const u8,
    // TODO: make perms a bitfield
    pub perms: Permissions,
    pub offset: usize,
    pub dev_major: usize,
    pub dev_minor: usize,
    pub inode: usize,
    /// If there is no pathname, this mapping was obtained via mmap(2)
    pub pathname: Option<String>,
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
        //take_while!(|ch: char| ch.is_whitespace())      >>
        take!(1)                                        >>
        pathname: opt!(take_until!("\n")) >>
        // pathname: opt!(map!(take_until!("\n"), String::from)) >>
        (Map {
            base: usize::from_str_radix(&base, 16).unwrap() as *const u8,
            ceiling: usize::from_str_radix(&ceiling, 16).unwrap() as *const u8,
            perms: perms.into(), 
            offset: usize::from_str_radix(&offset, 16).unwrap(), 
            dev_major: usize::from_str_radix(&dev_major, 16).unwrap(), 
            dev_minor: usize::from_str_radix(&dev_minor, 16).unwrap(),
            inode: usize::from_str_radix(&inode, 16).unwrap(),
            pathname: match pathname.unwrap() {
                "" => None,
                path => Some(path.trim().to_string()),
            }
        })
    )
);

fn map_from_str(input: &str) -> Result<Map> {
    let res = parse_map(input);

    match res {
        Ok(val) => Ok(val.1),
        Err(e) => Err(Error::new(ErrorKind::InvalidInput, format!("Invalid maps format: {}", e))),
    }
}

pub fn maps(pid: pid_t) -> Result<Vec<Map>> {
    let path = format!("/proc/{}/maps", pid);
    let mut file = File::open(path)?;
    let mut input = String::new();
    file.read_to_string(&mut input)?;

    let mut res: Vec<Map> = Vec::new();
    let mut iter: Vec<&str> = input.split("\n").collect();
    iter.pop();
    for s in iter {
        let map = map_from_str(&format!("{}\n", &s))?;
        res.push(map);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::*;

    //TODO: more tests ie: check none pathname
    #[test]
    fn test_parse_map() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = parse_map(input).unwrap().1;
        println!("{:?}", res);
        assert_eq!(res.base, 94458478931968 as *const u8);
        assert_eq!(res.ceiling, 94458479046656 as *const u8);
        assert_eq!(res.offset, 0);
        assert_eq!(res.dev_major, 8);
        assert_eq!(res.dev_minor, 2);
        assert_eq!(res.inode, 152522867);
        assert_eq!(res.pathname.unwrap(), "/bin/dash");
    }

    #[test]
    fn test_map_perms() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = map_from_str(input).unwrap();
        println!("{:?}", res);
        assert!(res.perms.readable);
        assert!(!res.perms.writable);
        assert!(res.perms.executable);
        assert_eq!(res.perms.privacy, Privacy::Private);
    }

    #[test]
    fn test_map_from_str() {
        let mut file = File::open("tests/example.txt").unwrap();
        let mut input = String::new();
        file.read_to_string(&mut input).unwrap();

        let mut iter: Vec<&str> = input.split("\n").collect();
        iter.pop();
        for s in iter {
            let map = map_from_str(&format!("{}\n", &s)).unwrap();
            println!("{:?}", map);
        }
    }

    #[test]
    fn test_maps() {
        use std::process::id;
        let m = maps(id() as pid_t);
        assert!(m.is_ok());
        println!("{:?}", m);
    }
}
