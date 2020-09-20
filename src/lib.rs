#![feature(test)]

extern crate test;
#[macro_use]
extern crate nom;

use std::{error, fmt, result};
use std::io::Read;
use std::ops::{Deref, DerefMut};
use libc::pid_t;
use std::fs::File;
use std::path::PathBuf;


pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidInput,
    IoError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::IoError => write!(f, "IO Error"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidInput => "Incorrect input data for memory mapping",
            Error::IoError => "I/O error",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Error {
        Error::IoError
    }
}

impl <'a>From<Error> for nom::Err<&'a str> {
    fn from(_: Error) -> nom::Err<&'a str> {
        nom::Err::Incomplete(nom::Needed::Unknown)
    }
}

impl <T>From<nom::Err<T>> for Error {
    fn from(_: nom::Err<T>) -> Error {
        Error::InvalidInput
    }
}

/// Represents the privacy of a mapping.
#[derive(PartialEq, Debug)]
pub enum Privacy {
    /// This mapping is shared
    Shared,
    /// This mapping is private (copy on write)
    Private,
}

/// Represents the permissions of for a memory mapping.
#[derive(Debug)]
pub struct Permissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub privacy: Privacy,
}

impl Permissions {
    fn from_str(input: &str) -> Result<Self> {
        if input.len() != 4 {
            return Err(Error::InvalidInput)
        }
        let input = input.as_bytes();
        let readable = input[0] == b'r';
        let writable = input[1] == b'w';
        let executable = input[2] == b'x';

        let privacy = match input[3] {
            b'p' => Privacy::Private,
            b's' => Privacy::Shared,
            _e => return Err(Error::InvalidInput),
        };

        Ok(Permissions {
            readable: readable,
            writable: writable,
            executable: executable,
            privacy: privacy,
        })
    }
}

/// This enum represents the pathname field of a given process.
/// Usually this is a file that backs up a given mapping.
#[derive(PartialEq, Debug)]
pub enum Path {
    /// A file backs up this mapping
    MappedFile(String),
    /// This mapping is the main thread stack
    Stack,
    /// This mapping is a thread's stack
    ThreadStack(usize),
    /// This mapping is the virtual dynamically linked shared object
    Vdso,
    /// This mapping is the process's heap
    Heap,
    /// This mapping holds variables updated by the kernel
    Vvar,
    /// This region is the vsyscall mapping
    Vsyscall,
}

impl From<&str> for Path {
    fn from(input: &str) -> Self {
        // TODO: add ThreadStack type
        match input {
            "[heap]" => Path::Heap,
            "[stack]" => Path::Stack,
            "[vdso]" => Path::Vdso,
            "[vvar]" => Path::Vvar,
            "[vsyscall]" => Path::Vvar,
            s => Path::MappedFile(s.to_string())
        }
    }
}


/// Holds data for a given memory mapped region.
/// [For more information.](http://man7.org/linux/man-pages/man5/proc.5.html)
#[derive(Debug)]
pub struct Map {
    /// Base of mapped region in process
    pub base: usize,
    /// Ceiling of mapped region in process
    pub ceiling: usize,
    /// Access permissions of memory region
    pub perms: Permissions,
    /// If this mapping is backed by a file, this is the offset into the file.
    pub offset: usize,
    /// Major device number
    pub dev_major: usize,
    /// Minor device number
    pub dev_minor: usize,
    /// The inode on the above device
    pub inode: usize,
    /// If there is no pathname, this mapping was obtained via mmap(2)
    pub pathname: Path,
}

impl Map {
    /// Calculate the size of the mapped region
    pub fn size_of_mapping(&self) -> usize {
        self.ceiling - self.base
    }

    fn from_str(input: &str) -> Result<Map> {
        let res = parse_map(input);

        match res {
            Ok(val) => Ok(val.1),
            Err(_e) => Err(Error::InvalidInput),
        }
    }
}

named!(parse_map<&str, Map>,
    do_parse!(
        base: map_res!(take_until!("-"), |b| usize::from_str_radix(b, 16))      >>
        take!(1)                                                                >>
        ceiling: map_res!(take_until!(" "), |b| usize::from_str_radix(b, 16))   >>
        take!(1)                                                                >>
        perms: map_res!(take_until!(" "), |b| Permissions::from_str(b))         >>
        take!(1)                                                                >>
        offset: map_res!(take_until!(" "), |b| usize::from_str_radix(b, 16))    >>
        take!(1)                                                                >>
        dev_major: map_res!(take_until!(":"), |b| usize::from_str_radix(b, 16)) >>
        take!(1)                                                                >>
        dev_minor: map_res!(take_until!(" "), |b| usize::from_str_radix(b, 16)) >>
        take!(1)                                                                >>
        inode: map_res!(take_until!(" "), |b| usize::from_str_radix(b, 16))     >>
        take!(1)                                                                >>
        pathname: opt!(take_until!("\n"))                                       >>
        (Map {
            base: base,
            ceiling: ceiling,
            perms: perms,
            offset: offset,
            dev_major: dev_major,
            dev_minor: dev_minor,
            inode: inode,
            pathname: pathname.unwrap().trim().into(),
        })
    )
);


/// A collection of memory mapped regions.
#[derive(Debug)]
pub struct Mappings(Vec<Map>);

impl Mappings {
    /// Returns mappings for a given pid
    pub fn from_pid(pid: pid_t) -> Result<Mappings> {
        let path = format!("/proc/{}/maps", pid);
        let mut file = File::open(path)?;
        let mut input = String::new();
        file.read_to_string(&mut input)?;

        let mut res: Vec<Map> = Vec::new();
        let mut iter: Vec<&str> = input.split("\n").collect();
        iter.pop();
        for s in iter {
            let map = Map::from_str(&format!("{}\n", &s))?;
            res.push(map);
        }

        Ok(Mappings(res))
    }

    pub fn from_path(path: &mut PathBuf) -> Result<Mappings> {
        path.push("maps");
        let mut file = File::open(path)?;
        let mut input = String::new();
        file.read_to_string(&mut input)?;

        let mut res: Vec<Map> = Vec::new();
        let mut iter: Vec<&str> = input.split("\n").collect();
        iter.pop();
        for s in iter {
            let map = Map::from_str(&format!("{}\n", &s))?;
            res.push(map);
        }

        Ok(Mappings(res))
    }
}

impl Deref for Mappings {
    type Target = Vec<Map>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Mappings {
    fn deref_mut(&mut self) -> &mut Vec<Map> { &mut self.0 }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use test::Bencher;

    //TODO: more tests ie: check none pathname
    #[test]
    fn test_parse_map() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = parse_map(input).unwrap().1;
        println!("{:?}", res);
        assert_eq!(res.base, 94458478931968);
        assert_eq!(res.ceiling, 94458479046656);
        assert_eq!(res.offset, 0);
        assert_eq!(res.dev_major, 8);
        assert_eq!(res.dev_minor, 2);
        assert_eq!(res.inode, 152522867);
        assert_eq!(res.pathname, Path::MappedFile("/bin/dash".to_string()));
    }

    #[test]
    fn test_map_path_types() {
        let input = "7fffdb68b000-7fffdb6ac000 rw-p 00000000 00:00 0                          [stack]\n";
        let res = Map::from_str(input).unwrap();
        assert_eq!(res.pathname, Path::Stack);

        let input = "7fffdb7a7000-7fffdb7aa000 r--p 00000000 00:00 0                          [vvar]\n";
        let res = Map::from_str(input).unwrap();
        assert_eq!(res.pathname, Path::Vvar);

        let input = "7fffdb7aa000-7fffdb7ac000 r-xp 00000000 00:00 0                          [vdso]\n";
        let res = Map::from_str(input).unwrap();
        assert_eq!(res.pathname, Path::Vdso);
    }

    #[test]
    fn test_map_from_str_invalid_inputs() {
        // Invalid permissions
        let input = "7fffdb68b000-7fffdb6ac000 rw- 00000000 00:00 0                          [stack]\n";
        let res = Map::from_str(input);
        assert!(res.is_err());

        // Invalid device
        let input = "7fffdb7a7000-7fffdb7aa000 r--p 00000000 0000 0                          [vvar]\n";
        let res = Map::from_str(input);
        assert!(res.is_err());

        // Invalid address format
        let input = "7fffdb7aa0007fffdb7ac000 r-xp 00000000 00:00 0                          [vdso]\n";
        let res = Map::from_str(input);
        assert!(res.is_err());
    }

    #[test]
    fn test_size_of_mapping() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = Map::from_str(input).unwrap();
        assert_eq!(res.size_of_mapping(), 114688usize);
    }

    #[test]
    fn test_map_perms() {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";
        let res = Map::from_str(input).unwrap();
        println!("{:?}", res);
        assert!(res.perms.readable);
        assert!(!res.perms.writable);
        assert!(res.perms.executable);
        assert_eq!(res.perms.privacy, Privacy::Private);
    }

    #[bench]
    fn bench_map_from_str(b: &mut Bencher) {
        let input = "55e8d4153000-55e8d416f000 r-xp 00000000 08:02 9175073                    /bin/dash\n";

        b.iter(||
            Map::from_str(input).unwrap()
        )
    }

    #[test]
    fn test_map_from_str() {
        let mut file = File::open("tests/example.txt").unwrap();
        let mut input = String::new();
        file.read_to_string(&mut input).unwrap();

        let mut iter: Vec<&str> = input.split("\n").collect();
        iter.pop();
        for s in iter {
            let map = Map::from_str(&format!("{}\n", &s)).unwrap();
            println!("{:?}", map);
        }
    }

    #[test]
    fn test_maps() {
        use std::process::id;
        let m = Mappings::from_pid(id() as pid_t);
        assert!(m.is_ok());
        println!("{:?}", m);
    }
}
