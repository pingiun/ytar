use std::{
    borrow::Cow,
    cmp,
    io,
};

use zerocopy::{AsBytes, FromBytes};

#[derive(FromBytes, AsBytes, Debug)]
#[repr(packed)]
pub struct InnerHeader {
    name: [u8; 100],
    _mode: [u8; 8],
    _uid: [u8; 8],
    _gid: [u8; 8],
    size: [u8; 12],
    _mtime: [u8; 12],
    _checksum: [u8; 8],
    typeflag: u8,
    _linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    _uname: [u8; 32],
    _gname: [u8; 32],
    _devmajor: [u8; 8],
    _devminor: [u8; 8],
    prefix: [u8; 155],
    _pad: [u8; 12],
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TypeFlag {
    Regular,
    HardLink,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Directory,
    FIFO,
    PaxNextFile,
    PaxFollowingFiles,
    Other(u8),
}

impl TypeFlag {
    fn from_u8(x: u8) -> TypeFlag {
        match x {
            b'0' | b'\0' => TypeFlag::Regular,
            b'1' => TypeFlag::HardLink,
            b'2' => TypeFlag::SymbolicLink,
            b'3' => TypeFlag::CharacterDevice,
            b'4' => TypeFlag::BlockDevice,
            b'5' => TypeFlag::Directory,
            b'6' => TypeFlag::FIFO,
            b'x' => TypeFlag::PaxNextFile,
            b'g' => TypeFlag::PaxFollowingFiles,
            o => TypeFlag::Other(o),
        }
    }
    fn to_u8(self) -> u8 {
        match self {
            TypeFlag::Regular => b'0',
            TypeFlag::HardLink => b'1',
            TypeFlag::SymbolicLink => b'2',
            TypeFlag::CharacterDevice => b'3',
            TypeFlag::BlockDevice => b'4',
            TypeFlag::Directory => b'5',
            TypeFlag::FIFO => b'6',
            TypeFlag::PaxNextFile => b'x',
            TypeFlag::PaxFollowingFiles => b'g',
            TypeFlag::Other(x) => x,
        }
    }
}

impl InnerHeader {
    pub fn is_posix(&self) -> bool {
        &self.magic == b"ustar\0" && &self.version == b"00"
    }

    pub fn typeflag(&self) -> TypeFlag {
        TypeFlag::from_u8(self.typeflag)
    }

    fn full_name(&self) -> Vec<u8> {
        let mut w: Vec<u8> = Vec::new();
        w.extend_from_slice(trim_slice(&self.prefix));
        w.push(b'/');
        w.extend_from_slice(trim_slice(&self.name));
        w
    }

    // pub fn path_string(&self) -> Result<String, FromUtf8Error> {
    //     let path = self.name();
    //     String::from_utf8(path)
    // }

    pub fn path(&self) -> Cow<'_, [u8]> {
        if self.prefix[0] == b'\0' {
            Cow::from(trim_slice(&self.name))
        } else {
            Cow::from(self.full_name())
        }
    }

    fn size_binary(&self) -> u64 {
        assert!(
            self.size[0] == 0b10000000
                && self.size[1] == 0
                && self.size[2] == 0
                && self.size[3] == 0,
            "size too big"
        );
        let mut buf = [0; 8];
        buf.copy_from_slice(&self.size[4..12]);
        u64::from_le_bytes(buf)
    }

    fn size_octal(&self) -> u64 {
        assert!(
            self.size[11] == b' ',
            "invalid size field, badly terminated"
        );
        u64::from_str_radix(
            std::str::from_utf8(&self.size[..11]).expect("invalid size field, not valid ascii"),
            8,
        )
        .expect("invalid size field, not an octal number")
    }

    pub fn size(&self) -> u64 {
        if self.size[0] >= 0b10000000 {
            self.size_binary()
        } else {
            self.size_octal()
        }
    }
}

fn trim_slice(x: &[u8]) -> &[u8] {
    let pos = x.iter().position(|e| *e == b'\0');
    if let Some(pos) = pos {
        x.split_at(pos).0
    } else {
        x
    }
}

pub struct TarReader<R: io::Read> {
    tar: R,
    next_header: usize,
    data_left: usize,
}

impl<R: io::Read> TarReader<R> {
    pub fn new(tar: R) -> Self {
        Self {
            tar,
            next_header: 0,
            data_left: 0,
        }
    }
    pub fn next(&mut self) -> io::Result<Option<InnerHeader>> {
        let mut buf = [0_u8; 512];
        while self.next_header != 0 {
            // Throw away data until we're at the next header
            let n = self.tar.read(&mut buf[..cmp::min(self.next_header, 512)])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while skipping to next file",
                ));
            }
            assert!(n <= self.next_header);
            self.next_header -= n;
        }
        self.next_header = 0;
        self.data_left = 0;
        let mut bytes_read = self.tar.read(&mut buf)?;
        if bytes_read == 0 {
            // Tars are supposed to end with two null blocks, but we might
            // as well support early ending.
            return Ok(None);
        }
        while bytes_read != 512 {
            let n = self.tar.read(&mut buf[bytes_read..])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading next header",
                ));
            }
            bytes_read += n;
        }
        let header: InnerHeader = zerocopy::transmute!(buf);
        if header.name[0] == b'\0' {
            // Next two blocks are probably all zeros, assume end of tar marker
            return Ok(None);
        }
        self.next_header = blocks(header.size() as usize) * 512;
        self.data_left = header.size() as usize;
        Ok(Some(header))
    }
}

impl<R: io::Read> io::Read for TarReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(self.data_left, buf.len());
        let bytes_read = self.tar.read(&mut buf[..len])?;
        assert!(bytes_read <= self.data_left);
        assert!(bytes_read <= self.next_header);
        self.data_left -= bytes_read;
        self.next_header -= bytes_read;
        Ok(bytes_read)
    }
}

fn blocks(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size / 512 + 1
    }
}

