//! ## Input: Zip Files
//!
//! - A Zip file 0: 0.zip
//!   - A Zip item 0: 00
//!     - Gzipped Names
//!       - name 0: 0
//!       - name 1: 1
//!       - name 2: 2
//!       - ...
//!     - Gzipped Jsonl
//!       - value 0: {helo: "wrld"}
//!       - value 1: {helo: "WRLD"}
//!       - value 2: {helo: "WWWW"}
//!       - ...
//!   - A Zip item 1: 01
//!   - A Zip item 2: 02
//!   - ...
//! - A Zip file 1: 1.zip
//! - A Zip file 2: 2.zip
//! - ...

//! ## Output: raw bytes or structured(asn1/der) bytes
//!
//! ### Structured
//!
//! - A Zip file 0: 0.zip
//!   - A Zip item 0: 00
//!     - name: 00
//!     - bloom bytes: 00
//!   - A Zip item 1: 01
//!   - A Zip item 2: 02
//!   - ...
//! - A Zip file 1: 1.zip
//! - A Zip file 2: 2.zip
//! - ...
//!
//! ### Raw bytes(when the length of the item names are fixed)
//!
//! - A Zip file   0.zip: e.g, 2B name + 2B bloom bytes
//!   - A Zip item   0: 0x0000-0x????
//!   - A Zip item   1: 0x0001-0x????
//!   - A Zip item   2: 0x0002-0x????
//!   - ...
//!   - A Zip item 255: 0x00ff-0x????
//! - A Zip file   1.zip: 0100????0101????0102????....01ff????
//! - A Zip file   2.zip: 0200????0201????0202????....02ff????
//! - ...
//! - A Zip file 255.zip: ff00????ff01????ff02????....ffff????

use std::io;

use io::BufRead;
use io::Read;

use io::Seek;

use io::Write;

use std::fs::File;

use serde_json::Map;
use serde_json::Value;

use zip::ZipArchive;
use zip::read::ZipFile;

use sha2::Digest;

use der::asn1::OctetStringRef;

/// A named bloom bytes(16-bit bloom bytes; very small).
#[derive(Default)]
pub struct NamedBloomBytesXs {
    pub name: String,
    pub data: [u8; 2],
}

impl NamedBloomBytesXs {
    pub fn clear(&mut self) {
        self.name.clear();
        self.data = [0; 2];
    }

    pub fn set_name(&mut self, name: &str) {
        self.name.push_str(name);
    }

    pub fn set_data(&mut self, dat: [u8; 2]) {
        self.data = dat;
    }
}

/// A named(small serial-like) bloom bytes(only 4 bytes / row).
pub struct NamedBloomBytesFixed {
    pub serial: u16,
    pub bloom: [u8; 2],
}

pub struct NamedJsonItem {
    pub name: String,
    pub json: Map<String, Value>,
}

pub fn update_bloom_xs(bloom: u16, hf: u16) -> u16 {
    let hf0: u16 = hf >> 12;
    let hf1: u16 = hf >> 8;
    let hf2: u16 = hf >> 4;
    let hf3: u16 = hf;

    let b0: u16 = 1 << (hf0 & 0x0f);
    let b1: u16 = 1 << (hf1 & 0x0f);
    let b2: u16 = 1 << (hf2 & 0x0f);
    let b3: u16 = 1 << (hf3 & 0x0f);

    bloom | b0 | b1 | b2 | b3
}

impl NamedJsonItem {
    pub fn get_value(&self, key: &str) -> Option<&Value> {
        self.json.get(key)
    }

    pub fn to_simple_value(&self, key: &str) -> SimpleValue {
        match self.get_value(key) {
            None => SimpleValue::Null,
            Some(Value::Bool(b)) => SimpleValue::Bool(*b),
            Some(Value::Number(n)) => match n.as_i64() {
                None => SimpleValue::Null,
                Some(i) => SimpleValue::Int(i),
            },
            Some(Value::String(s)) => SimpleValue::Str(s),
            _ => SimpleValue::Null,
        }
    }

    pub fn json_to_hash(&self, key: &str) -> u64 {
        self.to_simple_value(key).to_hash()
    }

    pub fn json2hash2bloom(&self, original_bloom: u16, key: &str) -> u16 {
        let ha: u64 = self.json_to_hash(key);

        let hi: u64 = ha >> 32;
        let lo: u64 = ha & 0xffff_ffff;

        let hl: u32 = (hi as u32) ^ (lo as u32);

        let h: u32 = hl >> 16;
        let l: u32 = hl & 0xffff;

        let hf: u16 = (h as u16) ^ (l as u16);

        update_bloom_xs(original_bloom, hf)
    }
}

#[derive(der::Sequence)]
pub struct NamedJsonAsn1<'a> {
    pub gzipped_names: OctetStringRef<'a>,
    pub gzipped_jsonl: OctetStringRef<'a>,
}

impl<'a> NamedJsonAsn1<'a> {
    pub fn slice2buf(gz: &[u8], buf: &mut Vec<u8>) -> Result<(), io::Error> {
        let mut dec = flate2::bufread::GzDecoder::new(gz);
        buf.clear();
        io::copy(&mut dec, buf)?;
        Ok(())
    }

    pub fn write_names(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        let gznames: &[u8] = self.gzipped_names.as_bytes();
        Self::slice2buf(gznames, buf)
    }

    pub fn write_jsonl(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        let gzjsonl: &[u8] = self.gzipped_jsonl.as_bytes();
        Self::slice2buf(gzjsonl, buf)
    }
}

impl<'a> NamedJsonAsn1<'a> {
    pub fn to_named_json_items(
        &self,
        nbuf: &mut Vec<u8>,
        jbuf: &mut Vec<u8>,
    ) -> Result<Vec<NamedJsonItem>, io::Error> {
        self.write_names(nbuf)?;
        self.write_jsonl(jbuf)?;

        let snames: &[u8] = nbuf;
        let sjsonl: &[u8] = jbuf;

        let inames = snames.lines();
        let ijsonl = BufRead::split(sjsonl, b'\n');

        let iobject = ijsonl.map(|rline| {
            rline.and_then(|line| {
                serde_json::from_slice::<Map<String, Value>>(&line).map_err(io::Error::other)
            })
        });

        let izip = inames.zip(iobject);
        let mapd = izip.map(|pair| {
            let (name, json) = pair;
            name.and_then(|sname: String| {
                Ok(NamedJsonItem {
                    name: sname,
                    json: json?,
                })
            })
        });

        mapd.collect()
    }
}

pub fn zfile2named_bloom<R, N>(
    zfile: &mut ZipFile<R>,
    named2bloom: &mut N,
    named: &mut NamedBloomBytesXs,
    abuf: &mut Vec<u8>,
    nbuf: &mut Vec<u8>,
    jbuf: &mut Vec<u8>,
) -> Result<(), io::Error>
where
    R: Read,
    N: FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error>,
{
    abuf.clear();
    named.clear();

    io::copy(zfile, abuf)?;
    let decoded: NamedJsonAsn1 = der::Decode::from_der(abuf).map_err(io::Error::other)?;
    let items: Vec<NamedJsonItem> = decoded.to_named_json_items(nbuf, jbuf)?;

    let name: &str = zfile.name();

    let bloom: [u8; 2] = named2bloom(name, &items)?;

    named.set_name(name);
    named.set_data(bloom);

    Ok(())
}

pub fn zip2named_bloom2writer<R, N, W>(
    zf: &mut ZipArchive<R>,
    named2bloom: &mut N,
    named: &mut NamedBloomBytesXs,
    abuf: &mut Vec<u8>,
    nbuf: &mut Vec<u8>,
    jbuf: &mut Vec<u8>,
    wtr: &mut W,
) -> Result<(), io::Error>
where
    R: Read + Seek,
    N: FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error>,
    W: FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>,
{
    let sz: usize = zf.len();

    for ix in 0..sz {
        let mut zfile = zf.by_index(ix)?;
        zfile2named_bloom(&mut zfile, named2bloom, named, abuf, nbuf, jbuf)?;
        wtr(named)?;
    }

    Ok(())
}

pub fn znames2named_bloom2writer<I, N, W>(
    znames: I,
    named2bloom: &mut N,
    named: &mut NamedBloomBytesXs,
    abuf: &mut Vec<u8>,
    nbuf: &mut Vec<u8>,
    jbuf: &mut Vec<u8>,
    wtr: &mut W,
) -> Result<(), io::Error>
where
    I: Iterator<Item = String>,
    N: FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error>,
    W: FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>,
{
    for zipname in znames {
        let f: File = File::open(zipname)?;
        let mut zf = ZipArchive::new(f)?;
        zip2named_bloom2writer(&mut zf, named2bloom, named, abuf, nbuf, jbuf, wtr)?;
    }
    Ok(())
}

pub enum SimpleValue<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Str(&'a str),
}

impl<'a> SimpleValue<'a> {
    pub fn null2hash() -> u64 {
        0
    }

    pub fn bool2hash(b: bool) -> u64 {
        let u: u8 = b.into();
        Self::slice2hash256sha(&[u])
    }

    pub fn slice2hash256sha(s: &[u8]) -> u64 {
        let res: &[u8] = &sha2::Sha256::digest(s);
        let sz: usize = res.len();
        if 32 != sz {
            return 0;
        }
        let mut a: [u8; 8] = [0; 8];
        a.copy_from_slice(&res[0..8]);
        u64::from_be_bytes(a)
    }

    pub fn int2hash256sha(i: i64) -> u64 {
        let a: [u8; 8] = i.to_be_bytes();
        Self::slice2hash256sha(&a)
    }

    pub fn str2hash256sha(s: &str) -> u64 {
        let sl: &[u8] = s.as_bytes();
        Self::slice2hash256sha(sl)
    }

    pub fn to_hash(&self) -> u64 {
        match self {
            Self::Null => Self::null2hash(),
            Self::Bool(b) => Self::bool2hash(*b),
            Self::Int(i) => Self::int2hash256sha(*i),
            Self::Str(s) => Self::str2hash256sha(s),
        }
    }
}

pub fn key2json2hash2bloom(
    key: String,
) -> impl FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error> {
    move |_name: &str, items: &[NamedJsonItem]| {
        Ok(items.iter().fold([0; 2], |state, next| {
            let original_bloom: u16 = u16::from_be_bytes(state);
            let updated_bloom: u16 = next.json2hash2bloom(original_bloom, &key);
            updated_bloom.to_be_bytes()
        }))
    }
}

pub fn rdr2znames2named_bloom2writer<R, N, W>(
    rdr: R,
    named2bloom: &mut N,
    wtr: &mut W,
) -> Result<(), io::Error>
where
    R: BufRead,
    N: FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error>,
    W: FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>,
{
    let mut named: NamedBloomBytesXs = NamedBloomBytesXs::default();
    let mut abuf: Vec<u8> = vec![];
    let mut nbuf: Vec<u8> = vec![];
    let mut jbuf: Vec<u8> = vec![];
    let lines = rdr.lines();
    let noerr = lines.map_while(Result::ok);
    znames2named_bloom2writer(
        noerr,
        named2bloom,
        &mut named,
        &mut abuf,
        &mut nbuf,
        &mut jbuf,
        wtr,
    )
}

pub fn stdin2znames2named_bloom2writer<N, W>(
    named2bloom: &mut N,
    wtr: &mut W,
) -> Result<(), io::Error>
where
    N: FnMut(&str, &[NamedJsonItem]) -> Result<[u8; 2], io::Error>,
    W: FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>,
{
    rdr2znames2named_bloom2writer(io::stdin().lock(), named2bloom, wtr)
}

pub fn stdin2znames2named_bloom2writer_default<W>(
    key: String,
) -> impl FnMut(&mut W) -> Result<(), io::Error>
where
    W: FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>,
{
    let mut bgen = key2json2hash2bloom(key);
    move |wtr: &mut W| stdin2znames2named_bloom2writer(&mut bgen, wtr)
}

/// Creates a named bloom bytes writer using a writer which writes to the buf.
pub fn bloom_writer_new<W, B>(
    mut bloom2buf: B,
    mut wtr: W,
) -> impl FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>
where
    B: FnMut(&NamedBloomBytesXs, &mut Vec<u8>) -> Result<(), io::Error>,
    W: Write,
{
    let mut buf: Vec<u8> = vec![];
    move |named: &NamedBloomBytesXs| {
        buf.clear();
        bloom2buf(named, &mut buf)?;
        wtr.write_all(&buf)
    }
}

/// Creates a buffer writer using the name converter.
pub fn name2word2bloom2buf<N>(
    name2word: N,
) -> impl FnMut(&NamedBloomBytesXs, &mut Vec<u8>) -> Result<(), io::Error>
where
    N: Fn(&str, &mut [u8; 2]) -> Result<(), io::Error>,
{
    let mut wbuf: [u8; 2] = [0; 2];
    move |named: &NamedBloomBytesXs, buf: &mut Vec<u8>| {
        let name: &str = &named.name;
        name2word(name, &mut wbuf)?;

        let ns: &[u8] = &wbuf;
        let ds: &[u8] = &named.data;

        Write::write_all(buf, ns)?;
        Write::write_all(buf, ds)?;

        Ok(())
    }
}
