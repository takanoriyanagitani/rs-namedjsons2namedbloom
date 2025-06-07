use std::process::ExitCode;

use std::io;

use io::BufWriter;
use io::Write;

use rs_namedjsons2namedbloom::NamedBloomBytesXs;
use rs_namedjsons2namedbloom::bloom_writer_new;
use rs_namedjsons2namedbloom::name2word2bloom2buf;
use rs_namedjsons2namedbloom::stdin2znames2named_bloom2writer_default;

pub fn name2word(name: &str, word: &mut [u8; 2]) -> Result<(), io::Error> {
    let dostimedate: u32 = u32::from_str_radix(name, 16).map_err(io::Error::other)?;
    let dostime: u16 = (dostimedate & 0xffff) as u16;
    let dt: [u8; 2] = dostime.to_be_bytes();
    word[0] = dt[0];
    word[1] = dt[1];
    Ok(())
}

pub fn bloom2buf() -> impl FnMut(&NamedBloomBytesXs, &mut Vec<u8>) -> Result<(), io::Error> {
    name2word2bloom2buf(name2word)
}

pub fn writer2bwriter<W>(wtr: W) -> impl FnMut(&NamedBloomBytesXs) -> Result<(), io::Error>
where
    W: Write,
{
    bloom_writer_new(bloom2buf(), wtr)
}

pub fn stdin2znames2named_bloom2stdout_default(key: String) -> Result<(), io::Error> {
    let o = io::stdout();
    let mut ol = o.lock();
    {
        let mut bw = BufWriter::new(&mut ol);

        let mut w = writer2bwriter(&mut bw);
        stdin2znames2named_bloom2writer_default(key)(&mut w)?;
        drop(w);

        bw.flush()?;
    }
    ol.flush()
}

pub fn env_val_by_key(key: &'static str) -> Result<String, io::Error> {
    std::env::var(key)
        .map_err(|e| format!("env var {key} missing: {e}"))
        .map_err(io::Error::other)
}

pub fn sub() -> Result<(), io::Error> {
    let target_key: String = env_val_by_key("ENV_BLOOM_TARGET_KEY")?;
    stdin2znames2named_bloom2stdout_default(target_key)
}

fn main() -> ExitCode {
    sub().map(|_| ExitCode::SUCCESS).unwrap_or_else(|e| {
        eprintln!("{e}");
        ExitCode::FAILURE
    })
}
