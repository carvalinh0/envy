//! Pulling the `envy` executable out of a downloaded release archive.

use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};

/// Extracts the file called `binary` (wherever it sits inside the archive).
/// `.zip` archives are read as zip, anything else as `.tar.gz`.
pub fn extract_binary(archive_name: &str, bytes: &[u8], binary: &str) -> Result<Vec<u8>> {
    if archive_name.ends_with(".zip") {
        from_zip(bytes, binary)
    } else {
        from_tar_gz(bytes, binary)
    }
}

fn from_tar_gz(bytes: &[u8], binary: &str) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .context("The release archive is corrupted.")?
    {
        let mut entry = entry.context("The release archive is corrupted.")?;
        let is_binary = entry.header().entry_type().is_file()
            && entry
                .path()?
                .file_name()
                .is_some_and(|name| name == std::ffi::OsStr::new(binary));
        if is_binary {
            let mut content = Vec::new();
            entry
                .read_to_end(&mut content)
                .context("The release archive is corrupted.")?;
            return Ok(content);
        }
    }
    bail!("The release archive does not contain '{binary}'.")
}

fn from_zip(bytes: &[u8], binary: &str) -> Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("The release archive is corrupted.")?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .context("The release archive is corrupted.")?;
        let is_binary = file.is_file()
            && file
                .name()
                .is_ok_and(|name| name.rsplit('/').next().is_some_and(|n| n == binary));
        if is_binary {
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .context("The release archive is corrupted.")?;
            return Ok(content);
        }
    }
    bail!("The release archive does not contain '{binary}'.")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    pub fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, path, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    pub fn zip_file(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (path, content) in entries {
            writer.start_file(*path, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn extracts_from_a_nested_tar_gz() {
        let archive = tar_gz(&[
            ("envy-v1.0.0-x/README.md", b"docs"),
            ("envy-v1.0.0-x/envy", b"BINARY"),
        ]);
        let content = extract_binary("envy-v1.0.0-x.tar.gz", &archive, "envy").unwrap();
        assert_eq!(content, b"BINARY");
    }

    #[test]
    fn extracts_from_a_nested_zip() {
        let archive = zip_file(&[
            ("envy-v1.0.0-x/README.md", b"docs"),
            ("envy-v1.0.0-x/envy.exe", b"EXE"),
        ]);
        let content = extract_binary("envy-v1.0.0-x.zip", &archive, "envy.exe").unwrap();
        assert_eq!(content, b"EXE");
    }

    #[test]
    fn does_not_confuse_similar_names() {
        let archive = tar_gz(&[("d/envy-extra", b"WRONG"), ("d/envy", b"RIGHT")]);
        assert_eq!(
            extract_binary("a.tar.gz", &archive, "envy").unwrap(),
            b"RIGHT"
        );
    }

    #[test]
    fn reports_a_missing_binary() {
        let archive = tar_gz(&[("d/README.md", b"docs")]);
        let err = extract_binary("a.tar.gz", &archive, "envy").unwrap_err();
        assert!(err.to_string().contains("does not contain 'envy'"), "{err}");

        let archive = zip_file(&[("d/README.md", b"docs")]);
        assert!(extract_binary("a.zip", &archive, "envy.exe").is_err());
    }

    #[test]
    fn reports_corrupted_archives() {
        assert!(extract_binary("a.tar.gz", b"not an archive", "envy").is_err());
        assert!(extract_binary("a.zip", b"not an archive", "envy.exe").is_err());
    }
}
