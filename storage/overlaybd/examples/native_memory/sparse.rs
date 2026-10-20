use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};

pub fn write_pages(file: &mut File, data: &[u8], zero_gap: &mut u64) -> io::Result<()> {
    for page in data.chunks(4096) {
        if page.iter().all(|byte| *byte == 0) {
            *zero_gap = zero_gap
                .checked_add(page.len() as u64)
                .ok_or_else(|| io::Error::other("sparse image offset overflow"))?;
        } else {
            if *zero_gap != 0 {
                file.seek(SeekFrom::Current(i64::try_from(*zero_gap).map_err(
                    |_| io::Error::other("sparse seek exceeds signed offset"),
                )?))?;
                *zero_gap = 0;
            }
            file.write_all(page)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    fn roundtrip(name: &str, chunks: &[Vec<u8>]) {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!(".native-sparse-{}-{name}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut gap = 0;
        let expected: Vec<_> = chunks.iter().flatten().copied().collect();
        for chunk in chunks {
            write_pages(&mut file, chunk, &mut gap).unwrap();
        }
        file.set_len(expected.len() as u64).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn holes_before_between_and_after_data_preserve_offsets() {
        roundtrip(
            "mixed",
            &[
                vec![0; 4096],
                vec![7; 4096],
                vec![0; 8192],
                vec![9; 4096],
                vec![0; 4096],
            ],
        );
    }
    #[test]
    fn all_zero_logical_image_keeps_its_full_length() {
        roundtrip("zero", &[vec![0; 4096], vec![0; 8192]]);
    }
}
