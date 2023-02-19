use std::fs::File;
use std::io::Write;
use std::{env, fs, io, slice, str};

use md5::Md5;
use rand::Rng;
use sha2::Sha256;
use subprocess::{Exec, Redirection};

#[inline]
pub const fn const_min(v1: usize, v2: usize) -> usize {
    if v1 <= v2 {
        v1
    } else {
        v2
    }
}

#[inline]
pub const fn string_substr(src_str: &str, pos: usize, n: usize) -> Result<&str, str::Utf8Error> {
    let rlen = const_min(n, src_str.len() - pos);
    let s = unsafe {
        // First, we build a &[u8]...
        let slice = slice::from_raw_parts(src_str.as_ptr().add(pos), rlen);

        // ... and then convert that slice into a string slice
        str::from_utf8(slice)
    };
    s
}

#[inline]
pub fn get_current_cmdname(cmd_line: &str) -> &str {
    if let Some(trim_pos) = cmd_line.rfind('/') {
        return cmd_line.get((trim_pos + 1)..).unwrap();
    }
    cmd_line
}

pub fn write_to_file(filepath: &str, data: &str) -> bool {
    let file = File::create(&filepath);
    if file.is_ok() {
        let _ = file.unwrap().write_all(data.as_bytes());
        return true;
    }
    log::error!("'{}' open failed: {:?}", filepath, file.err());
    false
}

pub fn create_temporary_directory(max_tries: Option<u32>) -> Option<String> {
    let tmp_dir = env::temp_dir();
    let max_tries = max_tries.unwrap_or(1000);

    let mut i: u32 = 0;
    let mut rng = rand::thread_rng();
    loop {
        let res_path = format!("{}/{}", tmp_dir.to_string_lossy(), rng.gen::<u64>());
        if fs::create_dir_all(res_path.as_str()).is_ok() {
            return Some(res_path);
        }
        if i == max_tries {
            return None;
        }
        i += 1;
    }
}

pub fn exec(command: &str, interactive: Option<bool>) -> (String, bool) {
    let interactive = interactive.unwrap_or(false);
    if interactive {
        let ret_code = Exec::shell(command).join().unwrap();
        return (String::new(), ret_code.success());
    }
    let child_proc = Exec::shell(command).stdout(Redirection::Pipe).capture().unwrap();
    let mut child_out = child_proc.stdout_str();
    if child_out.ends_with('\n') {
        child_out.pop();
    }
    (child_out, child_proc.success())
}

pub fn generate_sha256sum(filepath: &str) -> Option<String> {
    let mut file_obj = File::open(filepath).unwrap();

    // create a Sha256 hasher instance
    use sha2::Digest;
    let mut hasher = Sha256::new();
    let _ = io::copy(&mut file_obj, &mut hasher);

    // process input message
    let result = format!("{:x}", hasher.finalize());
    Some(result)
}

pub fn generate_md5sum(filepath: &str) -> Option<String> {
    let mut file_obj = File::open(filepath).unwrap();

    // create a Md5 hasher instance
    use md5::Digest;
    let mut hasher = Md5::new();
    let _ = io::copy(&mut file_obj, &mut hasher);

    // process input message
    let result = format!("{:x}", hasher.finalize());
    Some(result)
}

// This function assumes that given pkg:
// 1) if is_db_entry=false is `pkgname-version-release.arch.extension`
// 2) if is_db_entry=true is `pkgname-version-release.arch`
pub fn get_name_of_pkg(pkg: &str, is_db_entry: bool) -> String {
    let take_count = if is_db_entry { 2 } else { 3 };
    let mut pkg = pkg.split('/').filter(|s| !s.is_empty()).last().unwrap().to_string();
    let work = pkg.split('-').rev().take(take_count).collect::<Vec<_>>().join("-");

    pkg.truncate(pkg.len() - (work.len() + 1));
    pkg.trim().to_string()
}

// Retrieve the compression command for an archive extension, or cat for .tar
pub fn get_compression_command(db_extension: &str) -> String {
    let fallback_cmd = match db_extension {
        "tar.gz" => "gzip -c -f -n".to_owned(),
        "tar.bz2" => "bzip2 -c -f".to_owned(),
        "tar.xz" => "xz -c -z -".to_owned(),
        "tar.zst" => "zstd -c -z -q -".to_owned(),
        "tar.lrz" => "lrzip -q".to_owned(),
        "tar.lzo" => "lzop -q".to_owned(),
        "tar.Z" => "compress -c -f".to_owned(),
        "tar.lz4" => "lz4 -q".to_owned(),
        "tar.lz" => "lzip -c -f".to_owned(),
        "tar" => "cat".to_owned(),
        _ => "".to_owned(),
    };

    let db_extension = if let Some(strpos) = db_extension.find("tar.") {
        string_substr(&db_extension, strpos + 4, db_extension.len() - 4).unwrap()
    } else {
        ""
    };

    if db_extension.is_empty() {
        return fallback_cmd;
    }

    if let Ok(makepkgconfig_content) = fs::read_to_string("/etc/makepkg.conf") {
        let temp_compress_cmd = makepkgconfig_content
            .lines()
            .into_iter()
            .filter(|elem| elem.starts_with(&format!("COMPRESS{}", db_extension.to_uppercase())))
            .last()
            .unwrap_or("")
            .split('=')
            .last()
            .unwrap_or("")
            .to_string();

        if temp_compress_cmd.starts_with('(') && temp_compress_cmd.ends_with(')') {
            return string_substr(&temp_compress_cmd, 1, temp_compress_cmd.len() - 2)
                .unwrap()
                .to_owned();
        }
    }

    fallback_cmd
}
