use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{env, fs, io, slice, str};

use base64::engine::general_purpose::STANDARD;
use base64::write::EncoderStringWriter;
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

pub fn write_to_file(filepath: &str, data: &str) -> io::Result<()> {
    let mut file = File::create(filepath)?;
    file.write_all(data.as_bytes())?;
    Ok(())
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

pub fn touch_file(filepath: &str) -> io::Result<()> {
    if !Path::new(&filepath).exists() {
        File::options().write(true).create_new(true).open(filepath)?;
        return Ok(());
    }

    use std::fs::FileTimes;
    use std::time::SystemTime;

    let file_dest = File::open(filepath)?;

    let curr_time = SystemTime::now();
    let times = FileTimes::new().set_accessed(curr_time).set_modified(curr_time);
    file_dest.set_times(times)?;

    Ok(())
}

pub fn create_tempfile(max_tries: Option<u32>) -> Option<(File, String)> {
    let tmp_dir = env::temp_dir();
    let max_tries = max_tries.unwrap_or(1000);

    let mut i: u32 = 0;
    let mut rng = rand::thread_rng();
    loop {
        let res_path = format!("{}/.tempfile-{}", tmp_dir.to_string_lossy(), rng.gen::<u64>());
        if !Path::new(&res_path).exists() {
            if let Ok(file_obj) = File::options().write(true).create_new(true).open(&res_path) {
                return Some((file_obj, res_path));
            }
        }
        if i == max_tries {
            return None;
        }
        i += 1;
    }
}

pub fn exec(command: &str, interactive: bool) -> (String, bool) {
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

// NOTE: if the None value is provided as sign key, then we just check if gpg is fine and contain
// some keys which can be used
pub fn is_gpg_key_exist(sign_key: Option<&str>) -> bool {
    // construct args for gpg
    let mut gpg_args: Vec<&str> = vec!["--list-secret-key"];
    if let Some(sign_key) = sign_key {
        gpg_args.push(sign_key);
    }

    let exit_status = Exec::cmd("gpg")
        .args(&gpg_args)
        .stderr(subprocess::NullFile)
        .stdout(subprocess::NullFile)
        .join()
        .expect("Failed to run gpg binary");

    exit_status.success()
}

pub fn create_file_sign(filepath: &str, sign_key: Option<&str>) -> anyhow::Result<()> {
    // construct args for gpg
    let mut gpg_args: Vec<&str> =
        vec!["--batch", "--yes", "--detach-sign", "--use-agent", "--no-armor"];

    if let Some(sign_key) = sign_key {
        gpg_args.extend_from_slice(&["-u", sign_key]);
    }
    gpg_args.push(filepath);

    let gpg_proc = Exec::cmd("gpg")
        .args(&gpg_args)
        .stderr(Redirection::Merge)
        .stdout(Redirection::Pipe)
        .capture()?;
    if !gpg_proc.success() {
        anyhow::bail!(
            "failed to sign file with exit status {:?}: {}",
            gpg_proc.exit_status,
            gpg_proc.stdout_str()
        );
    }

    Ok(())
}

#[inline]
pub fn make_db_filename(db_prefix: &str, db_type: &str, db_suffix: &str) -> String {
    format!("{db_prefix}.{db_type}.{db_suffix}")
}

pub fn read_filenames_of_dir(dir_path: &str) -> Vec<String> {
    fs::read_dir(dir_path)
        .expect("Failed to read dir")
        .flat_map(Result::ok)
        .map(|entry| entry.path().file_name().unwrap().to_str().unwrap().to_owned())
        .collect()
}

pub fn compress_into_db_file(
    working_path: &str,
    files_arg: &[String],
    compress_cmd: &str,
    db_filepath: &str,
) -> anyhow::Result<()> {
    // create file if it doesn't exist or truncate if it does
    let db_fileobj = File::create(db_filepath)?;

    // construct args for bsdtar
    let mut bsdtar_args: Vec<String> = vec!["-cf".into(), "-".into()];
    bsdtar_args.extend_from_slice(files_arg);

    let bsdtar_cmd = Exec::cmd("bsdtar").args(&bsdtar_args).cwd(working_path);

    // run our pipeline
    let exit_status =
        { bsdtar_cmd | Exec::shell(compress_cmd) }.stdout(Redirection::File(db_fileobj)).join()?;

    if !exit_status.success() {
        anyhow::bail!("pipeline failed with exit status: {exit_status:?}");
    }

    Ok(())
}

pub fn generate_sha256sum(filepath: &str) -> Option<String> {
    let mut file_obj = File::open(filepath).ok()?;

    // create a Sha256 hasher instance
    use sha2::Digest;
    let mut hasher = Sha256::new();
    io::copy(&mut file_obj, &mut hasher).ok()?;

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

// format a metadata entry
#[inline]
fn format_entry(field_name: &str, value: &Option<String>) -> String {
    if value.is_none() {
        return String::new();
    }
    format!("%{field_name}%\n{}\n\n", value.as_ref().unwrap())
}

fn format_entry_mul(field_name: &str, values: &[String]) -> String {
    if values.is_empty() {
        return String::new();
    }

    let mut result = String::from(&format!("%{field_name}%\n"));
    for value in values.iter() {
        result.push_str(&format!("{value}\n"));
    }

    result += "\n";
    result
}

// Retrieve the compression command for an archive extension, or cat for .tar
pub fn get_compression_command(db_extension: &str, makepkgconf_path: Option<&str>) -> String {
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
        string_substr(db_extension, strpos + 4, db_extension.len() - 4).unwrap()
    } else {
        ""
    };

    if db_extension.is_empty() || makepkgconf_path.is_none() {
        return fallback_cmd;
    }

    if let Ok(makepkgconfig_content) = fs::read_to_string(makepkgconf_path.unwrap()) {
        let temp_compress_cmd = makepkgconfig_content
            .lines()
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

pub fn get_pkg_files(pkgpath: &str) -> Vec<String> {
    let mut file_list = crate::pkginfo::list_archive(pkgpath);
    file_list.sort();

    use std::collections::HashSet;
    let mut sorted_files =
        file_list.into_iter().collect::<HashSet<String>>().into_iter().collect::<Vec<String>>();
    sorted_files.sort();

    sorted_files
}

pub fn create_db_desc_entry(
    pkgpath: &str,
    pkg_entrypath: &str,
    workingdb_path: &str,
    pkginfo: &crate::pkginfo::PkgInfo,
    csize: String,
    pkg_sha256sum: Option<String>,
    pkg_pgpsig: Option<String>,
) -> io::Result<()> {
    let mut desc_content = String::new();
    desc_content.push_str(&format_entry(
        "FILENAME",
        &Some(Path::new(pkgpath).file_name().unwrap().to_string_lossy().to_string()),
    ));
    desc_content.push_str(&format_entry("NAME", &pkginfo.pkgname));
    desc_content.push_str(&format_entry("BASE", &pkginfo.pkgbase));
    desc_content.push_str(&format_entry("VERSION", &pkginfo.pkgver));
    desc_content.push_str(&format_entry("DESC", &pkginfo.pkgdesc));
    desc_content.push_str(&format_entry_mul("GROUPS", &pkginfo.groups));
    desc_content.push_str(&format_entry("CSIZE", &Some(csize)));
    desc_content.push_str(&format_entry("ISIZE", &pkginfo.pkg_isize));

    // add checksums
    desc_content.push_str(&format_entry("SHA256SUM", &pkg_sha256sum));

    // add PGP sig
    desc_content.push_str(&format_entry("PGPSIG", &pkg_pgpsig));

    desc_content.push_str(&format_entry("URL", &pkginfo.url));
    desc_content.push_str(&format_entry_mul("LICENSE", &pkginfo.licenses));
    desc_content.push_str(&format_entry("ARCH", &pkginfo.arch));
    desc_content.push_str(&format_entry("BUILDDATE", &pkginfo.builddate));
    desc_content.push_str(&format_entry("PACKAGER", &pkginfo.packager));
    desc_content.push_str(&format_entry_mul("REPLACES", &pkginfo.replaces));
    desc_content.push_str(&format_entry_mul("CONFLICTS", &pkginfo.conflicts));
    desc_content.push_str(&format_entry_mul("PROVIDES", &pkginfo.provides));

    desc_content.push_str(&format_entry_mul("DEPENDS", &pkginfo.depends));
    desc_content.push_str(&format_entry_mul("OPTDEPENDS", &pkginfo.optdepends));
    desc_content.push_str(&format_entry_mul("MAKEDEPENDS", &pkginfo.makedepends));
    desc_content.push_str(&format_entry_mul("CHECKDEPENDS", &pkginfo.checkdepends));

    let mut desc_entry_file = File::create(format!("{workingdb_path}/{pkg_entrypath}/desc"))?;
    desc_entry_file.write_all(desc_content.as_bytes())?;

    Ok(())
}

pub fn gen_pkg_integrity(
    pkgpath: &str,
    csize: &mut String,
    include_sigs: bool,
    pkg_sha256sum: &mut Option<String>,
    pkg_pgpsig: &mut Option<String>,
) -> bool {
    // compute base64'd PGP signature
    *pkg_pgpsig = None;

    let sig_filename = format!("{pkgpath}.sig");
    if include_sigs && Path::new(&sig_filename).exists() {
        if exec(&format!("grep -q 'BEGIN PGP SIGNATURE' '{sig_filename}'"), true).1 {
            log::error!("Cannot use armored signatures for packages: {sig_filename}");
            return false;
        }

        let pgpsigsize = fs::metadata(&sig_filename).unwrap().len();
        if pgpsigsize > 16384 {
            log::error!("Invalid package signature file '{sig_filename}'.");
            return false;
        }
        log::info!("Adding package signature...");

        {
            let mut encoder = EncoderStringWriter::new(&STANDARD);
            let mut file_obj = File::open(sig_filename).expect("Failed to open sig file to read");
            io::copy(&mut file_obj, &mut encoder).expect("Failed to read sig file");

            *pkg_pgpsig = Some(encoder.into_inner());
        }
    }

    *csize = format!("{}", fs::metadata(pkgpath).unwrap().len());

    // compute checksums
    log::info!("Computing checksums...");
    *pkg_sha256sum = generate_sha256sum(pkgpath);

    true
}

pub fn is_file_in_archive(arc_filepath: &str, needle_pattern: &str) -> bool {
    let exit_status = Exec::cmd("bsdtar")
        .args(&["-tqf", arc_filepath, needle_pattern])
        .stderr(subprocess::NullFile)
        .stdout(subprocess::NullFile)
        .join()
        .expect("Failed to run bsdtar binary");

    exit_status.success()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    const PKGPATH: &str = "xz-5.4.5-2-x86_64.pkg.tar.zst";

    #[test]
    fn getting_min_val() {
        assert_eq!(crate::utils::const_min(4, 4), 4);
        assert_eq!(crate::utils::const_min(4, 1), 1);
        assert_eq!(crate::utils::const_min(1, 4), 1);
    }
    #[test]
    fn getting_string_substr() {
        assert_eq!(crate::utils::string_substr("ABCDEF", 4, 42), Ok("EF"));
        assert_eq!(crate::utils::string_substr("ABCDEF", 1, 10), Ok("BCDEF"));
        assert_eq!(crate::utils::string_substr("ABCDEF", 2, 3), Ok("CDE"));
    }
    #[test]
    fn test_make_db_filename() {
        assert_eq!(crate::utils::make_db_filename("ads", "b", "c"), "ads.b.c".to_owned());
        assert_eq!(crate::utils::make_db_filename("a", "bsd", "c"), "a.bsd.c".to_owned());
        assert_eq!(crate::utils::make_db_filename("a", "b", "csd"), "a.b.csd".to_owned());
        assert_eq!(crate::utils::make_db_filename("a", "b", "c"), "a.b.c".to_owned());
    }
    #[test]
    fn getting_current_cmdline() {
        assert_eq!(crate::utils::get_current_cmdname("../../repo-add"), "repo-add");
        assert_eq!(crate::utils::get_current_cmdname("../../../../repo-remove"), "repo-remove");
        assert_eq!(crate::utils::get_current_cmdname("./repo-remove"), "repo-remove");
        assert_eq!(crate::utils::get_current_cmdname("/usr/bin/repo-add"), "repo-add");
    }
    #[test]
    fn write_data_tofile() {
        // empty file
        let filepath = {
            use rand::Rng;
            use std::env;

            let tmp_dir = env::temp_dir();
            let mut rng = rand::thread_rng();
            format!("{}/.tempfile-{}", tmp_dir.to_string_lossy(), rng.gen::<u64>())
        };

        assert!(crate::utils::write_to_file(&filepath, "123451231231").is_ok());
        assert!(Path::new(&filepath).exists());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "123451231231");
        assert!(crate::utils::write_to_file(&filepath, "1234").is_ok());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "1234");

        // cleanup
        assert!(fs::remove_file(&filepath).is_ok());

        assert!(crate::utils::write_to_file(&filepath, "562").is_ok());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "562");
        assert!(fs::remove_file(&filepath).is_ok());
    }
    #[test]
    fn running_execs() {
        assert_eq!(crate::utils::exec("echo long text", false), ("long text".to_owned(), true));
        assert_eq!(crate::utils::exec("echo 123124", false), ("123124".to_owned(), true));
        assert_eq!(
            crate::utils::exec("echo long text &>/dev/null; false", true),
            ("".to_owned(), false)
        );
        assert_eq!(
            crate::utils::exec("echo 123124 &>/dev/null; true", true),
            ("".to_owned(), true)
        );
    }
    #[test]
    fn getting_pkgname_from_path() {
        assert_eq!(crate::utils::get_name_of_pkg(PKGPATH, false), "xz");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, false), "xzz");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, false), " ");
    }
    #[test]
    fn getting_pkgname_from_dbentry() {
        assert_eq!(crate::utils::get_name_of_pkg(PKGPATH, true), "xz-5.4.5");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, true), "xzz-5.4.5");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, true), "xz-5.4");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, true), "xz-5.4.");
        assert_ne!(crate::utils::get_name_of_pkg(PKGPATH, true), " ");
    }
    #[test]
    fn touch_file() {
        use rand::Rng;
        use std::env;

        let tmp_dir = env::temp_dir();
        let mut rng = rand::thread_rng();
        let filepath = format!("{}/.tempfile-{}", tmp_dir.to_string_lossy(), rng.gen::<u64>());

        assert!(!Path::new(&filepath).exists());
        assert!(crate::utils::touch_file(&filepath).is_ok());
        assert!(Path::new(&filepath).exists());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), "".to_owned());

        let desc_content = "testdata: abcd";
        {
            let mut desc_file = fs::File::options().write(true).open(&filepath).unwrap();
            use std::io::prelude::*;
            desc_file.write_all(desc_content.as_bytes()).unwrap();
        }

        assert_eq!(fs::read_to_string(&filepath).unwrap(), desc_content.to_owned());
        assert!(crate::utils::touch_file(&filepath).is_ok());
        assert_eq!(fs::read_to_string(&filepath).unwrap(), desc_content.to_owned());

        // cleanup
        assert!(fs::remove_file(&filepath).is_ok());

        // test perms
        assert!(crate::utils::touch_file("/.testfile-rust-repo-add").is_err());
    }
    #[test]
    fn getting_pkgfiles() {
        let expected_pkgfiles = fs::read_to_string("xz-files")
            .unwrap()
            .lines()
            .filter(|x| *x != "%FILES%" && !x.is_empty())
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(crate::utils::get_pkg_files(PKGPATH), expected_pkgfiles);
        assert_ne!(crate::utils::get_pkg_files(PKGPATH), [" "]);
        assert_ne!(crate::utils::get_pkg_files(PKGPATH), vec![] as Vec<String>);
    }
    #[test]
    fn getting_compression_cmd() {
        let makepkgconf_path = Some("makepkg.conf");

        // custom
        assert_eq!(
            crate::utils::get_compression_command("tar.gz", makepkgconf_path),
            "gzip -c -f -n -h"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.bz2", makepkgconf_path),
            "bzip2 -c -f -h"
        );
        assert_eq!(crate::utils::get_compression_command("tar.xz", makepkgconf_path), "xz -c -z -");
        assert_eq!(
            crate::utils::get_compression_command("tar.zst", makepkgconf_path),
            "zstd -c -T0 --ultra -20 -"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.lrz", makepkgconf_path),
            "lrzip -q -h"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.lzo", makepkgconf_path),
            "lzop -q -h"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.Z", makepkgconf_path),
            "compress -c -f -h"
        );
        assert_eq!(crate::utils::get_compression_command("tar.lz4", makepkgconf_path), "lz4 -q -h");
        assert_eq!(
            crate::utils::get_compression_command("tar.lz", makepkgconf_path),
            "lzip -c -f -h"
        );
        assert_eq!(crate::utils::get_compression_command("tar", makepkgconf_path), "cat");
        assert_eq!(crate::utils::get_compression_command("", makepkgconf_path), "");

        // fallback
        let makepkgconf_path = Some("makepkg-nonexist.conf");
        assert_eq!(
            crate::utils::get_compression_command("tar.gz", makepkgconf_path),
            "gzip -c -f -n"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.bz2", makepkgconf_path),
            "bzip2 -c -f"
        );
        assert_eq!(crate::utils::get_compression_command("tar.xz", makepkgconf_path), "xz -c -z -");
        assert_eq!(
            crate::utils::get_compression_command("tar.zst", makepkgconf_path),
            "zstd -c -z -q -"
        );
        assert_eq!(crate::utils::get_compression_command("tar.lrz", makepkgconf_path), "lrzip -q");
        assert_eq!(crate::utils::get_compression_command("tar.lzo", makepkgconf_path), "lzop -q");
        assert_eq!(
            crate::utils::get_compression_command("tar.Z", makepkgconf_path),
            "compress -c -f"
        );
        assert_eq!(crate::utils::get_compression_command("tar.lz4", makepkgconf_path), "lz4 -q");
        assert_eq!(crate::utils::get_compression_command("tar.lz", makepkgconf_path), "lzip -c -f");
        assert_eq!(crate::utils::get_compression_command("tar", makepkgconf_path), "cat");
        assert_eq!(crate::utils::get_compression_command("", makepkgconf_path), "");

        // fallback on None
        let makepkgconf_path = None;
        assert_eq!(
            crate::utils::get_compression_command("tar.gz", makepkgconf_path),
            "gzip -c -f -n"
        );
        assert_eq!(
            crate::utils::get_compression_command("tar.bz2", makepkgconf_path),
            "bzip2 -c -f"
        );
        assert_eq!(crate::utils::get_compression_command("tar.xz", makepkgconf_path), "xz -c -z -");
        assert_eq!(
            crate::utils::get_compression_command("tar.zst", makepkgconf_path),
            "zstd -c -z -q -"
        );
        assert_eq!(crate::utils::get_compression_command("tar.lrz", makepkgconf_path), "lrzip -q");
        assert_eq!(crate::utils::get_compression_command("tar.lzo", makepkgconf_path), "lzop -q");
        assert_eq!(
            crate::utils::get_compression_command("tar.Z", makepkgconf_path),
            "compress -c -f"
        );
        assert_eq!(crate::utils::get_compression_command("tar.lz4", makepkgconf_path), "lz4 -q");
        assert_eq!(crate::utils::get_compression_command("tar.lz", makepkgconf_path), "lzip -c -f");
        assert_eq!(crate::utils::get_compression_command("tar", makepkgconf_path), "cat");
        assert_eq!(crate::utils::get_compression_command("", makepkgconf_path), "");
    }
    #[test]
    fn generating_pkg_integrity() {
        let pkg_info = crate::pkginfo::PkgInfo::from_archive(PKGPATH);

        let mut pkg_csize = String::new();
        let mut pkg_sha256sum: Option<String> = None;
        let mut pkg_pgpsig: Option<String> = None;

        assert!(crate::utils::gen_pkg_integrity(
            PKGPATH,
            &mut pkg_csize,
            true,
            &mut pkg_sha256sum,
            &mut pkg_pgpsig,
        ));
        assert_eq!(pkg_csize, "648678".to_owned());
        assert_eq!(
            pkg_sha256sum,
            Some("6bcf35ecc6869a74926b204f16f01704c60115b956b098d3e59b655d1d36a2aa".to_owned())
        );
        assert_eq!(pkg_pgpsig, Some("iQGzBAABCAAdFiEEiC3P5I4gUdSOJWKr87YHSI2zWkcFAmZHWccACgkQ87YHSI2zWkca+wv+NwT5s2m93pO+A7p9vs1XfrIEroK44wyYqqVqleBT0/1xIdVcDlZJCfN2ef6s56C+ZVf60EYaIo328VLzTY2dFARH+I9ILbpXfHPR2o8DPD0VnRMzgvI+k945pJd8xS+Oh9nGGUnf84hXLYsEZJAh134+Tefiqwukc50Mnlits0tlxIlFroNzOJT3F+xQ/PhiWMygeCSMg8fMORlUt3pV3FB8Dz826Yn+MxPcu6b8C001+kgCyjMJLUo8uxecQpHeuBJzcmK+PYdt0x3jNmJd2IVmH2XWXgn0lkqkOsofge8i22kbdrsS7E46Bt5FBI5BFt8R2zhkpCr4zInkNV4XUmW2zqvWZ88axNvYSx7NO4rCWmIw2hjJTsjkrVRD+qifJo5xzYXhQSSgzWEU7S8TvDwfTmT2ArOgI1+uCQ+dDtTviv4bTT/jQTKUHsj4jvZzCXEe7TkQAnckjZwNXMIeT0T8OWfneGc3j/CkeGYSm9+rZRsYqFa7GFbs47T0tQ8N".to_owned()));

        let mut pkg_csize = String::new();
        let mut pkg_sha256sum: Option<String> = None;
        let mut pkg_pgpsig: Option<String> = None;

        assert!(crate::utils::gen_pkg_integrity(
            PKGPATH,
            &mut pkg_csize,
            false,
            &mut pkg_sha256sum,
            &mut pkg_pgpsig,
        ));
        assert_eq!(pkg_csize, "648678".to_owned());
        assert_eq!(
            pkg_sha256sum,
            Some("6bcf35ecc6869a74926b204f16f01704c60115b956b098d3e59b655d1d36a2aa".to_owned())
        );
        assert_eq!(pkg_pgpsig, None);
    }
    #[test]
    fn creating_db_entry() {
        let pkg_info = crate::pkginfo::PkgInfo::from_archive(PKGPATH);

        let workingdb_path =
            crate::utils::create_temporary_directory(None).expect("Failed to create temp dir");
        let pkg_entrypath =
            format!("{}-{}", pkg_info.pkgname.as_ref().unwrap(), pkg_info.pkgver.as_ref().unwrap());

        fs::create_dir(format!("{}/{}", &workingdb_path, &pkg_entrypath))
            .expect("Failed to create dir");

        let mut pkg_csize = String::new();
        let mut pkg_sha256sum: Option<String> = None;

        assert!(crate::utils::gen_pkg_integrity(
            PKGPATH,
            &mut pkg_csize,
            true,
            &mut pkg_sha256sum,
            &mut None,
        ));

        crate::utils::create_db_desc_entry(
            PKGPATH,
            &pkg_entrypath,
            &workingdb_path,
            &pkg_info,
            pkg_csize.clone(),
            pkg_sha256sum,
            None,
        )
        .expect("Failed to create db entry");

        let pkgentry_content =
            fs::read_to_string(format!("{}/{}/desc", &workingdb_path, &pkg_entrypath)).unwrap();
        fs::remove_dir_all(&workingdb_path).expect("Failed to cleanup");

        const K_DB_DESC_TEST_DATA: &str = r#"%FILENAME%
xz-5.4.5-2-x86_64.pkg.tar.zst

%NAME%
xz

%BASE%
xz

%VERSION%
5.4.5-2

%DESC%
Library and command line tools for XZ and LZMA compressed files

%CSIZE%
648678

%ISIZE%
2513790

%SHA256SUM%
6bcf35ecc6869a74926b204f16f01704c60115b956b098d3e59b655d1d36a2aa

%URL%
https://tukaani.org/xz/

%LICENSE%
GPL
LGPL
custom

%ARCH%
x86_64

%BUILDDATE%
1704482661

%PACKAGER%
CachyOS <admin@cachyos.org>

%PROVIDES%
liblzma.so=5-64

%DEPENDS%
sh

"#;

        assert_eq!(pkgentry_content, K_DB_DESC_TEST_DATA);
    }
    #[test]
    fn check_file_presence_in_arc() {
        assert!(crate::utils::is_file_in_archive(PKGPATH, ".PKGINFO"));
        assert!(!crate::utils::is_file_in_archive(PKGPATH, ".PKGIFO"));
        assert!(crate::utils::is_file_in_archive(PKGPATH, "*"));
    }
}
