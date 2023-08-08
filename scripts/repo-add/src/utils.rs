use std::fs::File;
use std::io::Write;
use std::path::Path;
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

pub fn create_tempfile(max_tries: Option<u32>) -> Option<(File, String)> {
    let tmp_dir = env::temp_dir();
    let max_tries = max_tries.unwrap_or(1000);

    let mut i: u32 = 0;
    let mut rng = rand::thread_rng();
    loop {
        let res_path = format!("{}/.tempfile-{}", tmp_dir.to_string_lossy(), rng.gen::<u64>());
        if !Path::new(&res_path).exists() {
            if let Ok(file_obj) = File::options().write(true).create_new(true).open(&res_path) {
				return Some((file_obj, res_path))
			}
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

// format a metadata entry
#[inline]
fn format_entry(field_name: &str, value: &Option<String>) -> String {
    if value.is_none() {
        return String::new();
    }
    format!("%{}%\n{}\n\n", field_name, value.as_ref().unwrap())
}

fn format_entry_mul(field_name: &str, values: &[String]) -> String {
    if values.is_empty() {
        return String::new();
    }

    let mut result = String::from(&format!("%{}%\n", field_name));
    for value in values.iter() {
        result.push_str(&format!("{}\n", value));
    }

    result += "\n";
    result
}

#[inline]
fn insert_entry_nf(
    insert_fields: &mut Vec<String>,
    insert_params: &mut Vec<String>,
    field_name: &str,
    value: &Option<String>,
) {
    if value.is_none() {
        return;
    }
    insert_fields.push(field_name.to_owned());
    insert_params.push(value.as_ref().unwrap().clone());
}

#[inline]
fn insert_entry_mul_nf(
    insert_fields: &mut Vec<String>,
    insert_params: &mut Vec<String>,
    field_name: &str,
    values: &[String],
) {
    if values.is_empty() {
        return;
    }
    insert_fields.push(field_name.to_owned());
    insert_params.push(values.join(","));
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
    pkg_md5sum: Option<String>,
    pkg_sha256sum: Option<String>,
    pkg_pgpsig: Option<String>,
) {
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
    desc_content.push_str(&format_entry("MD5SUM", &pkg_md5sum));
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

    let mut desc_entry_file =
        File::create(&format!("{}/{}/desc", &workingdb_path, &pkg_entrypath)).unwrap();
    let _ = desc_entry_file.write_all(desc_content.as_bytes());
}

pub fn gen_pkg_integrity(
    pkgpath: &str,
    pkg_info: &crate::pkginfo::PkgInfo,
    csize: &mut String,
    pkg_md5sum: &mut Option<String>,
    pkg_sha256sum: &mut Option<String>,
    pkg_pgpsig: &mut Option<String>,
) -> bool {
    // compute base64'd PGP signature
    *pkg_pgpsig = None;
    if Path::new(&format!("{}.sig", pkg_info.pkgname.as_ref().unwrap())).exists() {
        let sig_filename = format!("{}.sig", pkg_info.pkgname.as_ref().unwrap());
        if exec(&format!("grep -q 'BEGIN PGP SIGNATURE' \"{}\"", &sig_filename), Some(true)).1 {
            log::error!("Cannot use armored signatures for packages: {}", &sig_filename);
            return false;
        }

        let pgpsigsize = fs::metadata(&sig_filename).unwrap().len();
        if pgpsigsize > 16384 {
            log::error!("Invalid package signature file '{}'.", &sig_filename);
            return false;
        }
        log::info!("Adding package signature...");
        *pkg_pgpsig = Some(exec(&format!("base64 \"{}\" | tr -d '\n'", sig_filename), None).0);
    }

    *csize = format!("{}", fs::metadata(pkgpath).unwrap().len());

    // compute checksums
    log::info!("Computing checksums...");
    *pkg_md5sum = generate_md5sum(pkgpath);
    *pkg_sha256sum = generate_sha256sum(pkgpath);

    true
}

pub fn create_db_entry_nf(
    conn: &mut rusqlite::Connection,
    pkgpath: &str,
    pkg_info: &crate::pkginfo::PkgInfo,
    csize: String,
    pkg_md5sum: &Option<String>,
    pkg_sha256sum: &Option<String>,
    pkg_pgpsig: &Option<String>,
) -> anyhow::Result<()> {
    let mut insert_fields: Vec<String> = vec![];
    let mut insert_params: Vec<String> = vec![];

    // 1. Get package id
    let package_id = make_lookup_pkgentry_nf(conn, pkg_info);

    // 2. Insert available fields into buffer
    insert_entry_nf(&mut insert_fields, &mut insert_params, "name", &pkg_info.pkgname);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "version", &pkg_info.pkgver);
    insert_entry_nf(
        &mut insert_fields,
        &mut insert_params,
        "filename",
        &Some(Path::new(pkgpath).file_name().unwrap().to_string_lossy().to_string()),
    );
    insert_entry_nf(&mut insert_fields, &mut insert_params, "base", &pkg_info.pkgbase);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "desc", &pkg_info.pkgdesc);

    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "groups", &pkg_info.groups);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "csize", &Some(csize));
    insert_entry_nf(&mut insert_fields, &mut insert_params, "isize", &pkg_info.pkg_isize);

    // add checksums
    insert_entry_nf(&mut insert_fields, &mut insert_params, "md5sum", &pkg_md5sum);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "sha256sum", &pkg_sha256sum);

    // add PGP sig
    insert_entry_nf(&mut insert_fields, &mut insert_params, "pgpsig", &pkg_pgpsig);

    insert_entry_nf(&mut insert_fields, &mut insert_params, "url", &pkg_info.url);
    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "license", &pkg_info.licenses);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "arch", &pkg_info.arch);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "builddate", &pkg_info.builddate);
    insert_entry_nf(&mut insert_fields, &mut insert_params, "packager", &pkg_info.packager);
    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "replaces", &pkg_info.replaces);
    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "conflicts", &pkg_info.conflicts);
    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "provides", &pkg_info.provides);

    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "depends", &pkg_info.depends);
    insert_entry_mul_nf(&mut insert_fields, &mut insert_params, "optdepends", &pkg_info.optdepends);
    insert_entry_mul_nf(
        &mut insert_fields,
        &mut insert_params,
        "makedepends",
        &pkg_info.makedepends,
    );
    insert_entry_mul_nf(
        &mut insert_fields,
        &mut insert_params,
        "checkdepends",
        &pkg_info.checkdepends,
    );

    let param_args_q = insert_params.iter().map(|_| "?").collect::<Vec<_>>().join(",");

    // 3. Construct query
    let insert_query = if package_id.is_some() {
        format!(
            "INSERT OR REPLACE INTO packages (id, {}) VALUES ({}, {})",
            insert_fields.join(","),
            package_id.unwrap(),
            param_args_q
        )
    } else {
        format!(
            "INSERT OR REPLACE INTO packages ({}) VALUES ({})",
            insert_fields.join(","),
            param_args_q
        )
    };

    // 4. Insert the package entry into the database
    let mut stmt = conn.prepare(&insert_query)?;
    let row = stmt.execute(rusqlite::params_from_iter(insert_params.clone()))?;

    if row <= 0 {
        anyhow::bail!("ZERO rows inserted!");
    }

    Ok(())
}

pub fn create_db_files_entry_nf(
    conn: &mut rusqlite::Connection,
    pkgpath: &str,
    pkg_info: &crate::pkginfo::PkgInfo,
) -> bool {
    // 1. Get package id
    let package_id = make_lookup_pkgentry_nf(conn, pkg_info);
    if package_id.is_none() {
        log::error!("Failed to get package from db");
        return false;
    }

    // 2. Get files
    let sorted_files = get_pkg_files(pkgpath);

    // 3. Add files for the package entry in the database
    conn.execute("UPDATE packages SET files = ?2 WHERE id = ?1", rusqlite::params![
        package_id,
        sorted_files.join(",")
    ])
    .unwrap();

    true
}

pub fn remove_from_db_by_id_nf(conn: &mut rusqlite::Connection, package_id: i64) -> bool {
    // 1. Delete entry from table
    conn.execute("DELETE FROM packages WHERE id = ?", [package_id]).unwrap();

    true
}

pub fn get_old_entryval_nf(
    conn: &rusqlite::Connection,
    package_id: i64,
) -> Option<(String, String, String)> {
    let select_query = "SELECT name, version, filename FROM packages WHERE id = ?";
    if let Ok(mut stmt) = conn.prepare_cached(select_query) {
        return stmt
            .query_row([package_id], |row| {
                return Ok((row.get(0).unwrap(), row.get(1).unwrap(), row.get(2).unwrap()));
            })
            .ok();
    }

    None
}

pub fn get_pkgentry_nf(
    conn: &rusqlite::Connection,
    pkg_info: &crate::pkginfo::PkgInfo,
) -> Option<i64> {
    let select_query = "SELECT id FROM packages WHERE name = ? AND version = ? AND arch = ?";
    if let Ok(mut stmt) = conn.prepare_cached(select_query) {
        return stmt
            .query_row(
                [
                    pkg_info.pkgname.as_ref().unwrap(),
                    pkg_info.pkgver.as_ref().unwrap(),
                    pkg_info.arch.as_ref().unwrap(),
                ],
                |row| row.get(0),
            )
            .ok();
    }

    None
}

pub fn make_lookup_pkgentry_nf(
    conn: &rusqlite::Connection,
    pkg_info: &crate::pkginfo::PkgInfo,
) -> Option<i64> {
    let select_query = "SELECT id FROM packages WHERE name = ? AND arch = ?";
    if let Ok(mut stmt) = conn.prepare_cached(select_query) {
        if let Ok(pkg_id) = stmt.query_row(
            [pkg_info.pkgname.as_ref().unwrap(), pkg_info.arch.as_ref().unwrap()],
            |row| row.get(0),
        ) {
            return Some(pkg_id);
        }
    }

    None
}

pub fn make_simple_lookup_pkgentry_nf(conn: &rusqlite::Connection, pkgname: &str) -> Option<i64> {
    let select_query = "SELECT id FROM packages WHERE name = ?";
    if let Ok(mut stmt) = conn.prepare_cached(select_query) {
        if let Ok(pkg_id) = stmt.query_row([pkgname], |row| row.get(0)) {
            return Some(pkg_id);
        }
    }

    None
}

pub fn make_db_connections(
    tmp_work_dir: &str,
) -> rusqlite::Result<(Option<rusqlite::Connection>, Option<rusqlite::Connection>)> {
    Ok((
        Some(rusqlite::Connection::open(format!("{}/db/pacman.db", tmp_work_dir))?),
        Some(rusqlite::Connection::open(format!("{}/files/pacman.db", tmp_work_dir))?),
    ))
}
