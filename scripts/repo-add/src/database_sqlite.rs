use crate::utils;
use std::path::Path;

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

pub fn create_db_entry_nf(
    conn: &mut rusqlite::Connection,
    pkgpath: &str,
    pkg_info: &crate::pkginfo::PkgInfo,
    csize: String,
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
    insert_entry_nf(&mut insert_fields, &mut insert_params, "sha256sum", pkg_sha256sum);

    // add PGP sig
    insert_entry_nf(&mut insert_fields, &mut insert_params, "pgpsig", pkg_pgpsig);

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

    if row == 0 {
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
    let sorted_files = utils::get_pkg_files(pkgpath);

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
                Ok((row.get(0).unwrap(), row.get(1).unwrap(), row.get(2).unwrap()))
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
