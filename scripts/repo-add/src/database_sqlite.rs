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
    conn.execute("DELETE FROM packages WHERE id = ?", [package_id]).unwrap() != 0
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

pub fn run_migrations(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    const K_CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    base TEXT,
    desc TEXT,
    groups TEXT,
    url TEXT,
    license TEXT,
    arch TEXT,
    builddate TEXT,
    packager TEXT,
    csize TEXT,
    isize TEXT,
    sha256sum TEXT,
    pgpsig TEXT,
    replaces TEXT,
    depends TEXT,
    optdepends TEXT,
    makedepends TEXT,
    checkdepends TEXT,
    conflicts TEXT,
    provides TEXT,
    files TEXT
);"#;

    conn.execute(K_CREATE_TABLE, [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pkginfo::PkgInfo;
    use std::fs;

    #[derive(Debug, PartialEq)]
    struct DBPackage {
        id: i64,
        name: String,
        version: String,
        filename: String,
        base: Option<String>,
        desc: Option<String>,
        groups: Option<String>,
        url: Option<String>,
        license: Option<String>,
        arch: Option<String>,
        builddate: Option<String>,
        packager: Option<String>,
        c_size: Option<String>,
        i_size: Option<String>,
        sha256sum: Option<String>,
        pgpsig: Option<String>,
        replaces: Option<String>,
        depends: Option<String>,
        optdepends: Option<String>,
        makedepends: Option<String>,
        checkdepends: Option<String>,
        conflicts: Option<String>,
        provides: Option<String>,
        files: Option<String>,
    }

    const K_INSERT_TEST_DATA: &str = r#"
INSERT INTO packages (id, name, version, filename, arch)
VALUES (1, 'xz', '5.4.5-2', 'xz-5.4.5-2-x86_64.pkg.tar.zst', 'x86_64')
"#;

    const PKGPATH: &str = "xz-5.4.5-2-x86_64.pkg.tar.zst";

    #[test]
    fn creating_db_entry() {
        let pkg_info = PkgInfo::from_archive(PKGPATH);

        let mut conn =
            rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        let mut pkg_csize = String::new();
        let mut pkg_sha256sum: Option<String> = None;

        assert!(crate::utils::gen_pkg_integrity(
            PKGPATH,
            &mut pkg_csize,
            true,
            &mut pkg_sha256sum,
            &mut None,
        ));

        crate::database_sqlite::create_db_entry_nf(
            &mut conn,
            PKGPATH,
            &pkg_info,
            pkg_csize.clone(),
            &pkg_sha256sum,
            &None,
        )
        .expect("Failed to create db entry");

        let mut stmt = conn.prepare("SELECT * FROM packages").expect("Failed to prepare statement");
        let mut pkg_iter = stmt
            .query_map([], |row| {
                Ok(DBPackage {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    version: row.get(2)?,
                    filename: row.get(3)?,
                    base: row.get(4)?,
                    desc: row.get(5)?,
                    groups: row.get(6)?,
                    url: row.get(7)?,
                    license: row.get(8)?,
                    arch: row.get(9)?,
                    builddate: row.get(10)?,
                    packager: row.get(11)?,
                    c_size: row.get(12)?,
                    i_size: row.get(13)?,
                    sha256sum: row.get(14)?,
                    pgpsig: row.get(15)?,
                    replaces: row.get(16)?,
                    depends: row.get(17)?,
                    optdepends: row.get(18)?,
                    makedepends: row.get(19)?,
                    checkdepends: row.get(20)?,
                    conflicts: row.get(21)?,
                    provides: row.get(22)?,
                    files: row.get(23)?,
                })
            })
            .expect("Failed to create query iter");

        let expected_pkg = DBPackage {
            id: 1,
            name: "xz".to_owned(),
            version: "5.4.5-2".to_owned(),
            filename: "xz-5.4.5-2-x86_64.pkg.tar.zst".to_owned(),
            base: Some("xz".to_owned()),
            desc: Some(
                "Library and command line tools for XZ and LZMA compressed files".to_owned(),
            ),
            groups: None,
            url: Some("https://tukaani.org/xz/".to_owned()),
            license: Some("GPL,LGPL,custom".to_owned()),
            arch: Some("x86_64".to_owned()),
            builddate: Some("1704482661".to_owned()),
            packager: Some("CachyOS <admin@cachyos.org>".to_owned()),
            c_size: Some(pkg_csize),
            i_size: Some("2513790".to_owned()),
            sha256sum: pkg_sha256sum,
            pgpsig: None,
            replaces: None,
            depends: Some("sh".to_owned()),
            optdepends: None,
            makedepends: None,
            checkdepends: None,
            conflicts: None,
            provides: Some("liblzma.so=5-64".to_owned()),
            files: None,
        };

        assert_eq!(pkg_iter.next().unwrap(), Ok(expected_pkg));
        assert_eq!(pkg_iter.next(), None);
    }

    #[test]
    fn simple_db_entry_lookup() {
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert_eq!(crate::database_sqlite::make_simple_lookup_pkgentry_nf(&conn, "xz"), Some(1));
        assert_eq!(crate::database_sqlite::make_simple_lookup_pkgentry_nf(&conn, "xzz"), None);
        assert_eq!(crate::database_sqlite::make_simple_lookup_pkgentry_nf(&conn, " "), None);
    }

    #[test]
    fn make_pkginfo_lookup_db_entry() {
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert_eq!(
            crate::database_sqlite::make_lookup_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            Some(1)
        );
        assert_eq!(
            crate::database_sqlite::make_lookup_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-3".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            Some(1)
        );
        assert_eq!(
            crate::database_sqlite::make_lookup_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("aarch64".to_owned()),
                ..Default::default()
            }),
            None
        );
        assert_eq!(
            crate::database_sqlite::make_lookup_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xzz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            None
        );
        assert_eq!(
            crate::database_sqlite::make_lookup_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some(" ".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            None
        );
    }

    #[test]
    fn getting_pkg_db_entry() {
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert_eq!(
            crate::database_sqlite::get_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            Some(1)
        );
        assert_eq!(
            crate::database_sqlite::get_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-3".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            None
        );
        assert_eq!(
            crate::database_sqlite::get_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("aarch64".to_owned()),
                ..Default::default()
            }),
            None
        );
        assert_eq!(
            crate::database_sqlite::get_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some("xzz".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            None
        );
        assert_eq!(
            crate::database_sqlite::get_pkgentry_nf(&conn, &PkgInfo {
                pkgname: Some(" ".to_owned()),
                pkgver: Some("5.4.5-2".to_owned()),
                arch: Some("x86_64".to_owned()),
                ..Default::default()
            }),
            None
        );
    }

    #[test]
    fn getting_old_db_entry_vals() {
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert_eq!(
            crate::database_sqlite::get_old_entryval_nf(&conn, 1),
            Some(("xz".to_owned(), "5.4.5-2".to_owned(), PKGPATH.to_owned()))
        );
        assert_eq!(crate::database_sqlite::get_old_entryval_nf(&conn, 2), None);
    }

    #[test]
    fn creating_files_db_entry() {
        let mut conn =
            rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert!(!crate::database_sqlite::create_db_files_entry_nf(&mut conn, PKGPATH, &PkgInfo {
            pkgname: Some("xz".to_owned()),
            pkgver: Some("5.4.5-2".to_owned()),
            arch: Some("aarch64".to_owned()),
            ..Default::default()
        }));
        assert!(!crate::database_sqlite::create_db_files_entry_nf(&mut conn, PKGPATH, &PkgInfo {
            pkgname: Some("xzz".to_owned()),
            pkgver: Some("5.4.5-2".to_owned()),
            arch: Some("x86_64".to_owned()),
            ..Default::default()
        }));
        assert!(!crate::database_sqlite::create_db_files_entry_nf(&mut conn, PKGPATH, &PkgInfo {
            pkgname: Some(" ".to_owned()),
            pkgver: Some("5.4.5-2".to_owned()),
            arch: Some("x86_64".to_owned()),
            ..Default::default()
        }));

        assert!(crate::database_sqlite::create_db_files_entry_nf(&mut conn, PKGPATH, &PkgInfo {
            pkgname: Some("xz".to_owned()),
            pkgver: Some("5.4.5-2".to_owned()),
            arch: Some("x86_64".to_owned()),
            ..Default::default()
        }));

        let mut stmt = conn
            .prepare("SELECT files FROM packages WHERE id = ?1")
            .expect("Failed to prepare statement");
        let mut pkg_files_iter =
            stmt.query_map([1], |row| row.get(0)).expect("Failed to create query iter");

        let expected_pkgfiles = fs::read_to_string("xz-files")
            .unwrap()
            .lines()
            .filter(|x| *x != "%FILES%" && !x.is_empty())
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(pkg_files_iter.next().unwrap(), Ok(expected_pkgfiles.join(",")));
    }

    #[test]
    fn removing_db_entry_by_id() {
        let mut conn =
            rusqlite::Connection::open_in_memory().expect("Failed to make db connection");
        crate::database_sqlite::run_migrations(&conn).expect("Failed to run migrations");

        conn.execute(K_INSERT_TEST_DATA, []).expect("Failed to insert");

        assert!(crate::database_sqlite::remove_from_db_by_id_nf(&mut conn, 1));
        assert!(!crate::database_sqlite::remove_from_db_by_id_nf(&mut conn, 1));
    }
}
