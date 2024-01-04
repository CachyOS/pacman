mod config;
mod parse_args;
mod pkginfo;
mod utils;

use config::VERSION;
use fern::colors::{Color, ColoredLevelConfig};
use lazy_static::lazy_static;
use path_absolutize::*;
use rand::Rng;
use rayon::prelude::*;
use signal_hook::consts::{SIGABRT, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fs, str};

macro_rules! handle_signal {
    ($is_signaled:expr) => {
        if $is_signaled.load(Ordering::Relaxed) {
            return;
        }
    };
}

macro_rules! handle_signal_ext {
    // If a signal was received, wait for the signal handler thread to finish and clean up resources
    // before exiting
    ($is_signaled:expr,$sig_handle:expr) => {
        if $is_signaled.load(Ordering::SeqCst) {
            $sig_handle.join().unwrap();
            clean_up();
            return;
        }
    };
}

lazy_static! {
    static ref G_TMPWORKINGDIR: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
}

// print usage instructions
fn print_usage(cmd_line: &str) {
    let cmd_line = utils::get_current_cmdname(cmd_line);
    println!("{} (pacman) {}\n", cmd_line, VERSION);
    if cmd_line == "repo-add" {
        println!("Usage: repo-add [options] <path-to-db> <package> ...\n");
        println!("repo-add will update a package database by reading a package file.");
        println!("Multiple packages to add can be specified on the command line.\n");
        println!("Options:");
        println!("  -n, --new         only add packages that are not already in the database");
        println!("  -R, --remove      remove old package file from disk after updating database");
        println!(
            "  -p, --prevent-downgrade  do not add package to database if a newer version is \
             already present"
        );
    } else if cmd_line == "repo-remove" {
        println!("Usage: repo-remove [options] <path-to-db> <packagename> ...\n");
        println!("repo-remove will update a package database by removing the package name");
        println!("specified on the command line from the given repo database. Multiple");
        println!("packages to remove can be specified on the command line.\n");
        println!("Options:");
    } else {
        println!("Please move along, there is nothing to see here.");
        return;
    }
    println!("  --use-new-db-format      use new DB format");
    println!("  --nocolor         turn off color in output");
    println!("  -q, --quiet       minimize output");
    println!("  -s, --sign        sign database with GnuPG after update");
    println!("  -k, --key <key>   use the specified key to sign the database");
    println!("  -v, --verify      verify database's signature before update");
    println!("\nSee {}(8) for more details and descriptions of the available options.\n", cmd_line);

    if cmd_line == "repo-add" {
        println!("Example:  repo-add /path/to/repo.db.tar.gz pacman-3.0.0-1-i686.pkg.tar.gz");
    } else if cmd_line == "repo-remove" {
        println!("Example:  repo-remove /path/to/repo.db.tar.gz kernel26");
    }
}

// print version
fn print_version(cmd_line: &str) {
    let cmd_line = utils::get_current_cmdname(cmd_line);
    println!("{} (pacman) {}\n", cmd_line, VERSION);
    println!("Copyright (c) 2023 CachyOS Team.\n");
    println!("This is free software; see the source for copying conditions.");
    println!("There is NO WARRANTY, to the extent permitted by law.");
}

// print elephant
fn print_elephant() {
    let mut rng = rand::thread_rng();
    let random_num = rng.gen::<u8>() % 2;
    #[rustfmt::skip]
    let encoded_elephant = if random_num == 0 {
        "H4sIAL3qBE4CAyWLwQ3AMAgD/0xh5UPzYiFUMgjq7LUJsk7yIQNAQTAikFUDnqkrOQFOUm0Wd9pHCi13ONjBpVdqcWx+EdXVX4vXvGv5cgztB9+fJxZ7AAAA\n"
    } else {
        "H4sIAJVWBU4CA21RMQ7DIBDbeYWrDgQJ7rZ+IA/IB05l69alcx5fc0ASVXUk4jOO\n7yAAUWtorygwJ4hlMii0YkJKKRKGvsMsiykl1SalvrMD1gUXyXRkGZPx5OPft81K\ntNAiAjyGjYO47h1JjizPkJrCWbK/4C+uLkT7bzpGc7CT9bmOzNSW5WLSO5vexjmH\nZL9JFFZeAa0a2+lKjL2anpYfV+0Zx9LJ+/MC8nRayuDlSNy2rfAPibOzsiWHL0jLSsjFAQAA\n"
    };

    print!(
        "{}",
        utils::exec(
            &format!("printf \"%s\" '{encoded_elephant}' | base64 -d | gzip -d"),
            Some(true)
        )
        .0
    );
}

fn find_pkgentry(pkgname: &str) -> Option<String> {
    let workingdb_path = format!("{}/db", *G_TMPWORKINGDIR.lock().unwrap());
    for dir_entry in fs::read_dir(workingdb_path).unwrap() {
        let dir_entry_path = dir_entry.as_ref().unwrap().path();
        let entry_pkgname = utils::get_name_of_pkg(dir_entry_path.to_str().unwrap(), true);
        if entry_pkgname == pkgname {
            return Some(dir_entry_path.to_str().unwrap().to_owned());
        }
    }
    None
}

fn find_pkgentry_nf(
    conn: &rusqlite::Connection,
    pkg_info: &pkginfo::PkgInfo,
) -> Option<(String, String, String)> {
    if let Some(package_id) = utils::make_lookup_pkgentry_nf(conn, pkg_info) {
        return utils::get_old_entryval_nf(conn, package_id);
    }

    None
}

// remove existing entries from the DB
fn db_remove_entry(pkgname: &str) -> bool {
    let mut is_found = false;

    while let Some(pkgentry) = find_pkgentry(pkgname) {
        is_found = true;

        log::info!(
            "Removing existing entry '{}'...",
            Path::new(&pkgentry).file_name().unwrap().to_str().unwrap()
        );
        let _ = fs::remove_dir_all(&pkgentry);

        // remove entries in "files" database
        let (filesentry, _) = utils::exec(
            &format!("echo \"{}\" | sed 's/\\(.*\\)\\/db\\//\\1\\/files\\//'", &pkgentry),
            None,
        );
        let _ = fs::remove_dir_all(filesentry);
    }
    is_found
}

fn check_gpg(argstruct: &parse_args::ArgStruct) -> bool {
    if !Path::new("/sbin/gpg").exists() {
        log::error!("Cannot find the gpg binary! Is GnuPG installed?");
        return false;
    }
    if !argstruct.verify {
        let (_, ret_status) = utils::exec(
            &format!(
                "gpg --list-secret-key {} &>/dev/null",
                argstruct.gpgkey.as_ref().unwrap_or(&String::new())
            ),
            Some(true),
        );
        if !ret_status {
            if argstruct.gpgkey.is_some() && !argstruct.gpgkey.as_ref().unwrap().is_empty() {
                log::error!(
                    "The key {} does not exist in your keyring.",
                    argstruct.gpgkey.as_ref().unwrap()
                );
            } else if !argstruct.key {
                log::error!("There is no key in your keyring.");
            }
            return false;
        }
    }
    true
}

// sign the package database once repackaged
fn create_signature(dbfile: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    if !argstruct.sign {
        return true;
    }

    let mut db_name = String::from(dbfile);
    if let Some(strpos) = db_name.find(".tmp.") {
        db_name = String::from(utils::string_substr(&db_name, strpos + 5, usize::MAX).unwrap());
    }
    log::info!("Signing database '{}'...", db_name);

    let mut signwithkey = String::new();
    if argstruct.gpgkey.is_some() && !argstruct.gpgkey.as_ref().unwrap().is_empty() {
        signwithkey = format!("-u \"{}\"", argstruct.gpgkey.as_ref().unwrap());
    }

    let (_, ret_code) = utils::exec(
        &format!(
            "gpg --detach-sign --use-agent --no-armor {} \"{}\" &>/dev/null",
            signwithkey, dbfile
        ),
        Some(true),
    );
    if ret_code {
        log::info!("Created signature file '{}.sig'", db_name);
        return true;
    }
    log::error!("Failed to sign package database file '{}'", db_name);
    false
}

// verify the existing package database signature
fn verify_signature(dbfile: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    if !argstruct.verify {
        return true;
    }

    log::info!("Verifying database signature...");
    if !Path::new(&format!("{}.sig", dbfile)).exists() {
        log::warn!("No existing signature found, skipping verification.");
        return true;
    }

    let (_, ret_code) = utils::exec(&format!("gpg --verify \"{}.sig\"", dbfile), Some(true));
    if ret_code {
        log::info!("Database signature file verified.");
        return true;
    }
    log::error!("Database signature was NOT valid!");
    false
}

fn verify_repo_extension(dbpath: &str) -> bool {
    if dbpath.contains(".db.tar") {
        let strpos = dbpath.find(".db").unwrap();
        let extension = utils::string_substr(dbpath, strpos + 4, usize::MAX).unwrap();
        if !utils::get_compression_command(extension).is_empty() {
            return true;
        }
    }

    log::error!("'{}' does not have a valid database archive extension.", dbpath);
    false
}

// write an entry to the pacman database
fn db_write_entry(pkgpath: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    // read info from the zipped package
    let pkginfo = pkginfo::PkgInfo::from_archive(pkgpath);

    // ensure 'pkgname' and 'pkgver' variables were found
    if pkginfo.pkgname.is_none() || pkginfo.pkgver.is_none() {
        log::error!("Invalid package file '{}'.", pkgpath);
        return false;
    }

    let mut oldfilename: Option<String> = None;
    let mut oldfile: Option<String> = None;

    let workingdb_path = format!("{}/db", *G_TMPWORKINGDIR.lock().unwrap());
    let pkg_entrypath =
        format!("{}-{}", pkginfo.pkgname.as_ref().unwrap(), pkginfo.pkgver.as_ref().unwrap());
    if Path::new(&format!("{}/{}", &workingdb_path, &pkg_entrypath)).exists() {
        log::warn!("An entry for '{}' already existed", &pkg_entrypath);
        if argstruct.only_add_new {
            return true;
        }
    } else if let Some(pkgentry) = find_pkgentry(pkginfo.pkgname.as_ref().unwrap()) {
        let version = utils::exec(
            &format!("sed -n '/^%VERSION%$/ {}' \"{}/desc\"", "{n;p;q}", pkgentry),
            None,
        )
        .0;
        let vercmp = utils::exec(
            &format!("vercmp \"{}\" \"{}\"", version, pkginfo.pkgver.as_ref().unwrap()),
            None,
        )
        .0;
        if vercmp.parse::<i32>().unwrap() > 0 {
            log::warn!(
                "A newer version for '{}' is already present in database",
                pkginfo.pkgname.as_ref().unwrap()
            );
            if argstruct.prevent_downgrade {
                return true;
            }
        }
        if argstruct.rm_existing {
            oldfilename = Some(
                utils::exec(
                    &format!("sed -n '/^%FILENAME%$/ {}' \"{}/desc\"", "{n;p;q;}", pkgentry),
                    None,
                )
                .0,
            );
            oldfile = oldfilename.clone();

            let parent_path = Path::new(pkgpath).parent().unwrap().to_string_lossy();
            if !parent_path.is_empty() {
                oldfile = Some(format!("{}/{}", parent_path, oldfilename.as_ref().unwrap()));
            }
        }
    }

    // generate package integrity
    let mut csize = String::new();
    let mut pkg_md5sum: Option<String> = None;
    let mut pkg_sha256sum: Option<String> = None;
    let mut pkg_pgpsig: Option<String> = None;

    if !utils::gen_pkg_integrity(
        pkgpath,
        &pkginfo,
        &mut csize,
        &mut pkg_md5sum,
        &mut pkg_sha256sum,
        &mut pkg_pgpsig,
    ) {
        return false;
    }

    // remove an existing entry if it exists, ignore failures
    db_remove_entry(pkginfo.pkgname.as_ref().unwrap());

    // create package directory
    let _ = fs::create_dir(format!("{}/{}", &workingdb_path, &pkg_entrypath));

    // create desc entry
    log::info!("Creating 'desc' db entry...");
    {
        utils::create_db_desc_entry(
            pkgpath,
            &pkg_entrypath,
            &workingdb_path,
            &pkginfo,
            csize,
            pkg_md5sum,
            pkg_sha256sum,
            pkg_pgpsig,
        );
    }

    // copy updated package entry into "files" database
    let mut options = fs_extra::dir::CopyOptions::new();
    options.overwrite = true;
    options.copy_inside = true;
    let _ = fs_extra::dir::copy(
        format!("{}/db/{}", *G_TMPWORKINGDIR.lock().unwrap(), &pkg_entrypath),
        format!("{}/files/{}", *G_TMPWORKINGDIR.lock().unwrap(), &pkg_entrypath),
        &options,
    )
    .unwrap();

    // create files file
    log::info!("Creating 'files' db entry...");
    let files_path = format!("{}/files/{}/files", *G_TMPWORKINGDIR.lock().unwrap(), &pkg_entrypath);

    let sorted_files = utils::get_pkg_files(pkgpath);
    let _ = utils::write_to_file(&files_path, &format!("%FILES%\n{}\n", sorted_files.join("\n")));

    if argstruct.rm_existing && oldfile.is_some() {
        log::info!("Removing old package file '{}'", oldfilename.as_ref().unwrap());
        let _ = fs::remove_file(oldfile.as_ref().unwrap());
        let _ = fs::remove_file(format!("{}.sig", oldfile.as_ref().unwrap()));
    }

    true
}

fn db_write_entry_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgpath: &str,
    argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    // read info from the zipped package
    let pkginfo = pkginfo::PkgInfo::from_archive(pkgpath);

    // ensure 'pkgname' and 'pkgver' variables were found
    if pkginfo.pkgname.is_none() || pkginfo.pkgver.is_none() {
        log::error!("Invalid package file '{}'.", pkgpath);
        return false;
    }

    let mut oldfilename: Option<String> = None;
    let mut oldfile: Option<String> = None;

    // let workingdb_path = G_TMPWORKINGDIR.lock().unwrap();
    {
        let conn_lock = connections.lock().unwrap();
        if utils::get_pkgentry_nf(conn_lock.0, &pkginfo).is_some() {
            log::warn!(
                "An entry for '{}-{}' already existed",
                pkginfo.pkgname.as_ref().unwrap(),
                pkginfo.pkgver.as_ref().unwrap()
            );
            if argstruct.only_add_new {
                return true;
            }
        } else if let Some((_, pkgver, pkg_filename)) = find_pkgentry_nf(conn_lock.0, &pkginfo) {
            let vercmp = utils::exec(
                &format!("vercmp \"{}\" \"{}\"", pkgver, pkginfo.pkgver.as_ref().unwrap()),
                None,
            )
            .0;
            if vercmp.parse::<i32>().unwrap() > 0 {
                log::warn!(
                    "A newer version for '{}' is already present in database",
                    pkginfo.pkgname.as_ref().unwrap()
                );
                if argstruct.prevent_downgrade {
                    return true;
                }
            }
            if argstruct.rm_existing {
                oldfilename = Some(pkg_filename);
                oldfile = oldfilename.clone();

                let parent_path = Path::new(pkgpath).parent().unwrap().to_string_lossy();
                if !parent_path.is_empty() {
                    oldfile = Some(format!("{}/{}", parent_path, oldfilename.as_ref().unwrap()));
                }
            }
        }
    }

    // generate package integrity
    let mut csize = String::new();
    let mut pkg_md5sum: Option<String> = None;
    let mut pkg_sha256sum: Option<String> = None;
    let mut pkg_pgpsig: Option<String> = None;

    if !utils::gen_pkg_integrity(
        pkgpath,
        &pkginfo,
        &mut csize,
        &mut pkg_md5sum,
        &mut pkg_sha256sum,
        &mut pkg_pgpsig,
    ) {
        return false;
    }

    // Insert the package entry into the database
    log::info!("Inserting pkg into db...");
    {
        let mut connection_lock = connections.lock().unwrap();
        utils::create_db_entry_nf(
            connection_lock.0,
            pkgpath,
            &pkginfo,
            csize.clone(),
            &pkg_md5sum,
            &pkg_sha256sum,
            &pkg_pgpsig,
        )
        .expect("Failed to insert");

        utils::create_db_entry_nf(
            connection_lock.1,
            pkgpath,
            &pkginfo,
            csize,
            &pkg_md5sum,
            &pkg_sha256sum,
            &pkg_pgpsig,
        )
        .expect("Failed to insert");
    }

    // Insert files info
    utils::create_db_files_entry_nf(connections.lock().unwrap().1, pkgpath, &pkginfo);

    if argstruct.rm_existing && oldfile.is_some() {
        log::info!("Removing old package file '{}'", oldfilename.as_ref().unwrap());
        let _ = fs::remove_file(oldfile.as_ref().unwrap());
        let _ = fs::remove_file(format!("{}.sig", oldfile.as_ref().unwrap()));
    }

    true
}

fn prepare_repo_db(cmd_line: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    if argstruct.use_new_db_format {
        if let Ok(status) = prepare_repo_db_nf(cmd_line, argstruct) {
            if !status {
                return false;
            }
        }
        if let Ok(status) = create_needed_repo_db_nf(cmd_line) {
            if !status {
                return false;
            }
        }

        return true;
    }

    // ensure the path to the DB exists; LOCKFILE is always an absolute path
    let repodir = Path::new(argstruct.lockfile.as_ref().unwrap()).parent();
    if !repodir.as_ref().unwrap().exists() {
        log::error!("{} does not exist.", repodir.as_ref().unwrap().to_string_lossy());
        return false;
    }
    let repos = ["db", "files"];
    for repo in repos {
        let dbfile = format!(
            "{}/{}.{}.{}",
            repodir.as_ref().unwrap().to_string_lossy(),
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );

        if Path::new(&dbfile).exists() {
            // there are two situations we can have here:
            // a DB with some entries, or a DB with no contents at all.
            if !utils::exec(
                &format!("bsdtar -tqf \"{}\" '*/desc' >/dev/null 2>&1", &dbfile),
                Some(true),
            )
            .1
            {
                // check empty case
                if !utils::exec(&format!("bsdtar -tqf \"{}\" '*' 2>/dev/null", &dbfile), None)
                    .0
                    .is_empty()
                {
                    log::error!("Repository file '{}' is not a proper pacman database.", &dbfile);
                    return false;
                }
            }
            if !verify_signature(&dbfile, argstruct) {
                return false;
            }
            log::info!(
                "Extracting {} to a temporary location...",
                Path::new(&dbfile).file_name().unwrap().to_str().unwrap()
            );
            utils::exec(
                &format!(
                    "bsdtar -xf \"{}\" -C \"{}/{}\"",
                    dbfile,
                    *G_TMPWORKINGDIR.lock().unwrap(),
                    repo
                ),
                None,
            );
        } else {
            // only a missing "db" database is currently an error
            if cmd_line.ends_with("repo-remove") && repo == "db" {
                log::error!("Repository file '{}' was not found.", dbfile);
                return false;
            } else if cmd_line.ends_with("repo-add") {
                // check if the file can be created (write permission, directory existence, etc)
                if !utils::exec(&format!("touch \"{}\" &>/dev/null", &dbfile), Some(true)).1 {
                    log::error!("Repository file '{}' could not be created.", &dbfile);
                    return false;
                }
                let _ = fs::remove_file(dbfile);
            }
        }
    }
    true
}

fn prepare_repo_db_nf(
    cmd_line: &str,
    argstruct: &Arc<parse_args::ArgStruct>,
) -> anyhow::Result<bool> {
    // ensure the path to the DB exists; LOCKFILE is always an absolute path
    let repodir = Path::new(argstruct.lockfile.as_ref().unwrap()).parent();
    if !repodir.as_ref().unwrap().exists() {
        log::error!("{} does not exist.", repodir.as_ref().unwrap().to_string_lossy());
        return Ok(false);
    }
    let repos = ["db", "files"];
    for repo in repos {
        let dbfile = format!(
            "{}/{}.{}.{}",
            repodir.as_ref().unwrap().to_string_lossy(),
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );

        if Path::new(&dbfile).exists() {
            // there are two situations we can have here:
            // a DB with some entries, or a DB with no contents at all.
            if !utils::exec(
                &format!("bsdtar -tqf \"{}\" 'pacman.db' >/dev/null 2>&1", &dbfile),
                Some(true),
            )
            .1
            {
                // check empty case
                if !utils::exec(&format!("bsdtar -tqf \"{}\" '*' 2>/dev/null", &dbfile), None)
                    .0
                    .is_empty()
                {
                    log::error!("Repository file '{}' is not a proper pacman database.", &dbfile);
                    return Ok(false);
                }
            }
            if !verify_signature(&dbfile, argstruct) {
                return Ok(false);
            }
            log::info!(
                "Extracting {} to a temporary location...",
                Path::new(&dbfile).file_name().unwrap().to_str().unwrap()
            );
            utils::exec(
                &format!(
                    "bsdtar -xf \"{}\" -C \"{}/{}\"",
                    dbfile,
                    *G_TMPWORKINGDIR.lock().unwrap(),
                    repo
                ),
                None,
            );

            // Check the actual pacman db
            let conn = rusqlite::Connection::open_with_flags(
                format!("{}/{}", *G_TMPWORKINGDIR.lock().unwrap(), repo),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;

            // Check if the database has the proper format
            if conn
                .execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packages'", [
                ])
                .is_err()
            {
                log::error!("Repository file '{}' is not a proper pacman database.", &dbfile);
                return Ok(false);
            }

            // Check if the database is not empty
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM packages")?;
            let count: i64 = stmt.query_row([], |row| row.get(0))?;
            if count <= 0 {
                log::error!("Repository file '{}' is not a proper pacman database.", &dbfile);
                return Ok(false);
            }
        } else {
            // only a missing "db" database is currently an error
            if cmd_line.ends_with("repo-remove") && repo == "db" {
                log::error!("Repository file '{}' was not found.", dbfile);
                return Ok(false);
            } else if cmd_line.ends_with("repo-add") {
                // check if the file can be created (write permission, directory existence, etc)
                if !utils::exec(&format!("touch \"{}\" &>/dev/null", &dbfile), Some(true)).1 {
                    log::error!("Repository file '{}' could not be created.", &dbfile);
                    return Ok(false);
                }
                let _ = fs::remove_file(dbfile);
            }
        }
    }
    Ok(true)
}

fn create_needed_repo_db_nf(cmd_line: &str) -> anyhow::Result<bool> {
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
    md5sum TEXT,
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
)"#;

    let repos = ["db", "files"];
    for repo in repos {
        let dbfile_path = format!("{}/{}/pacman.db", *G_TMPWORKINGDIR.lock().unwrap(), repo);

        if cmd_line.ends_with("repo-add") {
            let conn = rusqlite::Connection::open(dbfile_path)?;
            // Create the packages table if it doesn't exist
            conn.execute(K_CREATE_TABLE, []).unwrap();
        }
    }
    Ok(true)
}

fn rotate_db(argstruct: &Arc<parse_args::ArgStruct>, is_signaled: &Arc<AtomicBool>) {
    let saved_dir = env::current_dir().unwrap_or("".into());
    {
        let dirname = Path::new(argstruct.lockfile.as_ref().unwrap()).parent();
        let _ = env::set_current_dir(dirname.unwrap());
    }

    let repos = ["db", "files"];
    repos.into_par_iter().for_each(|repo| {
        handle_signal!(is_signaled);
        let dirname = Path::new(argstruct.lockfile.as_ref().unwrap()).parent();
        let filename = format!(
            "{}.{}.{}",
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );
        let tempname =
            format!("{}/.tmp.{}", dirname.as_ref().unwrap().to_string_lossy(), &filename);
        let sig_filename = format!("{}.sig", &filename);

        // hardlink or move the previous version of the database and signature to .old
        // extension as a backup measure
        if dirname.as_ref().unwrap().exists() {
            let old_filename = format!("{}.old", &filename);
            if !utils::exec(
                &format!("ln -f \"{}\" \"{}\" 2>/dev/null", &filename, &old_filename),
                Some(true),
            )
            .1
            {
                let _ = fs::rename(&filename, &old_filename);
            }

            let old_sig_filename = format!("{}.sig", &old_filename);
            if Path::new(&sig_filename).exists() {
                if !utils::exec(
                    &format!("ln -f \"{}\" \"{}\" 2>/dev/null", &sig_filename, &old_sig_filename),
                    Some(true),
                )
                .1
                {
                    let _ = fs::rename(&sig_filename, &old_sig_filename);
                }
            } else {
                let _ = fs::remove_file(&old_sig_filename);
            }
        }

        // rotate the newly-created database and signature into place
        let _ = fs::rename(&tempname, &filename);
        let sig_tempname = format!("{}.sig", &tempname);
        if Path::new(&sig_tempname).exists() {
            let _ = fs::rename(&sig_tempname, &sig_filename);
        }

        let dblink = format!("{}.{}", argstruct.repo_db_prefix.as_ref().unwrap(), repo);
        let sig_dblink = format!("{}.sig", &dblink);
        let _ = fs::remove_file(&dblink);
        let _ = fs::remove_file(&sig_dblink);

        if !utils::exec(&format!("ln -sf \"{}\" \"{}\" 2>/dev/null", filename, dblink), Some(true)).1 && !utils::exec(&format!("ln -f \"{}\" \"{}\" 2>/dev/null", filename, dblink), Some(true))
                .1 {
            let _ = fs::copy(&filename, &dblink);
        }

        if Path::new(&sig_filename).exists() && !utils::exec(
                &format!("ln -sf \"{}\" \"{}\" 2>/dev/null", sig_filename, sig_dblink),
                Some(true),
            )
            .1 && !utils::exec(
                    &format!("ln -f \"{}\" \"{}\" 2>/dev/null", sig_filename, sig_dblink),
                    Some(true),
                )
                .1 {
            let _ = fs::copy(&sig_filename, &sig_dblink);
        }
    });
    let _ = env::set_current_dir(saved_dir);
}

fn create_db(argstruct: &Arc<parse_args::ArgStruct>, is_signaled: &Arc<AtomicBool>) -> bool {
    let is_fail = AtomicBool::new(false);

    let repos = ["db", "files"];
    repos.into_par_iter().for_each(|repo| {
        handle_signal!(is_signaled);
        // LOCKFILE is already guaranteed to be absolute so this is safe
        let dirname = Path::new(argstruct.lockfile.as_ref().unwrap()).parent();
        let filename = format!(
            "{}.{}.{}",
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );
        // this ensures we create it on the same filesystem, making moves atomic
        let tempname =
            format!("{}/.tmp.{}", dirname.as_ref().unwrap().to_string_lossy(), &filename);

        let workingdb_path = format!("{}/{}", *G_TMPWORKINGDIR.lock().unwrap(), repo);
        let files = fs::read_dir(&workingdb_path)
            .unwrap()
            .map(|res| {
                res.map(|e| String::from(e.path().file_name().unwrap().to_str().unwrap())).unwrap()
            })
            .collect::<Vec<String>>()
            .join("\n");

		let mut tmpfile_path: Option<String> = None;
		let working_tar_arg = if files.is_empty() {
            // we have no packages remaining? zip up some emptyness
            log::warn!("No packages remain, creating empty database.");
            "-T /dev/null".to_owned()
        } else {
			use std::io::Write;
			let (mut tmpfile, filepath) = utils::create_tempfile(None).expect("Failed to create tmpfile");
			tmpfile.write_all(files.as_bytes()).unwrap();
			tmpfile_path = Some(filepath);
			format!("$(cat {})", &tmpfile_path.as_ref().unwrap())
		};

        let compress_cmd =
            utils::get_compression_command(argstruct.repo_db_suffix.as_ref().unwrap());
        utils::exec(
            &format!(
                "cd \"{}\"; bsdtar -cf - {} | {} > \"{}\"",
                &workingdb_path, working_tar_arg, compress_cmd, tempname
            ),
            None,
        );

		if let Some(tmpfile_path) = tmpfile_path {
			let _ = fs::remove_file(tmpfile_path);
		}

        if !create_signature(&tempname, argstruct) {
            is_fail.store(true, Ordering::Relaxed);
        }
    });

    !is_fail.load(Ordering::Acquire)
}

fn add_pkg_to_db(pkgfile: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    if !Path::new(pkgfile).exists() {
        log::error!("File '{}' not found.", pkgfile);
        return false;
    }

    if !utils::exec(&format!("bsdtar -tqf \"{}\" .PKGINFO >/dev/null 2>&1", pkgfile), Some(true)).1
    {
        log::error!("'{}' is not a package file, skipping", pkgfile);
        return false;
    }

    log::info!("Adding package '{}'", pkgfile);
    db_write_entry(pkgfile, argstruct)
}

fn add_pkg_to_db_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgfile: &str,
    argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    if !Path::new(pkgfile).exists() {
        log::error!("File '{}' not found.", pkgfile);
        return false;
    }

    if !utils::exec(&format!("bsdtar -tqf \"{}\" .PKGINFO >/dev/null 2>&1", pkgfile), Some(true)).1
    {
        log::error!("'{}' is not a package file, skipping", pkgfile);
        return false;
    }

    log::info!("Adding package '{}'", pkgfile);
    db_write_entry_nf(connections, pkgfile, argstruct)
}

fn remove_pkg_from_db(pkgname: &str, _argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    log::info!("Searching for package '{}'...", pkgname);
    db_remove_entry(pkgname)
}

fn remove_pkg_from_db_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgname: &str,
    _argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    log::info!("Searching for package '{}'...", pkgname);
    let remove_one_pkg = |conn: &mut rusqlite::Connection, needle| {
        if let Some(package_id) = utils::make_simple_lookup_pkgentry_nf(conn, needle) {
            utils::remove_from_db_by_id_nf(conn, package_id);
            return true;
        }

        false
    };

    let mut is_found = false;
    log::info!("Removing existing entry '{}'...", pkgname);
    {
        let mut connection_lock = connections.lock().unwrap();
        while remove_one_pkg(connection_lock.0, pkgname) {
            is_found = true;
        }
    }
    {
        let mut connection_lock = connections.lock().unwrap();
        while remove_one_pkg(connection_lock.1, pkgname) {
            is_found = true;
        }
    }

    is_found
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let argument = args[1].as_str();
        if argument == "--help" || argument == "-h" {
            print_usage(args[0].as_str());
            return;
        } else if argument == "--version" || argument == "-V" {
            print_version(args[0].as_str());
            return;
        }
    }

    // figure out what program we are
    let cmd_line = utils::get_current_cmdname(args[0].as_str());
    if cmd_line == "repo-elephant" {
        print_elephant();
        return;
    }

    if cmd_line != "repo-add" && cmd_line != "repo-remove" {
        log::error!("Invalid command name '{}' specified.", cmd_line);
        std::process::exit(1);
    }

    {
        let tmpval = utils::create_temporary_directory(None);
        if tmpval.is_none() {
            log::error!("Cannot create temp directory for database building.");
            std::process::exit(1);
        }
        *G_TMPWORKINGDIR.lock().unwrap() = tmpval.unwrap();
    }
    for repo in ["db", "files"] {
        let repo_path = format!("{}/{}", *G_TMPWORKINGDIR.lock().unwrap(), repo);
        let _ = fs::create_dir(repo_path);
    }

    // Create a shared atomic boolean to track if a signal was received
    let is_signaled = Arc::new(AtomicBool::new(false));
    let signal_clone = Arc::clone(&is_signaled);

    // Set up signal handlers
    let signals = Signals::new([SIGINT, SIGTERM, SIGABRT]);
    if signals.is_err() {
        log::error!("can't set signal handler: {:?}", signals);
        clean_up();
        std::process::exit(1);
    }
    let mut signals = signals.unwrap();
    let sig_handle = std::thread::spawn(move || {
        for signal in signals.forever() {
            // Set the atomic boolean to true if a signal is received
            signal_clone.store(true, Ordering::SeqCst);

            if signal == SIGTERM {
                exit_term_callback("SIGTERM signal caught. Exiting...");
                return;
            } else if signal == SIGINT {
                exit_term_callback("Aborted by user! Exiting...");
                return;
            }

            clean_up();
            std::process::exit(0);
        }
    });

    let (pos_args, mut arg_struct) = parse_args::parse_args(&args);
    set_up_logging(arg_struct.use_colors);
    if pos_args.is_none() || pos_args.unwrap().is_empty() {
        print_usage(args[0].as_str());
        clean_up();
        return;
    }

    if arg_struct.quiet {
        log::set_max_level(log::LevelFilter::Off);
    }

    arg_struct.repo_db_file = Some(pos_args.unwrap()[0].to_owned());
    arg_struct.lockfile = Some(format!(
        "{}.lck",
        Path::new(&pos_args.unwrap()[0]).absolutize().unwrap().to_str().unwrap()
    ));

    // Verify DB extension
    if !verify_repo_extension(arg_struct.repo_db_file.as_ref().unwrap().as_str()) {
        clean_up();
        std::process::exit(1);
    }

    arg_struct.repo_db_prefix =
        Some(Path::new(&pos_args.unwrap()[0]).file_stem().unwrap().to_str().unwrap().to_owned());
    if let Some(strpos) = arg_struct.repo_db_prefix.as_ref().unwrap().find(".db") {
        arg_struct.repo_db_prefix = Some(String::from(
            utils::string_substr(&arg_struct.repo_db_prefix.unwrap(), 0, strpos).unwrap(),
        ));
    }
    arg_struct.repo_db_suffix = Some(pos_args.unwrap()[0].to_owned());
    if let Some(strpos) = arg_struct.repo_db_suffix.as_ref().unwrap().find(".db") {
        arg_struct.repo_db_suffix = Some(String::from(
            utils::string_substr(&arg_struct.repo_db_suffix.unwrap(), strpos + 4, usize::MAX)
                .unwrap(),
        ));
    }

    // Check installed GPG
    if (arg_struct.sign || arg_struct.verify) && !check_gpg(&arg_struct) {
        clean_up();
        std::process::exit(1);
    }

    // Prepare DB
    let arg_struct = Arc::new(arg_struct);
    if !prepare_repo_db(args[0].as_str(), &arg_struct) {
        clean_up();
        std::process::exit(1);
    }

    let pos_args = pos_args.unwrap().get(1..);

    let is_fail = AtomicBool::new(false);
    if arg_struct.use_new_db_format {
        // Open the SQLite database connections
        let db_connections = utils::make_db_connections(&G_TMPWORKINGDIR.lock().unwrap());
        if let Err(err) = db_connections {
            log::error!("Sqlite error: {:?}", err);
            clean_up();
            std::process::exit(1);
        }

        let db_connections = db_connections.unwrap();
        let db_conn = &mut db_connections.0.unwrap();
        let files_conn = &mut db_connections.1.unwrap();
        let connections = Arc::new(Mutex::from((db_conn, files_conn)));

        pos_args.unwrap().into_par_iter().for_each(|elem| {
            let action_func = if arg_struct.cmd_line == "repo-remove" {
                remove_pkg_from_db_nf
            } else {
                add_pkg_to_db_nf
            };
            handle_signal!(is_signaled);
            let mut conn_handle = Arc::clone(&connections);
            if !action_func(&mut conn_handle, elem, &arg_struct) {
                is_fail.store(true, Ordering::Relaxed);
            }
        });
    } else {
        pos_args.unwrap().into_par_iter().for_each(|elem| {
            let action_func = if arg_struct.cmd_line == "repo-remove" {
                remove_pkg_from_db
            } else {
                add_pkg_to_db
            };
            handle_signal!(is_signaled);
            if !action_func(elem, &arg_struct) {
                is_fail.store(true, Ordering::Relaxed);
            }
        });
    }
    handle_signal_ext!(is_signaled, sig_handle);

    // if the whole operation was a success, re-zip and rotate databases
    if is_fail.load(Ordering::Acquire) {
        log::error!("No packages modified, nothing to do.");
        clean_up();
        std::process::exit(1);
    }
    handle_signal_ext!(is_signaled, sig_handle);

    log::info!("Creating updated database file '{}'", arg_struct.repo_db_file.as_ref().unwrap());
    if !create_db(&arg_struct, &is_signaled) {
        clean_up();
        std::process::exit(1);
    }
    rotate_db(&arg_struct, &is_signaled);

    handle_signal_ext!(is_signaled, sig_handle);

    // log::info!("argstruct: {:?}\n", arg_struct);
    // log::info!("pos_args: {:?}\n", pos_args);
    //
    // let pkg_info = pkginfo::PkgInfo::from_file("../.PKGINFO");
    // let pkgpath = "firefox-developer-edition-116.0b8-1.1-x86_64.pkg.tar.zst";
    // let pkg_info = pkginfo::PkgInfo::from_archive(pkgpath);
    // log::info!("pkginfo: {:?}", pkg_info);
    clean_up();
}

fn exit_term_callback(err_msg: &str) {
    log::error!("{}", err_msg);
    clean_up();
    std::process::exit(1);
}

fn clean_up() {
    if Path::new(&*G_TMPWORKINGDIR.lock().unwrap()).exists() {
        let _ = fs::remove_dir_all(&*G_TMPWORKINGDIR.lock().unwrap());
    }
}

// ===================== Logging Set Up =====================
fn set_up_logging(is_colored: bool) {
    // here we set up our fern Dispatch
    if is_colored {
        // configure colors for the whole line
        let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        // we actually don't need to specify the color for debug and info, they are white by default
        .info(Color::White)
        .debug(Color::White)
        // depending on the terminals color scheme, this is the same as the background color
        .trace(Color::BrightBlack);

        let colors_level = colors_line.info(Color::Green);
        fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{color_line}{level}{color_line}\x1B[0m] {message}",
                color_line = format_args!(
                    "\x1B[{}m",
                    colors_line.get_color(&record.level()).to_fg_str()
                ),
                level = colors_level.color(record.level()),
                message = message,
            ));
        })
        // output to stdout
        .chain(std::io::stdout())
        .apply()
        .unwrap();
    } else {
        fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{level}] {message}",
                level = record.level(),
                message = message,
            ));
        })
        // output to stdout
        .chain(std::io::stdout())
        .apply()
        .unwrap();
    }
}
