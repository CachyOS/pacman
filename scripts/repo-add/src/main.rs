mod config;
mod database_sqlite;
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
    println!("{} (pacman) {}\n", cmd_line, VERSION);
    println!("Copyright (c) 2023-2024 CachyOS Team.\n");
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
        utils::exec(&format!("printf '%s' '{encoded_elephant}' | base64 -d | gzip -d"), true).0
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
    if let Some(package_id) = database_sqlite::make_lookup_pkgentry_nf(conn, pkg_info) {
        return database_sqlite::get_old_entryval_nf(conn, package_id);
    }

    None
}

// remove existing entries from the DB
fn db_remove_entry(pkgname: &str, is_db_modified: &Arc<&mut AtomicBool>) -> bool {
    let mut is_found = false;

    while let Some(pkgentry) = find_pkgentry(pkgname) {
        is_found = true;

        log::info!(
            "Removing existing entry '{}'...",
            Path::new(&pkgentry).file_name().unwrap().to_str().unwrap()
        );
        fs::remove_dir_all(&pkgentry).unwrap();

        // remove entries in "files" database
        let (filesentry, _) = utils::exec(
            &format!("echo '{}' | sed 's/\\(.*\\)\\/db\\//\\1\\/files\\//'", &pkgentry),
            false,
        );
        fs::remove_dir_all(filesentry).unwrap();

        is_db_modified.store(true, Ordering::Relaxed);
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
            true,
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
        signwithkey = format!("-u '{}'", argstruct.gpgkey.as_ref().unwrap());
    }

    let (_, ret_code) = utils::exec(
        &format!(
            "gpg --batch --yes --detach-sign --use-agent --no-armor {} '{}' &>/dev/null",
            signwithkey, dbfile
        ),
        true,
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
    let dbfile_sig = format!("{}.sig", dbfile);
    if !Path::new(&dbfile_sig).exists() {
        log::warn!("No existing signature found, skipping verification.");
        return true;
    }

    let (_, ret_code) = utils::exec(&format!("gpg --verify '{}'", dbfile_sig), true);
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
        if !utils::get_compression_command(extension, None).is_empty() {
            return true;
        }
    }

    log::error!("'{}' does not have a valid database archive extension.", dbpath);
    false
}

// write an entry to the pacman database
fn db_write_entry(
    pkgpath: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
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
            &format!("sed -n '/^%VERSION%$/ {}' '{}/desc'", "{n;p;q}", pkgentry),
            false,
        )
        .0;
        // "version" is newer than version from pkginfo(incomming package)
        if alpm::Version::new(version)
            > alpm::Version::new(pkginfo.pkgver.as_ref().unwrap().as_bytes())
        {
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
                    &format!("sed -n '/^%FILENAME%$/ {}' '{}/desc'", "{n;p;q;}", pkgentry),
                    false,
                )
                .0,
            );
            oldfile.clone_from(&oldfilename);

            let parent_path = Path::new(pkgpath).parent().unwrap().to_string_lossy();
            if !parent_path.is_empty() {
                oldfile = Some(format!("{}/{}", parent_path, oldfilename.as_ref().unwrap()));
            }
        }
    }

    // generate package integrity
    let mut csize = String::new();
    let mut pkg_sha256sum: Option<String> = None;
    let mut pkg_pgpsig: Option<String> = None;

    if !utils::gen_pkg_integrity(
        pkgpath,
        &mut csize,
        argstruct.include_sigs,
        &mut pkg_sha256sum,
        &mut pkg_pgpsig,
    ) {
        return false;
    }

    // remove an existing entry if it exists, ignore failures
    db_remove_entry(pkginfo.pkgname.as_ref().unwrap(), is_db_modified);

    // create package directory
    fs::create_dir(format!("{}/{}", &workingdb_path, &pkg_entrypath))
        .expect("Failed to create dir");

    // create desc entry
    log::info!("Creating 'desc' db entry...");
    {
        utils::create_db_desc_entry(
            pkgpath,
            &pkg_entrypath,
            &workingdb_path,
            &pkginfo,
            csize,
            pkg_sha256sum,
            pkg_pgpsig,
        )
        .expect("Failed to create db entry");
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
    utils::write_to_file(&files_path, &format!("%FILES%\n{}\n", sorted_files.join("\n")))
        .expect("Failed to write data to file");

    if argstruct.rm_existing && oldfile.is_some() {
        log::info!("Removing old package file '{}'", oldfilename.as_ref().unwrap());
        fs::remove_file(oldfile.as_ref().unwrap()).unwrap();
        fs::remove_file(format!("{}.sig", oldfile.as_ref().unwrap())).unwrap();
    }

    is_db_modified.store(true, Ordering::Relaxed);

    true
}

fn db_write_entry_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgpath: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
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
        if database_sqlite::get_pkgentry_nf(conn_lock.0, &pkginfo).is_some() {
            log::warn!(
                "An entry for '{}-{}' already existed",
                pkginfo.pkgname.as_ref().unwrap(),
                pkginfo.pkgver.as_ref().unwrap()
            );
            if argstruct.only_add_new {
                return true;
            }
        } else if let Some((_, pkgver, pkg_filename)) = find_pkgentry_nf(conn_lock.0, &pkginfo) {
            // "pkgver" is newer than version from pkginfo(incomming package)
            if alpm::Version::new(pkgver)
                > alpm::Version::new(pkginfo.pkgver.as_ref().unwrap().as_bytes())
            {
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
                oldfile.clone_from(&oldfilename);

                let parent_path = Path::new(pkgpath).parent().unwrap().to_string_lossy();
                if !parent_path.is_empty() {
                    oldfile = Some(format!("{}/{}", parent_path, oldfilename.as_ref().unwrap()));
                }
            }
        }
    }

    // generate package integrity
    let mut csize = String::new();
    let mut pkg_sha256sum: Option<String> = None;
    let mut pkg_pgpsig: Option<String> = None;

    if !utils::gen_pkg_integrity(
        pkgpath,
        &mut csize,
        argstruct.include_sigs,
        &mut pkg_sha256sum,
        &mut pkg_pgpsig,
    ) {
        return false;
    }

    // Insert the package entry into the database
    log::info!("Inserting pkg into db...");
    {
        let mut connection_lock = connections.lock().unwrap();
        database_sqlite::create_db_entry_nf(
            connection_lock.0,
            pkgpath,
            &pkginfo,
            csize.clone(),
            &pkg_sha256sum,
            &pkg_pgpsig,
        )
        .expect("Failed to insert");

        database_sqlite::create_db_entry_nf(
            connection_lock.1,
            pkgpath,
            &pkginfo,
            csize,
            &pkg_sha256sum,
            &pkg_pgpsig,
        )
        .expect("Failed to insert");
    }

    // Insert files info
    database_sqlite::create_db_files_entry_nf(connections.lock().unwrap().1, pkgpath, &pkginfo);

    if argstruct.rm_existing && oldfile.is_some() {
        log::info!("Removing old package file '{}'", oldfilename.as_ref().unwrap());
        fs::remove_file(oldfile.as_ref().unwrap()).unwrap();
        fs::remove_file(format!("{}.sig", oldfile.as_ref().unwrap())).unwrap();
    }

    is_db_modified.store(true, Ordering::Relaxed);

    true
}

fn prepare_repo_db(cmd_line: &str, argstruct: &Arc<parse_args::ArgStruct>) -> bool {
    if argstruct.use_new_db_format {
        if !prepare_repo_db_nf(cmd_line, argstruct).expect("Failed to prepare db") {
            return false;
        }
        if !create_needed_repo_db_nf(cmd_line).expect("Failed to create needed for db") {
            return false;
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
            if !utils::is_file_in_archive(&dbfile, "*/desc") {
                // check empty case
                if utils::is_file_in_archive(&dbfile, "*") {
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
                    "bsdtar -xf '{}' -C '{}/{}'",
                    dbfile,
                    *G_TMPWORKINGDIR.lock().unwrap(),
                    repo
                ),
                false,
            );
        } else {
            // only a missing "db" database is currently an error
            if cmd_line == "repo-remove" && repo == "db" {
                log::error!("Repository file '{}' was not found.", dbfile);
                return false;
            } else if cmd_line == "repo-add" {
                // check if the file can be created (write permission, directory existence, etc)
                if utils::touch_file(&dbfile).is_err() {
                    log::error!("Repository file '{}' could not be created.", &dbfile);
                    return false;
                }
                fs::remove_file(dbfile).expect("Failed to remove db file");
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
    let repodir = Path::new(argstruct.lockfile.as_ref().unwrap())
        .parent()
        .expect("Failed to get parent of path");
    if !repodir.exists() {
        log::error!("{} does not exist.", repodir.to_string_lossy());
        return Ok(false);
    }
    let repos = ["db", "files"];
    for repo in repos {
        let dbfile = format!(
            "{}/{}.{}.{}",
            repodir.to_string_lossy(),
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );

        if Path::new(&dbfile).exists() {
            // there are two situations we can have here:
            // a DB with some entries, or a DB with no contents at all.
            if !utils::is_file_in_archive(&dbfile, "pacman.db") {
                // check empty case
                if utils::is_file_in_archive(&dbfile, "*") {
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
                    "bsdtar -xf '{}' -C '{}/{}'",
                    dbfile,
                    *G_TMPWORKINGDIR.lock().unwrap(),
                    repo
                ),
                false,
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
            if cmd_line == "repo-remove" && repo == "db" {
                log::error!("Repository file '{}' was not found.", dbfile);
                return Ok(false);
            } else if cmd_line == "repo-add" {
                // check if the file can be created (write permission, directory existence, etc)
                if utils::touch_file(&dbfile).is_err() {
                    log::error!("Repository file '{}' could not be created.", &dbfile);
                    return Ok(false);
                }
                fs::remove_file(dbfile).expect("Failed to remove db file");
            }
        }
    }
    Ok(true)
}

fn create_needed_repo_db_nf(cmd_line: &str) -> anyhow::Result<bool> {
    let repos = ["db", "files"];
    for repo in repos {
        let dbfile_path = format!("{}/{}/pacman.db", *G_TMPWORKINGDIR.lock().unwrap(), repo);

        let conn = rusqlite::Connection::open(dbfile_path)?;
        if cmd_line == "repo-add" {
            // Create the packages table if it doesn't exist
            database_sqlite::run_migrations(&conn).unwrap();
        }
    }
    Ok(true)
}

fn rotate_db(argstruct: &Arc<parse_args::ArgStruct>, is_signaled: &Arc<AtomicBool>) {
    let saved_dir = env::current_dir().unwrap_or("".into());
    {
        let dirname = Path::new(argstruct.lockfile.as_ref().unwrap())
            .parent()
            .expect("Failed to get parent path");
        env::set_current_dir(dirname).expect("Failed to change pwd");
    }

    let repos = ["db", "files"];
    repos.into_par_iter().for_each(|repo| {
        handle_signal!(is_signaled);
        let dirname = Path::new(argstruct.lockfile.as_ref().unwrap())
            .parent()
            .expect("Failed to get parent path");
        let filename = format!(
            "{}.{}.{}",
            argstruct.repo_db_prefix.as_ref().unwrap(),
            repo,
            argstruct.repo_db_suffix.as_ref().unwrap()
        );
        let tempname = format!("{}/.tmp.{}", dirname.to_string_lossy(), &filename);
        let sig_filename = format!("{}.sig", &filename);

        // hardlink or move the previous version of the database and signature to .old
        // extension as a backup measure
        if Path::new(&filename).exists() {
            let old_filename = format!("{}.old", &filename);
            if fs::hard_link(&filename, &old_filename).is_err() {
                if let Err(err_msg) = fs::rename(&filename, &old_filename) {
                    log::error!(
                        "Failed to rename file '{}'->'{}': {}",
                        &filename,
                        &old_filename,
                        err_msg
                    );
                }
            }

            let old_sig_filename = format!("{}.sig", &old_filename);
            if Path::new(&sig_filename).exists() {
                if fs::hard_link(&sig_filename, &old_sig_filename).is_err() {
                    if let Err(err_msg) = fs::rename(&sig_filename, &old_sig_filename) {
                        log::error!(
                            "Failed to rename file '{}'->'{}': {}",
                            &sig_filename,
                            &old_sig_filename,
                            err_msg
                        );
                    }
                }
            } else if Path::new(&old_sig_filename).exists() {
                fs::remove_file(&old_sig_filename).unwrap();
            }
        }

        // rotate the newly-created database and signature into place
        fs::rename(&tempname, &filename).unwrap();
        let sig_tempname = format!("{}.sig", &tempname);
        if Path::new(&sig_tempname).exists() {
            fs::rename(&sig_tempname, &sig_filename).unwrap();
        }

        let dblink = format!("{}.{}", argstruct.repo_db_prefix.as_ref().unwrap(), repo);
        let sig_dblink = format!("{}.sig", &dblink);
        if Path::new(&dblink).exists() {
            fs::remove_file(&dblink).unwrap();
        }
        if Path::new(&sig_dblink).exists() {
            fs::remove_file(&sig_dblink).unwrap();
        }

        if std::os::unix::fs::symlink(&filename, &dblink).is_err()
            && fs::hard_link(&filename, &dblink).is_err()
        {
            let _ = fs::copy(&filename, &dblink).expect("Failed to copy");
        }

        if Path::new(&sig_filename).exists()
            && std::os::unix::fs::symlink(&sig_filename, &sig_dblink).is_err()
            && fs::hard_link(&sig_filename, &sig_dblink).is_err()
        {
            let _ = fs::copy(&sig_filename, &sig_dblink).expect("Failed to copy");
        }
    });
    env::set_current_dir(saved_dir).expect("Failed to change pwd");
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
            let (mut tmpfile, filepath) =
                utils::create_tempfile(None).expect("Failed to create tmpfile");
            tmpfile.write_all(files.as_bytes()).unwrap();
            tmpfile_path = Some(filepath);
            format!("$(cat {})", &tmpfile_path.as_ref().unwrap())
        };

        let compress_cmd =
            utils::get_compression_command(argstruct.repo_db_suffix.as_ref().unwrap(), None);
        utils::exec(
            &format!(
                "cd '{}'; bsdtar -cf - {} | {} > '{}'",
                &workingdb_path, working_tar_arg, compress_cmd, tempname
            ),
            false,
        );

        if let Some(tmpfile_path) = tmpfile_path {
            fs::remove_file(tmpfile_path).unwrap();
        }

        if !create_signature(&tempname, argstruct) {
            is_fail.store(true, Ordering::Relaxed);
        }
    });

    !is_fail.load(Ordering::Acquire)
}

fn add_pkg_to_db(
    pkgfile: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
    argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    if !Path::new(pkgfile).exists() {
        log::error!("File '{}' not found.", pkgfile);
        return false;
    }

    if !utils::is_file_in_archive(pkgfile, ".PKGINFO") {
        log::error!("'{}' is not a package file, skipping", pkgfile);
        return false;
    }

    log::info!("Adding package '{}'", pkgfile);
    db_write_entry(pkgfile, is_db_modified, argstruct)
}

fn add_pkg_to_db_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgfile: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
    argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    if !Path::new(pkgfile).exists() {
        log::error!("File '{}' not found.", pkgfile);
        return false;
    }

    if !utils::is_file_in_archive(pkgfile, ".PKGINFO") {
        log::error!("'{}' is not a package file, skipping", pkgfile);
        return false;
    }

    log::info!("Adding package '{}'", pkgfile);
    db_write_entry_nf(connections, pkgfile, is_db_modified, argstruct)
}

fn remove_pkg_from_db(
    pkgname: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
    _argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    log::info!("Searching for package '{}'...", pkgname);
    db_remove_entry(pkgname, is_db_modified)
}

fn remove_pkg_from_db_nf(
    connections: &mut Arc<Mutex<(&mut rusqlite::Connection, &mut rusqlite::Connection)>>,
    pkgname: &str,
    is_db_modified: &Arc<&mut AtomicBool>,
    _argstruct: &Arc<parse_args::ArgStruct>,
) -> bool {
    log::info!("Searching for package '{}'...", pkgname);
    let remove_one_pkg = |conn: &mut rusqlite::Connection, needle| {
        if let Some(package_id) = database_sqlite::make_simple_lookup_pkgentry_nf(conn, needle) {
            database_sqlite::remove_from_db_by_id_nf(conn, package_id);
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
            is_db_modified.store(true, Ordering::Relaxed);
        }
    }
    {
        let mut connection_lock = connections.lock().unwrap();
        while remove_one_pkg(connection_lock.1, pkgname) {
            is_found = true;
            is_db_modified.store(true, Ordering::Relaxed);
        }
    }

    is_found
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    let cmd_line = utils::get_current_cmdname(args[0].as_str()).to_owned();

    if args.len() > 1 {
        let argument = args[1].as_str();
        if argument == "--help" || argument == "-h" {
            print_usage(&cmd_line);
            return;
        } else if argument == "--version" || argument == "-V" {
            print_version(&cmd_line);
            return;
        }
    }

    // figure out what program we are
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
        fs::create_dir(repo_path).expect("Failed to create dir");
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

    let (pos_args, mut arg_struct) = parse_args::parse_args(&mut args);
    set_up_logging(arg_struct.use_colors);
    if pos_args.is_none() || pos_args.unwrap().is_empty() {
        print_usage(&cmd_line);
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
    if !prepare_repo_db(&cmd_line, &arg_struct) {
        clean_up();
        std::process::exit(1);
    }

    let pos_args = pos_args.unwrap().get(1..);

    let is_fail = AtomicBool::new(false);
    let mut is_db_modified = AtomicBool::new(false);
    let is_db_modified = Arc::new(&mut is_db_modified);
    if arg_struct.use_new_db_format {
        // Open the SQLite database connections
        let db_connections = database_sqlite::make_db_connections(&G_TMPWORKINGDIR.lock().unwrap());
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
            let action_func =
                if cmd_line == "repo-remove" { remove_pkg_from_db_nf } else { add_pkg_to_db_nf };
            handle_signal!(is_signaled);
            let mut conn_handle = Arc::clone(&connections);
            if !action_func(&mut conn_handle, elem, &is_db_modified, &arg_struct) {
                is_fail.store(true, Ordering::Relaxed);
            }
        });
    } else {
        pos_args.unwrap().into_par_iter().for_each(|elem| {
            let action_func =
                if cmd_line == "repo-remove" { remove_pkg_from_db } else { add_pkg_to_db };
            handle_signal!(is_signaled);
            if !action_func(elem, &is_db_modified, &arg_struct) {
                is_fail.store(true, Ordering::Relaxed);
            }
        });
    }
    handle_signal_ext!(is_signaled, sig_handle);

    // if the whole operation was a success, re-zip and rotate databases
    if is_fail.load(Ordering::Acquire) {
        log::error!("Package database was not modified due to errors.");
        clean_up();
        std::process::exit(1);
    }

    // if the whole operation was a success, re-zip and rotate databases
    if !is_db_modified.load(Ordering::Acquire) {
        log::error!("No changes made to package database.");
        clean_up();
        std::process::exit(0);
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
        fs::remove_dir_all(&*G_TMPWORKINGDIR.lock().unwrap()).expect("Failed to cleanup");
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
