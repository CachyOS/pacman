#[derive(Debug)]
pub struct ArgStruct {
    pub quiet: bool,
    pub only_add_new: bool,
    pub rm_existing: bool,
    pub sign: bool,
    pub key: bool,
    pub verify: bool,
    pub clean_lock: bool,
    pub use_colors: bool,
    pub prevent_downgrade: bool,
    pub include_sigs: bool,
    pub use_new_db_format: bool,

    pub repo_db_file: Option<String>,
    pub repo_db_prefix: Option<String>,
    pub repo_db_suffix: Option<String>,
    pub lockfile: Option<String>,
    pub gpgkey: Option<String>,
}

impl ArgStruct {
    pub fn new() -> Self {
        Self {
            quiet: false,
            only_add_new: false,
            rm_existing: false,
            sign: false,
            key: false,
            verify: false,
            clean_lock: false,
            use_colors: true,
            prevent_downgrade: false,
            include_sigs: false,
            use_new_db_format: false,

            repo_db_file: None,
            repo_db_prefix: None,
            repo_db_suffix: None,
            lockfile: None,
            gpgkey: None,
        }
    }
}

pub fn parse_args(pargs: &mut Vec<String>) -> (Option<&[String]>, ArgStruct) {
    let mut argstruct = ArgStruct::new();
    pargs.remove(0);

    let mut i = 0;
    while i < pargs.len() {
        let argument = pargs[i].as_str();
        if argument == "--quiet" || argument == "-q" {
            argstruct.quiet = true;
        } else if argument == "--new" || argument == "-n" {
            argstruct.only_add_new = true;
        } else if argument == "--remove" || argument == "-R" {
            argstruct.rm_existing = true;
        } else if argument == "--nocolor" {
            argstruct.use_colors = false;
        } else if argument == "--sign" || argument == "-s" {
            argstruct.sign = true;
        } else if argument == "--key" || argument == "-k" {
            pargs.remove(i);
            if i < pargs.len() {
                argstruct.gpgkey = Some(pargs.remove(i).clone());
                argstruct.key = true;
            }
            continue;
        } else if argument == "--verify" || argument == "-v" {
            argstruct.verify = true;
        } else if argument == "--prevent-downgrade" || argument == "-p" {
            argstruct.prevent_downgrade = true;
        } else if argument == "--include-sigs" {
            argstruct.include_sigs = true;
        } else if argument == "--use-new-db-format" {
            argstruct.use_new_db_format = true;
        } else if argument == "--" {
            pargs.remove(i);
            break;
        } else {
            i += 1;
            continue;
        }
        pargs.remove(i);
    }

    (Some(pargs), argstruct)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sign_after_pos() {
        let mut args: Vec<String> = vec![
            "./repo-add".to_owned(),
            "-v".to_owned(),
            "-p".to_owned(),
            "-n".to_owned(),
            "core.db.tar.zst".to_owned(),
            "pacman-6.0.2-8-x86_64.pkg.tar.zst".to_owned(),
            "pacman-6.0.2-9-x86_64.pkg.tar.zst".to_owned(),
            "-s".to_owned(),
        ];
        let (pos_args, argstruct) = crate::parse_args::parse_args(&mut args);

        let expected_pos = vec![
            "core.db.tar.zst".to_owned(),
            "pacman-6.0.2-8-x86_64.pkg.tar.zst".to_owned(),
            "pacman-6.0.2-9-x86_64.pkg.tar.zst".to_owned(),
        ];
        assert_eq!(pos_args, Some(expected_pos.as_slice()));
        assert!(argstruct.sign);
        assert!(argstruct.verify);
        assert!(argstruct.prevent_downgrade);
        assert!(argstruct.only_add_new);
        assert!(!argstruct.quiet);
        assert!(argstruct.use_colors);
    }

    #[test]
    fn sign_after_pos_tailing() {
        let mut args: Vec<String> = vec![
            "./repo-add".to_owned(),
            "-v".to_owned(),
            "-p".to_owned(),
            "-n".to_owned(),
            "core.db.tar.zst".to_owned(),
            "pacman-6.0.2-8-x86_64.pkg.tar.zst".to_owned(),
            "pacman-6.0.2-9-x86_64.pkg.tar.zst".to_owned(),
            "--".to_owned(),
            "-s".to_owned(),
        ];
        let (pos_args, argstruct) = crate::parse_args::parse_args(&mut args);

        let expected_pos = vec![
            "core.db.tar.zst".to_owned(),
            "pacman-6.0.2-8-x86_64.pkg.tar.zst".to_owned(),
            "pacman-6.0.2-9-x86_64.pkg.tar.zst".to_owned(),
            "-s".to_owned(),
        ];
        assert_eq!(pos_args, Some(expected_pos.as_slice()));
        assert!(!argstruct.sign);
        assert!(argstruct.verify);
        assert!(argstruct.prevent_downgrade);
        assert!(argstruct.only_add_new);
        assert!(!argstruct.quiet);
        assert!(argstruct.use_colors);
    }

    #[test]
    fn no_pos_pkgs() {
        let mut args: Vec<String> = vec![
            "./repo-add".to_owned(),
            "-v".to_owned(),
            "-p".to_owned(),
            "-n".to_owned(),
            "-s".to_owned(),
            "-R".to_owned(),
            "-k".to_owned(),
            "F3B607488DB35A47".to_owned(),
            "-q".to_owned(),
            "--nocolor".to_owned(),
            "--include-sigs".to_owned(),
            "--use-new-db-format".to_owned(),
            "core.db.tar.zst".to_owned(),
        ];
        let (pos_args, argstruct) = crate::parse_args::parse_args(&mut args);

        let expected_pos = vec!["core.db.tar.zst".to_owned()];
        assert_eq!(pos_args, Some(expected_pos.as_slice()));
        assert!(argstruct.sign);
        assert!(argstruct.verify);
        assert!(argstruct.prevent_downgrade);
        assert!(argstruct.only_add_new);
        assert!(argstruct.quiet);
        assert!(argstruct.rm_existing);
        assert!(!argstruct.use_colors);
        assert!(argstruct.include_sigs);
        assert!(argstruct.use_new_db_format);
        assert!(argstruct.key);
        assert_eq!(argstruct.gpgkey, Some("F3B607488DB35A47".to_owned()));
    }

    #[test]
    fn no_pos_args() {
        let mut args: Vec<String> = vec![
            "./repo-add".to_owned(),
            "-v".to_owned(),
            "-p".to_owned(),
            "-n".to_owned(),
            "-s".to_owned(),
            "-R".to_owned(),
            "-k".to_owned(),
            "F3B607488DB35A47".to_owned(),
            "-q".to_owned(),
            "--nocolor".to_owned(),
            "--include-sigs".to_owned(),
            "--use-new-db-format".to_owned(),
        ];
        let (pos_args, argstruct) = crate::parse_args::parse_args(&mut args);

        let expected_pos = vec![];
        assert_eq!(pos_args, Some(expected_pos.as_slice()));
        assert!(argstruct.sign);
        assert!(argstruct.verify);
        assert!(argstruct.prevent_downgrade);
        assert!(argstruct.only_add_new);
        assert!(argstruct.quiet);
        assert!(argstruct.rm_existing);
        assert!(!argstruct.use_colors);
        assert!(argstruct.include_sigs);
        assert!(argstruct.use_new_db_format);
        assert!(argstruct.key);
        assert_eq!(argstruct.gpgkey, Some("F3B607488DB35A47".to_owned()));
    }
}
