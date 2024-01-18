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
