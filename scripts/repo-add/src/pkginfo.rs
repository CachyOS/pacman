use std::fs::File;
use std::{fs, io};

use akv::reader::ArchiveReader;

#[derive(Debug, PartialEq)]
pub struct PkgInfo {
    pub pkgname: Option<String>,
    pub pkgbase: Option<String>,
    pub pkgver: Option<String>,
    pub basever: Option<String>,
    pub pkgdesc: Option<String>,
    pub url: Option<String>,
    pub builddate: Option<String>,
    pub packager: Option<String>,
    pub arch: Option<String>,
    pub pkg_isize: Option<String>,

    pub groups: Vec<String>,
    pub licenses: Vec<String>,
    pub depends: Vec<String>,
    pub optdepends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub conflicts: Vec<String>,
    pub replaces: Vec<String>,
    pub provides: Vec<String>,
    pub backup: Vec<String>,
}

impl PkgInfo {
    pub fn new() -> Self {
        Self {
            pkgname: None,
            pkgbase: None,
            pkgver: None,
            basever: None,
            pkgdesc: None,
            url: None,
            builddate: None,
            packager: None,
            arch: None,
            pkg_isize: None,

            groups: vec![],
            licenses: vec![],
            depends: vec![],
            optdepends: vec![],
            makedepends: vec![],
            checkdepends: vec![],
            conflicts: vec![],
            replaces: vec![],
            provides: vec![],
            backup: vec![],
        }
    }

    pub fn parse_line(&mut self, line: &str) -> bool {
        let split_line = line.split('=').collect::<Vec<&str>>();

        // Just drop the line, if the line is not pair separated by '='.
        if split_line.len() < 2 {
            return false;
        }

        let right_part = split_line[1..].join("=");

        let key = split_line[0].trim();
        let value = right_part.trim();

        let mut res_status = true;
        match key {
            "pkgname" => self.pkgname = Some(value.to_owned()),
            "pkgbase" => self.pkgbase = Some(value.to_owned()),
            "pkgver" => self.pkgver = Some(value.to_owned()),
            "basever" => self.basever = Some(value.to_owned()),
            "pkgdesc" => self.pkgdesc = Some(value.to_owned()),
            "group" => self.groups.push(value.to_owned()),
            "url" => self.url = Some(value.to_owned()),
            "license" => self.licenses.push(value.to_owned()),
            "builddate" => self.builddate = Some(value.to_owned()),
            "packager" => self.packager = Some(value.to_owned()),
            "arch" => self.arch = Some(value.to_owned()),
            "size" => self.pkg_isize = Some(value.to_owned()),
            "depend" => self.depends.push(value.to_owned()),
            "optdepend" => self.optdepends.push(value.to_owned()),
            "makedepend" => self.makedepends.push(value.to_owned()),
            "checkdepend" => self.checkdepends.push(value.to_owned()),
            "conflict" => self.conflicts.push(value.to_owned()),
            "replaces" => self.replaces.push(value.to_owned()),
            "provides" => self.provides.push(value.to_owned()),
            "backup" => self.backup.push(value.to_owned()),
            _ => res_status = false,
        };

        res_status
    }

    pub fn from_string(content: &str) -> Self {
        let mut pkginfo = PkgInfo::new();

        let lines = content.lines().filter(|line| !(line.is_empty() || line.starts_with('#')));
        for line in lines {
            pkginfo.parse_line(line);
        }

        pkginfo
    }

    pub fn from_file(file_path: &str) -> Self {
        let file_content = fs::read_to_string(file_path);
        if file_content.is_err() {
            return PkgInfo::new();
        }
        PkgInfo::from_string(&file_content.unwrap())
    }

    pub fn from_archive(file_path: &str) -> Self {
        let file_archive = File::open(file_path);
        if file_archive.is_err() {
            log::error!("could not open file {}: {:?}", file_path, file_archive.err());
            return PkgInfo::new();
        }
        let file_metadata = fs::metadata(file_path);
        let pkg_isize = format!("{}", file_metadata.unwrap().len());

        let mut pkginfo = PkgInfo::new();
        pkginfo.pkg_isize = Some(pkg_isize);

        let mut archive_reader = ArchiveReader::open_io(file_archive.unwrap());
        if archive_reader.is_err() {
            log::error!("error while reading package  {}: {:?}\n", file_path, archive_reader.err());
            return PkgInfo::new();
        }
        while let Some(entry) = archive_reader.as_mut().unwrap().next_entry().unwrap() {
            if entry.pathname_utf8().unwrap() != ".PKGINFO" {
                continue;
            }
            let entry_reader = entry.into_reader();
            let entry_content = io::read_to_string(entry_reader).unwrap();
            for content_line in entry_content.lines() {
                pkginfo.parse_line(content_line);
            }

            break;
        }

        pkginfo
    }
}

pub fn list_archive(file_path: &str) -> Vec<String> {
    let file_archive = File::open(file_path);
    if file_archive.is_err() {
        log::error!("could not open file {}: {:?}", file_path, file_archive.err());
        return vec![];
    }

    let mut arc_files = vec![];

    let mut archive_reader = ArchiveReader::open_io(file_archive.unwrap());
    if archive_reader.is_err() {
        log::error!("error while reading package  {}: {:?}\n", file_path, archive_reader.err());
        return vec![];
    }
    while let Some(entry) = archive_reader.as_mut().unwrap().next_entry().unwrap() {
        let entry_path = entry.pathname_mb();

        // Ignore if package entry has broken path (that is failed to convert to utf8), or if the
        // entry starts with '.'.
        if entry_path.is_err()
            || entry_path.as_ref().unwrap().to_str().unwrap().to_owned().starts_with('.')
        {
            continue;
        }
        arc_files.push(entry_path.unwrap().to_str().unwrap().to_owned());
    }

    arc_files
}

#[cfg(test)]
mod tests {
    use crate::pkginfo::PkgInfo;

    #[test]
    fn basic_xz() {
        let pkgpath = "xz-5.4.5-2-x86_64.pkg.tar.zst";
        let pkg_info = PkgInfo::from_archive(pkgpath);

        let pkg_info_expected = PkgInfo {
            pkgname: Some("xz".to_owned()),
            pkgbase: Some("xz".to_owned()),
            pkgver: Some("5.4.5-2".to_owned()),
            pkgdesc: Some(
                "Library and command line tools for XZ and LZMA compressed files".to_owned(),
            ),
            basever: None,
            url: Some("https://tukaani.org/xz/".to_owned()),
            builddate: Some("1704482661".to_owned()),
            packager: Some("CachyOS <admin@cachyos.org>".to_owned()),
            arch: Some("x86_64".to_owned()),
            pkg_isize: Some("2513790".to_owned()),
            groups: vec![],
            licenses: vec!["GPL".to_owned(), "LGPL".to_owned(), "custom".to_owned()],
            depends: vec!["sh".to_owned()],
            optdepends: vec![],
            makedepends: vec![],
            checkdepends: vec![],
            conflicts: vec![],
            replaces: vec![],
            provides: vec!["liblzma.so=5-64".to_owned()],
            backup: vec![],
        };

        assert_eq!(pkg_info, pkg_info_expected);
    }
}
