cargo = find_program('cargo', required: true)

meson.add_dist_script(
  'build-aux/dist-vendor.sh',
  meson.build_root() / 'meson-dist' / 'repo-add' + '-' + PACKAGE_VERSION,
  meson.source_root()
)

cargo_sources = files(
  'Cargo.toml',
  'Cargo.lock',
)

subdir('src')
