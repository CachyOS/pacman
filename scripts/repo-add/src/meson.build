global_conf = configuration_data()
global_conf.set_quoted('VERSION', PACKAGE_VERSION)
config = configure_file(
  input: 'config.rs.in',
  output: 'config.rs',
  configuration: global_conf
)
# Copy the config.rs output to the source directory.
run_command(
  'cp',
  meson.build_root() / 'scripts' / 'repo-add' / 'src' / 'config.rs',
  meson.source_root() / 'scripts' / 'repo-add' / 'src' / 'config.rs',
  check: true
)

manifest_path = meson.source_root() / 'scripts' / 'repo-add' / 'Cargo.toml'
cargo_home = meson.build_root() / 'cargo-home'
cargo_target_dir = meson.build_root() / 'src'

cargo_options = [ '--manifest-path', manifest_path ]
cargo_options += [ '--target-dir', cargo_target_dir ]

if get_option('buildtype').startswith('debug')
  rust_target = 'debug'
  message('Building repo-add in debug mode')
else
  cargo_options += [ '--release' ]
  rust_target = 'release'
  message('Building repo-add in release mode')
endif

cargo_env = [ 'CARGO_HOME=' + cargo_home ]

repo_add = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: 'repo-add',
  console: true,
  install: true,
  install_dir: BINDIR,
  command: [
    'env',
    cargo_env,
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', 'src' / rust_target / 'repo-add', '@OUTPUT@',
  ]
)
