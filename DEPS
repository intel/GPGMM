use_relative_paths = True

gclient_gn_args_file = 'build/config/gclient_args.gni'
gclient_gn_args = [
  'build_with_chromium',
  'generate_location_tags',
]

vars = {
  'chromium_git': 'https://chromium.googlesource.com',
  'github_git': 'https://github.com',

  'gpgmm_standalone': True,
  'build_with_chromium': False,

  # Required by Chromium's //testing to generate directory->tags mapping used by ResultDB.
  'generate_location_tags': False,

  # GN CIPD package version.
  'gpgmm_gn_version': 'git_revision:bd99dbf98cbdefe18a4128189665c5761263bcfb',

  # ninja CIPD package version.
  # https://chrome-infra-packages.appspot.com/p/infra/3pp/tools/ninja
  'gpgmm_ninja_version': 'version:2@1.8.2.chromium.3',
}

deps = {
  # Dependencies required to use GN/Clang in standalone
  'build': {
    'url': '{chromium_git}/chromium/src/build@d0fad164969ab7f41f163f9ee738ea692f43df53',
    'condition': 'gpgmm_standalone',
  },
  'buildtools': {
    'url': '{chromium_git}/chromium/src/buildtools@5408fe0e010a7d36bb2684d5f38df67dcdfe31de',
    'condition': 'gpgmm_standalone',
  },
  'buildtools/clang_format/script': {
    'url': '{chromium_git}/external/github.com/llvm/llvm-project/clang/tools/clang-format.git@99803d74e35962f63a775f29477882afd4d57d94',
    'condition': 'gpgmm_standalone',
  },

  'buildtools/linux64': {
    'packages': [{
      'package': 'gn/gn/linux-amd64',
      'version': Var('gpgmm_gn_version'),
    }],
    'dep_type': 'cipd',
    'condition': 'gpgmm_standalone and host_os == "linux"',
  },
  'buildtools/mac': {
    'packages': [{
      'package': 'gn/gn/mac-${{arch}}',
      'version': Var('gpgmm_gn_version'),
    }],
    'dep_type': 'cipd',
    'condition': 'gpgmm_standalone and host_os == "mac"',
  },
  'buildtools/win': {
    'packages': [{
      'package': 'gn/gn/windows-amd64',
      'version': Var('gpgmm_gn_version'),
    }],
    'dep_type': 'cipd',
    'condition': 'gpgmm_standalone and host_os == "win"',
  },

  'buildtools/third_party/libc++/trunk': {
    'url': '{chromium_git}/external/github.com/llvm/llvm-project/libcxx.git@549781a48cef7a038cadbe8ae9034c2d63685d9a',
    'condition': 'gpgmm_standalone',
  },
  'buildtools/third_party/libc++abi/trunk': {
    'url': '{chromium_git}/external/github.com/llvm/llvm-project/libcxxabi.git@b74d7716111d7eda5c03cb8f5dfc940e1c2c0030',
    'condition': 'gpgmm_standalone',
  },
  'tools/clang': {
    'url': '{chromium_git}/chromium/src/tools/clang@bae2f662bc24c1747721fe006e8d9d8be81f1d03',
    'condition': 'gpgmm_standalone',
  },
  'tools/clang/dsymutil': {
    'packages': [
      {
        'package': 'chromium/llvm-build-tools/dsymutil',
        'version': 'M56jPzDv1620Rnm__jTMYS62Zi8rxHVq7yw0qeBFEgkC',
      }
    ],
    'condition': 'checkout_mac or checkout_ios',
    'dep_type': 'cipd',
  },
 'third_party/ninja': {
    'packages': [{
        'package': 'infra/3pp/tools/ninja/${{platform}}',
        'version': Var('gpgmm_ninja_version'),
      }],
    'dep_type': 'cipd',
  },
  # Testing, GTest and GMock
  'testing': {
    'url': '{chromium_git}/chromium/src/testing@427915c5f68fc7e1eb6b031375e376254c761416',
    'condition': 'gpgmm_standalone',
  },
  'third_party/googletest': {
    'url': '{chromium_git}/external/github.com/google/googletest@ec25eea8f8237cf86c30703f59747e42f34b6f75',
    'condition': 'gpgmm_standalone',
  },
  'third_party/vulkan-deps': {
    'url': '{chromium_git}/vulkan-deps@d7dfd14fa0d0bc1411976c7800a9076bab44524a',
    'condition': 'gpgmm_standalone',
  },
  # Dependency of //testing
  'third_party/catapult': {
    'url': '{chromium_git}/catapult.git@c4e9d16032d8217ec6de404a66f4f0cc1d8e366a',
    'condition': 'gpgmm_standalone',
  },
  'third_party/jsoncpp/source': {
    'url': '{chromium_git}/external/github.com/open-source-parsers/jsoncpp@8190e061bc2d95da37479a638aa2c9e483e58ec6',
    'condition': 'gpgmm_standalone',
  },
  # Fuzzing
  'third_party/libFuzzer/src': {
    'url': '{chromium_git}/chromium/llvm-project/compiler-rt/lib/fuzzer.git@debe7d2d1982e540fbd6bd78604bf001753f9e74',
    'condition': 'gpgmm_standalone',
  },
  'third_party/google_benchmark/src': {
    'url': '{chromium_git}/external/github.com/google/benchmark.git@e991355c02b93fe17713efe04cbc2e278e00fdbd',
    'condition': 'gpgmm_standalone',
  },
}

hooks = [
  # Pull the compilers and system libraries for hermetic builds
  {
    'name': 'sysroot_x86',
    'pattern': '.',
    'condition': 'checkout_linux and ((checkout_x86 or checkout_x64) and gpgmm_standalone)',
    'action': ['python3', 'build/linux/sysroot_scripts/install-sysroot.py',
               '--arch=x86'],
  },
  {
    'name': 'sysroot_x64',
    'pattern': '.',
    'condition': 'checkout_linux and (checkout_x64 and gpgmm_standalone)',
    'action': ['python3', 'build/linux/sysroot_scripts/install-sysroot.py',
               '--arch=x64'],
  },
  {
    # Update the Mac toolchain if possible, this makes builders use "hermetic XCode" which is
    # is more consistent (only changes when rolling build/) and is cached.
    'name': 'mac_toolchain',
    'pattern': '.',
    'condition': 'checkout_mac',
    'action': ['python3', 'build/mac_toolchain.py'],
  },
  {
    # Update the Windows toolchain if necessary. Must run before 'clang' below.
    'name': 'win_toolchain',
    'pattern': '.',
    'condition': 'checkout_win and gpgmm_standalone',
    'action': ['python3', 'build/vs_toolchain.py', 'update', '--force'],
  },
  {
    # Note: On Win, this should run after win_toolchain, as it may use it.
    'name': 'clang',
    'pattern': '.',
    'action': ['python3', 'tools/clang/scripts/update.py'],
    'condition': 'gpgmm_standalone',
  },
  {
    # Pull rc binaries using checked-in hashes.
    'name': 'rc_win',
    'pattern': '.',
    'condition': 'checkout_win and (host_os == "win" and gpgmm_standalone)',
    'action': [ 'download_from_google_storage',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-browser-clang/rc',
                '-s', 'build/toolchain/win/rc/win/rc.exe.sha1',
    ],
  },
  # Pull clang-format binaries using checked-in hashes.
  {
    'name': 'clang_format_win',
    'pattern': '.',
    'condition': 'host_os == "win"',
    'action': [ 'download_from_google_storage',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-clang-format',
                '-s', 'buildtools/win/clang-format.exe.sha1',
    ],
  },
  {
    'name': 'clang_format_mac',
    'pattern': '.',
    'condition': 'host_os == "mac"',
    'action': [ 'download_from_google_storage',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-clang-format',
                '-s', 'buildtools/mac/clang-format.sha1',
    ],
  },
  {
    'name': 'clang_format_linux',
    'pattern': '.',
    'condition': 'host_os == "linux"',
    'action': [ 'download_from_google_storage',
                '--no_resume',
                '--no_auth',
                '--bucket', 'chromium-clang-format',
                '-s', 'buildtools/linux64/clang-format.sha1',
    ],
  },
  # Update build/util/LASTCHANGE.
  {
    'name': 'lastchange',
    'pattern': '.',
    'condition': 'gpgmm_standalone',
    'action': ['python3', 'build/util/lastchange.py',
               '-o', 'build/util/LASTCHANGE'],
  },
]

recursedeps = [
  # vulkan-deps provides vulkan-headers, spirv-tools, and gslang
  'third_party/vulkan-deps',
]
