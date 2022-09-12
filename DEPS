use_relative_paths = True

gclient_gn_args_file = 'build/config/gclient_args.gni'
gclient_gn_args = [
  'checkout_dawn',
  'checkout_webnn',
  'build_with_chromium',
  'generate_location_tags',
]

vars = {
  'chromium_git': 'https://chromium.googlesource.com',
  'dawn_git': 'https://dawn.googlesource.com',
  'github_git': 'https://github.com',

  'gpgmm_standalone': True,
  'build_with_chromium': False,

  # Checkout and download Dawn by default. This can be disabled with custom_vars.
  'checkout_dawn': False,

  # Checkout and download WebNN by default. This can be disabled with custom_vars.
  'checkout_webnn': False,

  # Required by Chromium's //testing to generate directory->tags mapping used by ResultDB.
  'generate_location_tags': False,

  # GN CIPD package version.
  'gpgmm_gn_version': 'git_revision:fc295f3ac7ca4fe7acc6cb5fb052d22909ef3a8f',
}

deps = {
  # Dependencies required to test integrations
  # Note: rolling Dawn also may require vulkan-deps to be rolled below.
  # TODO(gpgmm): Consider linking vulkan-deps to Dawn like Tint.
  # TODO(gpgmm): WebNN hard codes builds to third_party/dawn and should be fixed if the
  # build errors are related to Dawn version mismatches.
  'third_party/dawn': {
    'url': '{dawn_git}/dawn.git@08f4b557fcf03e7fa6fea0342fb47b7c194f27be',
    'condition': 'checkout_dawn or checkout_webnn',
  },

  'third_party/webnn_native': {
    'url': '{github_git}/webmachinelearning/webnn-native.git@9add656df0e715aa9cf1d28536c132dd6506f784',
    'condition': 'checkout_webnn',
  },

  # Dependencies required to use GN/Clang in standalone
  'build': {
    'url': '{chromium_git}/chromium/src/build@efa2ea67b377f19f19b166acfb3300f5bb33b7ac',
    'condition': 'gpgmm_standalone',
  },
  'buildtools': {
    'url': '{chromium_git}/chromium/src/buildtools@a7f5ad05c477e997b063b250eae6529ecc460a9f',
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
    'url': '{chromium_git}/external/github.com/llvm/llvm-project/libcxx.git@60f90783c34aeab2c49682c6d4ce5520c8cb56b3',
    'condition': 'gpgmm_standalone',
  },
  'buildtools/third_party/libc++abi/trunk': {
    'url': '{chromium_git}/external/github.com/llvm/llvm-project/libcxxabi.git@5c3e02e92ae8bbc1bf1001bd9ef0d76e044ddb86',
    'condition': 'gpgmm_standalone',
  },
  'tools/clang': {
    'url': '{chromium_git}/chromium/src/tools/clang@0a2285903bf27182c56d8a1cc8b0e0d8a1ce8c31',
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

  # Testing, GTest and GMock
  'testing': {
    'url': '{chromium_git}/chromium/src/testing@37190e994cfd6b263880286d94399c31c22bd7cb',
    'condition': 'gpgmm_standalone',
  },
  'third_party/googletest': {
    'url': '{chromium_git}/external/github.com/google/googletest@0e0d9feefab1b51aaab9dfd70132e93c0b6964e5',
    'condition': 'gpgmm_standalone',
  },
  'third_party/vulkan-deps': {
    'url': '{chromium_git}/vulkan-deps@ad7395b46266b715abd0410fbcd3c56b79c97511',
    'condition': 'gpgmm_standalone',
  },
  # Dependency of //testing
  'third_party/catapult': {
    'url': '{chromium_git}/catapult.git@7ee071132a536a6616589cc2411674d1b459b4da',
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
  # Apply Dawn integration patch.
  # Patch can be removed should GPGMM be merged into upstream.
  # Removes un-tracked files from previous apply.
  {
    'name': 'apply_dawn_patch_1',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': [ 'git', '-C', './third_party/dawn/',
                'clean', '-f', '-x',
    ],
  },
  # Removes un-staged changes from previous apply.
  {
    'name': 'apply_dawn_patch_2',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': [ 'git', '-C', './third_party/dawn/',
                'checkout', '.',
    ],
  },
  {
    'name': 'apply_dawn_patch_3',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': [ 'git', '-C', './third_party/dawn/',
                'apply', '--ignore-space-change', '--ignore-whitespace',
                '../../.github/workflows/.patches/dawn.diff',
    ],
  },
]

recursedeps = [
  # vulkan-deps provides vulkan-headers, spirv-tools, and gslang
  'third_party/vulkan-deps',

  # Dawn and Tint's revision are linked
  'third_party/dawn',

  # WebNN and DirectML revision are linked
  'third_party/webnn_native',
]
