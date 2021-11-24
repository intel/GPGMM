use_relative_paths = True

gclient_gn_args_file = 'build/config/gclient_args.gni'
gclient_gn_args = [
  'checkout_dawn',
  'checkout_webnn',
]

vars = {
  'chromium_git': 'https://chromium.googlesource.com',
  'dawn_git': 'https://dawn.googlesource.com',
  'github_git': 'https://github.com',

  'gpgmm_standalone': True,

  # Checkout and download Dawn by default. This can be disabled with custom_vars.
  'checkout_dawn': False,

  # Checkout and download WebNN by default. This can be disabled with custom_vars.
  'checkout_webnn': False,
}

deps = {
  # Dependencies required to test integrations
  # Note: rolling Dawn also may require vulkan-deps to be rolled below.
  # TODO(gpgmm): Consider linking vulkan-deps to Dawn like Tint.
  # TODO(gpgmm): WebNN hard codes builds to third_party/dawn and should be fixed if the
  # build errors are related to Dawn version mismatches.
  'third_party/dawn': {
    'url': '{dawn_git}/dawn.git@22da31cf43e13b6aa57d66d89983ea6c5f5b094e',
    'condition': 'checkout_dawn or checkout_webnn',
  },

  'third_party/webnn_native': {
    'url': '{github_git}/webmachinelearning/webnn-native.git@f59b5bb7d349be685c99962a2047b84580fcdcfd',
    'condition': 'checkout_webnn',
  },

  # Dependencies required to use GN/Clang in standalone
  'build': {
    'url': '{chromium_git}/chromium/src/build@3769c3b43c3804f9f7f14c6e37f545639fda2852',
    'condition': 'gpgmm_standalone',
  },
  'buildtools': {
    'url': '{chromium_git}/chromium/src/buildtools@235cfe435ca5a9826569ee4ef603e226216bd768',
    'condition': 'gpgmm_standalone',
  },
  'tools/clang': {
    'url': '{chromium_git}/chromium/src/tools/clang@b12d1c836e2bb21b966bf86f7245bab9d257bb6b',
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
    'url': '{chromium_git}/chromium/src/testing@3e2640a325dc34ec3d9cb2802b8da874aecaf52d',
    'condition': 'gpgmm_standalone',
  },
  'third_party/googletest': {
    'url': '{chromium_git}/external/github.com/google/googletest@2828773179fa425ee406df61890a150577178ea2',
    'condition': 'gpgmm_standalone',
  },
  'third_party/vulkan-deps': {
    'url': '{chromium_git}/vulkan-deps@df0528b581a1709ccad790c205d3c11d0b657ed6',
    'condition': 'gpgmm_standalone',
  },
  'third_party/jsoncpp/source': {
    'url': '{chromium_git}/external/github.com/open-source-parsers/jsoncpp@9059f5cad030ba11d37818847443a53918c327b1',
    'condition': 'gpgmm_standalone',
  },
}

hooks = [
  # Pull the compilers and system libraries for hermetic builds
  {
    'name': 'sysroot_x86',
    'pattern': '.',
    'condition': 'checkout_linux and ((checkout_x86 or checkout_x64) and gpgmm_standalone)',
    'action': ['python', 'build/linux/sysroot_scripts/install-sysroot.py',
               '--arch=x86'],
  },
  {
    'name': 'sysroot_x64',
    'pattern': '.',
    'condition': 'checkout_linux and (checkout_x64 and gpgmm_standalone)',
    'action': ['python', 'build/linux/sysroot_scripts/install-sysroot.py',
               '--arch=x64'],
  },
  {
    # Update the Mac toolchain if possible, this makes builders use "hermetic XCode" which is
    # is more consistent (only changes when rolling build/) and is cached.
    'name': 'mac_toolchain',
    'pattern': '.',
    'condition': 'checkout_mac',
    'action': ['python', 'build/mac_toolchain.py'],
  },
  {
    # Update the Windows toolchain if necessary. Must run before 'clang' below.
    'name': 'win_toolchain',
    'pattern': '.',
    'condition': 'checkout_win and gpgmm_standalone',
    'action': ['python', 'build/vs_toolchain.py', 'update', '--force'],
  },
  {
    # Note: On Win, this should run after win_toolchain, as it may use it.
    'name': 'clang',
    'pattern': '.',
    'action': ['python', 'tools/clang/scripts/update.py'],
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
    'action': ['python', 'build/util/lastchange.py',
               '-o', 'build/util/LASTCHANGE'],
  },
  # Apply Dawn-GPGMM integration patch.
  # Patch can be removed should GPGMM be merged into upstream.
  {
    'name': 'apply_dawn_integration_patch',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': [ 'git', '-C', './third_party/dawn/',
                'apply', '--ignore-space-change', '--ignore-whitespace',
                '../../patches/gpgmm_dawn.diff',
    ],
  },
]

recursedeps = [
  # buildtools provides clang_format, libc++, and libc++abi
  'buildtools',

  # vulkan-deps provides vulkan-headers, spirv-tools, and gslang
  'third_party/vulkan-deps',

  # Dawn and Tint's revision are linked
  'third_party/dawn',

  # WebNN and DirectML revision are linked
  'third_party/webnn_native',
]
