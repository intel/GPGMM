use_relative_paths = True

gclient_gn_args_file = 'build/config/gclient_args.gni'
gclient_gn_args = [
  'checkout_dawn',
  'checkout_webnn',
  'checkout_skia',
]

vars = {
  'chromium_git': 'https://chromium.googlesource.com',
  'dawn_git': 'https://dawn.googlesource.com',
  'github_git': 'https://github.com',
  'skia_git': 'https://skia.googlesource.com',

  'gpgmm_standalone': True,

  # Checkout and download Dawn by default. This can be disabled with custom_vars.
  'checkout_dawn': False,

  # Checkout and download WebNN by default. This can be disabled with custom_vars.
  'checkout_webnn': False,

  # Checkout and download SKIA by default. This can be disabled with custom_vars.
  'checkout_skia': False,
}

deps = {
  # Dependencies required to test integrations
  # Note: rolling Dawn also may require vulkan-deps to be rolled below.
  # TODO(gpgmm): Consider linking vulkan-deps to Dawn like Tint.
  'third_party/dawn': {
    'url': '{dawn_git}/dawn.git@6c6707021ab747005401961e90cb5659fd74c256',
    'condition': 'checkout_dawn',
  },

  'third_party/webnn_native': {
    'url': '{github_git}/webmachinelearning/webnn-native.git@b57593468549961e016e14bc65b998483a635bc9',
    'condition': 'checkout_webnn',
  },

  'third_party/skia': {
    'url': '{skia_git}/skia.git@c01225114a00f3c3c20ef81e9c2903b720140467',
    'condition': 'checkout_skia',
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
  # This can be removed once GPGMM is integrated with the upstream project.
  {
    'name': 'fetch_dawn_integration_patch',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': [ 'git', '-C', './third_party/dawn/',
                'fetch', 'https://github.com/bbernhar/dawn', 'gpgmm',
    ],
  },
  {
    'name': 'apply_dawn_integration_patch',
    'pattern': '.',
    'condition': 'checkout_dawn',
    'action': ['git', '-C', './third_party/dawn/',
               '-c', 'user.name=Custom Patch', '-c', 'user.email=custompatch@example.com',
               'cherry-pick', 'FETCH_HEAD',
    ],
  },
  # Apply WebNN-GPGMM integration patch.
  # This can be removed once GPGMM is integrated with the upstream project.
  {
    'name': 'fetch_webnn_integration_patch',
    'pattern': '.',
    'condition': 'checkout_webnn',
    'action': [ 'git', '-C', './third_party/webnn_native/',
                'fetch', 'https://github.com/bbernhar/webnn-native', 'gpgmm',
    ],
  },
  {
    'name': 'apply_webnn_integration_patch',
    'pattern': '.',
    'condition': 'checkout_webnn',
    'action': ['git', '-C', './third_party/webnn_native/',
               '-c', 'user.name=Custom Patch', '-c', 'user.email=custompatch@example.com',
               'cherry-pick', 'FETCH_HEAD',
    ],
  },
  # Apply SKIA-GPGMM integration patch.
  # This can be removed once GPGMM is integrated with the upstream project.
  {
    'name': 'fetch_skia_integration_patch',
    'pattern': '.',
    'condition': 'checkout_skia',
    'action': [ 'git', '-C', './third_party/skia/',
                'fetch', 'https://github.com/bbernhar/skia', 'gpgmm',
    ],
  },
  {
    'name': 'apply_skia_integration_patch',
    'pattern': '.',
    'condition': 'checkout_skia',
    'action': ['git', '-C', './third_party/skia/',
               '-c', 'user.name=Custom Patch', '-c', 'user.email=custompatch@example.com',
               'cherry-pick', 'FETCH_HEAD',
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
