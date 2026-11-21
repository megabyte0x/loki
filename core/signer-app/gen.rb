require 'xcodeproj'
# Generate the project IN this directory (core/signer-app/), referencing Sources/main.swift here.
Dir.chdir(__dir__)
proj_path = File.join(__dir__, 'LokiSigner.xcodeproj')
project = Xcodeproj::Project.new(proj_path)
target = project.new_target(:application, 'LokiSigner', :osx, '13.0')
target.add_file_references(%w[Sources/main.swift Sources/Native.swift Sources/PromptPage.swift Sources/VaultAddresses.swift Sources/Recovery.swift Sources/SignerStatus.swift Sources/SignerLog.swift].map { |path| project.new_file(path) })
backend = project.new_file('libs/libse_backend.dylib')
embed = target.new_copy_files_build_phase('Embed Enclave backend')
embed.dst_subfolder_spec = '10'
embed.add_file_reference(backend).settings = { 'ATTRIBUTES' => ['CodeSignOnCopy'] }
target.build_configurations.each do |c|
  bs = c.build_settings
  bs['PRODUCT_BUNDLE_IDENTIFIER'] = 'cash.loki.signer'
  bs['PRODUCT_NAME'] = 'LokiSigner'
  bs['CODE_SIGN_STYLE'] = 'Automatic'
  # Your Apple Developer Team ID — from the environment, not hardcoded. If unset, Xcode's
  # automatic signing picks the only team on the machine. `export LOKI_DEV_TEAM=XXXXXXXXXX`.
  team = ENV['LOKI_DEV_TEAM'].to_s
  bs['DEVELOPMENT_TEAM'] = team unless team.empty?
  bs['CODE_SIGN_ENTITLEMENTS'] = 'LokiSigner.entitlements'
  bs['SWIFT_VERSION'] = '5.0'
  bs['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
  bs['GENERATE_INFOPLIST_FILE'] = 'NO'
  bs['INFOPLIST_FILE'] = 'Info.plist'
  bs['CODE_SIGN_IDENTITY'] = 'Apple Development'
  # Link the Rust signer static lib (libloki_poc.a) + the Swift Enclave backend
  # (libse_backend.dylib), both staged in libs/ by the build step.
  libs = File.join(__dir__, 'libs')
  bs['LIBRARY_SEARCH_PATHS'] = libs
  bs['LD_RUNPATH_SEARCH_PATHS'] = '@executable_path/../Frameworks'
  bs['OTHER_LDFLAGS'] = '-lloki_poc -lse_backend -framework Security -framework Foundation ' \
                        '-framework CoreFoundation -framework SystemConfiguration -framework AppKit ' \
                        '-lc++ -lresolv -liconv'
end
project.save
puts "project generated"
