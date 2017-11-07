Pod::Spec.new do |s|
  s.name             = 'OTP'
  s.version          = '0.1.0'
  s.summary          = 'One-Time Password Toolkit for Swift'

  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/alexaubry/OTP'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'alexaubry' => 'me@alexaubry.fr' }
  s.source           = { :git => 'https://github.com/alexaubry/OTP.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/_alexaubry'

  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.10'  
  s.watchos.deployment_target = '2.0'
  s.tvos.deployment_target = '9.0'
  s.requires_arc = true

  s.pod_target_xcconfig = { 'SWIFT_VERSION' => '4.0' }  

  s.ios.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/OTP/modules/ios/**' }
  s.osx.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/OTP/modules/macos/**' }
  s.watchos.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/OTP/modules/watchos/**' }
  s.tvos.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/OTP/modules/tvos/**' }

  s.preserve_paths = 'modules/ios/CommonCrypto/module.modulemap', 'modules/macos/CommonCrypto/module.modulemap', 'modules/watchos/CommonCrypto/module.modulemap', 'modules/tvos/CommonCrypto/module.modulemap'

  s.source_files = 'Sources/**/*.swift'
  s.documentation_url = "https://alexaubry.github.io/OTP/"
end
