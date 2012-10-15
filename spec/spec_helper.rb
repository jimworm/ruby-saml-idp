# encoding: utf-8
$LOAD_PATH.unshift File.dirname(__FILE__) + '/../lib'
$LOAD_PATH.unshift File.dirname(__FILE__)

STDERR.puts("Running Specs under Ruby Version #{RUBY_VERSION}")

require 'rspec'

require 'ruby-saml'
require 'ruby-saml-idp'

Dir[File.dirname(__FILE__) + "/support/**/*.rb"].each {|f| require f}

RSpec.configure do |config|
  config.mock_with :rspec
  config.include SamlRequestMacros
end
