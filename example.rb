#!/usr/bin/ruby 

require 'trapfilter'

tf = TrapFilter.new(:policy =>"drop") # when all rules true, ignore trap
tf.import(STDIN)
tf.add_rule('HOST' => 'test-srv.localdomain', 
            'IP' => '10.0.1.1',  
            'NETSCREEN-TRAP-MIB::netscreenTrapDesc.0' => '[Root]system-critical-00027')

tf.add_rule('HOST' => 'test-vpn-srv', 
            'IP' => '10.0.1.1',  
            'NETSCREEN-TRAP-MIB::netscreenTrapDesc.0' => '[Root]system-critical-00027')

if tf.filter
  puts "Filtered"
else
  tf.export(STDOUT)
end



