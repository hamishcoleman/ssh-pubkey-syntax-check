# -*- perl -*-
use Test::More 'no_plan';
use warnings;
use strict;

my $class = "SSH::Known_Host";
use_ok($class);

my $obj = new_ok($class);

is($obj->parse(), undef);
is($obj->error(), "Missing ssh known host line");

is($obj->parse('badline'), undef);
is($obj->error(), "Too few fields");

# TODO - Add a test with a "@cert-authority" field

# All the following sample lines have truncated key fields - the encoded key
# is not tested by this module, so that is fine.  Just dont be surprised

is($obj->parse('|1|aaa,test3 ssh-rsa AAAAB3NzaC1y'), undef);
is($obj->error(), "Invalid operators in hashed hostname");

is($obj->parse('|1|aaa ssh-rsa AAAAB3NzaC1y'), 1);
is($obj->hostname(), '|1|aaa');
is($obj->key_type(), 'ssh-rsa');
is($obj->key(), 'AAAAB3NzaC1y');

is($obj->parse('test4,[test4.cc]:z ssh-rsa AAAAB3NzaC1y'), undef);
is($obj->error(), "Invalid non-standard port number");
is($obj->hostname(), 'test4', 'hostname still gets set before we error out');

is($obj->parse('test5,[test5.cc]:10 ssh-dss AAAAB3NzaC1kc3MAA'), 1);
is($obj->hostname(), 'test5');
is($obj->key_type(), 'ssh-dss');
is($obj->key(), 'AAAAB3NzaC1kc3MAA');

my $hostnames;
@{$hostnames} = $obj->hostnames();
is_deeply($hostnames, ['test5','[test5.cc]:10']);

