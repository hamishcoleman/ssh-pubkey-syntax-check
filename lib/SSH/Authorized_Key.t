# -*- perl -*-
use Test::More 'no_plan';
use warnings;
use strict;

my $class = "SSH::Authorized_Key";
use_ok($class);

my $obj = new_ok($class);

is($obj->parse(), undef);
is($obj->error(), "Missing authorized_keys line");

is($obj->parse(('a'x8192).'b'), undef);
is($obj->error(), "Line is too long");

# All the following sample lines have truncated key fields - the encoded key
# is not tested by this module, so that is fine.  Just dont be surprised

is($obj->parse('no-user-rc ssh-ed25519 AAAAC3NzaC1lZ comment'), undef);
is($obj->error(), "processing the options field is not implemented");

is($obj->parse('ecdsa-sha2-nistp256 AAAAC3NzaC1lZ'), undef);
is($obj->error(), "Too few fields");

is($obj->parse('ssh-ed25519 AAAAC3NzaC1lZDI1 comment'), 1);
is($obj->key_type(), 'ssh-ed25519');
is($obj->key(), 'AAAAC3NzaC1lZDI1');
