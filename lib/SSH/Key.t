# -*- perl -*-
use Test::More 'no_plan';
use warnings;
use strict;

my $class = "SSH::Key";
use_ok($class);

# not really a test of the correct output...
ok(scalar(SSH::Key::_keytypes())>0);

# Test the internal key part extractor
is(SSH::Key::_extract_next_keypart('123'), undef, 'Runt key');
is(SSH::Key::_extract_next_keypart("\x00\x00\x00\x0bbad"), undef, 'Runt val');

my $binary = "\x00\x00\x00\x0bssh-ed25519abab";
my ($val, $remain) = SSH::Key::_extract_next_keypart($binary);
is($val, 'ssh-ed25519');
is($remain, 'abab');

# Test the object interface
my $obj = new_ok($class);

is($obj->parse(), undef, "missing an encoded value is an error");
is($obj->error(), "Base64 key missing");

is($obj->parse('<>'), undef, "invalid base64 is an error");
is($obj->error(), "key length error");

is($obj->parse('AAAAC3NzaC1lZD'), undef, "truncated structure is an error");
is($obj->error(), "key structure length/val error");

is($obj->parse('AAAAC3NzaC1lZDI1NTE5AAAAIOqTtpQkv6bgHxWhr4QGf7WOY1760ArL/asGL3Lxqhlr'), $obj);

is($obj->type(), 'ssh-ed25519');
