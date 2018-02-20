# -*- perl -*-
use Test::More 'no_plan';
use warnings;
use strict;

my $class = "SSH::Keys";
use_ok($class);

ok(scalar(SSH::Keys::_keytypes())>0);

is(SSH::Keys::_extract_next_keypart('123'), undef, 'Runt key');
is(SSH::Keys::_extract_next_keypart("\x00\x00\x00\x0bbad"), undef, 'Runt val');

my $binary = "\x00\x00\x00\x0bssh-ed25519abab";
my ($val, $remain) = SSH::Keys::_extract_next_keypart($binary);
is($val, 'ssh-ed25519');
is($remain, 'abab');
