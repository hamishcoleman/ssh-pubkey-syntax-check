# -*- perl -*-
use Test::More 'no_plan';
use warnings;
use strict;

my $class = "SSH::Keys";
use_ok($class);

ok(scalar(SSH::Keys::_keytypes())>0);

