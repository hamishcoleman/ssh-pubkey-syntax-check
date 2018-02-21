package SSH::Key;
use warnings;
use strict;
#
#
#

use MIME::Base64;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub parse {
    my $self = shift;
    my $encoded = shift;

    # we are passed the base64 encoded text of the key.
    # This is an array of len,val pairs (len is u32 value)

    # TODO
    # - use a better base64 function that actually reports errors
    # - if the len pointer is ever beyond the remaining length then we fail
    # - pair 1 looks like the same as the string type

    # for ecdsa-sha2-nistp256
    # - pair 2 is a second string value
    # - pair 3 is binary

    # for ssh-rsa
    # - pair 2 is "01 00 01"
    # - pair 3 is binary of length 0101
    # - pair 4 is ?
    # - pair 5 is ?
    # - pair 6 is ?

    if (!defined($encoded)) {
        $self->error("Base64 key missing");
        return undef;
    }

    my $binary = decode_base64($encoded);
    if (!defined($binary)) {
        # never happens with this decode library
        $self->error("Base64 key decode error");
        return undef;
    }
    # stash the binary for debugging
    $self->{binary} = $binary;

    if (!length($binary)) {
        $self->error("key length error");
        return undef;
    }

    my $val;
    while (length($binary)) {
        ($val,$binary) = _extract_next_keypart($binary);
        if (!defined($val)) {
            $self->error("key structure length/val error");
            return undef;
        }
        push @{$self->{fields}}, $val;
    }

    # TODO - check the none name fields against correct values?

    # TODO - check number of fields found
    # - escda == 3?
    # - ssh-rsa == 6?

    $self->{encoded} = $encoded;
    $self->{type} = $self->{fields}[0];

    delete $self->{error};
    return $self;
}

# get the type of the key
sub type {
    my $self = shift;
    return $self->{type};
}

# TODO
# sub is_weak
#   however, "weak" might be a site-dependant value
# sub check_keytype
#   ensure that the type is on the list of ssh supported key types
#   (probably should be done as part of the parse)

# get/set error message
sub error {
    my $self = shift;
    my $message = shift;
    if (defined($message)) {
        $self->{error} = $message;
    }
    return $self->{error};
}

# Return a list of valid ssh key types
sub _keytypes {
    my @list = `ssh -Q key 2>/dev/null`;

    if (!scalar(@list)) {
        # if the ssh is too old to support this query, use a hardcoded list
        @list = qw(
            ssh-dss
            ssh-rsa
            ecdsa-sha2-nistp256
        );
    }

    for my $i (@list) {
        chomp $i;
    }

    return @list;
}

# Given a binary key fragment, extract the next chunk
sub _extract_next_keypart {
    my ($binary) = @_;

    if (length($binary)<4) {
        # not even room for the length field
        return undef;
    }

    my ($len) = unpack('N',$binary);
    my ($val) = unpack('N/a',$binary);

    if ($len>length($val)) {
        # this length value ran us off the end of the binary
        return undef;
    }

    return ($val,substr($binary,$len+4));
}



1;
