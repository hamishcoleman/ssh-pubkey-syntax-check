package SSH::Keys;
use warnings;
use strict;
#
#
#

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
