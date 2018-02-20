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

1;
