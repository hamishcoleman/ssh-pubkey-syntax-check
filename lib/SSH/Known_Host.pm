package SSH::Known_Host;
use warnings;
use strict;
#
# Parse SSH Known Host lines.
#

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

# get/set error message
sub error {
    my $self = shift;
    my $message = shift;
    if (defined($message)) {
        $self->{error} = $message;
    }
    return $self->{error};
}

sub parse {
    my $self = shift;
    my $line = shift;

    if (!defined($line)) {
        $self->error("Missing ssh known host line");
        return undef;
    }

# from sshd(8):
#  Each line in these files contains the following fields: markers
#  (optional), host-names, bits, exponent, modulus, comment.  The fields
#  are separated by spaces.
#
# This is partially inaccurate: markers,host-names,type,encoded,comment is the
# observed format

    my @f = split(/ /,$line);

#  The marker is optional, but if it is present then it must be one of
#  "@cert-authority", to indicate that the line contains a certification
#  authority (CA) key, or "@revoked", to indicate that the key contained
#  on the line is revoked and must not ever be accepted.  Only one marker
#  should be used on a key line.

    if ($f[0] =~ m/^@/) {
        # this is a marker field
        # TODO - should we confirm that it is one of the two allowed values?
        shift @f;
    }

#  The optional comment field continues to the end of the line, and is
#  not used.
# TODO - optionally look at the comment (and perhaps complain)

    # We now know that there is no marker, so check for enough fields
    if (scalar(@f)<3) {
        $self->error("Too few fields");

        # Without enough fields, we cannot really continue checking
        return undef;
    }

    $self->{key_type} = $f[1];

#  Hashed hostnames start with a "|" character.  Only one hashed hostname
#  may appear on a single line and none of the above negation or wildcard
#  operators may be applied.

    if ($f[0] =~ m/^\|/) {
        # this is a hashed hostname
        $self->{hostname} = $f[0];
        push @{$self->{hostnames}}, $f[0];

        if ($f[0] =~ m/[*?!,]/) {
            $self->error("Invalid operators in hashed hostname");
            return undef;
        }

        # TODO - could check the fields internal to the hashed value

    } else {
        my @hosts = split(/,/,$f[0]);

        # we use the first hostname on the line to reference this in messages
        $self->{hostname} = $hosts[0];
        $self->{hostnames} = \@hosts;

#  A hostname or address may optionally be enclosed within "[" and "]"
#  brackets then followed by ":" and a non-standard port number.

        for my $host (@hosts) {
            if ($host =~ m/\[/) {
                # if there is a square bracket anywhere in the hostname,
                # it must conform to the whole pattern

                if ($host !~ /^\[[^]]+]:\d+/) {
                    $self->error("Invalid non-standard port number");
                    return undef;
                }
            }
        }
    }

    $self->{key} = $f[2];
    delete $self->{error};

    return 1;
}

sub hostname {
    my $self = shift;
    return $self->{hostname};
}

sub hostnames {
    my $self = shift;
    return @{$self->{hostnames}};
}

sub key_type {
    my $self = shift;
    return $self->{key_type};
}

sub key {
    my $self = shift;
    return $self->{key};
}

1;
