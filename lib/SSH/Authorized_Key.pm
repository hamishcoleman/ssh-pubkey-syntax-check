package SSH::Authorized_Key;
use warnings;
use strict;
#
# Read ssh authorized_key file lines and parse the contents
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
        $self->error("Missing authorized_keys line");
        return undef;
    }

# from sshd(8):
#  Each line of the file contains one key (empty lines and lines starting
#  with a ‘#’ are ignored as comments).

#  Note that lines in this file can be several hundred bytes long (because
#  of the size of the public key encoding) up to a limit of 8 kilobytes,
#  which permits DSA keys up to 8 kilobits and RSA keys up to 16 kilobits.

    if (length($line) > (8*1024)) {
        $self->error("Line is too long");
        return undef;
    }

#  Public keys consist of the following space-separated fields:
#   options, keytype, base64-encoded key, comment.

    my @f = split(/ /,$line);

#  The options field is optional.
#
#  The keytype is "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
#  "ecdsa-sha2-nistp521", "ssh-ed25519", "ssh-dss" or "ssh-rsa"

    # We could fully check the keytype is valid here, but that is better
    # done in the SSH::Key module.
    #
    # We just want to check enough to see if this line might be prefixed
    # with an option field

    if ($f[0] !~ m/^ssh-/ and $f[0] !~ m/^ecdsa-/) {
        # doesnt look like any of the known keytypes, so it must be an option
        my $options_str = shift @f;

        # TODO - properly check the options field
        $self->error("processing the options field is not implemented");
        return undef;
    }

#  The options (if present) consist of comma-separated option specifica‐
#  tions.  No spaces are permitted, except within double quotes.  The fol‐
#  lowing option specifications are supported (note that option keywords are
#  case-insensitive):

    #  agent-forwarding no-agent-forwarding
    #  cert-authority
    #  command="command"
    #  environment="NAME=value"
    #  from="pattern-list"
    #  permitopen="host:port"
    #  port-forwarding no-port-forwarding
    #  principals="principals"
    #  pty no-pty
    #  restrict
    #  tunnel="n"
    #  user-rc no-user-rc
    #  X11-forwarding no-X11-forwarding

    # so check for the right number of fields
    if (scalar(@f)<3) {
        $self->error("Too few fields");
        return undef;
    }


    $self->{key_type} = $f[0];
    $self->{key} = $f[1];
    delete $self->{error};

    return 1;
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

