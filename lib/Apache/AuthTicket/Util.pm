# internal utility functions for Apache::AuthTicket and Apache2::AuthTicket
package Apache::AuthTicket::Util;

use strict;
use Digest::MD5 ();

# convert recognized true/false aliases to boolean. Multiple strings may be passed and the
# first defined one will be converted.  If none of the strings are defined,
# undef is returned.
sub str_config_value {
    for my $value (@_) {
        next unless defined $value;

        my $test = lc $value;

        # convert booleans to 1/0
        if ($test =~ /^(?:1|on|yes|true)$/) {
            return 1;
        }
        elsif ($test =~ /^(?:0|off|no|false)$/) {
            return 0;
        }
        else {
            # return value unchanged.
            return $value;
        }
    }

    return;
}

# compute a hash for the given values.
sub hash_for {
    return Digest::MD5::md5_hex(@_);
}

sub user_agent {
    my $r = shift;
    return $ENV{HTTP_USER_AGENT} || $r->headers_in->{'User-Agent'} || '';
}

1;
