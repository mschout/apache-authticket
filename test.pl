use strict;
use Test::More;

plan tests => 1;

my $mp_version = mod_perl_version();

if ($mp_version == 1) {
    use_ok('Apache::AuthTicket');
}

if ($mp_version == 2) {
    use_ok('Apache2::AuthTicket');
}

sub mod_perl_version {
    eval {
        require mod_perl;
    };
    unless ($@) {
        if ($mod_perl::VERSION >= 1.99) {
            die "mod_perl 2.0 RC5 or later is required to use this module\n";
        }

        return 1;
    }

    eval {
        require mod_perl2;
    };
    unless ($@) {
        return 2;
    }

    die "mod_perl version $mod_perl::VERSION is not supported\n";
}
