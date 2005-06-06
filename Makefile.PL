use ExtUtils::MakeMaker;

require 5.6.0;

my $mp_version = mod_perl_version();

my %prereq = (
    'DBI'           => 0,
    'Digest::MD5'   => 0,
    'SQL::Abstract' => 0,
    'Test::More'    => 0
);

if ($mp_version == 2) {
    $prereq{'Apache2::AuthCookie'} = '3.0';
}
else { # MP1
    $prereq{'Apache::AuthCookie'} = '3.0';
}

WriteMakefile(
    NAME          => 'Apache::AuthTicket',
    VERSION_FROM  => 'lib/Apache/AuthTicket.pm',
    AUTHOR        => 'Michael Schout <mschout@gkg.net>',
    ABSTRACT      => 'Ticket based authentication system for Apache',
    PREREQ_PM     => \%prereq
);

sub mod_perl_version {
    eval {
        require mod_perl2;
    };
    unless ($@) {
        return 2;
    }

    eval {
        require mod_perl;
    };
    unless ($@) {
        if ($mod_perl::VERSION >= 1.99) {
            # mod_perl 2 prior to RC5 (1.99_12 or earlier)
            die "mod_perl 2.0.0 RC5 or later is required for this module\n";
        }

        return 1;
    }

    die "mod_perl version $mod_perl::VERSION is not supported\n";
}

# :vim set ts=4 sw=4 ai et
