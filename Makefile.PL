use ExtUtils::MakeMaker;
use ExtUtils::Manifest qw(maniread);

BEGIN { require 5.004 }

sub chk_version {
    my ($pkg, $wanted) = @_;

    $! = 1;
    print "Checking for $pkg...";

    eval { 
        my $p; 
        ($p = $pkg.".pm") =~ s#::#/#g; 
        require $p;
    };

    my $vnum = ${"${pkg}::VERSION"} || 0;
    my $vstr = $vnum ? "found v$vnum"
                     : "not found";

    print $vnum >= $wanted ? "ok\n" : " " . $vstr . "\n";

    $vnum >= $wanted;
}

#--- Check for libapreq
my $libapreq_warning = "\n"
    ."You need libapreq version 0.31 or later to install this module\n"
    ."Look on CPAN for CPAN/modules/by-module/Apache/libapreq-0.31.tar.gz\n\n";
chk_version( 'Apache::Request' => 0.31 ) or die $libapreq_warning;
chk_version( 'Apache::Cookie' => 0.01 ) or die $libapreq_warning;

chk_version( 'DBI' => 0 ) or 
    die "\n"
    ."You need to have DBI installed in order to install this module\n\n";

chk_version( 'Digets::MD5' => 0 ) or 
    die "\n"
    ."You need to have Digetst::MD5 installed in order to "
    ."install this module\n\n";

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME          => 'Apache::TicketAccess',
    VERSION_FROM  => 'TicketAccess.pm',
    AUTHOR        => 'Michael Schout <mschout@gkg.net>',
    ABSTRACT      => 'Ticket based authentication system for Apache'
);
