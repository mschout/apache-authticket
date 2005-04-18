use ExtUtils::MakeMaker;

BEGIN { require 5.6.0 }

WriteMakefile(
    NAME          => 'Apache::AuthTicket',
    VERSION_FROM  => 'lib/Apache/AuthTicket.pm',
    AUTHOR        => 'Michael Schout <mschout@gkg.net>',
    ABSTRACT      => 'Ticket based authentication system for Apache',
    PREREQ_PM     => {
        'Apache::AuthCookie' => '3.0',
        'DBI'                => 0,
        'Digest::MD5'        => 0
    }
);

# :vim set ts=4 sw=4 ai et
