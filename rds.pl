use strict;

use Xymon::Plugin::Server::Dispatch;
use Xymon::Plugin::Server::Status qw(:colors);

sub rds_test {
    my ($host, $test, $ip) = @_;

    my $status = Xymon::Plugin::Server::Status->new($host, $test);
    my $log = `grep $host /usr/lib/xymon/server/ext/rds.log`;
    if ($log =~ /stopped/) {
        $status->add_status(GREEN, "$host: $log");
    }else {
        $status->add_status(RED, "$host: $log");
    }
    $status->report;
}

my $dispatch = Xymon::Plugin::Server::Dispatch
    ->new(rds => \&rds_test);

$dispatch->run;
