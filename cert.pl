use strict;
use Time::Piece;
use Xymon::Plugin::Server::Dispatch;
use Xymon::Plugin::Server::Status qw(:colors);
my $t = localtime;
my $today = $t->julian_day;
sub cert_test {
    my ($host, $test, $ip) = @_;
    my $color = 'red';
    my $expired_days = 0;
    my $status = Xymon::Plugin::Server::Status->new($host, $test);
    my $port = 443;
    
    my $cmd = "true | openssl s_client -connect $host:$port 2>/dev/null | openssl x509 -noout -issuer -subject -dates";
    my $log = `$cmd`;
    eval { 
      if($log =~ /notAfter\=(\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)/) {
          my $cert_day = Time::Piece->strptime($1,'%b %d %H:%M:%S %Y');
          $expired_days = $cert_day->julian_day - $today;
          if ($expired_days < 30) {
             $color = 'red'; $log = $log . " $expired_days";
          } else { 
             $color = 'green'; $log = $log . " $expired_days"; 
          }
        }
       };
        $status->add_status($color, "$host: $log");
        $status->report;
    }

my $dispatch = Xymon::Plugin::Server::Dispatch
    ->new(cert => \&cert_test);

$dispatch->run;
