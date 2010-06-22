#!/usr/bin/perl -w

use strict;
use warnings;
use diagnostics;

use File::Basename qw(basename);
use Benchmark;
use Test::MockModule;

use lib '/usr/local/pf/lib';
use pf::config;
use pf::flow::custom;

Log::Log4perl->init("/usr/local/pf/t/log.conf");
my $logger = Log::Log4perl->get_logger( basename($0) );
Log::Log4perl::MDC->put( 'proc', basename($0) );
Log::Log4perl::MDC->put( 'tid',  0 );

my $configfile = "/usr/local/pf/t/data/netflow.conf";
my ($illegal, $valid_dns, $valid_http);

# Profiling variables for use with
# perl -d:SmallProf
#%DB::packages = ('main' => 1, 'pf::flow' => 1);
#$DB::drop_zeros = 1;

my $flow = new pf::flow::custom();
our %netflow_conf = $flow->read_netflow_conf($configfile)
    or $logger->logdie("Problem reading $configfile. See logs for details.");

setup();
    
# Mocking violation_trigger to avoid triggering real violations
my $mock = new Test::MockModule('pf::flow');
$mock->mock('violation_trigger', sub { return 1; });

print $flow->flowToString($valid_dns) . "\n";
print $flow->flowToString($valid_http) . "\n";
print $flow->flowToString($illegal) . "\n";

timethis(1000,
    sub {
        $flow->parseFlow($valid_dns);
        $flow->parseFlow($valid_http);
        $flow->parseFlow($illegal);
    },
    "matching speed"
);

=item setup

Prepare environment for testing.

=cut
sub setup {
    $illegal = {
        11 => "\24f",
        21 => "\13\366\354\200",
        7 => "\370C",
        17 => "\0\0",
        2 => "\0\0\0\2",
        48 => "\0",
        22 => "\13\366\354\\",
        1 => "\0\0\0\315",
        16 => "\0\0",
        13 => "\0",
        6 => "\30",
        57 => "\0\36\276\212\245\@",
        61 => "\0",
        9 => "\30",
        51 => "\0",
        "SetId" => 256,
        12 => "J}_}",
        14 => "\0\1",
        15 => "DC(Q",
        8 => "\300\250\1i",
        4 => "\6",
        56 => "\0\37[\350\270O",
        10 => "\0\f",
        5 => "\0"
    };
    
    $valid_dns = {
        11 => "\0005",
        21 => "\13\367 \314",
        7 => "\311_",
        17 => "\0\0",
        2 => "\0\0\0\1",
        48 => "\0",
        22 => "\13\367 \314",
        1 => "\0\0\0V",
        16 => "\0\0",
        13 => "\30",
        6 => "\20",
        57 => "\0\0\0\0\0\0",
        61 => "\0",
        9 => "\30",
        51 => "\0",
        "SetId" => 256,
        12 => "\300\250\1\1",
        14 => "\0\0",
        15 => "\0\0\0\0",
        8 => "\300\250\1i",
        4 => "\21",
        56 => "\0\37[\350\270O",
        10 => "\0\f",
        5 => "\30"
    };
    
    $valid_http = {
        11 => "\0P",
        21 => "\13\367\232\204",
        7 => "\304~",
        17 => "\0\0",
        2 => "\0\0\0\1",
        48 => "\0",
        22 => "\13\367\232\204",
        1 => "\0\0\0(",
        16 => "\0\0",
        13 => "\0",
        6 => "\24",
        57 => "\0\36\276\212\245\@",
        61 => "\0",
        9 => "\30",
        51 => "\0",
        "SetId" => 256,
        12 => "\317\253\3\6",
        14 => "\0\1",
        15 => "DC(Q",
        8 => "\300\250\1i",
        4 => "\6",
        56 => "\0\37[\350\270O",
        10 => "\0\f",
        5 => "\0"
    };
}
