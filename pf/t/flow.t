#!/usr/bin/perl -w

use strict;
use warnings;
use diagnostics;

use File::Basename qw(basename);
Log::Log4perl->init("/usr/local/pf/t/log.conf");
my $logger = Log::Log4perl->get_logger( basename($0) );
Log::Log4perl::MDC->put( 'proc', basename($0) );
Log::Log4perl::MDC->put( 'tid',  0 );

use Test::More tests => 21;

# FIXME change this!
use lib '../lib';
use pf::config;

BEGIN { 
    use_ok('pf::flow'); 
    use_ok('pf::flow::custom');
}

# test the object
my $flow = new pf::flow::custom();
isa_ok($flow, 'pf::flow');

# subs
# TODO fill in subs
can_ok($flow, qw(
    ipFilter
    portFilter
));

# --- ipFilter working cases ---
# Match a full IP
ok($flow->ipFilter('10.66.0.100', '10.66.0.100'), "ipFilter matching an IP");

# Match with full wildcard
ok($flow->ipFilter('10.66.0.100', '*'), "ipFilter matching with full IP wildcard");

# Match with group wildcard
ok($flow->ipFilter('10.66.0.100', '*.66.0.100'), "ipFilter matching with group IP wildcard first group");
ok($flow->ipFilter('10.66.0.100', '10.*.0.100'), "ipFilter matching with group IP wildcard second group");
ok($flow->ipFilter('10.66.0.100', '10.66.*.100'), "ipFilter matching with group IP wildcard third group");
ok($flow->ipFilter('10.66.0.100', '10.66.0.*'), "ipFilter matching with group IP wildcard fourth group");
ok($flow->ipFilter('10.66.0.100', '*.66.0.*'), "ipFilter matching with group IP wildcard multi-match");

# Match with digit wildcard
ok($flow->ipFilter('10.66.0.100', '10.*6.0.100'), "ipFilter matching digit wildcard");

# --- ipFilter trying to trick the system ---
# Making sure . is not intepreted as regexp .
ok(!$flow->ipFilter('10.66.09100', '10.66.0.100'), "ipFilter . not interpreted as regexp");
ok(!$flow->ipFilter('10.66.0.100', '10.66.09100'), "ipFilter . not interpreted as regexp (case 2)");

# tricking wildcard
ok(!$flow->ipFilter('10.6.0.100', '10.*6.0.100'), "ipFilter weird wildcard");

# --- portFilter working cases ---
# Match a full IP
ok($flow->portFilter('80', '80'), "portFilter matching a port");

# Match with wildcard
ok($flow->portFilter('80', '*'), "portFilter matching a port with wildcard");

# Match with comma seperator
ok($flow->portFilter('100', '22,23,25,100,135'), "portFilter matching a port in a comma-seperated portlist");

# Match with list expansion
ok($flow->portFilter('25', '22-26,135'), "portFilter matching a port in a list expansion (xxx-xxx) portlist");

# --- trying to trick the system ---
# Making sure a port which is a subset of another port doesn't match
# 100 in 22,23,25,100,135 but not in 10,1000,1443 or 1100,1443
ok(!$flow->portFilter('100', '10,1000,1443'), "portFilter shouldn't match but 100 is in 1000");
ok(!$flow->portFilter('100', '1100,1443'), "portFilter shouldn't match but 100 is in 1100");
