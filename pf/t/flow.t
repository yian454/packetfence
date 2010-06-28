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

use lib '/usr/local/pf/lib';
use pf::config;

BEGIN { 
    use_ok('pf::flow'); 
    use_ok('pf::flow::custom');
}

# test the object
my $flow = new pf::flow::custom();
isa_ok($flow, 'pf::flow');

# subs
can_ok($flow, qw(
    new
    processFlowPacket
    parseFlow
    matchFlowAgainstRules
    shouldDiscardFlow
    getSourceIP
    getDestIP
    getSourcePort
    getDestPort
    getSourceMAC
    getDestMAC
    flowToString
    read_netflow_conf
    getNetflowConf
    getRulesIdForCategory
    ipFilter
    portFilter
));

# processFlowPacket
# TODO: grab a raw packet with a template using Dumper mock parseFlow() and expect truth
# TODO: grab a raw packet without a template using Dumper mock parseFlow() and expect falsehood (undef)

# parseFlow
# an almost end-to-end test
setup();
my $configfile = "/usr/local/pf/t/data/netflow.conf";
our %netflow_conf = $flow->read_netflow_conf($configfile)
    or $logger->logdie("Problem reading $configfile. See logs for details.");
# TODO: flow that triggers onUncategorizedNode()
#       mock node_view to return an uncategorized node
#       mock onUncategorizedNode() with a weird return value expected by the test
# TODO: flow that triggers onAuthorizedFlow() (mock it with custom return value expected by the test)
# TODO: flow that triggers onUnauthorizedFlow() (mock it with custom return value expected by the test)
# TODO: flow that triggers onUnknownSource() (mock it with custom return value expected by the test)

# shouldDiscardFlow - should always return 0
#ok(!$flow->shouldDiscardFlow(undef, undef), "shouldDiscardFlow always returns 0 (default)");

# onAuthorizedFlow - should always return 1
#ok($flow->onAuthorizedFlow($node_info, $policy, $matched_rule, $flowRef), "onAuthorizedFlow always returns 1 (default)");

# onUnauthorizedFlow - should always return 1
# TODO: mock violation_trigger
#ok($flow->onUnauthorizedFlow($node_info, $policy, $matched_rule, $trigger, $flowRef), "onUnauthorizedFlow always returns 1 (default)");

# onUnknownSource - should always return undef
#ok(!$flow->onUnknownSource('aa:bb:cc:dd:ee:ff', $flowRef), "onUnknownSourc always returns undef (default)");

# onUncategorizedNode - should always return undef
#ok(!$flow->onUncategorizedNod($node_info, $flowRef), "onUncategorizedNode always returns undef (default)");

# FIXME: I am at matchFlowAgainstRules()

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
# Multiple range matches
ok($flow->portFilter('1000', '10-100,999-1005'), "portFilter with more than one range");

=item setup

Prepare environment for testing.

=cut
sub setup {
    our $illegal = {
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
    
    our $valid_dns = {
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
    
    our $valid_http = {
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
