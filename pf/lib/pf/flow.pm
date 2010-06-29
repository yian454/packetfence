package pf::flow;

=head1 NAME

pf::flow - Module that deals with everything netflow/IPFIX related

=head1 SYNOPSIS

The pf::flow module contains the functions necessary for flow processing.

All the behavior contained here can be overridden in lib/pf/flow/custom.pm.

=cut

use strict;
use warnings;
use diagnostics;

use Log::Log4perl;
use Net::Flow qw(decode) ;

#TODO not sure about these yet
#use pf::config;
#use pf::util;
use pf::node;
use pf::violation;

# load module's constants
use pf::flow::constants;

# Be careful with these since it won't be inherited by subclasses
# TODO: I should wrap them behind accessor methods
our $TemplateArrayRef = undef;
our $templateReceivedFlag = 0;

=head1 SUBROUTINES

=over

=cut

=item new

Get a new instance of the flow object
 
=cut
sub new {
    my $logger = Log::Log4perl::get_logger("pf::flow");
    $logger->debug("instantiating new pf::flow object");
    my ( $class, %argv ) = @_;
    my $this = bless {}, $class;
    return $this;
}

=item processFlowPacket

Parses a flow packet. It decompose it in several streams using Net::Flow then pass each stream to parseFlow() if a 
template exists.

Returns undef if no template has been received yet (since we cannot interpret the flow). Otherwise returns 1.

=cut
sub processFlowPacket {
    my ($this, $packet) = @_; 
    my $logger = Log::Log4perl->get_logger("pf::flow");

    my ($HeaderHashRef,$FlowArrayRef,$ErrorsArrayRef);
    ($HeaderHashRef, $TemplateArrayRef, $FlowArrayRef, $ErrorsArrayRef) = Net::Flow::decode($packet, $TemplateArrayRef);

    # TODO: ERROR-HANDLING of Net::Flow
    if (@{$ErrorsArrayRef}) {
        foreach my $error (@{$ErrorsArrayRef}) {
            if ($error =~ /^WARNING/) {
                $logger->trace("got a warning from Net::Flow::decode. Usually normal: $error.");
            } else {
                $logger->warn("Net::Flow::decode error: $error.");
            }
        }
    }

    if (!$templateReceivedFlag && @{$TemplateArrayRef}) {
        $logger->info("Received the template. Flows are now interpreted.");
        $templateReceivedFlag = 1;
    }

    if (!@{$TemplateArrayRef}) {
        $logger->debug("No template received yet. Can't parse the netflow/IPFIX until a template has been received");
        return;
    } 

    foreach my $flowRef (@{$FlowArrayRef}) {
        $this->parseFlow($flowRef);
    }
    return 1;
}


=item parseFlow

Analyzes one flow

=cut
sub parseFlow {
    my ($this, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    $logger->trace($this->flowToString($flowRef));
        
    # TODO naive implementation, caching will need to be involved for any of this to scale
    # for caching, the modern CHI (unpackaged) or less-modern Cache (packaged as perl-Cache) would be interesting
        
    # flows are always oriented LAN to WAN because of configuration provided
    # so src MAC is what we are looking to monitor
    my $srcMac = $this->getSourceMAC($flowRef);
    my $node_info = node_view($srcMac);
    if (defined($node_info) && ref($node_info) eq 'HASH') {

        # provide an external hook to discard flows here
        # for ex: if src or dst mac is 802.1X, it's ok
        if ($this->shouldDiscardFlow($node_info, $flowRef)) {
            return;
        }

        # match all flow rules based on category and apply them
        # TODO cache node's category or cache rules applicable to the node
        my $category = $node_info->{'category'};

        # TODO: is it really undef or '' when a node doesn't have a category assigned?
        if (!defined($category)) {
            return $this->onUncategorizedNode($node_info, $flowRef);
        }

        my $netflow_conf = $this->getNetflowConf();

        # if there are no section for this category, stop here
        if (!defined($netflow_conf->{$category})) {
            return $this->onNoSectionDefinedForCategory($node_info, $category, $flowRef);
        }

        # grabbing rules to apply for a node category
        my @rules = $this->getRulesIdForCategory($netflow_conf, $category);
        my $policy = $netflow_conf->{$category}->{'policy'};

        # rule matcher, will return first rule id that matches
        my $matched_rule = $this->matchFlowAgainstRules($flowRef, $netflow_conf, @rules);

        # match in whitelist is an authorized flow
        if ($matched_rule && $policy eq $POLICY::WHITELIST) {
            return $this->onAuthorizedFlow($node_info, $policy, $matched_rule, $flowRef);

        # match in blacklist is an unauthorized flow
        } elsif ($matched_rule && $policy eq $POLICY::BLACKLIST) {
            my $trigger = {
                'id' => $netflow_conf->{$category}->{'id'},
                'description' => $netflow_conf->{$category}->{'description'}
            };
            return $this->onUnauthorizedFlow($node_info, $policy, $matched_rule, $trigger, $flowRef);

        # no match in whitelist is an unauthorized flow
        } elsif (!$matched_rule && $policy eq $POLICY::WHITELIST) {
            my $trigger = { 
                'id' => $netflow_conf->{$category}->{'id'},
                'description' => $netflow_conf->{$category}->{'description'}
            };
            return $this->onUnauthorizedFlow($node_info, $policy, undef, $trigger, $flowRef);

        # no match in blacklist is an authorized flow
        } elsif (!$matched_rule && $policy eq $POLICY::BLACKLIST) {
            return $this->onAuthorizedFlow($node_info, $policy, undef, $flowRef);
        }
    } else {
        return $this->onUnknownSource($srcMac, $flowRef);
    }
}

=item shouldDiscardFlow

If it returns 1, the flow will be discarded and not processed. Meant to be overridden in pf::flow::custom with custom
behavior.

=cut
sub shouldDiscardFlow {
    my ($this, $node_info, $flowRef) = @_;

    return 0;
}

=item onAuthorizedFlow

Called when a flow is seen as authorized.
Meant to be easily overridden in pf::flow::custom with custom behavior.

=cut
sub onAuthorizedFlow {
    # $matched_rule will be undef if policy is blacklist
    my ($this, $node_info, $policy, $matched_rule, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    if ($policy eq $POLICY::WHITELIST) {
        $logger->debug("flow matched allowed rule id: \"$matched_rule\".");
    } else {
        $logger->debug("flow didn't match any blacklisted traffic pattern: allowed");
    }
    return 1;
}

=item onUnauthorizedFlow

Called when a flow is seen as unauthorized.
Meant to be easily overridden in pf::flow::custom with custom behavior.

=cut
sub onUnauthorizedFlow {
    # $matched_rule will be undef if policy is whitelist
    # $trigger is a hashref with id and description taken from netflow.conf
    my ($this, $node_info, $policy, $matched_rule, $trigger, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    if ($policy eq $POLICY::BLACKLIST) {
        $logger->debug("flow matched disallowed rule id: \"$matched_rule\".");
    } else {
        $logger->debug("flow didn't match any whitelisted traffic pattern: disallowed");
    }

    # TODO flowToString should be removed before release
    $logger->info("flow is not authorized according to rules! Reporting flow as a violation. "
        . "trigger id: " . $trigger->{'id'} . " "
        . "description: " . $trigger->{'description'} . " "
        . "flow details: " . $this->flowToString($flowRef)
    );

    violation_trigger($node_info->{'mac'}, $trigger->{'id'}, "flow");

    return 1;
}

=item onUnknownSource

Called when a source MAC is unknown to the system.
Meant to be easily overridden in pf::flow::custom with custom behavior.

=cut
sub onUnknownSource {
    my ($this, $srcMac, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    # TODO consider putting some parameter in pf.conf: netflow.violation_on_unknown_mac=enabled|disabled
    $logger->warn("Flow about a node unknown to PacketFence! MAC: $srcMac flow: ".$this->flowToString($flowRef));

    return;
}

=item onUncategorizedNode

Called when a node doesn't have a category.
Meant to be easily overridden in pf::flow::custom with custom behavior.

=cut
sub onUncategorizedNode {
    my ($this, $node_info, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    # TODO consider putting some parameter in pf.conf: netflow.violation_on_uncategorized_node=enabled|disabled
    $logger->debug("Flow about a node with no category");

    return;
}

=item onNoSectionDefinedForCategory

Called when a flow is detected and resolved to a category but the category doesn't have a section in the configuration.

Meant to be easily overridden in pf::flow::custom with custom behavior.

=cut
sub onNoSectionDefinedForCategory {
    my ($this, $node_info, $category, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    # TODO consider putting some parameter in pf.conf: netflow.violation_on_unmatched_flows=enabled|disabled
    $logger->debug("Flow without a category match in configuration file. Category: $category");

    return;
}

sub matchFlowAgainstRules {
    my ($this, $flowRef, $netflow_conf, @rules) = @_;

    # assume it doesn't match
    my $matches = 0;
    foreach my $rule_id (@rules) {

        my $srcip_match = $this->isIpInFilter($this->getSourceIP($flowRef), $netflow_conf->{$rule_id}->{'src_ip'});
        my $srcport_match = $this->isPortInFilter($this->getSourcePort($flowRef), $netflow_conf->{$rule_id}->{'src_port'});
        my $dstip_match = $this->isIpInFilter($this->getDestIP($flowRef), $netflow_conf->{$rule_id}->{'dst_ip'});
        my $dstport_match = $this->isPortInFilter($this->getDestPort($flowRef), $netflow_conf->{$rule_id}->{'dst_port'});

        if ($srcip_match && $srcport_match && $dstip_match && $dstport_match) {
            $matches = $rule_id;
        }
    }
    return $matches;
}

=item isIpInFilter

Tells if IP is listed in filter. Supported expressions are - and * (at the group level and at the single digit level).

=cut
sub isIpInFilter {
    my ($this, $ip, $filter) = @_;

    # processing ranges first. Altering the filter on match to reflect the IP value that matched.
    if ($filter =~ /\b\d+-\d+\b/) {
        $filter = $this->processIpRange($ip, $filter);
    }

    # TODO regexp pre-compilation could be useful: http://www.stonehenge.com/merlyn/UnixReview/col28.html
    # \Q..\E is to quote regexp characters in $filter so that ie . won't match
    if ($ip =~ /^\Q$filter\E$/) {
        # full IP match
        return 1;
    } elsif ($filter =~ /^\*$/) {
        # full wildcard match
        return 1;
    } elsif ($filter =~ /\*/) {
        # replace first group wildcard (*.x.x.x) in the filter, we change wildcard to match 1-999
        $filter =~ s'^\*\.'\d{1,3}.';
        # replace last group wildcard (x.x.x.*) in the filter, we change wildcard to match 1-999
        $filter =~ s'\.\*$'.\d{1,3}';
        # there's a group wildcard (x.*.x.x) in the filter, we change wildcard to match 1-999
        $filter =~ s'\.\*\.'.\d{1,3}.'g;
        # there's a single digit wildcard (x.*x.x.x) in the filter, we change wildcard to match single digit
        $filter =~ s'\*'\d'g;
        # quote the .
        $filter =~ s'\.'\.'g;
        if ($ip =~ /^$filter$/) {
            return 1;
        }
    }
    return 0;
}

=item isPortInFilter

Tells if port is listed in filter. Supported expressions are , * and -.

=cut
sub isPortInFilter {
    my ($this, $port, $filter) = @_;

    # TODO regexp pre-compilation could be useful: http://www.stonehenge.com/merlyn/UnixReview/col28.html
    # \Q..\E is to quote regexp characters in $filter so that ie . won't match
    if ($port =~ /^\Q$filter\E$/x) {
        # full port match
        return 1;
    } elsif ($filter =~ /^\*$/) {
        # full wildcard match
        return 1;
    } elsif ($filter =~ /\b$port\b/) {
        # match port directly into a longer expression but no expansion required yet (no dash)
        # ex: 100 in 22,23,25,100,135 but not in 10,1000,1443 or 1100,1443
        return 1;
    } elsif ($filter =~ /\b(\d+)-(\d+)\b/) {
        # here I will alter the filter removing each attempted range so I create a local copy
        my $f = $filter;
        # trying to match the port in all port ranges (destroying the range so loop iteration will match the next)
        while ($f =~ s/\b(\d+)-(\d+)\b//) {
            # matches xxx-xxx with correct boundaries
            if (($port >= $1) && ($port <= $2)) {
                return 1;
            }
        }
    }
    return 0;
}

=item processIpRange

Takes the range in a filter expression and transforms it if it matches to allow further filter procesing. 
For example: input filter 10.12-70.0.* with ip 10.66.0.100 will return 10.66.0.*

This is a very naive approach, I couldn't do better at the time. Feel free to suggest an improved version.

=cut
sub processIpRange {
    my ($this, $ip, $filter) = @_;

    my @ip_groups = split('\.', $ip);
    my @filter_groups = split('\.', $filter);

    # processing each group one at a time
    for (my $i = 0; $i < 4; $i++) {
        if ($filter_groups[$i] =~ /^(\d+)-(\d+)$/) {
            if ($ip_groups[$i] >= $1 && $ip_groups[$i] <= $2) {
                # replacing filter by actual IP for further processing
                $filter_groups[$i] = $ip_groups[$i];
            }
        }
    }
    return(join('.', @filter_groups));
}

# information about what is in flows in RFC3954 (see references)
sub getSourceIP {
    my ($this, $flowRef) = @_;
    return(join('.', unpack('CCCC', $flowRef->{8})));
}

sub getDestIP {
    my ($this, $flowRef) = @_;
    return(join('.', unpack('CCCC', $flowRef->{12})));
}

sub getSourcePort {
    my ($this, $flowRef) = @_;
    return(hex(unpack("H*", $flowRef->{7})));
}

sub getDestPort {
    my ($this, $flowRef) = @_;
    return(hex(unpack("H*", $flowRef->{11})));
}

sub getSourceMAC {
    my ($this, $flowRef) = @_;
    return(join(':', unpack('H2 H2 H2 H2 H2 H2', $flowRef->{56})));
}

sub getDestMAC {
    my ($this, $flowRef) = @_;
    return(join(':', unpack('H2 H2 H2 H2 H2 H2', $flowRef->{57})));
}

=item flowToString

Convenient little wrapper that will output the flow reference in the form: src ip:port (mac) <-> dst ip:port (mac)

=cut
sub flowToString {
    my ($this, $flowRef) = @_;

    return(
        $this->getSourceIP($flowRef) . ":" . $this->getSourcePort($flowRef)
        . " (" . $this->getSourceMAC($flowRef) . ")"
        . " <-> "
        . $this->getDestIP($flowRef) .":". $this->getDestPort($flowRef)
        . " (". $this->getDestMAC($flowRef) . ")"
    );
}

# I am not using these so far
# Size of flow: hex(unpack("H*",$flowRef->{1}));
# Next Hop Address: join('.', unpack('CCCC',$flowRef->{15}));

# Time-related (all time is epoch or sysUpTime related, not so sure)
# startdate: int($flowRef->{22}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
# enddate: int($flowRef->{21}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
# my $start_time = hex(unpack("H*", $flowRef->{22}));
# my $end_time = hex(unpack("H*", $flowRef->{21}));

=item read_netflow_conf

Reads all the rules

=cut
sub read_netflow_conf {
    my ($this, $configfile) = @_;
    my $logger = Log::Log4perl::get_logger('pf::flow');

    my %netflow_conf;
    tie %netflow_conf, 'Config::IniFiles', (-file => $configfile);

    my @errors = @Config::IniFiles::errors;
    if (@errors) {
        $logger->error("Error reading $configfile: " . join( "\n", @errors ) . "\n");
        return;
    }

    # TODO trim arguments
    # TODO perform validation (in an external sub?)
    # TODO validation: policy whitelist and policy blacklist cannot be mixed under same node category
    # TODO validation: a section per category with id=, then section with [category XXXX]
    # TODO validation: categories must exist (and be case-sensitive about it)
    # TODO validation: in IPs allow * and any variation of x.x.*.x but not x.x.* (missing group) or x.*x.x.x (subgroup)

    # TODO performance: precompute the hash in the form once measurements can be made
    # Category => id = 
    #          => desc = 
    #          => policy = 
    #          => 1001 => src_ip=.., src_port=.., etc.
    #          => 1002 => src_ip=.., src_port=.., etc.

    return %netflow_conf;
}

=item getNetflowConf

Simple accessor to encapsulate the way I currently store %netflow_conf

=cut
sub getNetflowConf {
    # provided by pfnetflow's main package, returning a ref to avoid copy
    # TODO: this causes a warning on compilation, is there a way to prevent it?
    return \%::netflow_conf;
}

sub getRulesIdForCategory {
    my ($this, $netflow_conf, $category) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");
 
    my @matching_rules;
    foreach my $rule_id (keys %{$netflow_conf}) {
        if ($rule_id =~ /^$category (\d+)$/i) {
            push(@matching_rules, $rule_id);
        }
    }
    $logger->trace("matched ".scalar(@matching_rules)." rules");
    return @matching_rules;
}

=back

=head1 BUGS AND LIMITATIONS

It's a feature preview

=head1 REFERENCES

=over

=item RFC3954 - Cisco Systems NetFlow Services Export Version 9

http://www.ietf.org/rfc/rfc3954.txt

=back

=head1 AUTHOR

Olivier Bilodeau <obilodeau@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2010 Inverse inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
