package pf::SNMP::AlliedTelesis;

=head1 NAME

pf::SNMP::AlliedTelesis - Object oriented module to access SNMP enabled AliedTelesis Switches

=head1 SYNOPSIS

The pf::SNMP::AlliedTelesis module implements an object oriented interface
to access SNMP enabled AlliedTelesis switches.

=head1 STATUS

=over 

=item Supports

=over

=item 802.1X/Mac Authentication without VoIP

=back

Stacked switch support has not been tested.

=back

Tested on a AT8000GS with firmware 2.0.0.26.

=head1 BUGS AND LIMITATIONS

The minimum required firmware version is 2.0.0.26.

Dynamic VLAN assignment on ports with voice is not supported by vendor.

=head1 CONFIGURATION AND ENVIRONMENT

F<conf/switches.conf>

=cut

use strict;
use warnings;
use Log::Log4perl;
use Net::SNMP;
use base ('pf::SNMP');

# importing switch constants
use pf::SNMP::constants;
use pf::util;
use pf::config;

=head1 SUBROUTINES

=over

=cut
# CAPABILITIES
# access technology supported
sub supportsWiredMacAuth { return $TRUE; }
sub supportsWiredDot1x { return $TRUE; }

=item getVersion

=cut
sub getVersion {
    my ($this) = @_;
    my $oid_alliedFirmwareVersion = '.1.3.6.1.4.1.89.2.4.0';
    my $logger = Log::Log4perl::get_logger( ref($this) );
    if ( !$this->connectRead() ) {
        return '';
    }
    $logger->trace(
        "SNMP get_request for oid_alliedFirmwareVersion: $oid_alliedFirmwareVersion"
    );
    my $result = $this->{_sessionRead}->get_request( -varbindlist => [$oid_alliedFirmwareVersion] );
    my $runtimeSwVersion = ( $result->{$oid_alliedFirmwareVersion} || '' );

    return $runtimeSwVersion;
}

sub parseTrap {
    my ( $this, $trapString ) = @_;
    my $trapHashRef;
    my $logger = Log::Log4perl::get_logger( ref($this) );

    #-- secureMacAddrViolation SNMP v1 & v2c
    if ( $trapString
        =~ /BEGIN VARIABLEBINDINGS \.1\.3\.6\.1\.4\.1\.89\.2\.3\.1\.0 = STRING:\s.*MAC\s([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}).*port\sg(\d{2})\s.*/ ) {

        $trapHashRef->{'trapType'} = 'secureMacAddrViolation';
        $trapHashRef->{'trapIfIndex'} = $2;
        $trapHashRef->{'trapMac'} = $1;
        $trapHashRef->{'trapVlan'} = $this->getVlan( $trapHashRef->{'trapIfIndex'} );

    } else {
        $logger->debug("trap currently not handled");
        $trapHashRef->{'trapType'} = 'unknown';
    }
    return $trapHashRef;
}

sub _setVlan {
    my ( $this, $ifIndex, $newVlan, $oldVlan, $switch_locker_ref ) = @_;
    my $logger = Log::Log4perl::get_logger( ref($this) );
    if ( !$this->connectRead() ) {
        return 0;
    }
    my $OID_dot1qPvid = '1.3.6.1.2.1.17.7.1.4.5.1.1';    # Q-BRIDGE-MIB
    my $OID_dot1qVlanStaticUntaggedPorts
        = '1.3.6.1.2.1.17.7.1.4.3.1.4';                  # Q-BRIDGE-MIB
    my $OID_dot1qVlanStaticEgressPorts
        = '1.3.6.1.2.1.17.7.1.4.3.1.2';                  # Q-BRIDGE-MIB
    my $result;

    $logger->trace( "locking - trying to lock \$switch_locker{"
            . $this->{_ip}
            . "} in _setVlan" );
    {
        lock %{ $switch_locker_ref->{ $this->{_ip} } };
        $logger->trace( "locking - \$switch_locker{"
                . $this->{_ip}
                . "} locked in _setVlan" );

        # get current egress and untagged ports
        $this->{_sessionRead}->translate(0);
        $logger->trace(
            "SNMP get_request for dot1qVlanStaticUntaggedPorts and dot1qVlanStaticEgressPorts"
        );
        $result = $this->{_sessionRead}->get_request(
            -varbindlist => [
                "$OID_dot1qVlanStaticEgressPorts.$oldVlan",
                "$OID_dot1qVlanStaticEgressPorts.$newVlan",
                "$OID_dot1qVlanStaticUntaggedPorts.$oldVlan",
                "$OID_dot1qVlanStaticUntaggedPorts.$newVlan"
            ]
        );

        # calculate new settings
        my $egressPortsOldVlan
            = $this->modifyBitmask(
            $result->{"$OID_dot1qVlanStaticEgressPorts.$oldVlan"},
            $ifIndex - 1, 0 );
        my $egressPortsVlan
            = $this->modifyBitmask(
            $result->{"$OID_dot1qVlanStaticEgressPorts.$newVlan"},
            $ifIndex - 1, 1 );
        my $untaggedPortsOldVlan
            = $this->modifyBitmask(
            $result->{"$OID_dot1qVlanStaticUntaggedPorts.$oldVlan"},
            $ifIndex - 1, 0 );
        my $untaggedPortsVlan
            = $this->modifyBitmask(
            $result->{"$OID_dot1qVlanStaticUntaggedPorts.$newVlan"},
            $ifIndex - 1, 1 );
        $this->{_sessionRead}->translate(1);

        # set all values
        if ( !$this->connectWrite() ) {
            return 0;
        }

        $logger->trace(
            "SNMP set_request for egressPorts and untaggedPorts for old and new VLAN "
        );
        $result = $this->{_sessionWrite}->set_request(
            -varbindlist => [
                "$OID_dot1qVlanStaticEgressPorts.$newVlan",
                Net::SNMP::OCTET_STRING,
                $egressPortsVlan,
                "$OID_dot1qVlanStaticUntaggedPorts.$newVlan",
                Net::SNMP::OCTET_STRING,
                $untaggedPortsVlan,
                "$OID_dot1qVlanStaticUntaggedPorts.$oldVlan",
                Net::SNMP::OCTET_STRING,
                $untaggedPortsOldVlan,
                "$OID_dot1qVlanStaticEgressPorts.$oldVlan",
                Net::SNMP::OCTET_STRING,
                $egressPortsOldVlan
            ]
        );
        if ( !defined($result) ) {
            print $this->{_sessionWrite}->error . "\n";
            $logger->error(
                "error setting egressPorts and untaggedPorts for old and new vlan: "
                    . $this->{_sessionWrite}->error );
        }
    }
    $logger->trace( "locking - \$switch_locker{"
            . $this->{_ip}
            . "} unlocked in _setVlan" );
    return ( defined($result) );
}

sub authorizeMAC {
    my ( $this, $ifIndex, $deauthMac, $authMac, $deauthVlan, $authVlan ) = @_;
    my $logger = Log::Log4perl::get_logger( ref($this) );

    # from Q-BRIDGE-MIB (RFC4363)
    my $OID_dot1qStaticUnicastStatus = '1.3.6.1.2.1.17.7.1.3.1.1.4';

    if ( !$this->isProductionMode() ) {
        $logger->info("not in production mode ... we won't add or delete a static entry in the MAC address table");  
        return 1;
    }

    if ( !$this->connectWrite() ) {
        return 0;
    }

    if ($deauthMac && !$this->isFakeMac($deauthMac)) {

        my $mac_oid = mac2oid($deauthMac);

        $logger->trace("SNMP set_request for OID_dot1qStaticUnicastStatus");
        my $result = $this->{_sessionWrite}->set_request( -varbindlist => [
            "$OID_dot1qStaticUnicastStatus.$deauthVlan.$mac_oid.$ifIndex", Net::SNMP::INTEGER, $SNMP::Q_BRIDGE::INVALID
        ]);
        $logger->info("Deauthorizing $deauthMac ($mac_oid) on ifIndex $ifIndex, vlan $deauthVlan");
    }

    if ($authMac && !$this->isFakeMac($authMac)) {

        my $mac_oid = mac2oid($authMac);

        $logger->trace("SNMP set_request for OID_dot1qStaticUnicastStatus");

        my $vlan = $this->getVlan($ifIndex);

        $logger->trace("SNMP set_request for $OID_dot1qStaticUnicastStatus");
        my $result = $this->{_sessionWrite}->set_request( -varbindlist => [
            "$OID_dot1qStaticUnicastStatus.$vlan.$mac_oid.$ifIndex", Net::SNMP::INTEGER, $SNMP::Q_BRIDGE::OTHER
        ]);
        $logger->info("Authorizing $authMac ($mac_oid) on ifIndex $ifIndex, vlan $vlan "
            . "(don't worry if VLAN is not ok, it'll be re-assigned later)");
    }
    return 1;
}

sub isPortSecurityEnabled {
    my ( $this, $ifIndex ) = @_;
    my $logger = Log::Log4perl::get_logger( ref($this) );

    my $OID_swIfLockOperStatus = '1.3.6.1.4.1.89.43.1.1.8';    # RADLAN swInterface MIB

    if ( !$this->connectRead() ) {
        return 0;
    }

    $logger->trace("SNMP get_request for OID_swIfLockOperStatus: $OID_swIfLockOperStatus.$ifIndex");
    my $result = $this->{_sessionRead}->get_request( -varbindlist => [ "$OID_swIfLockOperStatus.$ifIndex" ] );
    return ( exists(
             $result->{"$OID_swIfLockOperStatus.$ifIndex"} )
        && ( $result->{"$OID_swIfLockOperStatus.$ifIndex"} == 1 ) );
}

sub getSecureMacAddresses {
    my ( $this, $ifIndex ) = @_;
    my $logger = Log::Log4perl::get_logger( ref($this) );
    my $OID_dot1qStaticUnicastStatus = '1.3.6.1.2.1.17.7.1.3.1.1.4';

    my $secureMacAddrHashRef = {};
    if ( !$this->connectRead() ) {
        return $secureMacAddrHashRef;
    }

    $this->{_sessionRead}->translate(0);
    $logger->trace("SNMP get_table for dot1qStaticUnicastStatus: $OID_dot1qStaticUnicastStatus");
    my $result = $this->{_sessionRead}->get_table( -baseoid => "$OID_dot1qStaticUnicastStatus" );
    $this->{_sessionRead}->translate(1);

    while ( my $oid_including_mac = each( %{$result} ) ) {
       if ($oid_including_mac =~ 
            /^$OID_dot1qStaticUnicastStatus\.                               # query OID
            ([0-9]+)\.                                                             # <vlan>.
            ([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)   # MAC in OID format
            /x) {

            my $vlan = $1;
            my $mac = sprintf( "%02x:%02x:%02x:%02x:%02x:%02x", $2, $3, $4, $5, $6, $7 );
            push @{$secureMacAddrHashRef->{$mac}}, $vlan;
       }
    }
    return $secureMacAddrHashRef;
}

=back

=head1 AUTHOR

Francois Gaudreault <fgaudreault@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2012 Inverse Inc.

=head1 LICENSE

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
