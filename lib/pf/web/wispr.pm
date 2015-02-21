#!/usr/bin/perl
package pf::web::wispr;

=head1 NAME

pf::web::wispr - wispr implementation in mod_perl

=cut

=head1 DESCRIPTION

pf::web::wispr return xml when your authentication is success or failure.

=cut

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::Request;
use Apache2::Access;
use Apache2::Connection;
use Apache2::Const;
use Log::Log4perl;
use Template;

use pf::authentication;
use pf::config;
use pf::iplog qw(ip2mac);
use pf::node;
use pf::web;
use pf::Portal::Session;
use pf::util;
use pf::locationlog;
use pf::enforcement qw(reevaluate_access);

=head1 SUBROUTINES

=over

=item handler

The handler check in all authentication sources if the username and password are correct
and return an xml file to the wispr client

=cut

sub handler {

    my $r = (shift);
    my $req = Apache2::Request->new($r);
    my $logger = Log::Log4perl->get_logger('auth_handler');

    $logger->trace("hitting wispr");


    my $portalSession = pf::Portal::Session->new();
    my $mac;

    if (defined($portalSession->getGuestNodeMac)) {
        $mac = $portalSession->getGuestNodeMac;
    }
    else {
        $mac = $portalSession->getClientMac;
    }

    my $profile = pf::Portal::ProfileFactory->instantiate($mac);
    my @sources = ($profile->getInternalSources, $profile->getExclusiveSources );

    my $proto = isenabled($Config{'captive_portal'}{'secure_redirect'}) ? $HTTPS : $HTTP;

    my $response;
    my $template = Template->new({
        INCLUDE_PATH => [$CAPTIVE_PORTAL{'TEMPLATE_DIR'}],
    });

    my %info;
    my $pid;

    my $stash = {
        'code_result' => "100",
        'result' => "Authentication Failure",
    };

    # Trace the user in the apache log
    $r->user($req->param("username"));

    my ($return, $message, $source_id) = pf::authentication::authenticate( $req->param("username"), $req->param("password"), @sources );
    if ($return) {
        $logger->info("Authentification success for wispr client");
        $stash = {
                  'code_result' => "50",
                  'result' => "Authentication Success",
                 };


        $info{'pid'} = 'admin';
        $pid = $req->param("username") if (defined $req->param("username"));
        $r->pnotes->{pid}=$pid;
        $r->pnotes->{mac} = $mac;
        %info = (%info, (pid => $pid), (user_agent => $r->headers_in->{"User-Agent"}), (mac =>  $mac));
    }


    my $params = { username => $pid };

    my $locationlog_entry = locationlog_view_open_mac($mac);
    if ($locationlog_entry) {
        $params->{connection_type} = $locationlog_entry->{'connection_type'};
        $params->{SSID} = $locationlog_entry->{'ssid'};
    }

    my $source;
    # obtain node information provided by authentication module. We need to get the role (category here)
    # as web_node_register() might not work if we've reached the limit
    my $role = &pf::authentication::match([@sources], $params, $Actions::SET_ROLE, \$source);

    $logger->warn("Got role $role for username $pid");

    my $value = &pf::authentication::match([@sources], $params, $Actions::SET_ACCESS_DURATION);
    if (defined $value) {
        $logger->trace("No unregdate found - computing it from access duration");
        $value = access_duration($value);
    }
    else {
        $value = &pf::authentication::match([@sources], $params, $Actions::SET_UNREG_DATE);
        $value = pf::config::dynamic_unreg_date($value);
    }

    $logger->trace("Got unregdate $value for username $pid");

    if (defined $value) {
        %info = (
            'unregdate' => $value,
            'category' => $role,
            'pid' => $user_name,
            );
        if (defined $role) {
            %info = (%info, (category => $role));
        }
        # create a person entry for pid if it doesn't exist
        if ( !pf::person::person_exist($user_name) ) {
            $logger->info("creating person $user_name because it doesn't exist");
            pf::person::person_add($user_name);
            pf::lookup::person::lookup_person($user_name,$source);
        } else {
            $logger->debug("person $user_name already exists");
        }
        pf::person::person_modify($user_name,
           'source'  => $source,
           'portal'  => $profile->getName,
        );
        node_modify($mac,%info);
    }

    $r->pnotes->{info}=\%info;
    $template->process( "response_wispr.tt", $stash, \$response ) || $logger->error($template->error());
    $r->content_type('text/xml');
    $r->no_cache(1);
    $r->print($response);
    if (defined($pid)) {
        $r->handler('modperl');
        $r->set_handlers(PerlCleanupHandler => \&register);
    }
    return Apache2::Const::OK;

}

=item register

Register the node if the authentication was successfull

=cut

sub register {
    my $r = (shift);
    my $mac = $r->pnotes->{mac};
    node_register( $mac,$r->pnotes->{pid}, %{$r->pnotes->{info}} );
    reevaluate_access( $mac, 'manage_register' );
}

=back

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2015 Inverse inc.

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
