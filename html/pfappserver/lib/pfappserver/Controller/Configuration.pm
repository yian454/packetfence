package pfappserver::Controller::Configuration;

=head1 NAME

pfappserver::Controller::Configuration - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=cut

use strict;
use warnings;

use Date::Parse;
use HTTP::Status qw(:constants is_error is_success);
use Moose;
use namespace::autoclean;
use POSIX;
use URI::Escape::XS;
use Log::Log4perl qw(get_logger);

use pf::os;
use pf::util qw(load_oui download_oui);
# imported only for the $TIME_MODIFIER_RE regex. Ideally shouldn't be
# imported but it's better than duplicating regex all over the place.
use pf::config;
use pf::admin_roles;
use pfappserver::Form::Config::Pf;

BEGIN {extends 'pfappserver::Base::Controller'; }

=head1 METHODS

=cut

=head2 _process_section

=cut

our %ALLOWED_SECTIONS = (
    general => undef,
    network => undef,
    trapping => undef,
    registration => undef,
    guests_self_registration => undef,
    guests_admin_registration => undef,
    billing => undef,
    alerting => undef,
    scan => undef,
    maintenance => undef,
    expire => undef,
    services => undef,
    vlan => undef,
    inline => undef,
    servicewatch => undef,
    captive_portal => undef,
    advanced => undef,
    provisioning => undef,
    webservices => undef,
    active_active => undef,
);


=head2 index

=cut

sub index :Path :Args(0) { }


=head2 section

The generic handler for all pf sections

=cut

sub section :Path :Args(1) :AdminRole('CONFIGURATION_MAIN_READ') {
    my ($self, $c, $section) = @_;
    my $logger = get_logger();
    if (exists $ALLOWED_SECTIONS{$section} ) {
        my ($params, $form);
        my ($status,$status_msg,$results);

        $c->stash->{section} = $section;

        my $model = $c->model('Config::Pf');
        $form = $c->form("Config::Pf", section => $section);
        if ($c->request->method eq 'POST') {
            if(admin_can([$c->user->roles], 'CONFIGURATION_MAIN_UPDATE')) {
                $form->process(params => $c->req->params);
                $logger->info("Processed form");
                if ($form->has_errors) {
                    $status = HTTP_PRECONDITION_FAILED;
                    $status_msg = $form->field_errors;
                } else {
                    ($status,$status_msg) = $model->update($section, $form->value);
                    if (is_success($status)) {
                        ($status,$status_msg) = $model->commit();
                    }
                }
            } else {
                $c->response->status(HTTP_UNAUTHORIZED);
                $c->stash->{status_msg} = "You don't have the rights to perform this action.";
                $c->stash->{current_view} = 'JSON';
                $c->detach();
            }
        } else {
            ($status,$results) = $model->read($section);
            if (is_success($status)) {
                $form->process(init_object => $results);
                $c->stash->{form} = $form;
            } else {
                $status_msg = $results;
            }
        }
        $c->log->info("status $status");
        if(is_error($status)) {
            $c->stash(
                current_view => 'JSON',
                status_msg => $status_msg
            );
        }
        $c->response->status($status);
    } else {
        $c->go('Root','default');
    }
}

=head2 duration

Given the number of seconds since the Epoch and a trigger, returns the formatted end date.

=cut

sub duration :Local :Args(2) {
    my ($self, $c, $time, $trigger) = @_;

    my $status = HTTP_PRECONDITION_FAILED;
    if ($time && $trigger) {
        my $duration = access_duration($trigger, $time);
        if ($duration) {
            $status = HTTP_OK;
            $c->stash->{status_msg} = $duration;
        }
    }
    $c->stash->{current_view} = 'JSON';
    $c->response->status($status);
}

=head2 interfaces

=cut

sub interfaces :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Interface', 'index');
}

=head2 switches

=cut

sub switches :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Config::Switch', 'index');
}

=head2 floating_devices

=cut

sub floating_devices :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Config::FloatingDevice', 'index');
}

=head2 authentication

=cut

sub authentication :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Authentication', 'index');
}

=head2 users

=cut

sub users :Local {
    my ($self, $c) = @_;

    $c->go('Controller::User', 'create');
}

=head2 violations

=cut

sub violations :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Violation', 'index');
}

=head2 soh

=cut

sub soh :Local {
    my ($self, $c) = @_;

    $c->go('Controller::SoH', 'index');
}

=head2 roles

=cut

sub roles :Local {
    my ($self, $c) = @_;

    $c->go('Controller::Roles', 'index');
}

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

__PACKAGE__->meta->make_immutable;

1;
