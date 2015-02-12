package captiveportal::PacketFence::Controller::Node::Manager;

use Moose;
use namespace::autoclean;
use pf::config;
use pf::node;
use pf::enforcement qw(reevaluate_access);

BEGIN {extends 'captiveportal::Base::Controller'; }

=head1 NAME

captiveportal::PacketFence::Controller::Node::Manager - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 index

=cut

sub unreg :Local :Args(1) {
    my ($self, $c, $mac) = @_;
    my $username = $c->session->{username};
    my $node = node_view($mac);
    if ($username && $node) {
        $c->log->info("$username attempting to unregister $mac");
        if (($username ne $default_pid || $username ne $admin_pid ) && $username eq $node->{pid}) {
            node_deregister($mac, %$node);
            reevaluate_access($mac, "node_modify");
            $c->response->redirect("/status");
            $c->detach;
        } else {
            $self->showError($c,"Not allowed to deregister $mac");
        }

    } else {
        $self->showError($c,"Not logged in or node ID $mac is not known");
    }
}


=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2014 Inverse inc.

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
