package pf::ConfigStore::Profile;

=head1 NAME

pf::ConfigStore::Profile add documentation

=cut

=head1 DESCRIPTION

pf::ConfigStore::Profile

=cut

use Moo;
use namespace::autoclean;
use pf::config;

use pf::ConfigStore;

extends 'pf::ConfigStore';
with 'pf::ConfigStore::Role::ValidGenericID';

=head1 METHODS

=head2 _buildCachedConfig

=cut

sub _buildCachedConfig { $cached_profiles_config }

=head2 remove

Delete an existing item

=cut

sub remove {
    my ($self,$id) = @_;
    if ($id eq 'default') {
        return undef ;
    }
    return $self->SUPER::remove($id);
}

=head2 cleanupAfterRead

Clean up switch data

=cut

sub cleanupAfterRead {
    my ($self, $id, $profile) = @_;
    $self->expand_list($profile, $self->_fields_expanded);
}

=head2 cleanupBeforeCommit

Clean data before update or creating

=cut

sub cleanupBeforeCommit {
    my ($self, $id, $profile) = @_;
    $self->flatten_list($profile, $self->_fields_expanded);
}

=head2 _fields_expanded

=cut

sub _fields_expanded {
    return qw(sources filter locale mandatory_fields allowed_devices provisioners scans);
}

__PACKAGE__->meta->make_immutable;

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

