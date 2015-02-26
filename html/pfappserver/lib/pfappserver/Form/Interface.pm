package pfappserver::Form::Interface;

=head1 NAME

pfappserver::Form::Interface - Web form for a network interface

=head1 DESCRIPTION

Form definition to create or update a network interface.

=cut

use HTML::FormHandler::Moose;

extends 'pfappserver::Base::Form';
with 'pfappserver::Base::Form::Role::Help';

# Form select options
has 'types' => ( is => 'ro' );

has_field 'name' =>
  (
   type => 'Hidden',
  );
has_field 'ipaddress' =>
  (
   type => 'IPAddress',
   label => 'IP Address',
  );
has_field 'netmask' =>
  (
   type => 'IPAddress',
   label => 'Netmask',
   element_attr => { 'placeholder' => '255.255.255.0' },
  );
has_field 'type' =>
  (
   type => 'Select',
   label => 'Type',
   element_class => ['chzn-deselect'],
   element_attr => { 'data-placeholder' => 'None' },
  );
has_field 'dns' =>
  (
   type => 'IPAddresses',
   label => 'DNS',
   wrapper_attr => { 'style' => 'display: none' },
   tags => { after_element => \&help,
             help => 'The primary DNS server of your network.' },
  );

has_field 'dhcpd_enabled' => 
   (
    type => 'Toggle',
    checkbox_value => 1,
    default => 1,
    label => 'Enable DHCP Server',
   );

has_field 'high_availability' => 
   (
    type => 'Toggle',
    checkbox_value => 1,
    unchecked_value => 0,
    default => 0,
   );

has_field 'vip' =>
  (
   type => 'IPAddress',
   label => 'Virtual IP Address',
  );

has_field 'nat_enabled' => (
    type => 'Toggle',
    checkbox_value => 1,
    unchecked_value => 0,
    default => 1,
    label => 'Enable NATting',
);

has_field 'active_active_enabled' => (
    type => 'Toggle',
    checkbox_value => 1,
    unchecked_value => 0,
    default => 0,
    label => 'Enable Active/Active',
);

has_field 'active_active_ip' => (
    type => 'IPAddress',
    label => 'Active/Active IP Address',
);

has_field 'active_active_members' => (
    type => 'IPAddresses',
    label => 'Active/Active ip members',
);

has_field 'active_active_dhcpd_master' => (
    type => 'Toggle',
    checkbox_value => 1,
    unchecked_value => 0,
    default => 0,
    label => 'Define dhcpd master',
);

=head2 options_type

=cut

sub options_type {
    my $self = shift;

    # $self->types comes from pfappserver::Model::Enforcement->getAvailableTypes
    my @types;
    if ( defined $self->types ) {
        for my $type ( @{$self->types} ) {
            # we remove inline, even though it may still be in pf.conf for backwards compatibility reasons.
            next if ($type eq 'inline' || $type eq 'inlinel3');
            push @types, ( $type => $self->_localize($type) );
        }
    }


    return ('none' => 'None', @types);
}

=head2 validate

Force DNS to be defined when the 'inline' type is selected

=cut

sub validate {
    my $self = shift;

    if (defined $self->value->{type} &&  
        ( $self->value->{type} eq 'inlinel2' or 
          $self->value->{type} eq 'inline' ) 
        ) {
        unless ($self->value->{dns}) {
            $self->field('dns')->add_error('Please specify your DNS server.');
        }
    }
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
