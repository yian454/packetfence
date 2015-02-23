package pfappserver::Form::Config::Scan::WMI;

=head1 NAME

pfappserver::Form::Config::Scan::WMI - Web form to add a WMI Scan Engine

=head1 DESCRIPTION

Form definition to create or update a WMI Scan Engine.

=cut

use HTML::FormHandler::Moose;
extends 'pfappserver::Form::Config::Scan';
with 'pfappserver::Base::Form::Role::Help';

use pf::config;
use pf::util;
use File::Find qw(find);

## Definition
has 'roles' => (is => 'ro', default => sub {[]});

has_field 'domain' =>
  (
   type => 'Text',
   label => 'Domain',
   required => 1,
   messages => { required => 'Please specify the windows domain' },
  );

has_field 'type' =>
  (
   type => 'Hidden',
  );

has_block definition =>
  (
   render_list => [ qw(id type username domain password categories oses duration registration dot1x dot1x_type rules) ],
  );

has_field 'wmi_policy' =>
  (
   type => 'Text',
   label => 'WMI client policy',
   tags => { after_element => \&help,
             help => 'Name of the policy to use' },
  );


has_field 'oses' =>
  (
   type => 'Hidden',
   label => 'OS',
   default => 'Windows',
  );


has_field 'rules' =>
(
    'type' => 'DynamicTable',
    'sortable' => 1,
    'do_label' => 0,
);

has_field 'rules.contains' =>
(
    type => 'Select',
    options_method => \&options_wmirules,
    widget_wrapper => 'DynamicTableRow',
);

=head2 options_wmirules

Returns the list of wmi rules to be displayed

=cut

sub options_wmirules {
    return  map { { value => $_, label => $_ } } @{pf::ConfigStore::WMI->new->readAllIds};
}

=over

=back

=head1 COPYRIGHT

Copyright (C) 2014 Inverse inc.

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
