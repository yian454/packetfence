package pfappserver::Form::Violation;

=head1 NAME

pfappserver::Form::Violation - Web form for a violation

=head1 DESCRIPTION

Form definition to create or update a violation.

=cut

use HTML::FormHandler::Moose;
extends 'pfappserver::Base::Form';
with 'pfappserver::Base::Form::Role::Help';

use HTTP::Status qw(:constants is_success);

use pf::action;

has '+field_name_space' => ( default => 'pfappserver::Form::Field' );
has '+widget_name_space' => ( default => 'pfappserver::Form::Widget' );
has '+language_handle' => ( builder => 'get_language_handle_from_ctx' );

# Form select options
has 'violations' => ( is => 'ro' );
has 'triggers' => ( is => 'ro' );
has 'templates' => ( is => 'ro' );
has 'roles' => (is => 'ro', default => sub {[]});
has 'placeholders' => ( is => 'ro' );

# Form fields
has_field 'enabled' =>
  (
   type => 'Toggle',
   widget => 'Switch',
   label => 'Enabled',
  );
has_field 'id' =>
  (
   type => 'Text',
   label => 'Identifier',
   messages => { required => 'Please specify an identifier for the violation.' },
   tags => { after_element => \&help,
             help => 'Use a number above 1500000 if you want to be able to delete this violation later.' },
  );
has_field 'desc' =>
  (
   type => 'Text',
   label => 'Description',
   required => 1,
   element_class => ['input-large'],
   messages => { required => 'Please specify a brief description of the violation.' },
  );
has_field 'actions' =>
  (
   type => 'Select',
   multiple => 1,
   label => 'Actions',
   localize_labels => 1,
   element_class => ['chzn-select', 'input-xxlarge'],
   element_attr => {'data-placeholder' => 'Click to add an action' }
  );
has_field 'vclose' =>
  (
   type => 'Select',
   label => 'Violation to close',
   element_class => ['chzn-deselect'],
   element_attr => {'data-placeholder' => 'Select a violation'},
   wrapper_attr => {style => 'display: none'},
   tags => { after_element => \&help,
             help => 'When selecting the <strong>close</strong> action, triggering the violation will close this violation. This is an experimental workflow for Mobile Device Management (MDM).' },
  );
has_field 'target_category' =>
  (
   type => 'Select',
   label => 'Set role',
   options_method => \&options_roles,
   element_class => ['chzn-deselect'],
   element_attr => {'data-placeholder' => 'Select a role'},
   wrapper_attr => {style => 'display: none'},
   tags => { after_element => \&help,
             help => 'When selecting the <strong>role</strong> action, triggering the violation will change the node to this role.' },
  );
has_field 'priority' =>
  (
   type => 'IntRange',
   label => 'Priority',
   range_start => 1,
   range_end => 10,
   tags => { after_element => \&help,
             help => 'Range 1-10, with 1 the higest priority and 10 the lowest. Higher priority violations will be addressed first if a host has more than one.' },
  );
has_field 'whitelisted_categories' =>
  (
   type => 'Select',
   multiple => 1,
   label => 'Whitelisted Roles',
   options_method => \&options_roles,
   element_class => ['chzn-select', 'input-xxlarge'],
   element_attr => {'data-placeholder' => 'Click to add a role'},
   tags => { after_element => \&help,
             help => 'Nodes with the selected roles won\'t be affected by a violation of this type.' },
  );
has_field 'trigger' =>
  (
   type => 'Select',
   multiple => 1,
   label => 'Triggers',
   element_class => ['chzn-select', 'input-xxlarge'],
   element_attr => {'data-placeholder' => 'Click to add a trigger' },
#   tags => { after_element => \&help,
#             help => 'Method to reference external detection methods such as Detect (SNORT), Nessus, OpenVAS, OS (DHCP Fingerprint Detection), USERAGENT (Browser signature), VENDORMAC (MAC address class), etc.' },
  );
has_field 'auto_enable' =>
  (
   type => 'Toggle',
   label => 'Auto Enable',
   tags => { after_element => \&help,
             help => 'Specifies if a host can self remediate the violation (enable network button) or if they can not and must call the help desk.' },
  );
has_field 'max_enable' =>
  (
   type => 'PosInteger',
   label => 'Max Enables',
   tags => { after_element => \&help,
             help => 'Number of times a host will be able to try and self remediate before they are locked out and have to call the help desk. This is useful for users who just <i>click through</i> violation pages.'},
  );
has_field 'grace' =>
  (
   type => 'Duration',
   label => 'Grace',
   tags => { after_element => \&help,
             help => 'Amount of time before the violation can reoccur. This is useful to allow hosts time (in the example 2 minutes) to download tools to fix their issue, or shutoff their peer-to-peer application.' },
  );
has_field 'window_dynamic' =>
  (
   type => 'Checkbox',
   label => 'Dynamic Window',
   checkbox_value => 'dynamic',
   tags => { after_element => \&help,
             help => 'Only works for accounting violations.  The violation will be opened according to the time you set in the accounting violation (ie. You have an accounting violation for 10GB/month.  If you bust the bandwidth after 3 days, the violation will open and the release date will be set for the last day of the current month).' },
  );
has_field 'window' =>
  (
   type => 'Duration',
   label => 'Window',
   tags => { after_element => \&help,
             help => 'Amount of time before a violation will be closed automatically. Instead of allowing people to reactivate the network, you may want to open a violation for a defined amount of time instead.' },
  );
has_field 'delay_by' =>
  (
   type => 'Duration',
   label => 'Delay By',
   tags => { after_element => \&help,
             help => "Delay before triggering the violation." },
  );
has_field 'template' =>
  (
   type => 'Select',
   label => 'Template',
   tags => { after_element => \&help,
             help => 'HTML template the host will be redirected to while in violation. You can create new templates from the <em>Portal Profiles</em> configuration section.' }
  );
has_field 'button_text' =>
  (
   type => 'Text',
   label => 'Button Text',
   tags => { after_element => \&help,
             help => 'Text displayed on the violation form to hosts.' },
  );
has_field 'vlan' =>
  (
   type => 'Select',
   label => 'VLAN',
   options_method => \&options_roles,
   element_class => ['chzn-deselect'],
   element_attr => {'data-placeholder' => 'Select a VLAN'},
   tags => { after_element => \&help,
             help => 'Destination VLAN where PacketFence should put the client when a violation of this type is open.' }
  );
has_field 'redirect_url' =>
  (
   type => 'Text',
   label => 'Redirection URL',
   tags => { after_element => \&help,
             help => 'Destination URL where PacketFence will forward the device. By default it will use the Redirection URL from the portal profile configuration.' }
  );
has_field 'external_command' =>
  (
   type => 'Text',
   label => 'External Command',
   element_class => ['input-large'],
   messages => { required => 'Please specify the command you want to execute.' },
  );

=head2 around has_errors

Ignore validation errors for the trigger select field. An error would occur if a new trigger is added from the Web
interface. In this case, this new value is not in the initial options list and would cause the form to throw an error.

=cut

around 'has_errors'  => sub {
    my ( $orig, $self ) = @_;

    if ($self->$orig()) {
        my @error_fields = $self->error_fields;
        if (scalar @error_fields == 1 && $error_fields[0]->name eq 'trigger') {
            return 0;
        }
    }

    return $self->$orig;
};

=head2 update_fields

For violations other than the default, add placeholders with values from default violation.

=cut

sub update_fields {
    my $self = shift;

    unless ($self->{init_object} && $self->init_object->{id} eq 'defaults') {
        if ($self->placeholders) {
            foreach my $field ($self->fields) {
                if ($self->placeholders->{$field->name} && length $self->placeholders->{$field->name}) {
                    if (!ref $self->placeholders->{$field->name}
                        && $field->type eq 'Select'
                        && $field->options->[0]->{'value'} eq '') {
                        # Add a placeholder for select menus that can be unselected
                        my $val = sprintf "%s (%s)", $self->_localize('Default'), $self->placeholders->{$field->name};
                        $field->element_attr({ 'data-placeholder' => $val });
                    }
                    elsif ($field->name !~ m/^(id|enabled|desc)$/ && $field->type eq 'Text') {
                        # Add a placeholder for text fields other than 'id', 'enabled' and 'desc'
                        $field->element_attr({ placeholder => $self->placeholders->{$field->name} });
                    }
                }
            }
        }
    }

    $self->SUPER::update_fields();
}


=head2 options_actions

=cut

sub options_actions {
    my $self = shift;

    my @actions = map { $_ => $self->_localize("${_}_action") } @pf::action::VIOLATION_ACTIONS;

    return @actions;
}

=head2 options_vclose

=cut

sub options_vclose {
    my $self = shift;

    # $self->violations comes from pfappserver::Model::Config::Violations->readAll
    my @violations = map { $_->{id} => $_->{desc} || $_->{id} } @{$self->form->violations} if ($self->form->violations);

    return ('' => '', @violations);
}

=head2 options_roles

=cut

sub options_roles {
    my $self = shift;

    my @roles = map { $_->{name} => $_->{name} } @{$self->form->roles} if ($self->form->roles);

    return ('' => '', @roles);
}

=head2 options_trigger

=cut

sub options_trigger {
    my $self = shift;

    # $self->triggers comes from pfappserver::Model::Config::Violations->list_triggers
    my @triggers = map {
        my ($type, $tid) = split(/::/);
        $_ => $self->_localize($type)."::$tid" } @{$self->form->triggers} if ($self->form->triggers);

    return @triggers;
}

=head2 options_template

=cut

sub options_template {
    my $self = shift;

    my @templates = map { $_ => "$_.html" } @{$self->form->templates} if ($self->form->templates);

    return @templates;
}

=head2 validate

Make sure the ID is a positive integer, unless its 'defaults'

Make sure a violation is specified if the close action is selected.

Make sure a role is specified if the role action is selected.

=cut

sub validate {
    my $self = shift;

    # Check the violation ID
    unless ($self->value->{id} =~ m/^(defaults|\d+)$/) {
        $self->field('id')->add_error('The violation ID must be a positive integer.');
    }

    # If the close action is selected, make sure a valid closing violation (vclose) is specified
    if (grep {$_ eq 'close'} @{$self->value->{actions}}) {
        my $vclose = $self->value->{vclose};
        my @vids = map { $_->{id} } @{$self->violations};
        unless (defined $vclose && grep {$_ eq $vclose} @vids) {
            $self->field('vclose')->add_error('Specify a violation to close.');
        }
    }

    # If the role action is selected, make sure a valid role (target_category) is specified
    if (grep {$_ eq 'role'} @{$self->value->{actions}}) {
        my $role = $self->value->{target_category};
        my $roles_ref = $self->roles;
        my @roles = map { $_->{name} } @$roles_ref;
        unless (defined $role && grep {$_ eq $role} @roles) {
            $self->field('target_category')->add_error('Specify a role to use.');
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
