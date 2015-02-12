package pfconfig::cached_hash;

=head1 NAME

pfconfig::cached_hash

=cut

=head1 DESCRIPTION

pfconfig::cached_hash

This module serves as an interface to create a hash that
will proxy the access to it's attributes to the pfconfig
service

It is used as a bridge between a pfconfig namespace element
and a hash without having a memory footprint unless when
accessing data in the hash

=cut

=head1 USAGE

This class is used with tiying

Example : 
my %hash;
tie %hash, 'pfconfig::cached_hash', 'resource::default_switch';
print $hash{_ip};

This ties %hash to the namespace 'resource::default_switch' defined in
lib/pfconfig/namespaces/ and served though pfconfig

The access to the attribute _ip then generates a GET though pfconfig
that uses a UNIX socket

In order to call a method on this tied object 
my @keys = tied(%hash)->keys

=cut

use strict;
use warnings;

use Tie::Hash;
use IO::Socket::UNIX qw( SOCK_STREAM );
use JSON;
use pfconfig::timeme;
use List::MoreUtils qw(first_index);
use Data::Dumper;
use pfconfig::log;
our @ISA = ('Tie::StdHash');

# constructor of the tied hash
sub TIEHASH {
  my ($class, $config) = @_;
  my $self = bless {}, $class;

  $self->{"_namespace"} = $config;

  return $self;
}

# helper to build socket
sub get_socket {
  my $logger = get_logger;
  my $socket_path = '/dev/shm/pfconfig.sock';
  my $socket = IO::Socket::UNIX->new(
     Type => SOCK_STREAM,
     Peer => $socket_path,
  );
  return $socket;
}

sub get_from_subcache {
  my ($self, $key) = @_;
  if($self->is_valid()){
    return $self->{_subcache}{$key} if $self->{_subcache}{$key};
  }
  else{
    $self->{_subcache} = {};
    $self->{memorized_at} = time;
    return undef;
  }
  return undef;
}

sub set_in_subcache {
  my ($self, $key, $result) = @_;

  $self->{memorized_at} = time unless $self->{memorized_at};
  $self->{_subcache} = {} unless $self->{_subcache};
  $self->{_subcache}{$key} = $result;

} 

# accessor of the hash
sub FETCH {
  my ($self, $key) = @_;
  my $logger = get_logger;

  my $subcache_value = $self->get_from_subcache($key);
  return $subcache_value if $subcache_value; 

  return $self->{_internal_elements}{$key} if $self->{_internal_elements}{$key};

  my $reply = $self->_get_from_socket("$self->{_namespace};$key");
  my $result = $reply ? $self->_get_from_socket("$self->{_namespace};$key")->{element} : undef;

  $self->set_in_subcache($key, $result);

  return $result;
}

sub keys {
  my ($self) = @_;
  my $logger = get_logger;
  
  my @keys = @{$self->_get_from_socket($self->{_namespace}, "keys")};

  return @keys;
}

sub FIRSTKEY {
  my ($self) = @_;
  my $logger = get_logger;
  return $self->_get_from_socket($self->{_namespace}, "next_key", (last_key => undef))->{next_key};
}

sub NEXTKEY {
  my ($self, $last_key) = @_;
  my $logger = get_logger;
  return $self->_get_from_socket($self->{_namespace}, "next_key", (last_key => $last_key))->{next_key};
}

# setter of the hash
# stores it in the hash without any saving capabilities.
sub STORE {
  my( $self, $key, $value ) = @_;
  my $logger = get_logger;
  
  $self->{_internal_elements} = {} unless(defined($self->{_internal_elements}));

  $self->{_internal_elements}{$key} = $value;
}

sub _get_from_socket {
  my ($self, $what, $method, %additionnal_info) = @_;
  my $logger = get_logger;

  $method = $method || "hash_element";

  my %info = ((method => $method, key => $what), %additionnal_info);
  my $payload = encode_json(\%info);

  my $socket;
  
  # we need the connection to the cachemaster
  until($socket){
    $socket = $self->get_socket();
    last if($socket);
    $logger->error("Failed to connect to config service, retrying");
    select(undef, undef, undef, 0.1);
  }
     
  # we ask the cachemaster for our namespaced key
  my $line;
  pfconfig::timeme::timeme('socket fetching', sub {
    print $socket "$payload\n";
    chomp( $line = <$socket> );
  }, 0);

  # it returns it as a json hash - maybe not the best choice but it works
  my $result;
  pfconfig::timeme::timeme('decoding the socket result', sub {
    if($line && $line ne "undef"){
      $result = decode_json($line);
    }
    else {
      return undef;
    }
  }); 

  return $result
}

# helper to know if the raw memory cache is still valid
sub is_valid {
  my ($self) = @_;
  my $what = $self->{_namespace};
  my $logger = get_logger;
  my $control_file;
  ($control_file = $what) =~ s/\//;/g;
  my $file_timestamp = (stat("/usr/local/pf/var/".$control_file."-control"))[9];

  unless(defined($file_timestamp)){
    $logger->warn("Filesystem timestamp is not set for $what. Considering memory as invalid.");
    return 0;
  }

  my $memory_timestamp = $self->{memorized_at} || time;
  $logger->trace("Control file has timestamp $file_timestamp and memory has timestamp $memory_timestamp for key $what");
  # if the timestamp of the file is after the one we have in memory
  # then we are expired
  if ($memory_timestamp > $file_timestamp){
    $logger->trace("Memory configuration is still valid for key $what in local cached_hash");
    return 1;
  }
  else{
    $logger->info("Memory configuration is not valid anymore for key $what in local cached_hash");
    return 0;
  }
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

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:

