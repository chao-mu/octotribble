#!/usr/bin/env perl

use strict;
use warnings;

use v5.14;

# Core
use Data::Dumper;

# CPAN
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use Getopt::ArgParse;
use IO::Socket::IP;
use Net::Pcap;
use Net::Pcap::Easy;

sub assert_valid_ip;
sub assert_valid_port;
sub build_tcp_callback;

my $arg_parser = Getopt::ArgParse->new_parser(
  prog => 'Server Replay',
  description => 'Listens on a port and replays pcap content.'
);

$arg_parser->add_args(
  ['pcap', 'required' => 1],
  ['--port','default' => 55555],
  ['--host', 'default' => '127.0.0.1'],
  ['--client-ip', 'default' => '127.0.0.1'],
  ['--client-src-port', 'required' => 1],
  ['--server-ip', 'default' => '127.0.0.1'],
  ['--server-port', 'required' => 1],
);

my $args = $arg_parser->parse_args();

# Validate IP address parameters.
foreach my $host_arg_name (qw(host client_ip server_ip)) {
  assert_valid_ip($host_arg_name, $args->$host_arg_name);
}

# Validate port parameters.
foreach my $port_arg_name(qw(port client_src_port server_port)) {
  assert_valid_port($port_arg_name, $args->$port_arg_name);
}

# Open the PCAP.
my $error_msg;
my $pcap = pcap_open_offline($args->pcap, \$error_msg);
if (defined($error_msg)) {
  die "$error_msg\n";
}

# Listen on port.
my $port = $args->port;
my $bound_addr = $args->host;
say "Listening on $bound_addr:$port...";
my $server = IO::Socket::IP->new(
  'LocalHost' => $bound_addr,
  'LocalPort' => $port,
  'Listen' => 1,
  'Reuse' => 1
) or die "Cannot listen - $@\n";

# Accept a connection.
my $socket = $server->accept() or die "Accepting connection failed: $!\n";
say "Connection accepted!";

my $stream_details = {
  'client_ip' => $args->client_ip,
  'client_src_port' => $args->client_src_port,
  'server_ip' => $args->server_ip,
  'server_port' => $args->server_port
};

# Build what we will use to process our packets.
my $npe = Net::Pcap::Easy->new(
  'tcp_callback' => build_tcp_callback($stream_details),
  'pcap' => $pcap,
);

# Loop through the packets.
1 while ($npe->loop());

sub build_tcp_callback() {
  my ($stream_details) = @_;

  return sub () {
    my ($npe, $ether, $ip, $tcp, $header) = @_;

    my $data_length = length($tcp->{'data'});

    if (is_client_to_server($stream_details, $ip, $tcp) && $data_length > 0)
    {
      say "Expecting data from client.";
      my $pcap_data = $tcp->{'data'};
      my $data;
      $socket->recv(\$data, $data_length + 4096);
    }
    elsif (is_server_to_client($stream_details, $ip, $tcp) && $data_length > 0)
    {
      say "Sending data to client.";
      $socket->send($tcp->{'data'});
    }
  };
}

sub assert_valid_ip() {
  my ($arg_name, $ip) = @_;

  is_ipv4($ip) || is_ipv6($ip) or die "$arg_name must be a valid IP address\n";
}

sub assert_valid_port() {
  my ($arg_name, $port) = @_;

  $port =~ m/^\d+$/ or die "$arg_name must be a valid port\n";
}

sub is_client_to_server() {
  my ($stream_details, $ip, $tcp) = @_;

  return
    $ip->{'src_ip'} eq $stream_details->{'client_ip'} &&
    $ip->{'dest_ip'} eq $stream_details->{'server_ip'} &&
    $tcp->{'src_port'} eq $stream_details->{'client_src_port'} &&
    $tcp->{'dest_port'} eq $stream_details->{'server_port'};
}

sub is_server_to_client() {
  my ($stream_details, $ip, $tcp) = @_;

  return
    $ip->{'src_ip'} eq $stream_details->{'server_ip'} &&
    $ip->{'dest_ip'} eq $stream_details->{'client_ip'} &&
    $tcp->{'src_port'} eq $stream_details->{'server_port'} &&
    $tcp->{'dest_port'} eq $stream_details->{'client_src_port'};
}
