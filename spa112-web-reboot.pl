#!/usr/bin/env perl
#
# Reboot Cisco SPA112 device via web interface
#
# Usage: spa112-web-reboot.pl <device ip or name>
#

use strict;
use LWP::UserAgent;
use Net::Netrc;
use Digest::MD5 qw(md5_hex);

sub valid_fqdn($);
sub enc_pass($);

if ( @ARGV != 1 || not valid_fqdn($ARGV[0]) ) {
    print "Usage: spa112-web-reboot.pl <device ip or name>\n";
    exit 1;
}

#
# Get session parameters:
#
my ($device_addr,$device_mach,$device_user,$device_pass);
$device_addr = $ARGV[0];
$device_mach = Net::Netrc->lookup($device_addr);

die "ERROR: can't obtain netrc credentials for $device_addr."
    if $device_mach eq '';

$device_user = $device_mach->login;
$device_pass = $device_mach->password;

#
# Initialize global variables:
#

# LWP agent
my $ua = LWP::UserAgent->new;
$ua->timeout(10);

# URI strings
my ($uri_login,$uri_reboot);
$uri_login = "http://$device_addr/login.cgi";
$uri_reboot = "http://$device_addr/apply.cgi;session_id=<session_key>";

# Forms data
my %form_login = (
    'submit_button' => 'login',
    'keep_name' => 0,
    'enc' => 1,
    'user' => $device_user,
    'pwd' => enc_pass($device_pass)
    );
my %form_reboot = (
    'submit_button' => 'Reboot',
    'gui_action' => 'Apply',
    'need_reboot' => 1,
    'session_key' => ''
    );

#
# Authorize on device
#
my $res;
$res = $ua->post($uri_login,\%form_login);

die "ERROR: auth failed on $device_addr. Got answer: ".$res->status_line
    unless $res->is_success;

#
# Parse session key
#
my $session_key = '';
$session_key = $1 if ( $res->content =~ /var session_key='(\w+)';/ );

die "ERROR: can't parse session key for $device_addr."
    if $session_key eq '';

#
# Send reboot command
#
$uri_reboot =~ s/<session_key>/$session_key/;
$form_reboot{'session_key'} = $session_key;
$res = $ua->post($uri_reboot,\%form_reboot);

die "ERROR: sending reboot command failed. Got answer: ".$res->status_line
    unless $res->is_success;

exit 0;

#
# Check if valid hostname or ip address
#
sub valid_fqdn($) {
    my $testval = shift(@_);
    ( $testval =~ m/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]+)\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/ ) ? return 1 : return 0;
}

#
# Calculate hash of 64-byte long password
#
sub enc_pass($) {
    my $data = shift;
    $data = sprintf('%s%02d',$data,length $data);
    $data .= $data while (length $data < 64);
    $data = substr $data,0,64;
    return md5_hex($data);
}
