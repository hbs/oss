#!/usr/bin/perl -w 
#
# Proxy dialogue with SSH Agent Unix socket for platforms
# on which Unix Domain Sockets support in Java using JUDS
# is difficult to provide
#
# Copyright 2012-2013 Mathias Herberts 
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

use strict;

use Fcntl;

use IO::Socket::UNIX qw( SOCK_STREAM );

my $socket_path = $ENV{"SSH_AUTH_SOCK"};

my $socket = IO::Socket::UNIX->new(
   Type => SOCK_STREAM,
   Peer => $socket_path,
) or die("Can't connect to ssh-agent: $!\n");

#
# Open OUT first as OSSClient opens juds.in first
# Otherwise a deadlock could happen
#
sysopen(OUT, $ARGV[1], Fcntl::O_WRONLY);
sysopen(IN, $ARGV[0], Fcntl::O_RDONLY);

#
# Make I/O unbuffered
#

select($socket); $| = 1;
select(IN); $| = 1;
select(OUT); $| = 1;

our ($rin) = "";

vec($rin,fileno(IN),1) = 1;
vec($rin,fileno($socket),1) = 1;

while(1) {
  my $rout;
  my $eout;
  my $nfound;
  my $timeleft;

  ($nfound, $timeleft) = select($rout=$rin, '', $eout=$rin, 0.1);

  next unless $nfound;

  if (vec($rout,fileno(IN),1) == 1) {
    my $buf;
    sysread(IN, $buf, 1);
    if (0 == length($buf)) { exit(0); }
    $socket->send($buf);
  }

  if (vec($rout,fileno($socket),1) == 1) {
    my $buf;
    $socket->recv($buf, 1);
    if (0 == length($buf)) { exit(0); }
    syswrite(OUT, $buf, length $buf);
  }
}
