
# $Id: Login.pm,v 1.4 2001/04/05 23:32:42 nwiger Exp nwiger $
####################################################################
#
# Copyright (c) 2000-2001 Nathan Wiger (nate@nateware.com)
#
# This is designed to simulate a command-line login on UNIX machines.
# In an array context it returns the std getpwnam array or undef,
# and in a scalar context it returns just the username or undef if
# the login fails.
#
####################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
####################################################################

#========================= Configuration ===========================

# Basic module setup
package Unix::Login;
require 5.004;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(login);

# Straight from CPAN
$VERSION = do { my @r=(q$Revision: 1.4 $=~/\d+/g); sprintf "%d."."%02d"x$#r,@r }; 

# Errors
use Carp;
use strict;

# Configuration - this is blessed into our object
my %CONF = (

   # Max login attempts
   attempts       => 3,
   
   # What todo on failure
   failmesg       => "Login incorrect\n",
   failsleep      => 3,

   # Misc default strings
   banner         => "Please Login\n",
   bannerfile     => '',
   login          => "login: ",
   password       => "Password: ",

   # Do we allow them to login with no password??
   passreq        => 1,

   # If can't find homedir
   nohomemesg     => "No home directory! Setting HOME=/\n",

   # Set ENV variables?
   setenv         => 1,
   clearenv       => 0,
   path           => '/usr/bin:',
   supath         => '/usr/sbin:/usr/bin',
   maildir        => '/var/mail',

   # Use TomC's User::pwent module?
   pwent          => 0,
   
   # Exec the person's shell?
   cdhome         => 0,
   execshell      => 0

);

#=========================== Functions =============================

#------------------------------------------------
# "Constructor" function to handle defaults
#------------------------------------------------

#######
# Usage: $ul = new Unix::Login (banner => "Welcome to Bob's");
#
# This constructs a new Unix::Login object
#######

sub new {
   # Easy mostly-std new()
   my $self = shift;
   my $class = ref($self) || $self;

   # override presets with remaining stuff in @_
   my(%conf) = (%CONF, @_);
   return bless \%conf, $class;
}

#------------------------------------------------
# Private Functions (for public see "/__DATA__")
#------------------------------------------------

#######
# Usage: my($self, @args) = _self_or_default(@_);
#
# This is completely stolen from the amazing CGI.pm. I did 
# not write this!! Thanks, Lincoln Stein! :-)
#######

sub _self_or_default {

   return @_ if defined($_[0]) && (!ref($_[0])) && ($_[0] eq 'Unix::Login');
   my $Q;
   unless (defined($_[0]) && (ref($_[0]) eq 'Unix::Login' || UNIVERSAL::isa($_[0],'Unix::Login'))) {
      $Q = Unix::Login->new unless defined($Q);
      unshift(@_, $Q);
   }
   return @_;
}

#------------------------------------------------
# Public functions - all are exportable
#------------------------------------------------

#######
# Usage: $ul->login;
#
# This is designed to simulate a command-line long on UNIX machines.
# In an array context it returns the std getpwnam array or undef,
# and in a scalar contact it returns just the username or undef if
# the login fails.
#
# The args are optional; if no args are given, then the default
# banner is the basename of the script (`basename $0`), the
# default login prompt is "login: ", the default password string
# is "Password: ", and the default fail string is "Login incorrect".
#######

sub login {

   my($self, @attr) = _self_or_default(@_);
   my %tmp = ( %{ $self } , @attr );
   my $conf = \%tmp;

   my($logintry, $passwdtry, @pwstruct);

   # Print out banner once
   print "\n", $conf->{banner}, "\n";

   # Read our banner file; we print this each iteration
   my $banner = '';
   if ( $conf->{bannerfile} ) {
      if ( open(BFILE, "<" . $conf->{bannerfile})) {
         $banner = join '', <BFILE>; 
         close BFILE;
      }
   }

   # While loop
   for(my $i=0; $i < $conf->{attempts}; $i++) {

      print $banner;

      do {
         print $conf->{login};
         $logintry = <STDIN>;
         return undef unless $logintry;   # catch ^D
         chomp $logintry;
      } while (! $logintry);

      # Like UNIX login, exit if no username
      return undef unless $logintry;
   
      # Look it up by name - explicitly say "CORE::"
      # since we may be using User::pwent...
      (@pwstruct) = CORE::getpwnam($logintry);

      # Lose the echo during password entry
      system 'stty -echo';
      print $conf->{password};
      chomp($passwdtry = <STDIN>);
      print "\n";
      system 'stty echo';
   
      # Determine the salt used
      $pwstruct[1] ||= '**' if $conf->{passreq};     # catch for missing password
      my($salt) = substr $pwstruct[1], 0, 2;

      # We're cool, let's go
      last if (crypt($passwdtry, $salt) eq $pwstruct[1]);

      # Fake a UNIX login prompt wait
      sleep $conf->{failsleep};
      print $conf->{failmesg};
   } 

   
   # Do a few basic things
   if ( $conf->{setenv} ) {
      undef %ENV if $conf->{clearenv};	# clean slate
      $ENV{LOGNAME} = $pwstruct[0];
      $ENV{PATH}    = ($pwstruct[2] == 0) ? $conf->{supath} : $conf->{path};
      $ENV{HOME}    = $pwstruct[7];
      $ENV{SHELL}   = $pwstruct[8];
      $ENV{MAIL}    = $conf->{maildir} . '/' . $pwstruct[0];
   }

   # Fork a shell if, for some strange reason, we are asked to.
   # We use the little-known indirect object form of exec()
   # to set $0 to -sh so we get a login shell.
   if ( $conf->{ExecShell} ) {
      (my $shell = $pwstruct[8]) =~ s!^.*/!!;	# basename
      exec { "$pwstruct[8]" } "-$shell";
   }

   if ( $conf->{cdhome} ) {
      # Like real login, try to chdir to homedir
      unless ( -d $pwstruct[7] && chdir $pwstruct[7] ) {
          warn $conf->{nohomemesg};
          $ENV{HOME} = '/';
      }
   }

   # Return appropriate info
   if ( wantarray ) {
      return @pwstruct;
   } elsif ( $conf->{pwent} ) {
      require User::pwent;
      return User::pwent::getpwnam($pwstruct[0]);
   } else {
      return $pwstruct[0];
   }
}

1;

#
# Documentation starts down here
#
__END__

=head1 NAME

Unix::Login - Customizable Unix login prompt and validation

=head1 SYNOPSIS

   #
   # You can use the object-oriented syntax...
   #
   use Unix::Login;

   my $ul = Unix::Login->new(banner => "-- Welcome to Newix --\n");
   my $username = $ul->login || exit 1;


   #
   # Or, use the shorter function-oriented syntax
   #
   use Unix::Login qw(login);
   
   my(@pwent) = login(login => "Username: ", cdhome => 1)
	|| die "Sorry, you don't know your own password!\n";


=head1 DESCRIPTION

This is a simple yet flexible module that provides a Unix-esque login
prompt w/ password validation. This can be used in custom applications
that need to validate the username/password of the person using the app.

The above examples are pretty much all you'll ever need (and all this
module provides). Here are some specifics on the two functions provided:

=head2 new(option => value, option => value)

This creates a new Unix::Login object. You only need to use this if
you're using the object-oriented calling form. The parameters accepted
and their default values are:

   attempts      Max login attempts [3]
   failmesg      Print this on failure ["Login incorrect\n"]
   failsleep     And sleep for this many seconds [3]

   banner        Banner printed once up top ["Please Login\n"]
   bannerfile    If set, printed after banner (i.e. /etc/issue) []
   login         Prompt asking for username ["login: "]
   password      Prompt asking for password ["Password: "]

   passreq       Require a password for all users? [1]
   nohomemesg    Printed if no homedir ["No home directory! Setting HOME=/\n"]

   setenv        If true, setup HOME and other %ENV variables [1]
   clearenv      If true, first undef %ENV before setenv [0]
   path          If setenv, set PATH to this for non-root [/usr/bin:]
   supath        If setenv, set PATH to this for root [/usr/sbin:/usr/bin]
   maildir       If setenv, set MAIL to this dir/username [/var/mail]

   pwent         Return a User::pwent struct in scalar context? [0]
   cdhome        Chdir to the person's homedir on success? [0]
   execshell     Execute the person's shell as login session? [0]

If the "pwent" option is set, then User::pwent is used to provide
an object in a scalar context. See the man page for User::pwent.

If the "execshell" option is set, then if login() is successful the
user's shell is forked and the current process is terminated,
just like a real Unix login session. 

With these options, you could create a very Unix-like login
with the following:

   use Unix::Login;

   my $ul = Unix::Login->new(bannerfile => '/etc/issue',
                             banner     => `uname -rs`,
                             setenv     => 1,
                             clearenv   => 1,
                             cdhome     => 1,
                             execshell  => 1);

   my(@pwent) = $ul->login || exit 1;

This will validate our login, clear our environment and reset
it, then exec the shell as a login shell just like a real life
Unix login.

=head2 login(option => value, option => value)

This prompts for the username and password and tries to validate
the login. On success, it returns the same thing that getpwuid()
does: the username in a scalar context, or the passwd struct as
a list in a list context. It returns undef on failure. 

Just like new(), you can pass it an optional set of parameters.
These will specify options for that login prompt only. As such,
you can create a fully-customized login screen from the
function-oriented calling form:

   use Unix::Login qw(login);

   my(@pwent) = login(login => "User: ", password => "Pass: ")
	|| die "Sorry, try remembering your password next time.\n";

This would create a simple dialog which would return the passwd
struct if the user could be logged in. So, unless you really
like OO modularity, or intend on calling login() multiple times
(in which case setting options via new() would give you an
advantage), use this form.

=head1 VERSION

$Id: Login.pm,v 1.4 2001/04/05 23:32:42 nwiger Exp nwiger $

=head1 SEE ALSO

User::pwent(3), login(1), perlfunc(1)

=head1 AUTHOR

Copyright (c) 2000-2001 Nathan Wiger <nate@nateware.com>. All Rights Reserved.

This module is free software; you may copy this under the terms of
the GNU General Public License, or the Artistic License, copies of
which should have accompanied your Perl kit.

=cut


