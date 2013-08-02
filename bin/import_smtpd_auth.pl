#!/usr/bin/perl -w 
use strict;
use lib '/home/jcmurphy/src/perl/WWW-Splunk-1.10/lib';
use Net::Syslog;
use WWW::Splunk;
use Getopt::Std;

BEGIN { 
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;
}

my %opts;
getopt('u:p:s:D:hS:');

help() if exists $opts{h};
my ($U, $P) = (shift, shift);
help() unless defined($U) && defined($P);

my $D = 1;

my $splunk = new WWW::Splunk ({
          host    => $opts{S},
          port    => 8089,
          login   => $U,
          password => $P,
          unsafe_ssl => 1,
	  debug   => $D
  });

die unless $splunk;


# fetch successful authentications
# postfix doesnt appear (from the eis logs) to log the username for unsuccessful
# authentication attempts, so we wont bother processing those

# TODO: record the time of the last fully successful run of this script. 
# use that time when setting earliest_time. that way if there are any
# exceptions, we will eventually (when splunk comes back) do a query spanning
# the entire time range that it was unavailable for.

my $sid = $splunk->start_search ( { search => 'search sasl_method=LOGIN client=* sasl_username=*', 
				    earliest_time => '-1h',
				    #earliest_time => '2011-07-12 00:00',
				    #latest_time => '2011-07-12 12:00',
				    #time_format => '%Y-%m-%d %H:%M'
				}
				  );
L("sid $sid\n") if $D;

$splunk->poll_search ($sid);

use Data::Dumper;

my $sl = new Net::Syslog(Facility => 'mail', Priority => 'notice',
			 SyslogHost => $opts{s}
);

L("Waiting on results ..\n") if $D;

until ($splunk->results_read ($sid)) {
    L("Got results ..\n") if $D;
    my @res = $splunk->search_results($sid);
    L("Found " . ($#res+1) . " results.\n") if $D;
    foreach my $r (@res) {
		# client may be 'unknown[1.1.1.1]' for example if no DNS is available

		if (exists $r->{sasl_method}) {
		    $sl->send(cef($r->{_time},
			      $r->{sasl_username},
			      $r->{client},
			      $r->{host}));
		}

    }
}





exit 0;

sub help {
	print "
$0 [-D 0-9] [-h] <-w file>  <-S splunk server> <-s syslogserver> <username> <password>
   -D #      - debug level
   -w file   - write records to csv file
   -S server - read records from this splunk server
   -s server - send records in CEF format to syslog server\n";
	exit 0;
}

sub username {
    my $u = shift;
    $u =~ s/\@.*$//g;
    return $u;
}

sub client {
    my $c = shift;
    my @a = split(/\[/, $c);

    $a[1] =~ s/\]//g;
    return ($a[0], $a[1]);
}

sub convtime {
    my $t = shift;
    if ($t =~ /^(\d+)-(\d+)-(\d+)T(\d\d:\d\d:\d\d)/) {
	return ('ERR', 'JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC')[$2] ." $3 $1 $4";
    }
    return $t;
}

sub cef {
    my ($t, $u, $cn, $cip, $h) = (convtime(shift), username(shift), client(shift), shift);

    my $cef = "CEF:0|Postfix|Postfix|2|101|SMTP Authentication|2|act=Permit app=SMTP dvchost=$h proto=TCP";
    $cef .= " categorySignificance=/Informational categoryBehavior=/Authentication/Verify categoryOutcome=/Success categoryObject=/Host/Application/Service categoryDeviceGroup=/Application ";
    $cef .= " src=$cip ";
    $cef .= " shost=$cn " if $cn ne "unknown";
    $cef .= " suser=$u ";
    $cef .= " rt=$t start=$t msg=Successful SMTP authentication";

    return $cef;
}

sub L {
	my $m = shift;
	print scalar localtime, " ", $m;
}
