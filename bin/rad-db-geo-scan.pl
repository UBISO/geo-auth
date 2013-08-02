#!/usr/bin/perl -w
use strict;
use DBI;
use Data::Dumper;
use Net::LDAP;
use Try::Tiny;
use Getopt::Std;
use Config::Simple;

use UB::GeoScan;
use UB::AuthRecs;
use UB::AuthRecs::Radius;

my $D      = 0;

my %opts;
getopt( 'D:hH:w:U:c:', \%opts );

help("help requested") if exists $opts{h};

if ( exists $opts{D} ) {
	print "Debugging output enabled.\n";
	$D = $opts{D};
}

my $cfgfn = "/etc/geoauth.cfg";
$cfgfn = $opts{c} if( exists $opts{c} ); 
my $cfg = new Config::Simple();
$cfg->read($cfgfn) or help("failed to read config file: " . $cfg->error());


try {

	my $authdb = new UB::AuthRecs::Radius(
		{
			raddbdsn     => $cfg->param('radiusdb.dsn'),
			raddbuser    => $cfg->param('radiusdb.user'),
			raddbpass    => $cfg->param('radiusdb.pass'),
			debug        => $opts{D}
		}
	);

	my $geo = new UB::GeoScan(
	{
       ldap_server => $cfg->param("ldap.server"),
       ldap_binddn => $cfg->param("ldap.binddn"),
       ldap_base   => $cfg->param("ldap.base"),
       ldap_filter => $cfg->param("ldap.filter"),
       locdb_dsn   => $cfg->param("locationdb.dsn"),
       locdb_user  => $cfg->param("locationdb.user") || '',
       locdb_pass  => $cfg->param("locationdb.pass") || '' 
      }
    );
	
	my $numhrsago = $opts{H} || 2;
	my $sometimeago = time() - $numhrsago * 60 * 60;

	my $a = $authdb->fetch_records($sometimeago, $opts{U});

	print "" . ( $#$a + 1 ) . " records to consider.\n" if $D;
	print "User_Name, Local_Address, Remote_Address, NAS, Login_Time, Duration, Country, Region, City, Lat, Long\n"
	  if $D;

	my $byuser   = {};
	my $ldapuser = {};

	foreach my $r (@$a) {
		my ( $username, $localaddress, $remoteaddress, $nas, $logintime, $duration ) = @$r;

		next if ( $localaddress eq 'none' );
		next if ( $localaddress ne 'none' ) && $geo->rfc1918($localaddress);
		next if ( $localaddress ne 'none' ) && !$geo->ub($localaddress);
		  # sometimes the waps log the users previous IP, if they were travelling it will be a non-UB IP. skip those records.

		$remoteaddress = ( ( $remoteaddress eq 'none' ) ? $localaddress : $remoteaddress );
		  # use the wireless address if remote is 'none'

		my ( $cc, $reg, $city, $lat, $lon ) = $geo->lookuploc($remoteaddress);
		print join( ', ', @$r, $cc, $reg, $city, $lat, $lon ) . "\n" if $D;

		push @{ $byuser->{$username} },
		  {
			'localaddress'        => $localaddress,
			'remoteaddress'       => $remoteaddress,
			'nas'                 => $nas,
			'logintimestamp'      => $logintime,
			'logintime (eastern)' => scalar localtime($logintime),
			'duration'            => $duration,
			'country'             => $cc,
			'region'              => $reg,
			'city'                => $city,
			'lat'                 => $lat,
			'lon'                 => $lon
		  };

		$ldapuser->{$username} = $geo->lookupldap($username)
		  unless exists( $ldapuser->{$username} );
	}

# now loop over each user, as long as they have >1 record,
# do a velocity measurement between each couple. if vel exceeds 600 mph, print out
# records

	my @matches     = ();
	my $results     = {};
	my $userdetails = {};
	
	foreach my $u ( sort keys %$byuser ) {
		if ( $#{ $byuser->{$u} } > 0 ) {
			for ( my $i = 0 ; $i < $#{ $byuser->{$u} } ; $i++ ) {
				my $d = $geo->distance(
					$byuser->{$u}->[$i]->{lat},
					$byuser->{$u}->[$i]->{lon},
					$byuser->{$u}->[ $i + 1 ]->{lat},
					$byuser->{$u}->[ $i + 1 ]->{lon}
				);
				my $t =
				  $byuser->{$u}->[ $i + 1 ]->{logintimestamp} -
				  $byuser->{$u}->[$i]->{logintimestamp} +
				  $byuser->{$u}->[$i]->{duration};
				$t = 1 unless $t;    # no div/0
				my $v = $d / ( $t / ( 60 * 60 ) );

				if ( $v > 600 ) {
					push @matches, $u;
					$results->{$u} .= sprintf(
						"%-20.20s %-20.20s %10.2f %6.0d %8.2f\n",
						join( '/',
							$byuser->{$u}->[$i]->{country},
							$byuser->{$u}->[$i]->{region},
							$byuser->{$u}->[$i]->{city} ),
						join( '/',
							$byuser->{$u}->[ $i + 1 ]->{country},
							$byuser->{$u}->[ $i + 1 ]->{region},
							$byuser->{$u}->[ $i + 1 ]->{city} ),
						$d, $t,
						$v
					);
					
					if ( !exists $userdetails->{$u} ) {
						if ( defined( $ldapuser->{$u} ) ) {
							foreach my $attr ( $ldapuser->{$u}->attributes ) {
								$userdetails->{$u} .= sprintf( "%24.24s: %s\n",
									$attr, $ldapuser->{$u}->get_value($attr) );
							}
						}
						else {
							$userdetails->{$u} = "user not in ldap?\n";
						}
					}
				}
			}
		}
	}

	if ( $#matches == -1 ) {
		print "Nothing interesting.\n" if $D;
	}
	
	else {
		my $formatted = '';
		my $numu      = scalar keys %$results;
		foreach my $u ( sort keys %$results ) {
			$formatted .= "Username: $u\n";
			$formatted .= $userdetails->{$u} . "\n";
			$formatted .= sprintf( "%-20.20s %-20.20s %12s %6s %8s\n",
				"Origin", "Destination", "Distance", "Time", "Velocity" );
			$formatted .= sprintf( "%-20.20s %-20.20s %12s %6s %8s\n",
				"(Country)", "(Country)", "(Miles)", "(Secs)", "(mph)" );

			$formatted .= "-" x 78 . "\n";
			$formatted .= $results->{$u} . "\n";
		}
		if ($D) {
			print $formatted;
		}
		else {
			my $mailto = $cfg->param('radiushits.to') || $cfg->param('smtp.to');
			my $mailfrom = $cfg->param('radiushits.from') || $cfg->param('smtp.from');
			my $subj = $cfg->param('radiushits.subject');
			sendmail( $mailfrom, $mailto, "SMTP suspicious logins: $numu user(s)",
				$formatted );
		}
	}
	
	

}
catch {
	if ($D) {
		print "ERROR $_\n";
	}
	else {
		sendmail( $cfg->param('errorsfrom'), $cfg->param('errorsto'), "ERROR $0", $_ );
	}
};

exit 0;

sub sendmail {
	my ( $from, $to, $subj, $txt ) = ( shift, shift, shift, shift );

	use Net::SMTP;
	my $smtp = Net::SMTP->new($cfg->param('smtp.server'));
	$smtp->mail( $from );
	$smtp->to($to);
	$smtp->data();
	$smtp->datasend("To: $to\nSubject: $subj");
	$smtp->datasend("\n");
	$smtp->datasend($txt);
	$smtp->dataend();
	$smtp->quit;
}

sub help {
	my $m = shift;

	print "
$0 [-D 0-9] [-h] <-w dir> <-H hoursago>
   -D #        - debug level
   -h          - this message
   -c cfg      - config file, default: /etc/geoauth.cfg
   -w dir      - output webalized information to this dir
   -H hoursago - number of hours before now to query over, default=2
   -U user     - defaults to * [remember: username may be xx\@example.com or AD\\xx so you probably want
                 to specify -U %username%\n\n$m\n";
	exit 0;
}

